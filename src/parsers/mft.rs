use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};

use indicatif::{ProgressBar, ProgressStyle};
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::x30::FileNameAttr;
use mft::attribute::MftAttributeContent;
use mft::MftParser;

use crate::timefmt::format_unix_timestamp;
use crate::timeline::{join_macb_flags, TimelineEntry};

#[derive(Default)]
pub struct MftParseOptions {
    pub include_file_name_timestamps: bool,
    pub resident_dir: Option<PathBuf>,
    pub resident_report: Option<PathBuf>,
    pub drive_letter: Option<char>,
    pub quiet: bool,
}

#[derive(Default)]
pub struct ResidentStats {
    pub total_extracted: usize,
    pub total_bytes: u64,
}

/// Helper struct to hold unique timestamp entries for an attribute
struct TimestampCollector {
    // map: (secs, nanos) -> macb string
    entries: HashMap<(i64, u32), String>,
}

impl TimestampCollector {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn add(&mut self, ts: &mft::Timestamp, flag: char) {
        let secs = ts.as_second();
        // Ignore epoch zero / invalid timestamps
        if secs <= 0 {
            return;
        }
        let nanos = ts.subsec_nanosecond().max(0) as u32;
        let key = (secs, nanos);
        let current = self.entries.entry(key).or_insert_with(|| "....".to_string());
        *current = join_macb_flags(current, flag);
    }
}

pub fn parse_mft_reader<R: Read + Seek>(
    reader: R,
    options: &MftParseOptions,
) -> Result<(Vec<TimelineEntry>, ResidentStats), Box<dyn std::error::Error + Send + Sync>> {
    let mut parser = MftParser::from_read_seek(reader, None)?;
    let entry_count = parser.get_entry_count();

    let pb = if !options.quiet {
        let pb = ProgressBar::new(entry_count);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} entries ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    let mut timeline = Vec::new();
    let mut resident_stats = ResidentStats::default();
    let drive_prefix = options.drive_letter.unwrap_or('C');

    // Iterate by entry number to allow calling parser.get_full_path_for_entry(&entry) safely
    for entry_num in 0..entry_count {
        if let Some(ref pb) = pb {
            pb.inc(1);
        }

        let entry = match parser.get_entry(entry_num) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Skip base records that have no valid attributes or corrupted headers
        let entry_id = entry.header.record_number;
        let is_dir = entry.is_dir();
        let is_allocated = entry.is_allocated();

        let base_mode = if is_dir {
            "d/drwxrwxrwx".to_string()
        } else {
            "-/-rwxrwxrwx".to_string()
        };

        let status_flag = if is_allocated {
            String::new()
        } else {
            " (deleted)".to_string()
        };

        // Try to get full path
        let resolved_path = match parser.get_full_path_for_entry(&entry) {
            Ok(Some(p)) => {
                let p_str = p.to_string_lossy();
                format!("{}:\\{}", drive_prefix, p_str.trim_start_matches(['\\', '/']))
            }
            _ => {
                // Fallback to best name or unknown
                if let Some(best_name) = entry.find_best_name_attribute() {
                    format!("{}:\\[UNKNOWN]\\{}", drive_prefix, best_name.name)
                } else {
                    format!("{}:\\[UNKNOWN]\\entry_{}", drive_prefix, entry_id)
                }
            }
        };

        // Collect attributes: $STANDARD_INFORMATION (0x10), $FILE_NAME (0x30), $DATA (0x80)
        let mut std_info: Option<StandardInfoAttr> = None;
        let mut fn_attrs: Vec<FileNameAttr> = Vec::new();
        let mut file_size: u64 = 0;
        let mut ads_streams: Vec<(String, u64)> = Vec::new();

        for attr_res in entry.iter_attributes() {
            let attr = match attr_res {
                Ok(a) => a,
                Err(_) => continue,
            };

            match &attr.data {
                MftAttributeContent::AttrX10(info) => {
                    std_info = Some(info.clone());
                }
                MftAttributeContent::AttrX30(fn_attr) => {
                    if file_size == 0 && fn_attr.logical_size > 0 {
                        file_size = fn_attr.logical_size;
                    }
                    fn_attrs.push(fn_attr.clone());
                }
                MftAttributeContent::AttrX80(data_attr) => {
                    let attr_name = attr.header.name.clone();
                    let data_bytes = data_attr.data();
                    let stream_size = data_bytes.len() as u64;

                    if attr_name.is_empty() {
                        if stream_size > 0 {
                            file_size = stream_size;
                        }
                        // Check resident extraction
                        if let Some(ref res_dir) = options.resident_dir {
                            if !data_bytes.is_empty() && !is_dir {
                                extract_resident_file(
                                    res_dir,
                                    &resolved_path,
                                    data_bytes,
                                    &mut resident_stats,
                                );
                            }
                        }
                    } else {
                        // Alternate Data Stream (ADS)
                        ads_streams.push((attr_name.clone(), stream_size));

                        if let Some(ref res_dir) = options.resident_dir {
                            if !data_bytes.is_empty() {
                                let ads_path = format!("{}:{}", resolved_path, attr_name);
                                extract_resident_file(
                                    res_dir,
                                    &ads_path,
                                    data_bytes,
                                    &mut resident_stats,
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // 1. Process $STANDARD_INFORMATION (0x10) timestamps
        if let Some(info) = std_info {
            let mut collector = TimestampCollector::new();
            collector.add(&info.modified, 'm');
            collector.add(&info.accessed, 'a');
            collector.add(&info.mft_modified, 'c');
            collector.add(&info.created, 'b');

            for ((secs, nanos), macb) in collector.entries {
                if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
                    let full_name = format!("{}{}", resolved_path, status_flag);
                    timeline.push(TimelineEntry::new(
                        ts_iso,
                        secs,
                        nanos,
                        file_size,
                        macb,
                        base_mode.clone(),
                        0,
                        0,
                        entry_id.to_string(),
                        full_name,
                    ));

                    // Add entries for ADS if any
                    for (stream_name, stream_size) in &ads_streams {
                        let ads_full_name = format!("{}:{}{}", resolved_path, stream_name, status_flag);
                        timeline.push(TimelineEntry::new(
                            format_unix_timestamp(secs, nanos).unwrap_or_default(),
                            secs,
                            nanos,
                            *stream_size,
                            "....".to_string(),
                            base_mode.clone(),
                            0,
                            0,
                            entry_id.to_string(),
                            ads_full_name,
                        ));
                    }
                }
            }
        }

        // 2. Process $FILE_NAME (0x30) timestamps if requested
        if options.include_file_name_timestamps {
            for fn_attr in fn_attrs {
                let mut collector = TimestampCollector::new();
                collector.add(&fn_attr.modified, 'm');
                collector.add(&fn_attr.accessed, 'a');
                collector.add(&fn_attr.mft_modified, 'c');
                collector.add(&fn_attr.created, 'b');

                for ((secs, nanos), macb) in collector.entries {
                    if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
                        let fn_full_name = format!("{}{} ($FILE_NAME: {})", resolved_path, status_flag, fn_attr.name);
                        let fn_size = if fn_attr.logical_size > 0 {
                            fn_attr.logical_size
                        } else {
                            file_size
                        };

                        timeline.push(TimelineEntry::new(
                            ts_iso,
                            secs,
                            nanos,
                            fn_size,
                            macb,
                            base_mode.clone(),
                            0,
                            0,
                            entry_id.to_string(),
                            fn_full_name,
                        ));
                    }
                }
            }
        }
    }

    if let Some(pb) = pb {
        pb.finish_with_message("MFT parsing completed");
    }

    // Write resident extraction report if requested
    if let Some(ref report_path) = options.resident_report {
        let mut rep = File::create(report_path)?;
        writeln!(rep, "=== Resident Files Extraction Summary ===")?;
        writeln!(rep, "Total resident files extracted: {}", resident_stats.total_extracted)?;
        writeln!(rep, "Total bytes extracted: {} bytes ({:.2} MB)", resident_stats.total_bytes, resident_stats.total_bytes as f64 / 1_048_576.0)?;
    }

    Ok((timeline, resident_stats))
}

pub fn parse_mft_file(
    mft_path: &Path,
    options: &MftParseOptions,
) -> Result<(Vec<TimelineEntry>, ResidentStats), Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(mft_path)?;
    let reader = BufReader::new(file);
    parse_mft_reader(reader, options)
}

fn extract_resident_file(
    out_dir: &Path,
    file_path: &str,
    data: &[u8],
    stats: &mut ResidentStats,
) {
    // Sanitize path for safe filesystem extraction
    let clean_path = file_path
        .replace(":\\", "/")
        .replace(":/", "/")
        .replace('\\', "/")
        .replace(':', "_");
    let safe_rel = clean_path.trim_start_matches('/');

    let target_path = out_dir.join(safe_rel);
    if let Some(parent) = target_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Ok(mut f) = File::create(&target_path) {
        if f.write_all(data).is_ok() {
            stats.total_extracted += 1;
            stats.total_bytes += data.len() as u64;
        }
    }
}
