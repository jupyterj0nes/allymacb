use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt};
use indicatif::{ProgressBar, ProgressStyle};

use crate::error::{AllyError, ErrorCode, Result};
use crate::timefmt::{filetime_to_datetime, format_utc_iso};
use crate::anomaly;
use crate::timeline::{source, TimelineEntry};

/// Parent-directory path cache: MFT entry number -> (full directory path, size).
/// When present, the directory path of the record's *parent* reference is
/// looked up and joined with the file name carried by the USN record itself,
/// so RENAME_OLD_NAME / FILE_DELETE records keep their historical name.
pub type MftPathCache = HashMap<u64, (String, u64)>;

pub struct UsnParseOptions {
    pub drive_letter: Option<char>,
    pub quiet: bool,
    pub mft_path_cache: Option<MftPathCache>,
}

/// Statistics about records that were skipped, so the caller can surface them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UsnParseReport {
    pub records_parsed: usize,
    pub records_v4_skipped: usize,
    pub records_unsupported_version: usize,
    pub records_invalid_length: usize,
    pub records_no_timestamp: usize,
}

pub const USN_REASON_DESIRED_STORAGE_CLASS_CHANGE: u32 = 0x0100_0000;

/// Decodes USN Reason bitflags into human readable string
pub fn decode_usn_reason(reason: u32) -> String {
    let mut parts = Vec::new();

    if reason & 0x00000001 != 0 { parts.push("DATA_OVERWRITE"); }
    if reason & 0x00000002 != 0 { parts.push("DATA_EXTEND"); }
    if reason & 0x00000004 != 0 { parts.push("DATA_TRUNCATION"); }
    if reason & 0x00000010 != 0 { parts.push("NAMED_DATA_OVERWRITE"); }
    if reason & 0x00000020 != 0 { parts.push("NAMED_DATA_EXTEND"); }
    if reason & 0x00000040 != 0 { parts.push("NAMED_DATA_TRUNCATION"); }
    if reason & 0x00000100 != 0 { parts.push("FILE_CREATE"); }
    if reason & 0x00000200 != 0 { parts.push("FILE_DELETE"); }
    if reason & 0x00000400 != 0 { parts.push("EA_CHANGE"); }
    if reason & 0x00000800 != 0 { parts.push("SECURITY_CHANGE"); }
    if reason & 0x00001000 != 0 { parts.push("RENAME_OLD_NAME"); }
    if reason & 0x00002000 != 0 { parts.push("RENAME_NEW_NAME"); }
    if reason & 0x00004000 != 0 { parts.push("INDEXABLE_CHANGE"); }
    if reason & 0x00008000 != 0 { parts.push("BASIC_INFO_CHANGE"); }
    if reason & 0x00010000 != 0 { parts.push("HARD_LINK_CHANGE"); }
    if reason & 0x00020000 != 0 { parts.push("COMPRESSION_CHANGE"); }
    if reason & 0x00040000 != 0 { parts.push("ENCRYPTION_CHANGE"); }
    if reason & 0x00080000 != 0 { parts.push("OBJECT_ID_CHANGE"); }
    if reason & 0x00100000 != 0 { parts.push("REPARSE_POINT_CHANGE"); }
    if reason & 0x00200000 != 0 { parts.push("STREAM_CHANGE"); }
    if reason & 0x00400000 != 0 { parts.push("TRANSACTED_CHANGE"); }
    if reason & 0x00800000 != 0 { parts.push("INTEGRITY_CHANGE"); }
    if reason & USN_REASON_DESIRED_STORAGE_CLASS_CHANGE != 0 { parts.push("DESIRED_STORAGE_CLASS_CHANGE"); }
    if reason & 0x80000000 != 0 { parts.push("CLOSE"); }

    // Any bit we do not know about is still shown so nothing is lost.
    let known: u32 = 0x01FF_FFFF | 0x8000_0000;
    let unknown = reason & !known;
    let mut out = parts.join("+");
    if unknown != 0 {
        if !out.is_empty() {
            out.push('+');
        }
        out.push_str(&format!("0x{:08X}", unknown));
    }

    if out.is_empty() {
        format!("0x{:08X}", reason)
    } else {
        out
    }
}

pub fn decode_usn_file_attributes(attrs: u32) -> String {
    if attrs & 0x10 != 0 {
        "d/drwxrwxrwx".to_string()
    } else {
        "-/-rwxrwxrwx".to_string()
    }
}

/// Minimal header size: RecordLength(4) + MajorVersion(2) + MinorVersion(2).
const USN_COMMON_HEADER: u64 = 8;
/// USN_RECORD_V2 fixed part is 60 bytes, USN_RECORD_V3 is 76 bytes.
const USN_V2_FIXED: u64 = 60;
const USN_V3_FIXED: u64 = 76;
const USN_MAX_RECORD: u64 = 4096;

/// A decoded fixed part of a V2/V3 record, before the file name.
struct UsnFixed {
    /// Low 48 bits of the file reference (MFT entry number).
    entry_id: u64,
    /// Sequence number of the file reference (reserved for MFT cross-checks).
    #[allow(dead_code)]
    sequence: u16,
    parent_entry_id: u64,
    filetime: u64,
    reason: u32,
    file_attributes: u32,
    file_name_length: u64,
    file_name_offset: u64,
}

fn read_v2_fixed<R: Read>(r: &mut R) -> std::io::Result<UsnFixed> {
    let file_ref = r.read_u64::<LittleEndian>()?;
    let parent_ref = r.read_u64::<LittleEndian>()?;
    let _usn = r.read_i64::<LittleEndian>()?;
    let filetime = r.read_u64::<LittleEndian>()?;
    let reason = r.read_u32::<LittleEndian>()?;
    let _source_info = r.read_u32::<LittleEndian>()?;
    let _security_id = r.read_u32::<LittleEndian>()?;
    let file_attributes = r.read_u32::<LittleEndian>()?;
    let file_name_length = r.read_u16::<LittleEndian>()? as u64;
    let file_name_offset = r.read_u16::<LittleEndian>()? as u64;
    Ok(UsnFixed {
        entry_id: file_ref & 0x0000_FFFF_FFFF_FFFF,
        sequence: (file_ref >> 48) as u16,
        parent_entry_id: parent_ref & 0x0000_FFFF_FFFF_FFFF,
        filetime,
        reason,
        file_attributes,
        file_name_length,
        file_name_offset,
    })
}

/// USN_RECORD_V3: 128-bit FILE_ID_128 references (ReFS / NTFS with 128-bit IDs).
/// For NTFS the first 64 bits hold the classic MFT reference.
fn read_v3_fixed<R: Read>(r: &mut R) -> std::io::Result<UsnFixed> {
    let file_ref_lo = r.read_u64::<LittleEndian>()?;
    let _file_ref_hi = r.read_u64::<LittleEndian>()?;
    let parent_ref_lo = r.read_u64::<LittleEndian>()?;
    let _parent_ref_hi = r.read_u64::<LittleEndian>()?;
    let _usn = r.read_i64::<LittleEndian>()?;
    let filetime = r.read_u64::<LittleEndian>()?;
    let reason = r.read_u32::<LittleEndian>()?;
    let _source_info = r.read_u32::<LittleEndian>()?;
    let _security_id = r.read_u32::<LittleEndian>()?;
    let file_attributes = r.read_u32::<LittleEndian>()?;
    let file_name_length = r.read_u16::<LittleEndian>()? as u64;
    let file_name_offset = r.read_u16::<LittleEndian>()? as u64;
    Ok(UsnFixed {
        entry_id: file_ref_lo & 0x0000_FFFF_FFFF_FFFF,
        sequence: (file_ref_lo >> 48) as u16,
        parent_entry_id: parent_ref_lo & 0x0000_FFFF_FFFF_FFFF,
        filetime,
        reason,
        file_attributes,
        file_name_length,
        file_name_offset,
    })
}

pub fn parse_usn_reader<R: Read + Seek>(
    reader: R,
    total_size: u64,
    options: &UsnParseOptions,
) -> Result<Vec<TimelineEntry>> {
    let (timeline, _report) = parse_usn_reader_with_report(reader, total_size, options)?;
    Ok(timeline)
}

pub fn parse_usn_reader_with_report<R: Read + Seek>(
    mut reader: R,
    total_size: u64,
    options: &UsnParseOptions,
) -> Result<(Vec<TimelineEntry>, UsnParseReport)> {
    let mut timeline = Vec::new();
    let mut report = UsnParseReport::default();
    let drive_prefix = options.drive_letter.unwrap_or('C');

    let pb = if !options.quiet && total_size > 0 {
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    let mut current_offset: u64 = 0;
    let mut buf_4 = [0u8; 4];

    while current_offset + USN_COMMON_HEADER <= total_size {
        if let Some(ref pb) = pb {
            pb.set_position(current_offset);
        }

        reader.seek(SeekFrom::Start(current_offset)).map_err(|e| AllyError::Io {
            code: ErrorCode::IoError,
            source: e,
            context: format!("Seeking to USN offset 0x{:X}", current_offset),
        })?;

        if reader.read_exact(&mut buf_4).is_err() {
            break;
        }

        let record_len = u32::from_le_bytes(buf_4) as u64;

        // Skip null padding (common in USN journal cluster alignment)
        if record_len == 0 {
            current_offset += 4;
            continue;
        }

        // Validate sanity of record length (8-byte aligned, within file)
        if record_len < USN_V2_FIXED
            || record_len > USN_MAX_RECORD
            || record_len % 8 != 0
            || current_offset + record_len > total_size
        {
            report.records_invalid_length += 1;
            current_offset += 4;
            continue;
        }

        let major_ver = match reader.read_u16::<LittleEndian>() {
            Ok(v) => v,
            Err(e) => {
                return Err(AllyError::Usn {
                    code: ErrorCode::UsnTruncated,
                    offset: current_offset,
                    message: format!("Failed reading major version: {}", e),
                });
            }
        };
        let _minor_ver = reader.read_u16::<LittleEndian>().unwrap_or(0);

        let fixed = match major_ver {
            2 => read_v2_fixed(&mut reader),
            3 => {
                if record_len < USN_V3_FIXED {
                    report.records_invalid_length += 1;
                    current_offset += 4;
                    continue;
                }
                read_v3_fixed(&mut reader)
            }
            4 => {
                // USN_RECORD_V4 carries range-tracking extents only: no timestamp, no name.
                report.records_v4_skipped += 1;
                current_offset += record_len;
                continue;
            }
            _ => {
                report.records_unsupported_version += 1;
                current_offset += record_len;
                continue;
            }
        };
        let fixed = match fixed {
            Ok(f) => f,
            Err(e) => {
                return Err(AllyError::Usn {
                    code: ErrorCode::UsnTruncated,
                    offset: current_offset,
                    message: format!("Failed reading V{} record body: {}", major_ver, e),
                });
            }
        };

        // Extract filename, bounded by the record itself
        let mut file_name = String::new();
        let name_end = fixed.file_name_offset.saturating_add(fixed.file_name_length);
        if fixed.file_name_length > 0 && fixed.file_name_offset >= USN_COMMON_HEADER && name_end <= record_len {
            let _ = reader.seek(SeekFrom::Start(current_offset + fixed.file_name_offset));
            let mut name_bytes = vec![0u8; fixed.file_name_length as usize];
            if reader.read_exact(&mut name_bytes).is_ok() {
                let u16_chars: Vec<u16> = name_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                file_name = String::from_utf16_lossy(&u16_chars);
            }
        }

        let entry_id = fixed.entry_id;

        if let Some(dt) = filetime_to_datetime(fixed.filetime) {
            let ts_iso = format_utc_iso(dt);
            let secs = dt.timestamp();
            let nanos = dt.timestamp_subsec_nanos();

            let unknown_name = || {
                if !file_name.is_empty() {
                    format!("{}:\\[UNKNOWN]\\{}", drive_prefix, file_name)
                } else {
                    format!("{}:\\[UNKNOWN]\\entry_{}", drive_prefix, entry_id)
                }
            };

            let (full_path, size) = match options.mft_path_cache.as_ref() {
                Some(cache) => {
                    // Directory from the parent reference + the historical name in
                    // the record. Size from the file's own current entry when known.
                    let size = cache.get(&entry_id).map(|(_, s)| *s).unwrap_or(0);
                    match cache.get(&fixed.parent_entry_id) {
                        Some((parent_path, _)) if !file_name.is_empty() => {
                            let sep = if parent_path.ends_with('\\') { "" } else { "\\" };
                            (format!("{}{}{}", parent_path, sep, file_name), size)
                        }
                        _ => (unknown_name(), size),
                    }
                }
                None => (unknown_name(), 0),
            };

            let reason_str = decode_usn_reason(fixed.reason);
            let display_name = format!("{} (USN: {})", full_path, reason_str);
            let mode = decode_usn_file_attributes(fixed.file_attributes);

            timeline.push(TimelineEntry::new(
                ts_iso,
                secs,
                nanos,
                size,
                "....".to_string(),
                mode,
                0,
                0,
                entry_id.to_string(),
                display_name,
            )
            .with_source(source::USN)
            .with_flags(anomaly::column(&[anomaly::usn_flags(fixed.reason), anomaly::name_flags(&file_name)].concat())));
            report.records_parsed += 1;
        } else {
            report.records_no_timestamp += 1;
        }

        current_offset += record_len;
    }

    if let Some(pb) = pb {
        pb.finish_with_message("USN parsing completed");
    }

    Ok((timeline, report))
}

pub fn parse_usn_file(
    path: &Path,
    options: &UsnParseOptions,
) -> Result<Vec<TimelineEntry>> {
    let (timeline, report) = parse_usn_file_with_report(path, options)?;
    if !options.quiet && (report.records_v4_skipped > 0 || report.records_unsupported_version > 0) {
        eprintln!(
            "    [i] USN: {} records parsed, {} V4 range-tracking records skipped, {} unsupported-version records skipped",
            report.records_parsed, report.records_v4_skipped, report.records_unsupported_version
        );
    }
    Ok(timeline)
}

pub fn parse_usn_file_with_report(
    path: &Path,
    options: &UsnParseOptions,
) -> Result<(Vec<TimelineEntry>, UsnParseReport)> {
    let file = File::open(path).map_err(|e| AllyError::Io {
        code: ErrorCode::FileNotFound,
        source: e,
        context: format!("Opening USN file {}", path.display()),
    })?;
    let total_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let reader = BufReader::new(file);
    parse_usn_reader_with_report(reader, total_size, options)
}
