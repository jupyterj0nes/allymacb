use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt};
use indicatif::{ProgressBar, ProgressStyle};

use crate::error::{AllyError, ErrorCode, Result};
use crate::timefmt::{filetime_to_datetime, format_utc_iso};
use crate::timeline::TimelineEntry;

pub struct UsnParseOptions {
    pub drive_letter: Option<char>,
    pub quiet: bool,
    pub mft_path_cache: Option<HashMap<u64, (String, u64)>>,
}

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
    if reason & 0x80000000 != 0 { parts.push("CLOSE"); }

    if parts.is_empty() {
        format!("0x{:08X}", reason)
    } else {
        parts.join("+")
    }
}

pub fn decode_usn_file_attributes(attrs: u32) -> String {
    if attrs & 0x10 != 0 {
        "d/drwxrwxrwx".to_string()
    } else {
        "-/-rwxrwxrwx".to_string()
    }
}

pub fn parse_usn_reader<R: Read + Seek>(
    mut reader: R,
    total_size: u64,
    options: &UsnParseOptions,
) -> Result<Vec<TimelineEntry>> {
    let mut timeline = Vec::new();
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

    while current_offset + 60 <= total_size {
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

        // Validate sanity of record length
        if record_len < 60 || record_len > 4096 || current_offset + record_len > total_size {
            current_offset += 4;
            continue;
        }

        // Read the rest of the record header
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

        if major_ver != 2 && major_ver != 3 {
            current_offset += record_len;
            continue;
        }

        let file_ref = reader.read_u64::<LittleEndian>().unwrap_or(0);
        let _parent_ref = reader.read_u64::<LittleEndian>().unwrap_or(0);
        let _usn = reader.read_i64::<LittleEndian>().unwrap_or(0);
        let filetime = reader.read_u64::<LittleEndian>().unwrap_or(0);
        let reason = reader.read_u32::<LittleEndian>().unwrap_or(0);
        let _source_info = reader.read_u32::<LittleEndian>().unwrap_or(0);
        let _security_id = reader.read_u32::<LittleEndian>().unwrap_or(0);
        let file_attributes = reader.read_u32::<LittleEndian>().unwrap_or(0);
        let file_name_length = reader.read_u16::<LittleEndian>().unwrap_or(0) as usize;
        let file_name_offset = reader.read_u16::<LittleEndian>().unwrap_or(0) as u64;

        // Extract filename
        let mut file_name = String::new();
        if file_name_length > 0 && file_name_offset < record_len {
            let _ = reader.seek(SeekFrom::Start(current_offset + file_name_offset));
            let mut name_bytes = vec![0u8; file_name_length];
            if reader.read_exact(&mut name_bytes).is_ok() {
                let u16_chars: Vec<u16> = name_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                file_name = String::from_utf16_lossy(&u16_chars);
            }
        }

        let entry_id = file_ref & 0x0000_FFFF_FFFF_FFFF;

        if let Some(dt) = filetime_to_datetime(filetime) {
            let ts_iso = format_utc_iso(dt);
            let secs = dt.timestamp();
            let nanos = dt.timestamp_subsec_nanos();

            let (full_path, size) = if let Some(ref cache) = options.mft_path_cache {
                if let Some((cached_path, cached_size)) = cache.get(&entry_id) {
                    (cached_path.clone(), *cached_size)
                } else if !file_name.is_empty() {
                    (format!("{}:\\[UNKNOWN]\\{}", drive_prefix, file_name), 0)
                } else {
                    (format!("{}:\\[UNKNOWN]\\entry_{}", drive_prefix, entry_id), 0)
                }
            } else if !file_name.is_empty() {
                (format!("{}:\\[UNKNOWN]\\{}", drive_prefix, file_name), 0)
            } else {
                (format!("{}:\\[UNKNOWN]\\entry_{}", drive_prefix, entry_id), 0)
            };

            let reason_str = decode_usn_reason(reason);
            let display_name = format!("{} (USN: {})", full_path, reason_str);
            let mode = decode_usn_file_attributes(file_attributes);

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
            ));
        }

        current_offset += record_len;
    }

    if let Some(pb) = pb {
        pb.finish_with_message("USN parsing completed");
    }

    Ok(timeline)
}

pub fn parse_usn_file(
    path: &Path,
    options: &UsnParseOptions,
) -> Result<Vec<TimelineEntry>> {
    let file = File::open(path).map_err(|e| AllyError::Io {
        code: ErrorCode::FileNotFound,
        source: e,
        context: format!("Opening USN file {}", path.display()),
    })?;
    let total_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let reader = BufReader::new(file);
    parse_usn_reader(reader, total_size, options)
}
