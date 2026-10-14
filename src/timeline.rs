use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::error::{AllyError, ErrorCode, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub timestamp_secs: i64,
    pub timestamp_nanos: u32,
    pub size: u64,
    pub macb: String,
    pub mode: String,
    pub uid: u32,
    pub gid: u32,
    pub meta: String,
    pub file_name: String,
}

impl TimelineEntry {
    pub fn new(
        timestamp: String,
        timestamp_secs: i64,
        timestamp_nanos: u32,
        size: u64,
        macb: String,
        mode: String,
        uid: u32,
        gid: u32,
        meta: String,
        file_name: String,
    ) -> Self {
        Self {
            timestamp,
            timestamp_secs,
            timestamp_nanos,
            size,
            macb,
            mode,
            uid,
            gid,
            meta,
            file_name,
        }
    }
}

/// Helper function to join MACB flags like in mftmactime.py
pub fn join_macb_flags(existing: &str, flag: char) -> String {
    let mut chars: Vec<char> = if existing.len() == 4 {
        existing.chars().collect()
    } else {
        vec!['.', '.', '.', '.']
    };

    match flag {
        'm' => chars[0] = 'm',
        'a' => chars[1] = 'a',
        'c' => chars[2] = 'c',
        'b' => chars[3] = 'b',
        _ => {}
    }
    chars.into_iter().collect()
}

/// Escapes a CSV field if it contains commas, quotes, or newlines.
pub fn escape_csv(val: &str) -> String {
    if val.contains(',') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        format!("\"{}\"", val.replace('"', "\"\""))
    } else {
        val.to_string()
    }
}

pub struct TimelineWriter;

impl TimelineWriter {
    /// Writes timeline entries to an output file or stdout, sorted chronologically.
    pub fn write_entries(
        entries: &mut [TimelineEntry],
        output_path: Option<&Path>,
    ) -> Result<usize> {
        // Sort chronologically by (secs, nanos, path)
        entries.sort_by(|a, b| {
            a.timestamp_secs
                .cmp(&b.timestamp_secs)
                .then_with(|| a.timestamp_nanos.cmp(&b.timestamp_nanos))
                .then_with(|| a.file_name.cmp(&b.file_name))
        });

        let mut writer: Box<dyn Write> = match output_path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }
                let file = File::create(path).map_err(|e| AllyError::Csv {
                    code: ErrorCode::CsvExportFailed,
                    message: format!("Failed creating CSV file '{}': {}", path.display(), e),
                })?;
                Box::new(BufWriter::new(file))
            }
            None => Box::new(BufWriter::new(io::stdout())),
        };

        // Header matching mftmactime format
        writeln!(writer, "Date,Size,Type,Mode,UID,GID,Meta,File Name").map_err(|e| AllyError::Csv {
            code: ErrorCode::CsvExportFailed,
            message: format!("Failed writing CSV header: {}", e),
        })?;

        for entry in entries.iter() {
            writeln!(
                writer,
                "{},{},{},{},{},{},{},{}",
                entry.timestamp,
                entry.size,
                entry.macb,
                entry.mode,
                entry.uid,
                entry.gid,
                entry.meta,
                escape_csv(&entry.file_name)
            ).map_err(|e| AllyError::Csv {
                code: ErrorCode::CsvExportFailed,
                message: format!("Failed writing CSV row for '{}': {}", entry.file_name, e),
            })?;
        }

        writer.flush().map_err(|e| AllyError::Csv {
            code: ErrorCode::CsvExportFailed,
            message: format!("Failed flushing CSV buffer: {}", e),
        })?;

        Ok(entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_join_macb_flags() {
        assert_eq!(join_macb_flags("....", 'm'), "m...");
        assert_eq!(join_macb_flags("m...", 'a'), "ma..");
        assert_eq!(join_macb_flags("ma..", 'c'), "mac.");
        assert_eq!(join_macb_flags("mac.", 'b'), "macb");
    }

    #[test]
    fn test_escape_csv() {
        assert_eq!(escape_csv("simple.txt"), "simple.txt");
        assert_eq!(escape_csv("file,with,commas.txt"), "\"file,with,commas.txt\"");
        assert_eq!(escape_csv("file \"quoted\".txt"), "\"file \"\"quoted\"\".txt\"");
    }
}
