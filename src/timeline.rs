use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::error::{AllyError, ErrorCode, Result};

/// Values of the `source` column: which kind of evidence a row was built from.
pub mod source {
    /// `$STANDARD_INFORMATION` / `$FILE_NAME` of a live `$MFT` record.
    pub const MFT: &str = "mft";
    /// `$UsnJrnl:$J` record.
    pub const USN: &str = "usn";
    /// TSK bodyfile line.
    pub const BODYFILE: &str = "bodyfile";
    /// ext4 inode read from a disk image.
    pub const EXT4: &str = "ext4";
    /// Metadata of a file on the analyst's own filesystem (directory walk,
    /// extracted archive).
    pub const FS: &str = "fs";
    /// Recovered by `--carve` from raw sectors: an NTFS `FILE` record or an
    /// `$I30` index entry found outside the live `$MFT`.
    pub const CARVED: &str = "carved";
    /// Rows built without stating a source (tests, library users).
    pub const UNKNOWN: &str = "unknown";
}

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
    /// One of the constants in [`source`].
    pub source: &'static str,
    /// Anti-forensics indicators from [`crate::anomaly`], `+`-joined; usually empty.
    pub flags: String,
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
            source: source::UNKNOWN,
            flags: String::new(),
        }
    }

    /// Sets the `source` column (see [`source`]).
    pub fn with_source(mut self, source: &'static str) -> Self {
        self.source = source;
        self
    }

    /// Sets the `flags` column (see [`crate::anomaly`]).
    pub fn with_flags(mut self, flags: String) -> Self {
        self.flags = flags;
        self
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

/// RFC 4180 structural escaping: quotes the field when it contains a comma,
/// a double quote, or a line break. Does not touch anything else.
pub fn escape_csv(val: &str) -> String {
    if val.contains(',') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        format!("\"{}\"", val.replace('"', "\"\""))
    } else {
        val.to_string()
    }
}

/// Returns true when a cell would be interpreted as a formula by Excel,
/// LibreOffice or Google Sheets (CSV / formula injection).
pub fn is_formula_like(val: &str) -> bool {
    matches!(
        val.as_bytes().first(),
        Some(b'=') | Some(b'+') | Some(b'-') | Some(b'@') | Some(b'\t') | Some(b'\r')
    )
}

/// Escaping for untrusted free-text cells (file names, inode strings coming
/// from evidence). Applies the structural escaping of [`escape_csv`] and
/// additionally neutralises formula injection by prefixing a single quote
/// and quoting the field, following OWASP guidance. Evidence filesystems are
/// hostile by definition, so a file named `=cmd|' /C calc'!A0` must never
/// execute when an analyst opens the timeline in a spreadsheet.
pub fn escape_csv_text(val: &str) -> String {
    if is_formula_like(val) {
        format!("\"'{}\"", val.replace('"', "\"\""))
    } else {
        escape_csv(val)
    }
}

/// CSV header written before every timeline. Column order must match the
/// row format in [`TimelineWriter::write_entries`]. Tests reference this constant so the
/// header cannot drift between the writer and its assertions.
///
/// `time_created` is the timestamp of the MACB event each row represents.
/// `source` says what kind of evidence the row comes from (see [`source`]);
/// rows recovered by `--carve` say `carved`. `flags` lists anti-forensics
/// indicators (see [`crate::anomaly`]) and is empty on most rows.
pub const CSV_HEADER: &str = "time_created,size,type,mode,uid,gid,meta,file_name,source,flags";

/// Number of columns in [`CSV_HEADER`].
pub const CSV_COLUMNS: usize = 10;

/// Formats one timeline entry as a CSV row (without trailing newline).
/// Every column is escaped: `meta` and `file_name` carry evidence-controlled
/// text, the rest are escaped structurally so a malformed value can never
/// shift columns.
pub fn format_csv_row(entry: &TimelineEntry) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{}",
        escape_csv(&entry.timestamp),
        entry.size,
        escape_csv(&entry.macb),
        escape_csv(&entry.mode),
        entry.uid,
        entry.gid,
        escape_csv_text(&entry.meta),
        escape_csv_text(&entry.file_name),
        entry.source,
        escape_csv(&entry.flags)
    )
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
                        std::fs::create_dir_all(parent).map_err(|e| AllyError::Csv {
                            code: ErrorCode::CsvExportFailed,
                            message: format!(
                                "Failed creating output directory '{}': {}",
                                parent.display(),
                                e
                            ),
                        })?;
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

        // snake_case header (see CSV_HEADER); column order matches format_csv_row
        writeln!(writer, "{}", CSV_HEADER).map_err(|e| AllyError::Csv {
            code: ErrorCode::CsvExportFailed,
            message: format!("Failed writing CSV header: {}", e),
        })?;

        for entry in entries.iter() {
            writeln!(writer, "{}", format_csv_row(entry)).map_err(|e| AllyError::Csv {
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

    #[test]
    fn test_escape_csv_text_neutralises_formulas() {
        assert_eq!(escape_csv_text("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
        assert_eq!(escape_csv_text("+1+1"), "\"'+1+1\"");
        assert_eq!(escape_csv_text("-rf"), "\"'-rf\"");
        assert_eq!(escape_csv_text("@SUM(A1)"), "\"'@SUM(A1)\"");
        assert_eq!(escape_csv_text("\t=1"), "\"'\t=1\"");
        // Normal names are untouched
        assert_eq!(escape_csv_text("C:\\Windows\\cmd.exe"), "C:\\Windows\\cmd.exe");
        assert_eq!(escape_csv_text("a,b"), "\"a,b\"");
    }

    #[test]
    fn test_header_matches_row_column_count() {
        assert_eq!(CSV_HEADER.split(',').count(), CSV_COLUMNS);
        let e = TimelineEntry::new(
            "2024-01-01T00:00:00Z".into(),
            1_704_067_200,
            0,
            1,
            "m...".into(),
            "-rw-r--r--".into(),
            0,
            0,
            "4230,evil".into(),
            "/etc/passwd".into(),
        );
        let row = format_csv_row(&e);
        // The injected comma in meta must stay inside one quoted cell.
        assert_eq!(row, "2024-01-01T00:00:00Z,1,m...,-rw-r--r--,0,0,\"4230,evil\",/etc/passwd,unknown,");
        let row = format_csv_row(&e.with_source(source::CARVED).with_flags("future+pre_1980".into()));
        assert!(row.ends_with(",carved,future+pre_1980"));
    }
}
