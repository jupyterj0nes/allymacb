use std::collections::HashMap;
use std::io::BufRead;

use crate::error::{AllyError, ErrorCode};
use crate::timefmt::format_unix_timestamp;
use crate::anomaly;
use crate::timeline::{join_macb_flags, source, TimelineEntry};

/// Number of pipe-separated fields in a TSK 3.x bodyfile line:
/// `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`
const BODYFILE_FIELDS: usize = 11;
/// Fields that come *after* the name. The name may itself contain `|`, so the
/// line is split from the right and the remainder is `MD5|name`.
const FIELDS_AFTER_NAME: usize = BODYFILE_FIELDS - 2;

/// Per-stream parsing statistics so callers can report rejected evidence
/// instead of silently dropping it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyfileReport {
    pub lines_total: usize,
    pub lines_parsed: usize,
    pub lines_rejected: usize,
    /// First few rejection messages (line number + reason) for diagnostics.
    pub sample_errors: Vec<String>,
}

const MAX_SAMPLE_ERRORS: usize = 5;

fn parse_ts(value: &str, what: &str, line_num: usize) -> Result<i64, AllyError> {
    value.trim().parse().map_err(|_| AllyError::Bodyfile {
        code: ErrorCode::BodyfileTimestampInvalid,
        line: line_num,
        message: format!("Invalid {} value '{}'", what, value),
    })
}

fn parse_num<T: std::str::FromStr>(value: &str, what: &str, line_num: usize) -> Result<T, AllyError> {
    let v = value.trim();
    // An empty field is accepted as 0 (some collectors leave UID/GID blank).
    if v.is_empty() {
        return "0".parse().map_err(|_| AllyError::Bodyfile {
            code: ErrorCode::BodyfileNumericFieldInvalid,
            line: line_num,
            message: format!("Invalid {} value '{}'", what, value),
        });
    }
    v.parse().map_err(|_| AllyError::Bodyfile {
        code: ErrorCode::BodyfileNumericFieldInvalid,
        line: line_num,
        message: format!("Invalid {} value '{}' (expected an unsigned integer)", what, value),
    })
}

/// Parses a single SleuthKit bodyfile line into 0..4 TimelineEntry records (one per unique MACB timestamp).
///
/// The line is split from the right so that a `|` inside the file name does
/// not shift every column. A timestamp of 0 means "not set" (TSK convention)
/// and produces no row; negative (pre-1970) timestamps are kept because they
/// are a primary timestomping indicator.
pub fn parse_bodyfile_line(
    line: &str,
    line_num: usize,
    prefix: Option<&str>,
) -> Result<Vec<TimelineEntry>, AllyError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(Vec::new());
    }

    // rsplitn(N) yields at most N pieces: the trailing N-1 fields (reversed)
    // and the remaining head "MD5|name".
    let mut tail: Vec<&str> = trimmed.rsplitn(FIELDS_AFTER_NAME + 1, '|').collect();
    if tail.len() < FIELDS_AFTER_NAME + 1 {
        return Err(AllyError::Bodyfile {
            code: ErrorCode::BodyfileInvalidFieldCount,
            line: line_num,
            message: format!(
                "Expected {} pipe-separated fields, found {}",
                BODYFILE_FIELDS,
                trimmed.split('|').count()
            ),
        });
    }
    let head = tail.pop().unwrap_or("");
    tail.reverse();
    // tail now = [inode, mode, uid, gid, size, atime, mtime, ctime, crtime]

    let (_md5, raw_path) = match head.split_once('|') {
        Some(pair) => pair,
        None => {
            return Err(AllyError::Bodyfile {
                code: ErrorCode::BodyfileInvalidFieldCount,
                line: line_num,
                message: format!(
                    "Expected {} pipe-separated fields, found {}",
                    BODYFILE_FIELDS,
                    trimmed.split('|').count()
                ),
            });
        }
    };

    let inode = tail[0];
    let mode = tail[1];
    let uid: u32 = parse_num(tail[2], "UID", line_num)?;
    let gid: u32 = parse_num(tail[3], "GID", line_num)?;
    let size: u64 = parse_num(tail[4], "size", line_num)?;

    let atime = parse_ts(tail[5], "atime", line_num)?;
    let mtime = parse_ts(tail[6], "mtime", line_num)?;
    let ctime = parse_ts(tail[7], "ctime", line_num)?;
    let crtime = parse_ts(tail[8], "crtime", line_num)?;

    let full_path = if let Some(p) = prefix {
        format!("[{}] {}", p, raw_path)
    } else {
        raw_path.to_string()
    };

    // Group timestamps: secs -> macb string
    let mut ts_map: HashMap<i64, String> = HashMap::new();

    for (ts, flag) in [(mtime, 'm'), (atime, 'a'), (ctime, 'c'), (crtime, 'b')] {
        if ts != 0 {
            let cur = ts_map.entry(ts).or_insert_with(|| "....".to_string());
            *cur = join_macb_flags(cur, flag);
        }
    }

    let opt = |t: i64| if t != 0 { Some(t) } else { None };
    let flags = anomaly::column(
        &[anomaly::unix_flags(opt(mtime), opt(ctime), opt(crtime), anomaly::now_secs()), anomaly::name_flags(raw_path)].concat(),
    );

    let mut entries = Vec::new();
    for (secs, macb) in ts_map {
        if let Some(ts_iso) = format_unix_timestamp(secs, 0) {
            entries.push(
                TimelineEntry::new(
                    ts_iso,
                    secs,
                    0,
                    size,
                    macb,
                    mode.to_string(),
                    uid,
                    gid,
                    inode.to_string(),
                    full_path.clone(),
                )
                .with_source(source::BODYFILE)
                .with_flags(flags.clone()),
            );
        }
    }

    Ok(entries)
}

/// Parses a bodyfile stream and returns the entries together with a report
/// of how many lines were accepted or rejected. Lines that are not valid
/// UTF-8 (raw bytes in file names, as emitted by `fls -m`) are decoded
/// lossily instead of being dropped.
pub fn parse_bodyfile_stream_with_report<R: BufRead>(
    mut reader: R,
    prefix: Option<&str>,
) -> (Vec<TimelineEntry>, BodyfileReport) {
    let mut timeline = Vec::new();
    let mut report = BodyfileReport::default();
    let mut raw = Vec::new();
    let mut line_num = 0usize;

    loop {
        raw.clear();
        match reader.read_until(b'\n', &mut raw) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                report.lines_rejected += 1;
                if report.sample_errors.len() < MAX_SAMPLE_ERRORS {
                    report.sample_errors.push(format!("read error after line {}: {}", line_num, e));
                }
                break;
            }
        }
        line_num += 1;
        let line = String::from_utf8_lossy(&raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        report.lines_total += 1;

        match parse_bodyfile_line(&line, line_num, prefix) {
            Ok(entries) => {
                report.lines_parsed += 1;
                timeline.extend(entries);
            }
            Err(e) => {
                report.lines_rejected += 1;
                if report.sample_errors.len() < MAX_SAMPLE_ERRORS {
                    report.sample_errors.push(e.to_string());
                }
            }
        }
    }

    (timeline, report)
}

/// Convenience wrapper: parses the stream and prints a warning to stderr when
/// lines were rejected, so malformed evidence never disappears silently.
pub fn parse_bodyfile_stream<R: BufRead>(
    reader: R,
    prefix: Option<&str>,
) -> Vec<TimelineEntry> {
    let (timeline, report) = parse_bodyfile_stream_with_report(reader, prefix);
    if report.lines_rejected > 0 {
        eprintln!(
            "[!] Bodyfile{}: {} of {} lines rejected",
            prefix.map(|p| format!(" [{}]", p)).unwrap_or_default(),
            report.lines_rejected,
            report.lines_total
        );
        for msg in &report.sample_errors {
            eprintln!("    {}", msg);
        }
    }
    timeline
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_bodyfile_stream() {
        let sample = "0|/etc/passwd-|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|0\n";
        let cursor = Cursor::new(sample.as_bytes());
        let entries = parse_bodyfile_stream(cursor, Some("server01"));

        assert_eq!(entries.len(), 2);
        let ma_entry = entries.iter().find(|e| e.macb == "ma..").unwrap();
        assert_eq!(ma_entry.file_name, "[server01] /etc/passwd-");
        assert_eq!(ma_entry.size, 2323);
        assert_eq!(ma_entry.meta, "4230");
        assert_eq!(ma_entry.mode, "-rw-r--r--");

        let c_entry = entries.iter().find(|e| e.macb == "..c.").unwrap();
        assert_eq!(c_entry.file_name, "[server01] /etc/passwd-");
    }

    #[test]
    fn test_parse_bodyfile_invalid_line() {
        let bad_line = "0|/etc/bad|123";
        let err = parse_bodyfile_line(bad_line, 42, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::BodyfileInvalidFieldCount);
    }

    #[test]
    fn test_pipe_inside_name_does_not_shift_columns() {
        let line = "0|/tmp/a|b|100|-rw-r--r--|1000|1000|5|1700000000|1700000001|1700000002|1700000003";
        let entries = parse_bodyfile_line(line, 1, None).unwrap();
        assert_eq!(entries.len(), 4);
        for e in &entries {
            assert_eq!(e.file_name, "/tmp/a|b");
            assert_eq!(e.meta, "100");
            assert_eq!(e.mode, "-rw-r--r--");
            assert_eq!(e.uid, 1000);
            assert_eq!(e.gid, 1000);
            assert_eq!(e.size, 5);
        }
        let b = entries.iter().find(|e| e.macb == "...b").unwrap();
        assert_eq!(b.timestamp_secs, 1700000003);
    }

    #[test]
    fn test_negative_timestamp_is_kept() {
        let line = "0|/tmp/old|100|-rw-r--r--|0|0|5|-86400|1700000001|1700000002|1700000003";
        let entries = parse_bodyfile_line(line, 1, None).unwrap();
        let a = entries.iter().find(|e| e.macb == ".a..").expect("pre-1970 atime row must exist");
        assert_eq!(a.timestamp, "1969-12-31T00:00:00Z");
    }

    #[test]
    fn test_invalid_uid_is_rejected_not_coerced() {
        let line = "0|/tmp/x|100|-rw-r--r--|-1|65536x|5|1|1|1|1";
        let err = parse_bodyfile_line(line, 7, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::BodyfileNumericFieldInvalid);
    }

    #[test]
    fn test_stream_keeps_non_utf8_lines_and_reports_rejects() {
        let mut data = Vec::new();
        data.extend_from_slice(b"0|/tmp/one|1|-rw-r--r--|0|0|1|1|1|1|1\n");
        data.extend_from_slice(b"0|/tmp/caf\xe9|2|-rw-r--r--|0|0|1|1|1|1|1\n");
        data.extend_from_slice(b"garbage line\n");
        data.extend_from_slice(b"0|/tmp/three|3|-rw-r--r--|0|0|1|1|1|1|1\n");
        let (entries, report) = parse_bodyfile_stream_with_report(Cursor::new(data), None);
        assert_eq!(report.lines_total, 4);
        assert_eq!(report.lines_parsed, 3);
        assert_eq!(report.lines_rejected, 1);
        assert!(entries.iter().any(|e| e.file_name.starts_with("/tmp/caf")));
        assert_eq!(entries.len(), 3);
    }
}
