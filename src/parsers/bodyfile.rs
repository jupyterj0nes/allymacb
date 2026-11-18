use std::collections::HashMap;
use std::io::BufRead;
use std::sync::Arc;

use crate::error::{AllyError, ErrorCode};
use crate::timefmt::format_unix_timestamp;
use crate::anomaly;
use crate::hunt::{self, HuntRecord};
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

    let full_path = raw_path.to_string();
    let host: Option<Arc<str>> = prefix.map(Arc::from);

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
    for e in &mut entries {
        e.host = host.clone();
    }

    Ok(entries)
}

/// Hunt record of one bodyfile line: the inode's four times in whole seconds.
/// `fls` on NTFS writes the inode as `entry-type-id`: those lines are NTFS
/// records with their `$SI` times (the hunt then leaves out what NTFS does
/// not guarantee), and its `$FILE_NAME` lines are not records of their own.
fn hunt_record(line: &str, volume: u32) -> Option<Arc<HuntRecord>> {
    let fields: Vec<&str> = line.trim().rsplitn(10, '|').collect();
    if fields.len() < 10 || fields[9].contains("($FILE_NAME)") {
        return None;
    }
    let t = |s: &str| s.trim().parse::<f64>().ok().filter(|v| *v != 0.0).map(|v| (v.floor() as i64, ((v - v.floor()) * 1e9) as u32));
    let inode = fields[8].split('-').next().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
    let macb = hunt::Macb { a: t(fields[3]), m: t(fields[2]), c: t(fields[1]), b: t(fields[0]) };
    let evidence = if fields[8].contains('-') {
        // Sequence 0: unknown, so the allocation-order check stays out.
        hunt::Evidence::Ntfs { entry: inode, seq: 0, si: macb, fns: Vec::new() }
    } else {
        // The root directory: inode 2 on ext2/3/4, the line for `/` otherwise (XFS).
        let root = inode == 2 || fields[9].split_once('|').map(|(_, n)| n.trim_end_matches('/') == "").unwrap_or(false);
        hunt::Evidence::Unix { inode, t: macb, root }
    };
    Some(hunt::record(volume, evidence))
}

/// One record of a CSV stream (RFC 4180: quoted fields, `""` for a quote, a
/// line break inside quotes). `Ok(false)` at the end of the stream.
fn read_csv_record<R: BufRead>(reader: &mut R, fields: &mut Vec<String>) -> std::io::Result<bool> {
    fields.clear();
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let before = raw.len();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            if raw.is_empty() {
                return Ok(false);
            }
            break;
        }
        // a record ends at a line break outside quotes: an even number of them so far
        if raw.iter().filter(|b| **b == b'"').count() % 2 == 0 {
            break;
        }
        if raw.len() == before {
            break;
        }
    }
    while matches!(raw.last(), Some(b'\n') | Some(b'\r')) {
        raw.pop();
    }
    let text = String::from_utf8_lossy(&raw);
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    Ok(true)
}

/// Columns of the file listing a Cortex XDR online triage brings
/// (`bodyfile/bodyfile.csv`): the fields of a bodyfile, as a CSV table and
/// with the four times in milliseconds.
const CORTEX_LISTING_COLUMNS: [&str; 11] = ["md5", "name", "inode", "mode_as_string", "uid", "gid", "size", "atime", "mtime", "ctime", "crtime"];

/// The file listing of a Cortex XDR online triage, read as the bodyfile it
/// is: each row of the table comes out as one TSK bodyfile line
/// (`MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`), its times
/// in whole seconds.
pub struct CortexListing<R: BufRead> {
    reader: R,
    /// position of each bodyfile field in the table, in bodyfile order
    cols: [Option<usize>; 11],
    host_col: Option<usize>,
    host: Option<String>,
    buf: Vec<u8>,
    pos: usize,
    fields: Vec<String>,
    done: bool,
}

impl<R: BufRead> CortexListing<R> {
    /// `None` when the stream is not that table: its header must name the
    /// file, its inode and its four times.
    pub fn open(mut reader: R) -> Option<Self> {
        let mut header = Vec::new();
        if !read_csv_record(&mut reader, &mut header).ok()? {
            return None;
        }
        let at = |name: &str| header.iter().position(|h| h.trim().trim_start_matches('\u{feff}') == name);
        let mut cols = [None; 11];
        for (i, name) in CORTEX_LISTING_COLUMNS.iter().enumerate() {
            cols[i] = at(name);
        }
        // md5, uid, gid and size may be missing; the name, the inode and the times may not
        if [1usize, 2, 7, 8, 9, 10].iter().any(|i| cols[*i].is_none()) {
            return None;
        }
        let mut listing = Self { reader, cols, host_col: at("host_name"), host: None, buf: Vec::new(), pos: 0, fields: Vec::new(), done: false };
        // the first row is read now: it names the host the listing is of
        listing.fill();
        Some(listing)
    }

    /// The host the triage was taken from (the table's `host_name` column).
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Milliseconds since 1970 as bodyfile seconds: `1709294400123` -> `1709294400`.
    /// A bodyfile's times are whole seconds; the milliseconds are dropped.
    fn seconds(ms: &str) -> String {
        match ms.trim().parse::<i64>() {
            Ok(v) if v > 0 => (v / 1000).to_string(),
            _ => "0".to_string(),
        }
    }

    /// Puts the next row in the buffer as a bodyfile line.
    fn fill(&mut self) {
        self.buf.clear();
        self.pos = 0;
        while !self.done {
            match read_csv_record(&mut self.reader, &mut self.fields) {
                Ok(true) => {}
                _ => {
                    self.done = true;
                    return;
                }
            }
            let get = |i: usize| self.cols[i].and_then(|c| self.fields.get(c)).map(|s| s.as_str()).unwrap_or("");
            let name = get(1);
            if name.is_empty() {
                continue; // a blank line of the table
            }
            if self.host.is_none() {
                self.host = self.host_col.and_then(|c| self.fields.get(c)).map(|h| h.trim().to_string()).filter(|h| !h.is_empty());
            }
            let md5 = if get(0).trim().is_empty() { "0" } else { get(0).trim() };
            // a line break or a separator inside a name would split the line
            let name = name.replace(['\n', '\r'], " ");
            let line = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
                md5,
                name,
                get(2).trim(),
                get(3).trim(),
                get(4).trim(),
                get(5).trim(),
                get(6).trim(),
                Self::seconds(get(7)),
                Self::seconds(get(8)),
                Self::seconds(get(9)),
                Self::seconds(get(10)),
            );
            self.buf.extend_from_slice(line.as_bytes());
            return;
        }
    }
}

impl<R: BufRead> std::io::Read for CortexListing<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buf.len() {
            if self.done {
                return Ok(0);
            }
            self.fill();
            if self.buf.is_empty() {
                return Ok(0);
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
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
    let volume = hunt::new_volume();
    let host: Option<Arc<str>> = prefix.map(Arc::from);

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

        // The host is set here, shared by every row, rather than per line.
        match parse_bodyfile_line(&line, line_num, None) {
            Ok(entries) => {
                report.lines_parsed += 1;
                let record = hunt_record(&line, volume);
                timeline.extend(entries.into_iter().map(|mut e| {
                    e.host = host.clone();
                    e.with_hunt(record.clone())
                }));
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
        crate::say!(
            "[!] Bodyfile{}: {} of {} lines rejected",
            prefix.map(|p| format!(" [{}]", p)).unwrap_or_default(),
            report.lines_rejected,
            report.lines_total
        );
        for msg in &report.sample_errors {
            crate::say!("    {}", msg);
        }
    }
    timeline
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const LISTING: &str = "name,inode,mode_as_string,uid,gid,size,atime,mtime,ctime,crtime,md5,generated_time,agent_id,host_name\n\
/etc/passwd,4230,-rw-r--r--,0,0,2323,1710234798123,1710234798000,1710247956000,1710000000000,d41d8cd98f00b204e9800998ecf8427e,2026-11-01T10:00:00Z,a1,websrv01\n\
\"/srv/a, \"\"b\"\".txt\",77,-rw-r--r--,1000,1000,5,0,1710234799000,1710234799000,,,2026-11-01T10:00:00Z,a1,websrv01\n";

    #[test]
    fn a_cortex_listing_comes_out_as_bodyfile_lines() {
        let mut listing = CortexListing::open(Cursor::new(LISTING)).expect("the table is recognised");
        assert_eq!(listing.host(), Some("websrv01"));
        let mut body = String::new();
        std::io::Read::read_to_string(&mut listing, &mut body).unwrap();
        assert_eq!(
            body,
            "d41d8cd98f00b204e9800998ecf8427e|/etc/passwd|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|1710000000\n\
0|/srv/a, \"b\".txt|77|-rw-r--r--|1000|1000|5|0|1710234799|1710234799|0\n"
        );
    }

    #[test]
    fn a_cortex_listing_gives_the_same_rows_as_its_bodyfile() {
        let listing = CortexListing::open(Cursor::new(LISTING)).unwrap();
        let from_table = parse_bodyfile_stream(std::io::BufReader::new(listing), Some("websrv01"));
        let body = "d41d8cd98f00b204e9800998ecf8427e|/etc/passwd|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|1710000000\n\
0|/srv/a, \"b\".txt|77|-rw-r--r--|1000|1000|5|0|1710234799|1710234799|0\n";
        let from_body = parse_bodyfile_stream(Cursor::new(body), Some("websrv01"));
        assert!(!from_table.is_empty());
        assert_eq!(from_table.len(), from_body.len());
        // a line's rows come out in no fixed order: compared as sets
        let rows = |v: &[TimelineEntry]| {
            let mut r: Vec<(String, String, Option<String>)> = v.iter().map(|e| (e.file_name.clone(), e.timestamp.clone(), e.host.as_deref().map(str::to_string))).collect();
            r.sort();
            r
        };
        assert_eq!(rows(&from_table), rows(&from_body));
    }

    #[test]
    fn another_table_is_not_a_cortex_listing() {
        assert!(CortexListing::open(Cursor::new("name,size,owner\n/etc/passwd,10,root\n")).is_none());
        assert!(CortexListing::open(Cursor::new("")).is_none());
        // the header alone: recognised, and empty
        let mut empty = CortexListing::open(Cursor::new("name,inode,mode_as_string,uid,gid,size,atime,mtime,ctime,crtime,md5,host_name\n")).unwrap();
        let mut body = String::new();
        std::io::Read::read_to_string(&mut empty, &mut body).unwrap();
        assert!(body.is_empty() && empty.host().is_none());
    }

    #[test]
    fn test_parse_bodyfile_stream() {
        let sample = "0|/etc/passwd-|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|0\n";
        let cursor = Cursor::new(sample.as_bytes());
        let entries = parse_bodyfile_stream(cursor, Some("server01"));

        assert_eq!(entries.len(), 2);
        let ma_entry = entries.iter().find(|e| e.macb == "ma..").unwrap();
        assert_eq!(ma_entry.file_name, "/etc/passwd-");
        assert_eq!(ma_entry.host.as_deref(), Some("server01"));
        assert_eq!(ma_entry.size, 2323);
        assert_eq!(ma_entry.meta, "4230");
        assert_eq!(ma_entry.mode, "-rw-r--r--");

        let c_entry = entries.iter().find(|e| e.macb == "..c.").unwrap();
        assert_eq!(c_entry.file_name, "/etc/passwd-");
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
