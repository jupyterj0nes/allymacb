use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Arc;

use crate::error::{AllyError, ErrorCode, Result};
use crate::anomaly::{Rules, Severity};
use crate::context::Context;
use crate::hunt::{HuntRecord, Mark, State, SCORE_MAX};

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

/// Values of the `action` column: what happened to the file, when the
/// evidence says it outright. Only USN records do so far; MACB rows leave it
/// empty.
pub mod action {
    pub const CREATED: &str = "created";
    pub const DELETED: &str = "deleted";
    pub const RENAMED: &str = "renamed";
    /// Data written, extended or truncated.
    pub const MODIFIED: &str = "modified";
    /// Timestamps, attributes, security, links, streams: everything but data
    /// and name.
    pub const METADATA: &str = "metadata";
}

/// Values of the `deleted` column: how the file is known to be deleted.
/// Empty for a file that is not.
pub mod deleted {
    /// NTFS record not in use (live `$MFT` or carved), or ext4 inode with no
    /// links left.
    pub const UNALLOCATED: &str = "unallocated";
    /// ext4 inode with a deletion time.
    pub const DTIME: &str = "dtime";
    /// USN record with `FILE_DELETE`.
    pub const USN: &str = "usn";
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
    /// Collection the row came from (bodyfile or archive name, usually the
    /// host's), when there is one.
    pub host: Option<Arc<str>>,
    /// One of the constants in [`action`], or empty.
    pub action: &'static str,
    /// Volume of the file: drive letter of a loose `$MFT` or `$J`, partition
    /// of an image (`p2`).
    pub volume: Option<Arc<str>>,
    /// One of the constants in [`deleted`], or empty.
    pub deleted: &'static str,
    /// The input the row was read from, outermost first: `disk.E01:p2:$MFT`.
    pub evidence: Option<Arc<str>>,
    /// Anti-forensics indicators from [`crate::anomaly`] (`ALERT: a+b`,
    /// `WARN: a`); usually empty. Written in the analysis tail.
    pub flags: String,
    /// The record this row was built from, shared by all its rows, for
    /// `--investigation-from` (see [`crate::hunt`]). Not written to the CSV.
    pub hunt: Option<Arc<HuntRecord>>,
    /// The hunt's verdict on that record, written in the analysis tail.
    /// None when the hunt did not run or the row did not enter it.
    pub mark: Option<Arc<Mark>>,
    /// What the record's volume says about it (installed with the volume,
    /// part of a burst; see [`crate::context`]). Written in the analysis
    /// tail. None when the volume says nothing.
    pub context: Option<Arc<Context>>,
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
            host: None,
            action: "",
            volume: None,
            deleted: "",
            evidence: None,
            flags: String::new(),
            hunt: None,
            mark: None,
            context: None,
        }
    }

    /// Sets the `source` column (see [`source`]).
    pub fn with_source(mut self, source: &'static str) -> Self {
        self.source = source;
        self
    }

    /// Sets the rule indicators (see [`crate::anomaly`]).
    pub fn with_flags(mut self, flags: String) -> Self {
        self.flags = flags;
        self
    }

    /// Sets the `action` column (see [`action`]).
    pub fn with_action(mut self, action: &'static str) -> Self {
        self.action = action;
        self
    }

    /// Sets the `deleted` column (see [`deleted`]).
    pub fn with_deleted(mut self, deleted: &'static str) -> Self {
        self.deleted = deleted;
        self
    }

    /// Links the row to the record it was built from (see [`crate::hunt`]).
    pub fn with_hunt(mut self, record: Option<Arc<HuntRecord>>) -> Self {
        self.hunt = record;
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
/// The layout follows masstin's timeline, column for column: 14 that
/// describe the event, each in the position of masstin's column with the
/// closest meaning (`host` where masstin has `dst_computer`, `action` for
/// `event_type`, `type` for `event_id`, `meta` for `logon_id`, `file_name`
/// for `detail`, `evidence` for `log_filename`), then masstin's analysis
/// tail. `time_created` is the timestamp of the MACB event each row
/// represents; `source` says what kind of evidence it comes from (see
/// [`source`]).
///
/// The tail holds every verdict on the row's record, in the convention the
/// four tools share (masstin's `docs/csv-format.md`): `hunt` (one of
/// masstin's six states, see [`hunt_word`]), `hunt_score` (how rare the
/// record is, 0 to 100: the statistical hunt's `-10 · log10(q)` plus the
/// measured rarity of its rules, capped at 100) and `hunt_why` (one clause
/// per rule, `rule <id> (<level>): ...`, strongest first, then the hunt's
/// reasons in words). `verdict` and `notes` are the analyst's and are
/// written empty.
pub const CSV_HEADER: &str = "time_created,host,action,type,source,uid,gid,volume,size,mode,deleted,meta,file_name,evidence,hunt,hunt_score,hunt_why,verdict,notes";

/// Number of columns in [`CSV_HEADER`].
pub const CSV_COLUMNS: usize = 19;

/// What the rules of a row's record say once the volume has had its word:
/// the state they give, their points, and the clauses, the volume's last.
struct Judged {
    state: Option<State>,
    points: u32,
    why: String,
}

/// The rules of a row's record (rarity measured on an NTFS and on a Unix
/// reference volume) in the context the volume gives them: a record
/// installed with the volume is `baseline` and its time rules add nothing;
/// the follower of a burst is `habitual` and adds nothing; the first of a
/// burst, and a record the volume says nothing about, carry what the rules
/// say.
fn judged(entry: &TimelineEntry) -> Option<Judged> {
    let ntfs = matches!(entry.source, source::MFT | source::USN | source::CARVED);
    let (rules, state, points) = match entry.context.as_deref() {
        Some(Context::Installed(_)) => {
            let r = Rules::vouched(&entry.flags, ntfs)?;
            let state = r.severity.map(rule_state).or(Some(State::Baseline));
            (r, state, None)
        }
        Some(Context::Burst { leader: false, .. }) => (Rules::of(&entry.flags, ntfs)?, Some(State::Habitual), Some(0)),
        _ => {
            let r = Rules::of(&entry.flags, ntfs)?;
            let state = r.severity.map(rule_state);
            (r, state, None)
        }
    };
    let points = points.unwrap_or(rules.points);
    let why = match entry.context.as_deref() {
        Some(c) => format!("{}; {}", rules.why, c.clause()),
        None => rules.why,
    };
    Some(Judged { state, points, why })
}

/// The state a rule level gives: a high rule (`ALERT`) `significant`, a
/// medium one (`WARN`) `candidate`.
fn rule_state(severity: Severity) -> State {
    match severity {
        Severity::Alert => State::Significant,
        Severity::Warn => State::Candidate,
    }
}

/// The `hunt` column: the stronger of the statistical state and the state
/// the rules give in their context (`significant` over `candidate` over the
/// rest). Only masstin's six words ever go in it.
pub fn hunt_word(entry: &TimelineEntry) -> &'static str {
    let state = entry.mark.as_ref().map(|m| m.state);
    let rule = judged(entry).and_then(|r| r.state);
    strongest(state, rule).map(State::as_str).unwrap_or("")
}

fn strongest(state: Option<State>, rule: Option<State>) -> Option<State> {
    for s in [State::Significant, State::Candidate] {
        if state == Some(s) || rule == Some(s) {
            return Some(s);
        }
    }
    state.or(rule)
}

/// The analysis tail of a row with no verdict, written bare as masstin does.
const EMPTY_TAIL: &str = ",,,,,";

fn tail(entry: &TimelineEntry) -> String {
    let mark = entry.mark.as_deref();
    let rules = judged(entry);
    let state = strongest(mark.map(|m| m.state), rules.as_ref().and_then(|r| r.state));
    if state.is_none() && rules.is_none() {
        return EMPTY_TAIL.to_string();
    }
    // a record where only noise rules fired and no test spoke: no state, no score, the clause
    let word = state.map(State::as_str).unwrap_or("");
    // Test and rules add, capped at masstin's top; the baseline is not scored.
    let score = match (mark.and_then(|m| m.score), &rules) {
        (s, Some(r)) => Some((u32::from(s.unwrap_or(0)) + r.points).min(u32::from(SCORE_MAX))),
        (s, None) => s.map(u32::from),
    };
    let score = score.filter(|_| !word.is_empty() && state != Some(State::Baseline)).map(|s| s.to_string()).unwrap_or_default();
    let state = word;
    let test = mark.map(|m| m.why.as_str()).filter(|w| !w.is_empty());
    let why = match (rules.map(|r| r.why), test) {
        (Some(r), Some(t)) => format!("{}; {}", r, t),
        (Some(r), None) => r,
        (None, Some(t)) => t.to_string(),
        (None, None) => String::new(),
    };
    format!(",{},{},{},,", state, score, escape_csv_text(&why))
}

fn opt(v: &Option<Arc<str>>) -> &str {
    v.as_deref().unwrap_or("")
}

/// Formats one timeline entry as a CSV row (without trailing newline).
/// Every column is escaped: `meta` and `file_name` carry evidence-controlled
/// text, the rest are escaped structurally so a malformed value can never
/// shift columns.
pub fn format_csv_row(entry: &TimelineEntry) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{}{}",
        escape_csv(&entry.timestamp),
        escape_csv_text(opt(&entry.host)),
        entry.action,
        escape_csv(&entry.macb),
        entry.source,
        entry.uid,
        entry.gid,
        escape_csv_text(opt(&entry.volume)),
        entry.size,
        escape_csv(&entry.mode),
        entry.deleted,
        escape_csv_text(&entry.meta),
        escape_csv_text(&entry.file_name),
        escape_csv_text(opt(&entry.evidence)),
        tail(entry)
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
                .then_with(|| a.host.cmp(&b.host))
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
        assert_eq!(row, "2024-01-01T00:00:00Z,,,m...,unknown,0,0,,1,-rw-r--r--,,\"4230,evil\",/etc/passwd,,,,,,");
        assert_eq!(row.matches(',').count(), CSV_COLUMNS, "18 separators plus the one inside the quoted meta");

        let mut e = e.with_source(source::CARVED).with_flags("ALERT: future+pre_1980".into()).with_deleted(deleted::UNALLOCATED);
        e.host = Some("srv01".into());
        e.volume = Some("p2".into());
        e.evidence = Some("disk.E01:p2".into());
        let row = format_csv_row(&e);
        // Rules alone: a high rule gives `significant`, its measured points the score.
        assert_eq!(
            row,
            "2024-01-01T00:00:00Z,srv01,,m...,carved,0,0,p2,1,-rw-r--r--,unallocated,\"4230,evil\",/etc/passwd,disk.E01:p2,significant,100,rule future (high): a timestamp more than a day after the timeline was built; rule pre_1980 (high): a timestamp before 1980,,"
        );

        // Test and rules: the stronger state, the scores add, the rules speak first.
        e.mark = Some(Arc::new(Mark { state: State::Significant, score: Some(22), why: "a, b; c".into() }));
        let row = format_csv_row(&e);
        assert!(row.ends_with(",significant,100,\"rule future (high): a timestamp more than a day after the timeline was built; rule pre_1980 (high): a timestamp before 1980; a, b; c\",,"), "{}", row);
        e.mark = Some(Arc::new(Mark { state: State::Candidate, score: Some(9), why: "c".into() }));
        assert!(format_csv_row(&e).contains(",significant,100,rule future (high): "), "two never-fired rules already reach the cap");
        // A medium rule on a Unix record: m_before_b fires on 92 % of stock inodes, so it is noise
        // there: the test's state and score stand, the clause stays.
        let mut u = e.clone().with_source(source::EXT4);
        u.flags = "WARN: m_before_b".into();
        assert!(format_csv_row(&u).ends_with(",candidate,9,rule m_before_b (medium): modification before creation; c,,"), "{}", format_csv_row(&u));
        u.mark = Some(Arc::new(Mark { state: State::Habitual, score: Some(0), why: String::new() }));
        assert!(format_csv_row(&u).ends_with(",habitual,0,rule m_before_b (medium): modification before creation,,"), "{}", format_csv_row(&u));
        u.mark = None;
        assert!(format_csv_row(&u).ends_with(",,,rule m_before_b (medium): modification before creation,,"), "{}", format_csv_row(&u));
        // The same rule on NTFS is not measured: it keeps its level.
        let mut n = e.clone().with_source(source::MFT);
        n.mark = None;
        n.flags = "WARN: m_before_b".into();
        assert!(format_csv_row(&n).ends_with(",candidate,0,\"rule m_before_b (medium): modification before creation, rarity not measured\",,"), "{}", format_csv_row(&n));
        // The test alone.
        e.flags.clear();
        assert!(format_csv_row(&e).ends_with(",candidate,9,c,,"));
        e.mark = Some(Arc::new(Mark { state: State::Habitual, score: Some(0), why: String::new() }));
        assert!(format_csv_row(&e).ends_with(",habitual,0,,,"));
        e.mark = Some(Arc::new(Mark { state: State::Baseline, score: None, why: String::new() }));
        assert!(format_csv_row(&e).ends_with(",baseline,,,,"));
    }
}
