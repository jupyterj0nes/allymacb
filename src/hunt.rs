//! Statistical hunt for manipulated timestamps (`--investigation-from`).
//!
//! The indicators in [`crate::anomaly`] say what a record looks like. The
//! hunt says how often a record that looks like that turns up on the same
//! volume in normal operation, and keeps only what survives a false
//! discovery rate. It is masstin's graph-hunt applied to file records:
//!
//! 1. **Unit.** One state of one file record: an NTFS `FILE` record (live or
//!    carved), an ext4 inode (live, deleted or an older copy from the
//!    journal), a bodyfile line.
//! 2. **Activity.** The latest creation, modification or metadata change
//!    time the record shows, its `$FILE_NAME` copies and its USN records
//!    included. Access times are left out: reading a file does not make it
//!    part of the incident. An NTFS record used for the first time cannot be
//!    older than the first-use record numbered just before it (NTFS hands out
//!    the lowest free record), so that record's creation counts too: a file
//!    whose every timestamp was moved back still lands in the window.
//! 3. **Baseline and window.** Records active at or after the cutoff are the
//!    window, the others the baseline. Each volume is its own reference.
//! 4. **Coordinates.** How far each timestamp relation departs from what the
//!    filesystem writes on its own (see [`COORDS`]). A record is irregular
//!    when one of them is above zero.
//! 5. **Joint test.** T = sum over the coordinates above zero of
//!    -ln(share of null records at least as high). The null is the irregular
//!    baseline records of the volume, each with its T computed leaving
//!    itself out; p = (1 + #null T >= T) / (1 + N), a conformal p-value,
//!    valid whatever the dependence between coordinates.
//! 6. **Decision.** Benjamini-Hochberg across the irregular window records
//!    of every volume. The only number the analyst chooses is alpha.
//!
//! Coordinates that the volume cannot express are switched off by the data
//! itself: a whole-second test needs at least one sub-second value of that
//! kind on the volume, a USN coordinate needs a journal that reaches into
//! the baseline.
//!
//! The output follows masstin: every row of the timeline gets the hunt's
//! verdict on its record in the analysis tail (`hunt`, `hunt_score`,
//! `hunt_why`, see [`State`] and [`score_of`]), and `--hunt-out` writes a
//! findings table with the 19 columns of graph-hunt's, each in the position
//! of the one with the closest meaning (see [`HUNT_HEADER`]).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use mft::attribute::x30::FileNameAttr;
use mft::StandardInfoAttr;

use crate::anomaly;
use crate::error::{AllyError, ErrorCode, Result};
use crate::stats;
use crate::timeline::{escape_csv, escape_csv_text, source, TimelineEntry};

/// A timestamp as (seconds since 1970, nanoseconds).
pub type Ts = (i64, u32);

/// The four timestamps of a record; `None` = not set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Macb {
    pub m: Option<Ts>,
    pub a: Option<Ts>,
    pub c: Option<Ts>,
    pub b: Option<Ts>,
}

impl Macb {
    fn all(&self) -> impl Iterator<Item = Ts> {
        [self.m, self.a, self.c, self.b].into_iter().flatten()
    }
    /// Creation, modification and change: what the activity is made of.
    fn active(&self) -> impl Iterator<Item = Ts> {
        [self.m, self.c, self.b].into_iter().flatten()
    }
}

/// What a parser knows about one record, for the hunt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// One NTFS `FILE` record: `$STANDARD_INFORMATION` and every `$FILE_NAME`.
    Ntfs { entry: u64, seq: u16, si: Macb, fns: Vec<Macb> },
    /// One Unix inode state.
    Unix { inode: u64, t: Macb },
    /// One USN record, joined to the NTFS record with the same reference.
    Usn { entry: u64, seq: u16, reason: u32, time: Ts },
}

/// Attached to every timeline row built from one record, so the hunt can
/// rebuild the record and mark its rows.
#[derive(Debug, PartialEq, Eq)]
pub struct HuntRecord {
    /// Unique per record state in the run.
    pub unit: u64,
    /// Volume the record belongs to (see [`new_volume`]).
    pub volume: u32,
    pub evidence: Evidence,
}

static NEXT_VOLUME: AtomicU32 = AtomicU32::new(1);
static NEXT_UNIT: AtomicU64 = AtomicU64::new(1);

/// A new volume id; each parse of a `$MFT`, an ext4 volume, a bodyfile or a
/// USN journal takes one.
pub fn new_volume() -> u32 {
    NEXT_VOLUME.fetch_add(1, Ordering::Relaxed)
}

pub fn record(volume: u32, evidence: Evidence) -> Arc<HuntRecord> {
    Arc::new(HuntRecord { unit: NEXT_UNIT.fetch_add(1, Ordering::Relaxed), volume, evidence })
}

/// An NTFS timestamp; FILETIME 0 is "unset".
pub fn ntfs_ts(t: &mft::Timestamp) -> Option<Ts> {
    let s = t.as_second();
    if s == -crate::timefmt::SECS_BETWEEN_1601_AND_1970 && t.subsec_nanosecond() == 0 {
        return None;
    }
    Some((s, t.subsec_nanosecond().max(0) as u32))
}

pub fn si_macb(si: &StandardInfoAttr) -> Macb {
    Macb { m: ntfs_ts(&si.modified), a: ntfs_ts(&si.accessed), c: ntfs_ts(&si.mft_modified), b: ntfs_ts(&si.created) }
}

pub fn fn_macb(f: &FileNameAttr) -> Macb {
    Macb { m: ntfs_ts(&f.modified), a: ntfs_ts(&f.accessed), c: ntfs_ts(&f.mft_modified), b: ntfs_ts(&f.created) }
}

/// A Unix timestamp; (0, 0) is "unset".
pub fn unix_ts(t: Ts) -> Option<Ts> {
    if t == (0, 0) { None } else { Some(t) }
}

// ───────────────────────────── coordinates ──────────────────────────────────

/// How a coordinate's value reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Measure {
    Seconds,
    Flag,
    Count,
}

/// Kind of finding, used to order rows (the p-value is untouched).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Signature {
    /// An ordering the filesystem never writes, or two kernel records that
    /// disagree: the timestamps were written by hand.
    Contradiction,
    /// What timestomping tools leave: `$SI` behind `$FN`, whole seconds,
    /// timestamp-only journal records.
    Stomp,
    /// A name built to fool the reader.
    Name,
    /// Only what preserved-timestamp copies also produce.
    Copy,
}

impl Signature {
    pub fn as_str(self) -> &'static str {
        match self {
            Signature::Contradiction => "contradiction",
            Signature::Stomp => "stomp",
            Signature::Name => "name",
            Signature::Copy => "copy",
        }
    }
}

struct Coord {
    key: &'static str,
    what: &'static str,
    measure: Measure,
    signature: Signature,
}

const K: usize = 16;
const B_BEFORE_FN: usize = 0;
const B_AFTER_C: usize = 1;
const M_AFTER_C: usize = 2;
const M_BEFORE_B: usize = 3;
const WHOLE_B: usize = 4;
const WHOLE_M: usize = 5;
const WHOLE_C: usize = 6;
const WHOLE_A: usize = 7;
const WHOLE_FN: usize = 8;
const FUTURE: usize = 9;
const BEFORE_VOLUME: usize = 10;
const FN_BEFORE_USN: usize = 11;
const BASIC_INFO: usize = 12;
const BACKDATED: usize = 13;
const NAME: usize = 14;
const ALLOC_ORDER: usize = 15;

/// Every coordinate of the joint test.
const COORDS: [Coord; K] = [
    Coord { key: "b_before_fn", what: "$SI creation before the $FILE_NAME creation", measure: Measure::Seconds, signature: Signature::Stomp },
    Coord { key: "b_after_c", what: "creation after the metadata change time", measure: Measure::Seconds, signature: Signature::Contradiction },
    // Unix only: NTFS leaves `$SI` modified ahead of the change time on files
    // written through mapped sections (registry hives, WMI repository), and
    // those are written every day, so the baseline never holds them.
    Coord { key: "m_after_c", what: "modification after the metadata change time", measure: Measure::Seconds, signature: Signature::Contradiction },
    Coord { key: "m_before_b", what: "modification before creation", measure: Measure::Seconds, signature: Signature::Copy },
    Coord { key: "whole_sec_b", what: "creation time in whole seconds", measure: Measure::Flag, signature: Signature::Stomp },
    Coord { key: "whole_sec_m", what: "modification time in whole seconds", measure: Measure::Flag, signature: Signature::Stomp },
    Coord { key: "whole_sec_c", what: "metadata change time in whole seconds", measure: Measure::Flag, signature: Signature::Stomp },
    Coord { key: "whole_sec_a", what: "access time in whole seconds", measure: Measure::Flag, signature: Signature::Stomp },
    Coord { key: "whole_sec_fn", what: "$FILE_NAME times in whole seconds", measure: Measure::Flag, signature: Signature::Stomp },
    // The rule indicator: a time later than the analysis itself. The newest
    // time the volume wrote is no reference: files open at shutdown (hives,
    // logs) carry `$SI` times seconds after any `$FILE_NAME` change.
    Coord { key: "future", what: "a time later than the analysis itself", measure: Measure::Flag, signature: Signature::Contradiction },
    Coord { key: "before_volume", what: "creation before the volume was formatted", measure: Measure::Seconds, signature: Signature::Stomp },
    Coord { key: "fn_before_usn", what: "$FILE_NAME creation before the journal's create record", measure: Measure::Seconds, signature: Signature::Contradiction },
    Coord { key: "basic_info", what: "journal records that change only timestamps or attributes", measure: Measure::Count, signature: Signature::Stomp },
    Coord { key: "backdated", what: "an older copy of the record had later times", measure: Measure::Flag, signature: Signature::Contradiction },
    Coord { key: "name", what: "name tricks (bidi override, invisible characters, double extension)", measure: Measure::Count, signature: Signature::Name },
    Coord { key: "alloc_order", what: "$FILE_NAME creation before that of the record allocated just before it", measure: Measure::Seconds, signature: Signature::Stomp },
];

/// First record number NTFS hands to files; 0-23 are the metadata files.
const FIRST_USER_RECORD: u64 = 24;
/// Sequence number of a record slot that was never freed.
const FIRST_USE_SEQUENCE: u16 = 1;

fn diff(a: Ts, b: Ts) -> f64 {
    (a.0 - b.0) as f64 + (f64::from(a.1) - f64::from(b.1)) / 1e9
}

fn gap(a: Option<Ts>, b: Option<Ts>) -> f64 {
    match (a, b) {
        (Some(a), Some(b)) => diff(a, b).max(0.0),
        _ => 0.0,
    }
}

fn whole(t: Option<Ts>, enabled: bool) -> f64 {
    match t {
        Some((_, 0)) if enabled => 1.0,
        _ => 0.0,
    }
}

// ───────────────────────────── joint test ───────────────────────────────────
//
// Statistic: T(x) = sum over coordinates of -ln(share of null points at
// least as high in that coordinate), only for coordinates above zero. It
// is calibrated empirically: p = (1 + #null points with T >= T(x)) /
// (1 + N), the null points' own T being computed leaving themselves out.

struct JointNull {
    /// per coordinate, null values ascending
    cols: Vec<Vec<f64>>,
    /// per coordinate, distinct baseline days among `cols[k][i..]`
    days_from: Vec<Vec<usize>>,
    /// null T values ascending
    t_sorted: Vec<f64>,
    n: usize,
}

fn surprise(col: &[f64], v: f64, n: usize, self_in_null: bool) -> f64 {
    if v <= 0.0 || col.is_empty() {
        return 0.0;
    }
    let me = usize::from(self_in_null);
    let ge = col.len() - col.partition_point(|x| *x < v) - me;
    -stats::empirical_p(ge, n.saturating_sub(me)).ln()
}

impl JointNull {
    fn new(rows: &[[f64; K]], days: &[i64]) -> Self {
        let n = rows.len();
        let mut cols = Vec::with_capacity(K);
        let mut days_from = Vec::with_capacity(K);
        for k in 0..K {
            let mut v: Vec<(f64, i64)> = rows.iter().zip(days).map(|(r, d)| (r[k], *d)).collect();
            v.sort_by(|a, b| a.0.total_cmp(&b.0));
            let mut seen = HashSet::new();
            let mut from = vec![0usize; n + 1];
            for i in (0..n).rev() {
                seen.insert(v[i].1);
                from[i] = seen.len();
            }
            cols.push(v.into_iter().map(|(x, _)| x).collect::<Vec<f64>>());
            days_from.push(from);
        }
        let mut t_sorted: Vec<f64> = rows.iter().map(|r| (0..K).map(|k| surprise(&cols[k], r[k], n, true)).sum()).collect();
        t_sorted.sort_by(|a, b| a.total_cmp(b));
        JointNull { cols, days_from, t_sorted, n }
    }

    /// (p, T): conformal p of the joint statistic.
    fn test(&self, x: &[f64; K]) -> (f64, f64) {
        let t: f64 = (0..K).map(|k| surprise(&self.cols[k], x[k], self.n, false)).sum();
        let ge = self.t_sorted.len() - self.t_sorted.partition_point(|v| *v < t - 1e-12);
        (stats::empirical_p(ge, self.n), t)
    }

    /// Null records at least as high in coordinate `k`, and the distinct
    /// baseline days they fall on.
    fn marginal(&self, k: usize, v: f64) -> (usize, usize) {
        let idx = self.cols[k].partition_point(|x| *x < v);
        (self.cols[k].len() - idx, self.days_from[k][idx])
    }
}

// ───────────────────────────── the hunt ─────────────────────────────────────

pub struct HuntOptions {
    /// Cutoff, Unix seconds: records active at or after it are tested.
    pub from: i64,
    /// False discovery rate.
    pub alpha: f64,
}

/// What the hunt made of a record: the `hunt` column of the timeline, with
/// masstin's values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// Irregular, tested, q <= alpha.
    Significant,
    /// Irregular, tested, q > alpha: nothing that passes the bar.
    Candidate,
    /// Active in the window on a volume with nothing to compare it with: no
    /// irregular baseline record (when irregular), no baseline at all
    /// (otherwise).
    NotEvaluated,
    /// Active in the window with no coordinate above zero: like most of the
    /// volume's records. Not a test; q = 1.
    Habitual,
    /// Active before the cutoff: reference, not judged.
    Baseline,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Significant => "significant",
            State::Candidate => "candidate",
            State::NotEvaluated => "not_evaluated",
            State::Habitual => "habitual",
            State::Baseline => "baseline",
        }
    }
}

/// The hunt's verdict on one record, shared by every row built from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub state: State,
    /// `hunt_score`: how rare a tested record is (see [`score_of`]), 0 for a
    /// habitual one, None otherwise.
    pub score: Option<u8>,
    /// What is unusual, in words; empty when nothing is.
    pub why: String,
}

/// Top of the `hunt_score` scale.
pub const SCORE_MAX: u8 = 100;

/// The `hunt_score` of a q-value, as masstin computes it: `-10 log10 q`,
/// rounded and capped at 100 (the Phred scale). 0 is no rarer than chance,
/// 13 one in twenty (where `significant` starts at the default alpha), 20
/// one in a hundred, 30 one in a thousand. None for NaN (no test).
pub fn score_of(q: f64) -> Option<u8> {
    if q.is_nan() {
        return None;
    }
    if q <= 0.0 {
        return Some(SCORE_MAX);
    }
    Some((-10.0 * q.log10()).round().clamp(0.0, SCORE_MAX as f64) as u8)
}

/// How rare a score is, in words: `one in 160`.
pub fn score_words(score: u8) -> String {
    if score == 0 {
        return "no rarer than chance".to_string();
    }
    if score >= SCORE_MAX {
        return "one in ten thousand million or rarer".to_string();
    }
    let n = 10f64.powf(score as f64 / 10.0);
    // two significant figures, with separators
    let mag = 10f64.powi(n.log10().floor() as i32 - 1).max(1.0);
    let mut digits = ((n / mag).round() * mag).round().to_string();
    let mut out = String::new();
    while digits.len() > 3 {
        let rest = digits.split_off(digits.len() - 3);
        out = format!(",{}{}", rest, out);
    }
    format!("one in {}{}", digits, out)
}

/// One irregular record of the window.
pub struct Finding {
    pub unit: u64,
    pub volume: u32,
    /// Where the record lives: its host and volume as the timeline names
    /// them (`srv01 C:`), or the root of its path.
    pub place: String,
    pub file_name: String,
    pub meta: String,
    /// Owner of a Unix record; None on NTFS.
    pub owner: Option<u32>,
    /// Rule ids of the record with their level (see [`anomaly::ids`]).
    pub flags: String,
    /// Timeline rows of the record, joined journal records included.
    pub rows: usize,
    /// Sources of those rows, `+`-joined.
    pub logs: String,
    /// Earliest time the record shows.
    pub first: i64,
    pub activity: i64,
    /// NaN when not evaluated.
    pub p: f64,
    pub q: f64,
    pub t: f64,
    pub state: State,
    pub significant: bool,
    pub signature: Signature,
    /// What is unusual, in short phrases without counts, strongest first.
    pub why: String,
    /// The same phrases with the value and the baseline count behind each.
    pub evidence: String,
}

#[derive(Default)]
pub struct HuntReport {
    /// Significant first, then candidates, then not evaluated; within each
    /// by signature, p and surprise.
    pub findings: Vec<Finding>,
    /// One line per volume and per decision the data made, for stderr.
    pub notes: Vec<String>,
    /// Verdict per record (unit id).
    pub marks: HashMap<u64, Arc<Mark>>,
    /// Journal records joined to a live `$MFT` record: (entry, sequence) -> unit.
    usn_units: HashMap<(u64, u16), u64>,
}

impl HuntReport {
    /// The verdict a timeline row takes: its record's, or for a journal row
    /// that of the record it was joined to (as masstin's session end takes
    /// the state of its login).
    pub fn mark(&self, rec: &HuntRecord) -> Option<Arc<Mark>> {
        let unit = match rec.evidence {
            Evidence::Usn { entry, seq, .. } => *self.usn_units.get(&(entry, seq))?,
            _ => rec.unit,
        };
        self.marks.get(&unit).cloned()
    }

    /// Number of records with each state, in [`State`] order.
    pub fn counts(&self) -> [usize; 5] {
        let mut c = [0usize; 5];
        for m in self.marks.values() {
            c[m.state as usize] += 1;
        }
        c
    }
}

/// One record gathered from its rows.
struct Unit<'a> {
    rec: &'a HuntRecord,
    name: &'a str,
    meta: &'a str,
    source: &'static str,
    host: &'a str,
    volume: &'a str,
    uid: u32,
    rows: usize,
    sources: BTreeSet<&'static str>,
    flags: BTreeSet<&'a str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Ntfs,
    Unix,
}

/// What the volume tells about itself.
struct Volume {
    family: Family,
    /// Format time: `$MFT`'s own creation, or the root directory's.
    birth: Option<Ts>,
    /// Sub-second values seen, per kind: b, m, c, a, $FILE_NAME.
    subsec: [bool; 5],
    /// The USN journal joined to this volume, and whether its coordinates
    /// can be calibrated (it reaches into the baseline).
    usn_span: Option<(Ts, Ts)>,
    usn_on: bool,
    /// Host and volume of its first record, to tell volumes apart on stderr.
    example: String,
}

const NAME_FLAGS: [&str; 3] = [anomaly::RTLO_NAME, anomaly::INVISIBLE_NAME, anomaly::DOUBLE_EXT];

/// Runs the hunt over a finished timeline.
pub fn run(timeline: &[TimelineEntry], opts: &HuntOptions) -> HuntReport {
    let mut report = HuntReport::default();

    // ── gather records and journal entries ──
    let mut index: HashMap<u64, usize> = HashMap::new();
    let mut units: Vec<Unit> = Vec::new();
    let mut usn: HashMap<(u64, u16), Vec<(u32, Ts)>> = HashMap::new();
    for e in timeline {
        let Some(rec) = e.hunt.as_deref() else { continue };
        if let Evidence::Usn { entry, seq, reason, time } = rec.evidence {
            usn.entry((entry, seq)).or_default().push((reason, time));
            continue;
        }
        let i = *index.entry(rec.unit).or_insert_with(|| {
            units.push(Unit { rec, name: &e.file_name, meta: &e.meta, source: e.source, host: e.host.as_deref().unwrap_or(""), volume: e.volume.as_deref().unwrap_or(""), uid: e.uid, rows: 0, sources: BTreeSet::new(), flags: BTreeSet::new() });
            units.len() - 1
        });
        let u = &mut units[i];
        u.rows += 1;
        u.sources.insert(e.source);
        if e.file_name.len() < u.name.len() {
            u.name = &e.file_name;
        }
        u.flags.extend(anomaly::parse_column(&e.flags));
    }

    // ── volumes ──
    let mut volumes: HashMap<u32, Volume> = HashMap::new();
    for u in &units {
        let v = volumes.entry(u.rec.volume).or_insert_with(|| Volume {
            family: if matches!(u.rec.evidence, Evidence::Ntfs { .. }) { Family::Ntfs } else { Family::Unix },
            birth: None,
            subsec: [false; 5],
            usn_span: None,
            usn_on: false,
            example: place(u),
        });
        match &u.rec.evidence {
            Evidence::Ntfs { entry, si, fns, .. } => {
                for f in fns {
                    if f.all().any(|t| t.1 != 0) {
                        v.subsec[4] = true;
                    }
                }
                if *entry == 0 && u.source == source::MFT {
                    v.birth = fns.iter().filter_map(|f| f.b).min();
                }
                note_subsec(&mut v.subsec, si);
            }
            Evidence::Unix { inode, t } => {
                if *inode == 2 && u.source != source::CARVED {
                    v.birth = t.b;
                }
                note_subsec(&mut v.subsec, t);
            }
            Evidence::Usn { .. } => {}
        }
    }

    // ── the journal belongs to the one NTFS volume read from a live $MFT ──
    let live_ntfs: BTreeSet<u32> = units
        .iter()
        .filter(|u| u.source == source::MFT && matches!(u.rec.evidence, Evidence::Ntfs { .. }))
        .map(|u| u.rec.volume)
        .collect();
    let mut usn_volume: Option<u32> = None;
    if !usn.is_empty() {
        if live_ntfs.len() == 1 {
            let vid = *live_ntfs.iter().next().unwrap_or(&0);
            let times = usn.values().flatten().map(|(_, t)| *t);
            let span = (times.clone().min().unwrap_or_default(), times.max().unwrap_or_default());
            if let Some(v) = volumes.get_mut(&vid) {
                v.usn_span = Some(span);
                v.usn_on = span.0 .0 < opts.from;
                if !v.usn_on {
                    report.notes.push(format!(
                        "USN journal starts at {}, after the cutoff: its coordinates have no baseline and are off",
                        fmt_time(span.0 .0)
                    ));
                }
            }
            usn_volume = Some(vid);
        } else {
            report.notes.push(format!(
                "USN journal not joined: {} NTFS volumes read from a live $MFT, the journal cannot be matched to one",
                live_ntfs.len()
            ));
        }
    }

    // ── allocation order: first-use live records of each volume by number ──
    // unit index -> `$FILE_NAME` creation of the first-use record numbered just before it
    let mut prev_alloc: HashMap<usize, Ts> = HashMap::new();
    {
        let mut chain: Vec<(u32, u64, usize, Ts)> = units
            .iter()
            .enumerate()
            .filter(|(_, u)| u.source == source::MFT)
            .filter_map(|(i, u)| match &u.rec.evidence {
                Evidence::Ntfs { entry, seq, fns, .. } if *seq == FIRST_USE_SEQUENCE && *entry >= FIRST_USER_RECORD => {
                    fns.iter().filter_map(|f| f.b).min().map(|b| (u.rec.volume, *entry, i, b))
                }
                _ => None,
            })
            .collect();
        chain.sort_unstable_by_key(|c| (c.0, c.1));
        for w in chain.windows(2) {
            if w[0].0 == w[1].0 {
                prev_alloc.insert(w[1].2, w[0].3);
            }
        }
    }

    // ── coordinates ──
    struct Row {
        unit: usize,
        first: i64,
        activity: i64,
        journal: usize,
        x: [f64; K],
    }
    let mut rows: Vec<Row> = Vec::new();
    for (ui, u) in units.iter().enumerate() {
        let Some(v) = volumes.get(&u.rec.volume) else { continue };
        let mut x = [0.0f64; K];
        let activity: Option<Ts>;
        let first: Option<Ts>;
        let mut journal_rows = 0;
        match &u.rec.evidence {
            Evidence::Ntfs { entry, seq, si, fns } => {
                let journal: &[(u32, Ts)] = if usn_volume == Some(u.rec.volume) {
                    usn.get(&(*entry, *seq)).map(|v| v.as_slice()).unwrap_or(&[])
                } else {
                    &[]
                };
                if !journal.is_empty() && u.source == source::MFT {
                    report.usn_units.insert((*entry, *seq), u.rec.unit);
                    journal_rows = journal.len();
                }
                first = si.all().chain(fns.iter().flat_map(|f| f.all())).chain(journal.iter().map(|(_, t)| *t)).min();
                let before = prev_alloc.get(&ui).copied();
                activity = si.active().chain(fns.iter().flat_map(|f| f.active())).chain(journal.iter().map(|(_, t)| *t)).chain(before).max();
                x[ALLOC_ORDER] = gap(before, fns.iter().filter_map(|f| f.b).min());
                x[B_BEFORE_FN] = fns.iter().map(|f| gap(f.b, si.b)).fold(0.0, f64::max);
                x[B_AFTER_C] = gap(si.b, si.c);
                x[M_BEFORE_B] = gap(si.b, si.m);
                x[WHOLE_B] = whole(si.b, v.subsec[0]);
                x[WHOLE_M] = whole(si.m, v.subsec[1]);
                x[WHOLE_C] = whole(si.c, v.subsec[2]);
                x[WHOLE_A] = whole(si.a, v.subsec[3]);
                if v.subsec[4] && !fns.is_empty() && fns.iter().all(|f| [f.b, f.m, f.c].into_iter().flatten().all(|t| t.1 == 0)) {
                    x[WHOLE_FN] = 1.0;
                }
                x[BEFORE_VOLUME] = gap(v.birth, si.b);
                if v.usn_on {
                    let created = journal.iter().filter(|(r, _)| r & USN_FILE_CREATE != 0).map(|(_, t)| *t).min();
                    x[FN_BEFORE_USN] = gap(created, fns.iter().filter_map(|f| f.b).min());
                    x[BASIC_INFO] = journal.iter().filter(|(r, _)| !anomaly::usn_flags(*r).is_empty()).count() as f64;
                }
            }
            Evidence::Unix { t, .. } => {
                activity = t.active().max();
                first = t.all().min();
                x[B_AFTER_C] = gap(t.b, t.c);
                x[M_AFTER_C] = gap(t.m, t.c);
                x[M_BEFORE_B] = gap(t.b, t.m);
                x[WHOLE_B] = whole(t.b, v.subsec[0]);
                x[WHOLE_M] = whole(t.m, v.subsec[1]);
                x[WHOLE_C] = whole(t.c, v.subsec[2]);
                x[WHOLE_A] = whole(t.a, v.subsec[3]);
                x[BEFORE_VOLUME] = gap(v.birth, t.b);
            }
            Evidence::Usn { .. } => continue,
        }
        if u.flags.contains(anomaly::BACKDATED) {
            x[BACKDATED] = 1.0;
        }
        if u.flags.contains(anomaly::FUTURE) {
            x[FUTURE] = 1.0;
        }
        x[NAME] = NAME_FLAGS.iter().filter(|f| u.flags.contains(**f)).count() as f64;
        let Some(activity) = activity else { continue };
        let first = first.map_or(activity.0, |f| f.0.min(activity.0));
        rows.push(Row { unit: ui, first, activity: activity.0, journal: journal_rows, x });
    }

    // ── one null per volume, one family of tests for the run ──
    struct Tested {
        row: usize,
        /// false: the volume has no irregular baseline record
        evaluated: bool,
        p: f64,
        t: f64,
        marg: [(usize, usize); K],
        n: usize,
        days: usize,
    }
    let mut tested: Vec<Tested> = Vec::new();
    let mut vids: Vec<u32> = volumes.keys().copied().collect();
    vids.sort_unstable();
    let irregular = |r: &Row| r.x.iter().any(|x| *x > 0.0);
    for vid in vids {
        let v = &volumes[&vid];
        let in_volume: Vec<usize> = (0..rows.len()).filter(|&i| units[rows[i].unit].rec.volume == vid).collect();
        let baseline = in_volume.iter().filter(|&&i| rows[i].activity < opts.from).count();
        // With the journal on, only baseline records inside its span can
        // show a USN coordinate: the others would read as "never changed".
        let journal_from = if v.usn_on { v.usn_span.map(|s| s.0 .0) } else { None };
        let null_idx: Vec<usize> = in_volume
            .iter()
            .copied()
            .filter(|&i| rows[i].activity < opts.from && journal_from.is_none_or(|j| rows[i].activity >= j) && irregular(&rows[i]))
            .collect();
        let test_idx: Vec<usize> = in_volume.iter().copied().filter(|&i| rows[i].activity >= opts.from && irregular(&rows[i])).collect();
        let window = in_volume.len() - baseline;
        let null_rows: Vec<[f64; K]> = null_idx.iter().map(|&i| rows[i].x).collect();
        let null_days: Vec<i64> = null_idx.iter().map(|&i| rows[i].activity.div_euclid(86_400)).collect();
        let n_days = null_days.iter().collect::<HashSet<_>>().len();
        let jn = JointNull::new(&null_rows, &null_days);
        let kind = if v.family == Family::Ntfs { "ntfs" } else { "unix" };
        let origin: Arc<str> = format!("volume {} ({}, {})", vid, kind, v.example).into();
        let evaluated = !null_idx.is_empty();
        let off: Vec<&str> = switched_off(v).collect();
        report.notes.push(format!(
            "{}: {} records; baseline {}, of which {} irregular on {} day(s) form the null{}; window {}, {} irregular {}; highest reachable score {}{}",
            origin,
            in_volume.len(),
            baseline,
            null_idx.len(),
            n_days,
            if journal_from.is_some() { " (inside the USN journal's span)" } else { "" },
            window,
            test_idx.len(),
            if evaluated { "tested" } else { "not evaluated, nothing to compare them with" },
            score_of(stats::empirical_p(0, null_idx.len())).unwrap_or(0),
            if off.is_empty() { String::new() } else { format!("; off for lack of resolution: {}", off.join(", ")) },
        ));
        for &i in &in_volume {
            let r = &rows[i];
            let state = if r.activity < opts.from {
                State::Baseline
            } else if irregular(r) {
                continue;
            } else if baseline == 0 {
                State::NotEvaluated
            } else {
                State::Habitual
            };
            let score = (state == State::Habitual).then_some(0);
            report.marks.insert(units[r.unit].rec.unit, Arc::new(Mark { state, score, why: String::new() }));
        }
        for i in test_idx {
            let (p, t) = if evaluated { jn.test(&rows[i].x) } else { (f64::NAN, 0.0) };
            let mut marg = [(0usize, 0usize); K];
            for (k, m) in marg.iter_mut().enumerate() {
                if evaluated && rows[i].x[k] > 0.0 {
                    *m = jn.marginal(k, rows[i].x[k]);
                }
            }
            tested.push(Tested { row: i, evaluated, p, t, marg, n: jn.n, days: n_days });
        }
    }

    // Benjamini-Hochberg over the records that could be tested.
    let evaluated: Vec<usize> = (0..tested.len()).filter(|&j| tested[j].evaluated).collect();
    let mut q = vec![f64::NAN; tested.len()];
    for (j, qv) in evaluated.iter().zip(stats::benjamini_hochberg(&evaluated.iter().map(|&j| tested[j].p).collect::<Vec<_>>())) {
        q[*j] = qv;
    }
    for (j, ts) in tested.iter().enumerate() {
        let row = &rows[ts.row];
        let u = &units[row.unit];
        let state = if !ts.evaluated {
            State::NotEvaluated
        } else if q[j] <= opts.alpha {
            State::Significant
        } else {
            State::Candidate
        };
        let mut parts: Vec<(f64, usize)> = (0..K).filter(|&k| row.x[k] > 0.0).map(|k| (-stats::empirical_p(ts.marg[k].0, ts.n).ln(), k)).collect();
        parts.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        let signature = parts.iter().map(|(_, k)| COORDS[*k].signature).min().unwrap_or(Signature::Copy);
        let why: Vec<&str> = parts.iter().map(|(_, k)| COORDS[*k].what).collect();
        let evidence: Vec<String> = parts
            .iter()
            .map(|(_, k)| {
                let c = &COORDS[*k];
                let value = match c.measure {
                    Measure::Seconds => format!(" by {}", fmt_secs(row.x[*k])),
                    Measure::Count => format!(" ({})", row.x[*k]),
                    Measure::Flag => String::new(),
                };
                if ts.evaluated {
                    format!("{}{}: shared by {} of {} irregular baseline records, on {} of {} days", c.what, value, ts.marg[*k].0, ts.n, ts.marg[*k].1, ts.days)
                } else {
                    format!("{}{}: no irregular baseline record on this volume", c.what, value)
                }
            })
            .collect();
        let why = why.join("; ");
        report.marks.insert(u.rec.unit, Arc::new(Mark { state, score: score_of(q[j]), why: why.clone() }));
        let mut logs = u.sources.clone();
        if row.journal > 0 {
            logs.insert(source::USN);
        }
        report.findings.push(Finding {
            unit: u.rec.unit,
            volume: u.rec.volume,
            place: place(u),
            file_name: u.name.to_string(),
            meta: u.meta.to_string(),
            owner: matches!(u.rec.evidence, Evidence::Unix { .. }).then_some(u.uid),
            flags: anomaly::ids(&u.flags.iter().copied().collect::<Vec<_>>()),
            rows: u.rows + row.journal,
            logs: logs.into_iter().collect::<Vec<_>>().join("+"),
            first: row.first,
            activity: row.activity,
            p: ts.p,
            q: q[j],
            t: ts.t,
            state,
            significant: state == State::Significant,
            signature,
            why,
            evidence: evidence.join("; "),
        });
    }
    report.findings.sort_by(|a, b| {
        a.state
            .cmp(&b.state)
            .then(a.signature.cmp(&b.signature))
            .then(a.p.total_cmp(&b.p))
            .then(b.t.total_cmp(&a.t))
            .then(a.activity.cmp(&b.activity))
    });
    report
}

const USN_FILE_CREATE: u32 = 0x0000_0100;

fn note_subsec(subsec: &mut [bool; 5], t: &Macb) {
    for (k, v) in [t.b, t.m, t.c, t.a].into_iter().enumerate() {
        if matches!(v, Some((_, ns)) if ns != 0) {
            subsec[k] = true;
        }
    }
}

fn switched_off(v: &Volume) -> impl Iterator<Item = &'static str> + '_ {
    let mut kinds: Vec<usize> = vec![WHOLE_B, WHOLE_M, WHOLE_C, WHOLE_A];
    if v.family == Family::Ntfs {
        kinds.push(WHOLE_FN);
    }
    kinds.into_iter().filter(move |&k| !v.subsec[k - WHOLE_B]).map(|k| COORDS[k].key)
}

/// First path component, e.g. `C:` or `/`.
/// Host and volume of a record as the timeline names them (`srv01 p2`), the
/// root of its path standing in for a volume the timeline does not name.
fn place(u: &Unit) -> String {
    let volume = if u.volume.is_empty() { volume_root(u.name) } else { u.volume };
    [u.host, volume].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ")
}

/// Root of a path: `C:` for `C:\\x`, `/` for `/x`.
fn volume_root(example: &str) -> &str {
    match example.find(['\\', '/']) {
        Some(0) => "/",
        Some(i) => &example[..i],
        None => example,
    }
}

fn fmt_time(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_else(|| secs.to_string())
}

/// p and q as masstin writes them; empty when not evaluated.
fn fmt_p(p: f64) -> String {
    if p.is_nan() { String::new() } else { format!("{:.3e}", p) }
}

fn day_str(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
}

fn ts_str(secs: i64) -> String {
    chrono::DateTime::from_timestamp(secs, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default()
}

/// A gap in seconds, in the unit an analyst reads.
fn fmt_secs(s: f64) -> String {
    const DAY: f64 = 86_400.0;
    if s < 1.0 {
        format!("{:.3} s", s)
    } else if s < 120.0 {
        format!("{:.0} s", s)
    } else if s < 7_200.0 {
        format!("{:.0} min", s / 60.0)
    } else if s < 2.0 * DAY {
        format!("{:.1} h", s / 3_600.0)
    } else if s < 730.0 * DAY {
        format!("{:.0} days", s / DAY)
    } else {
        format!("{:.1} years", s / (365.25 * DAY))
    }
}

/// Parses the cutoff: `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS` or RFC 3339, UTC.
pub fn parse_cutoff(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(d) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(d.timestamp());
    }
    let t = s.trim_end_matches('Z');
    for f in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"] {
        if let Ok(d) = chrono::NaiveDateTime::parse_from_str(t, f) {
            return Some(d.and_utc().timestamp());
        }
    }
    chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d").ok().and_then(|d| d.and_hms_opt(0, 0, 0)).map(|d| d.and_utc().timestamp())
}

/// Header of the hunt CSV.
///
/// masstin's graph-hunt writes `rank, significant, p_value, q_value, day,
/// first_seen_utc, last_seen_utc, origin, destination, account, result,
/// events, logs, signature, why_unusual, evidence, chain, campaign,
/// cypher_snippet`. The same number of columns, each in the position of the
/// one with the closest meaning: `volume` for `origin`, `file_name` for
/// `destination`, `owner` for `account`, `rules` for `result`, `rows` and
/// `sources` for `events` and `logs`, `related` and `group` (empty for now)
/// for `chain` and `campaign`, `lookup` (the record's rows in the timeline)
/// for `cypher_snippet`.
pub const HUNT_HEADER: &str = "rank,significant,p_value,q_value,day,first_seen_utc,last_seen_utc,volume,file_name,owner,rules,rows,sources,signature,why_unusual,evidence,related,group,lookup";

/// Writes every tested record, significant first.
pub fn write_csv(report: &HuntReport, path: &Path) -> Result<()> {
    let csv_err = |e: std::io::Error| AllyError::Csv { code: ErrorCode::CsvExportFailed, message: format!("Writing hunt CSV '{}': {}", path.display(), e) };
    let mut w = BufWriter::new(File::create(path).map_err(csv_err)?);
    writeln!(w, "{}", HUNT_HEADER).map_err(csv_err)?;
    for (i, f) in report.findings.iter().enumerate() {
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},,,{}",
            i + 1,
            match f.state {
                State::Significant => "yes",
                State::NotEvaluated => "not evaluated",
                _ => "no",
            },
            fmt_p(f.p),
            fmt_p(f.q),
            day_str(f.activity),
            ts_str(f.first),
            ts_str(f.activity),
            escape_csv_text(&f.place),
            escape_csv_text(&f.file_name),
            f.owner.map(|u| u.to_string()).unwrap_or_default(),
            escape_csv(&f.flags),
            f.rows,
            f.logs,
            f.signature.as_str(),
            escape_csv_text(&f.why),
            escape_csv_text(&f.evidence),
            escape_csv_text(&format!("meta={}", f.meta)),
        )
        .map_err(csv_err)?;
    }
    w.flush().map_err(csv_err)
}

/// Short form of one finding for stderr.
pub fn describe(f: &Finding) -> String {
    let first = f.evidence.split("; ").next().unwrap_or("");
    let score = score_of(f.q).unwrap_or(0);
    format!("score {:>2} ({}) {:<13} {}  (meta {}): {}", score, score_words(score), f.signature.as_str(), f.file_name, f.meta, first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_masstins_phred_scale() {
        assert_eq!(score_of(1.0), Some(0));
        assert_eq!(score_of(0.05), Some(13));
        assert_eq!(score_of(0.01), Some(20));
        assert_eq!(score_of(6.280e-3), Some(22));
        assert_eq!(score_of(1e-12), Some(100));
        assert_eq!(score_of(0.0), Some(100));
        assert_eq!(score_of(f64::NAN), None);
        assert_eq!(score_words(0), "no rarer than chance");
        assert_eq!(score_words(13), "one in 20");
        assert_eq!(score_words(22), "one in 160");
        assert_eq!(score_words(30), "one in 1,000");
        assert_eq!(score_words(60), "one in 1,000,000");
    }

    #[test]
    fn cutoff_formats() {
        assert_eq!(parse_cutoff("2026-10-28"), Some(1_793_145_600));
        assert_eq!(parse_cutoff("2026-10-28 00:00:00"), Some(1_793_145_600));
        assert_eq!(parse_cutoff("2026-10-28T00:00:00Z"), Some(1_793_145_600));
        assert_eq!(parse_cutoff("2026-10-28T02:00:00+02:00"), Some(1_793_145_600));
        assert_eq!(parse_cutoff("yesterday"), None);
    }

    #[test]
    fn joint_null_counts() {
        let mut rows = vec![[0.0; K]; 4];
        rows[0][M_BEFORE_B] = 10.0;
        rows[1][M_BEFORE_B] = 20.0;
        rows[2][M_BEFORE_B] = 30.0;
        rows[3][WHOLE_M] = 1.0;
        let jn = JointNull::new(&rows, &[1, 1, 2, 3]);
        assert_eq!(jn.marginal(M_BEFORE_B, 15.0), (2, 2));
        assert_eq!(jn.marginal(M_BEFORE_B, 40.0), (0, 0));
        let mut x = [0.0; K];
        x[M_BEFORE_B] = 40.0;
        let (p, _) = jn.test(&x);
        assert!((p - 0.2).abs() < 1e-12, "beyond the whole null: floor 1/(N+1)");
        x[M_BEFORE_B] = 5.0;
        let (p, _) = jn.test(&x);
        assert!(p > 0.5);
    }

    #[test]
    fn durations() {
        assert_eq!(fmt_secs(0.5), "0.500 s");
        assert_eq!(fmt_secs(90.0), "90 s");
        assert_eq!(fmt_secs(3_600.0), "60 min");
        assert_eq!(fmt_secs(86_400.0 * 10.0), "10 days");
        assert_eq!(fmt_secs(86_400.0 * 365.25 * 3.0), "3.0 years");
    }
}
