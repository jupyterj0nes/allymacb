//! What a volume's own history says about a record before its rules give it
//! a state. Two things a `$MFT` (or a Unix root) tells about itself that a
//! rule evaluated record by record cannot see:
//!
//! * **The installation.** A volume is born at a moment, the creation time
//!   of its first record (`$MFT` on NTFS, the root inode on Unix), and is
//!   then populated in one burst: on the clean Server 2016 of the reference,
//!   98 % of the records changed in the four hours after the birth. Image
//!   extraction and servicing set times by hand (times preserved from the
//!   image, records reused by the servicing stack), so the timestamp rules
//!   fire there by the thousand: 16,615 of the 16,964 `b_after_c` of the
//!   reference fall in one of those hours. A record changed inside that
//!   window, with no time later than its end, was installed with the volume:
//!   it is `baseline`, vouched for by the volume itself, and its rules keep
//!   their clause and add nothing (the convention of the four tools: a rule
//!   on an entry something vouches for adds nothing). The window runs from
//!   the birth hour through every following hour that still changed at least
//!   one record in a thousand of the volume.
//!
//! * **The hour.** Outside the installation, every record with rules that
//!   count is judged with the others of its hour, against the hours of clean
//!   machines (`src/hours.rs`, measured by `scripts/measure_hours.py`): of
//!   the records that changed in the hour on the volume, what share carry
//!   the same pattern, and how many clean hours reach that share. The p is
//!   empirical, with the add-one correction, as in masstin's graph-hunt:
//!   `(1 + clean hours at or above the share) / (1 + clean hours)`. At or
//!   below alpha, the hour holds something clean machines do not: the first
//!   record keeps the state and the points and says how many came with it,
//!   and the others are `habitual` and point at it, because hundreds of
//!   records with the same pattern in one hour are one operation, not
//!   hundreds of anomalies (a pattern no clean hour has at all is not
//!   folded: nothing benign does that by the hundred, so every record keeps
//!   its state). Above alpha, the hour is one a clean machine
//!   has: `habitual`, no points, the clause gives the numbers. The first
//!   boot of a virtual machine (1,139 files with preserved times in one
//!   hour on the reference) and the hourly touch of `UsrClass.dat` are
//!   clean hours, and a case's hour that looks like them is judged like
//!   them. A pattern no clean hour has at all is never explained by its
//!   hour: the record keeps its state, and the corpus bound is its score.
//!   What this can say is bounded by the clean hours measured: with
//!   fourteen, no share is rarer than one in fifteen, and only the patterns
//!   clean machines never produce reach a state.

use std::collections::HashMap;
use std::sync::Arc;

use crate::anomaly;
use crate::hours::{self, CleanHour};
use crate::hunt::{Evidence, Macb, Ts};
use crate::timefmt::format_unix_timestamp;
use crate::timeline::TimelineEntry;

/// The hours after the volume's birth that still changed at least this
/// share of its records belong to the installation.
const INSTALL_SHARE: f64 = 0.001;

const HOUR: i64 = 3600;

/// The installation window of one volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// Birth of the volume: creation time of its first record.
    pub from: String,
    /// Last second of the last hour of the installation.
    pub to: String,
    /// Records installed with the volume.
    pub records: usize,
    /// Records of the volume.
    pub total: usize,
}

impl Install {
    /// The words the tail gives an installed record.
    pub fn clause(&self) -> String {
        format!("installed with the volume from {} to {} ({} of {} records)", self.from, self.to, self.records, self.total)
    }
}

/// What the volume says about one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Context {
    /// Changed inside the installation window, nothing later: `baseline`.
    Installed(Arc<Install>),
    /// One of the records with the same rules changed in the same hour,
    /// a share of the hour's records that clean hours do not reach.
    Burst {
        /// The first record of the burst keeps its state; the others are
        /// `habitual`.
        leader: bool,
        /// `meta` of the first record.
        leader_meta: Arc<str>,
        /// What the hour held.
        hour: Arc<Hour>,
    },
    /// One of the records with the same rules changed in the same hour, a
    /// share of the hour's records that clean hours reach: `habitual`.
    Chance(Arc<Hour>),
}

/// The records of one hour of one volume that carry one set of rules,
/// against the clean hours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hour {
    /// `2026-11-03T10`.
    pub label: String,
    /// Records of the volume changed in the hour.
    pub changed: usize,
    /// Of them, records with this set of rules.
    pub records: usize,
    /// The pattern that decided: the rarest among the set's, in clean hours.
    pub pattern: String,
    /// Records of the hour with that pattern.
    pub hits: usize,
    /// Clean hours whose share of that pattern reaches `hits / changed`.
    pub seen: usize,
    /// Clean hours measured for this kind of record.
    pub of: usize,
    /// No clean hour has the pattern at all.
    pub never: bool,
}

impl Hour {
    fn share(&self) -> String {
        if self.never {
            format!("{} of the {} records changed in {} carry {} and no clean hour has that pattern", self.hits, self.changed, self.label, self.pattern)
        } else {
            format!(
                "{} of the {} records changed in {} carry {} and {} of {} clean hours reach that share",
                self.hits, self.changed, self.label, self.pattern, self.seen, self.of
            )
        }
    }
}

impl Context {
    /// The words the tail adds after the rule clauses.
    pub fn clause(&self) -> String {
        match self {
            Context::Installed(w) => w.clause(),
            Context::Burst { leader: true, hour, .. } if hour.records == 1 || hour.never => hour.share(),
            Context::Burst { leader: true, hour, .. } => format!("burst: {} (the other {} habitual)", hour.share(), hour.records - 1),
            Context::Burst { leader: false, leader_meta, hour } => format!("same burst as record {} ({} records with these rules changed in {})", leader_meta, hour.records, hour.label),
            Context::Chance(hour) => format!("{} (what a clean machine does)", hour.share()),
        }
    }
}

/// What `attach` found on one volume, for stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeContext {
    /// Host and volume as the timeline names them (`srv01 C:`), or the
    /// evidence the volume came from.
    pub place: String,
    pub records: usize,
    pub install: Option<Install>,
    pub bursts: usize,
    /// Records folded into a burst as followers.
    pub folded: usize,
    /// Records whose rules the clean rate explains in their hour.
    pub chance: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ntfs,
    Unix,
    Usn,
}

struct Rec {
    volume: u32,
    kind: Kind,
    /// When the record last changed: `$SI` change time (then modification,
    /// then creation) on NTFS, ctime on Unix, the record's time on USN.
    change: Option<i64>,
    /// The latest of the record's times.
    latest: Option<i64>,
    /// Creation time, when this is the volume's first record.
    birth: Option<i64>,
    flags: String,
    meta: String,
    rows: Vec<usize>,
}

fn secs(t: Option<Ts>) -> Option<i64> {
    t.map(|(s, _)| s)
}

fn times(m: &Macb) -> impl Iterator<Item = i64> {
    [m.m, m.a, m.c, m.b].into_iter().flatten().map(|(s, _)| s)
}

fn hour_of(secs: i64) -> i64 {
    secs.div_euclid(HOUR)
}

fn hour_label(hour: i64) -> String {
    format_unix_timestamp(hour * HOUR, 0).map(|s| s[..13].to_string()).unwrap_or_else(|| hour.to_string())
}

fn stamp(secs: i64) -> String {
    format_unix_timestamp(secs, 0).unwrap_or_else(|| secs.to_string())
}

fn gather(timeline: &[TimelineEntry]) -> Vec<Rec> {
    let mut index: HashMap<u64, usize> = HashMap::new();
    let mut recs: Vec<Rec> = Vec::new();
    for (i, e) in timeline.iter().enumerate() {
        let Some(h) = e.hunt.as_deref() else { continue };
        if let Some(&k) = index.get(&h.unit) {
            recs[k].rows.push(i);
            continue;
        }
        let (kind, change, latest, birth) = match &h.evidence {
            Evidence::Ntfs { entry, si, fns, .. } => (
                Kind::Ntfs,
                secs(si.c).or(secs(si.m)).or(secs(si.b)),
                times(si).chain(fns.iter().flat_map(times)).max(),
                if *entry == 0 { secs(si.b) } else { None },
            ),
            Evidence::Unix { inode, t } => (Kind::Unix, secs(t.c).or(secs(t.m)).or(secs(t.b)), times(t).max(), if *inode == 2 { secs(t.b) } else { None }),
            Evidence::Usn { time, .. } => (Kind::Usn, Some(time.0), Some(time.0), None),
        };
        index.insert(h.unit, recs.len());
        recs.push(Rec { volume: h.volume, kind, change, latest, birth, flags: e.flags.clone(), meta: e.meta.clone(), rows: vec![i] });
    }
    recs
}

/// Reads the volumes' history off the timeline and writes it into every
/// row's `context`. Returns one summary per volume, file-record volumes
/// first, then the journals, which take the installation window of the
/// `$MFT` of the same place when both are in the run.
pub fn attach(timeline: &mut [TimelineEntry], alpha: f64) -> Vec<VolumeContext> {
    let recs = gather(timeline);
    let mut volumes: Vec<u32> = recs.iter().map(|r| r.volume).collect();
    volumes.sort_unstable();
    volumes.dedup();
    let kind_of = |v: u32| recs.iter().find(|r| r.volume == v).map(|r| r.kind).unwrap_or(Kind::Usn);
    volumes.sort_by_key(|&v| kind_of(v) == Kind::Usn);
    let mut summaries = Vec::with_capacity(volumes.len());
    let mut contexts: Vec<Option<Arc<Context>>> = (0..recs.len()).map(|_| None).collect();
    // the window of each file-record volume, by place, for its journal
    let mut windows: HashMap<String, (i64, i64)> = HashMap::new();
    for &v in &volumes {
        let members: Vec<usize> = (0..recs.len()).filter(|&k| recs[k].volume == v).collect();
        let total = members.len();
        let kind = recs[members[0]].kind;
        let mut per_hour: HashMap<i64, usize> = HashMap::new();
        for &k in &members {
            if let Some(c) = recs[k].change {
                *per_hour.entry(hour_of(c)).or_default() += 1;
            }
        }
        let first = &timeline[recs[members[0]].rows[0]];
        let place_key = format!("{} {}", first.host.as_deref().unwrap_or(""), first.volume.as_deref().unwrap_or(""));
        let evidence = first.evidence.as_deref().map(|e| e.rsplit(['\\', '/', ':']).next().unwrap_or(e).to_string());
        let mut parts: Vec<&str> = Vec::new();
        for part in [first.host.as_deref(), first.volume.as_deref(), evidence.as_deref()].into_iter().flatten() {
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
        let place = parts.join(" ");
        let place = if place.is_empty() { "?".to_string() } else { place };

        // ── installation ──
        let mut install: Option<Arc<Install>> = None;
        let mut installed = vec![false; recs.len()];
        let span = if kind == Kind::Usn {
            windows.get(&place_key).map(|&(start, last)| (start, last))
        } else {
            members.iter().filter_map(|&k| recs[k].birth).min().and_then(|birth| {
                let floor = ((total as f64) * INSTALL_SHARE).ceil().max(1.0) as usize;
                let start = hour_of(birth);
                let mut end = start;
                while per_hour.get(&end).copied().unwrap_or(0) >= floor {
                    end += 1;
                }
                (end > start).then_some((birth, end * HOUR - 1))
            })
        };
        if let Some((birth, last)) = span {
            let start = hour_of(birth) * HOUR;
            let mut count = 0;
            for &k in &members {
                let r = &recs[k];
                let inside = matches!(r.change, Some(c) if c >= start && c <= last) && r.latest.is_none_or(|l| l <= last);
                if inside {
                    installed[k] = true;
                    count += 1;
                }
            }
            let w = Arc::new(Install { from: stamp(birth), to: stamp(last), records: count, total });
            for &k in &members {
                if installed[k] && !recs[k].flags.is_empty() {
                    contexts[k] = Some(Arc::new(Context::Installed(w.clone())));
                }
            }
            if kind != Kind::Usn {
                windows.entry(place_key).or_insert((birth, last));
            }
            install = Some(w);
        }

        // ── the hour ──
        let clean: &[CleanHour] = match kind {
            Kind::Ntfs => hours::NTFS,
            Kind::Usn => hours::USN,
            Kind::Unix => hours::UNIX,
        };
        let mut groups: HashMap<(String, i64), Vec<usize>> = HashMap::new();
        let mut per_pattern: HashMap<(String, i64), usize> = HashMap::new();
        for &k in &members {
            let r = &recs[k];
            if installed[k] || r.flags.is_empty() {
                continue;
            }
            let Some(c) = r.change else { continue };
            let patterns = anomaly::patterns(&anomaly::parse_column(&r.flags), r.kind != Kind::Unix);
            if patterns.is_empty() {
                continue;
            }
            for p in &patterns {
                *per_pattern.entry((p.clone(), hour_of(c))).or_default() += 1;
            }
            groups.entry((patterns.join("+"), hour_of(c))).or_default().push(k);
        }
        let mut bursts = 0;
        let mut folded = 0;
        let mut chance = 0;
        if !clean.is_empty() {
            for ((key, hour), mut group) in groups {
                let changed = per_hour.get(&hour).copied().unwrap_or(group.len()).max(group.len());
                // the rarest of the set's patterns in clean hours decides
                let mut best: Option<Hour> = None;
                for pattern in anomaly::patterns(&anomaly::parse_column(&recs[group[0]].flags), kind != Kind::Unix) {
                    let hits = per_pattern.get(&(pattern.clone(), hour)).copied().unwrap_or(0);
                    let share = hits as f64 / changed as f64;
                    let clean_hits = |h: &CleanHour| h.hits.iter().find(|(r, _)| *r == pattern).map_or(0, |(_, n)| *n);
                    let never = clean.iter().all(|h| clean_hits(h) == 0);
                    let seen = clean.iter().filter(|h| clean_hits(h) as f64 / h.changed as f64 >= share).count();
                    let this = Hour { label: hour_label(hour), changed, records: group.len(), pattern, hits, seen, of: clean.len(), never };
                    let rarer = |h: &Hour| if h.never { -1 } else { h.seen as i64 };
                    if best.as_ref().is_none_or(|b| rarer(&this) < rarer(b)) {
                        best = Some(this);
                    }
                }
                let Some(what) = best else { continue };
                let p = if what.never { 0.0 } else { (1.0 + what.seen as f64) / (1.0 + what.of as f64) };
                let what = Arc::new(what);
                let _ = key;
                if p > alpha {
                    let ctx = Arc::new(Context::Chance(what));
                    for &k in &group {
                        contexts[k] = Some(ctx.clone());
                    }
                    chance += group.len();
                    continue;
                }
                group.sort_by_key(|&k| (recs[k].change, k));
                let leader: Arc<str> = Arc::from(recs[group[0]].meta.as_str());
                contexts[group[0]] = Some(Arc::new(Context::Burst { leader: true, leader_meta: leader.clone(), hour: what.clone() }));
                if what.never {
                    // a pattern clean machines never produce has no benign mass
                    // operation behind it: every record keeps its state
                    for &k in &group[1..] {
                        contexts[k] = Some(Arc::new(Context::Burst { leader: true, leader_meta: leader.clone(), hour: what.clone() }));
                    }
                    continue;
                }
                if group.len() > 1 {
                    let rest = Arc::new(Context::Burst { leader: false, leader_meta: leader, hour: what });
                    for &k in &group[1..] {
                        contexts[k] = Some(rest.clone());
                    }
                    bursts += 1;
                    folded += group.len() - 1;
                }
            }
        }
        summaries.push(VolumeContext { place, records: total, install: install.map(|w| (*w).clone()), bursts, folded, chance });
    }
    for (k, ctx) in contexts.into_iter().enumerate() {
        if let Some(ctx) = ctx {
            for &i in &recs[k].rows {
                timeline[i].context = Some(ctx.clone());
            }
        }
    }
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hunt;
    use crate::timeline::{format_csv_row, source};

    fn ts(s: i64) -> Option<Ts> {
        Some((s, 0))
    }

    /// One NTFS record with the given `$SI` times, `b_after_c` when b > c.
    fn ntfs(volume: u32, entry: u64, c: i64, b: i64, name: &str) -> TimelineEntry {
        let si = Macb { m: ts(c), a: ts(c), c: ts(c), b: ts(b) };
        let flags = if b > c { "WARN: b_after_c".to_string() } else { String::new() };
        let e = TimelineEntry::new(stamp(c), c, 0, 1, "mac.".into(), "-/-rwxrwxrwx".into(), 0, 0, entry.to_string(), name.into())
            .with_source(source::MFT)
            .with_flags(flags)
            .with_hunt(Some(hunt::record(volume, Evidence::Ntfs { entry, seq: 1, si, fns: vec![] })));
        e
    }

    const BIRTH: i64 = 1_792_985_767; // 2026-10-26T03:36:07Z

    /// A volume born at BIRTH: 2,000 records in the birth hour and the next
    /// (399 of them `b_after_c`), 3 two hours after that (none flagged), then life.
    fn volume() -> Vec<TimelineEntry> {
        let mut t = vec![ntfs(7, 0, BIRTH, BIRTH, "C:\\$MFT")];
        for i in 1..2000u64 {
            let c = BIRTH + 60 + i as i64;
            let b = if i % 5 == 0 { c + 120 } else { c - 1 };
            t.push(ntfs(7, i, c, b, &format!("C:\\Windows\\f{}", i)));
        }
        // two hours after the installation: 3 records, below one in a thousand
        for i in 0..3u64 {
            let c = BIRTH + 3 * 3600 + 100 + i as i64;
            t.push(ntfs(7, 5000 + i, c, c - 1, &format!("C:\\late{}", i)));
        }
        t
    }

    #[test]
    fn installation_is_baseline() {
        let mut t = volume();
        let s = attach(&mut t, 0.05);
        assert_eq!(s.len(), 1);
        let w = s[0].install.as_ref().expect("a window");
        assert_eq!(w.from, "2026-10-26T03:36:07Z");
        assert_eq!(w.to, "2026-10-26T04:59:59Z", "two hours changed one in a thousand or more; the third did not");
        assert_eq!((w.records, w.total), (2000, 2003));
        let flagged: Vec<&TimelineEntry> = t.iter().filter(|e| !e.flags.is_empty()).collect();
        assert_eq!(flagged.len(), 399);
        assert!(flagged.iter().all(|e| matches!(e.context.as_deref(), Some(Context::Installed(_)))));
        let row = format_csv_row(flagged[0]);
        assert!(row.ends_with(",baseline,,rule b_after_c (medium): $SI creation after the record change time; installed with the volume from 2026-10-26T03:36:07Z to 2026-10-26T04:59:59Z (2000 of 2003 records),,"), "{}", row);
        assert!(t.iter().filter(|e| e.flags.is_empty()).all(|e| e.context.is_none()), "nothing to say about a record with no rule");
        assert_eq!(s[0].bursts, 0);
    }

    /// One NTFS record with its times in the future: a pattern no clean hour has.
    fn future(volume: u32, entry: u64, c: i64, name: &str) -> TimelineEntry {
        let far = c + 10 * 365 * 86_400;
        let si = Macb { m: ts(far), a: ts(c), c: ts(c), b: ts(far) };
        TimelineEntry::new(stamp(c), c, 0, 1, "m..b".into(), "-/-rwxrwxrwx".into(), 0, 0, entry.to_string(), name.into())
            .with_source(source::MFT)
            .with_flags("ALERT: future".into())
            .with_hunt(Some(hunt::record(volume, Evidence::Ntfs { entry, seq: 1, si, fns: vec![] })))
    }

    #[test]
    fn the_hour_is_judged_against_clean_hours() {
        let n = hours::NTFS.len();
        assert!(n > 0, "the NTFS clean hours are measured");
        let mut t = volume();
        // the first boot, a week later: 300 records changed, 120 with
        // b_after_c. A share clean hours reach? The reference's own first
        // boot had one in ten; this is more, and fourteen clean hours cannot
        // vouch for one in twenty: habitual either way, the clause says which.
        let boot = BIRTH + 8 * 86_400;
        for i in 0..300u64 {
            let c = boot + (i as i64) * 7;
            let b = if i < 120 { c + 30 } else { c - 1 };
            t.push(ntfs(7, 9000 + i, c, b, &format!("C:\\boot{}", i)));
        }
        // two files with future times in an ordinary hour: no clean hour has that pattern
        let later = boot + 3 * 86_400;
        for i in 0..50u64 {
            let c = later + (i as i64) * 11;
            if i < 2 {
                t.push(future(7, 12_000 + i, c, &format!("C:\\Users\\bob\\f{}", i)));
            } else {
                t.push(ntfs(7, 12_000 + i, c, c - 1, &format!("C:\\Users\\bob\\d{}", i)));
            }
        }
        let s = attach(&mut t, 0.05);
        assert_eq!((s[0].bursts, s[0].folded, s[0].chance), (0, 0, 120), "{:?}", s[0]);
        let boot0 = t.iter().find(|e| e.meta == "9000").unwrap();
        let row = format_csv_row(boot0);
        assert!(matches!(boot0.context.as_deref(), Some(Context::Chance(_))), "{:?}", boot0.context);
        assert!(row.ends_with(&format!(",habitual,0,rule b_after_c (medium): $SI creation after the record change time; 120 of the 205 records changed in 2026-11-03T03 carry b_after_c and 0 of {n} clean hours reach that share (what a clean machine does),,")), "{}", row);
        let lead = t.iter().find(|e| e.meta == "12000").unwrap();
        let row = format_csv_row(lead);
        assert!(row.ends_with(",significant,56,rule future (high): a timestamp more than a day after the timeline was built; 2 of the 50 records changed in 2026-11-06T03 carry future and no clean hour has that pattern,,"), "{}", row);
        // a pattern no clean machine produces is not folded: both keep their state
        let second = t.iter().find(|e| e.meta == "12001").unwrap();
        assert_eq!(format_csv_row(second).split(',').nth(14), Some("significant"), "{}", format_csv_row(second));
    }

    #[test]
    fn a_lone_never_seen_pattern_keeps_its_state() {
        let mut t = volume();
        let quiet = BIRTH + 20 * 86_400;
        t.push(future(7, 13_000, quiet, "C:\\Users\\bob\\lone.txt"));
        attach(&mut t, 0.05);
        let lone = t.iter().find(|e| e.meta == "13000").unwrap();
        let row = format_csv_row(lone);
        assert!(row.ends_with(",significant,56,rule future (high): a timestamp more than a day after the timeline was built; 1 of the 1 records changed in 2026-11-15T03 carry future and no clean hour has that pattern,,"), "{}", row);
    }

    #[test]
    fn the_journal_takes_the_window_of_its_mft() {
        let mut t = volume();
        for e in t.iter_mut() {
            e.volume = Some("C:".into());
        }
        // journal records of the same place: one inside the installation, one a day later
        for (i, at) in [(1u64, BIRTH + 600), (2, BIRTH + 86_400)] {
            let mut e = TimelineEntry::new(stamp(at), at, 0, 0, "....".into(), "-/-rwxrwxrwx".into(), 0, 0, format!("{}", 50 + i), format!("C:\\x{} (USN: BASIC_INFO_CHANGE)", i))
                .with_source(source::USN)
                .with_flags("ALERT: usn_basic_info".into())
                .with_hunt(Some(hunt::record(9, Evidence::Usn { entry: 100 + i, seq: 1, reason: 0x8000, time: (at, 0) })));
            e.volume = Some("C:".into());
            t.push(e);
        }
        let s = attach(&mut t, 0.05);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].install.as_ref().map(|w| (w.records, w.total)), Some((1, 2)), "{:?}", s[1]);
        let inside = t.iter().find(|e| e.source == source::USN && e.meta == "51").unwrap();
        assert!(matches!(inside.context.as_deref(), Some(Context::Installed(_))));
        assert!(format_csv_row(inside).contains(",baseline,,rule usn_basic_info (high)"), "{}", format_csv_row(inside));
        let later = t.iter().find(|e| e.source == source::USN && e.meta == "52").unwrap();
        assert!(matches!(later.context.as_deref(), Some(Context::Chance(_))), "a journal record of a timestamp change alone in its hour: every clean hour has some: {:?}", later.context);
        assert!(format_csv_row(later).contains(",habitual,0,rule usn_basic_info (high)"), "{}", format_csv_row(later));
    }

    #[test]
    fn no_birth_no_window() {
        let mut t = volume();
        t.retain(|e| e.meta != "0");
        let s = attach(&mut t, 0.05);
        assert!(s[0].install.is_none());
        // without a window the installation itself is one burst
        assert_eq!((s[0].bursts, s[0].chance), (0, 399), "the 399 b_after_c records fall in two hours that clean hours cannot judge rarer than one in fifteen");
    }

    #[test]
    fn volumes_are_told_apart() {
        let mut t = volume();
        t.push(ntfs(8, 0, BIRTH + 50 * 86_400, BIRTH + 50 * 86_400 - 1, "D:\\$MFT"));
        t.push(ntfs(8, 1, BIRTH + 50 * 86_400 + 10, BIRTH + 50 * 86_400 + 100, "D:\\x"));
        let s = attach(&mut t, 0.05);
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].records, 2);
        assert_eq!(s[1].install.as_ref().map(|w| w.records), Some(2), "a volume of two records, both installed");
    }
}
