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
//!   count is judged with the others of its hour: how many records changed
//!   in that hour on the volume, how many of them carry the same rules, and
//!   how many the rules' clean rate would give (their rate on a clean
//!   volume times the records changed). When the hour holds no more than
//!   the rate gives (Poisson, p above alpha), the hits are what a clean
//!   machine produces in an hour like that: `habitual`, no points, the
//!   clause says the numbers. When it holds more, something happened in
//!   that hour that chance does not explain: the first record keeps the
//!   state and the points and says how many came with it, and the others
//!   are `habitual` and point at the first, because hundreds of records
//!   with the same rules in one hour are one operation (the first boot of a
//!   virtual machine, an update, a copy with preserved times), not hundreds
//!   of anomalies. A single file with a never-seen pattern in a quiet hour
//!   is more than the rate gives and keeps its state; a single `b_after_c`
//!   in an hour that changed a thousand files is not, and does not.

use std::collections::HashMap;
use std::sync::Arc;

use crate::anomaly;
use crate::hunt::{Evidence, Macb, Ts};
use crate::stats::poisson_tail;
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
    /// more of them than the clean rate gives.
    Burst {
        /// The first record of the burst keeps its state; the others are
        /// `habitual`.
        leader: bool,
        /// `meta` of the first record.
        leader_meta: Arc<str>,
        /// What the hour held.
        hour: Arc<Hour>,
    },
    /// One of the records with the same rules changed in the same hour, no
    /// more of them than the clean rate gives: `habitual`.
    Chance(Arc<Hour>),
}

/// The records of one hour of one volume that carry one set of rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Hour {
    /// `2026-11-03T10`.
    pub label: String,
    /// Records of the volume changed in the hour.
    pub changed: usize,
    /// Of them, records with these rules.
    pub records: usize,
    /// What the rules' clean rate gives on `changed` records.
    pub expected: f64,
}

// `expected` is a count, never NaN.
impl Eq for Hour {}

impl Hour {
    fn expected(&self) -> String {
        if self.expected < 0.01 {
            "under 0.01".to_string()
        } else if self.expected < 10.0 {
            format!("{:.2}", self.expected)
        } else {
            format!("{:.0}", self.expected)
        }
    }
}

impl Context {
    /// The words the tail adds after the rule clauses.
    pub fn clause(&self) -> String {
        match self {
            Context::Installed(w) => w.clause(),
            Context::Burst { leader: true, hour, .. } if hour.records == 1 => format!(
                "the only record with these rules among the {} changed in {}; the clean rate gives {}",
                hour.changed, hour.label, hour.expected()
            ),
            Context::Burst { leader: true, hour, .. } => format!(
                "burst: {} of the {} records changed in {} carry these rules; the clean rate gives {} (the others habitual)",
                hour.records, hour.changed, hour.label, hour.expected()
            ),
            Context::Burst { leader: false, leader_meta, hour } => format!(
                "same burst as record {} ({} of the {} records changed in {} carry these rules)",
                leader_meta, hour.records, hour.changed, hour.label
            ),
            Context::Chance(hour) => format!(
                "{} of the {} records changed in {} carry these rules; the clean rate gives {}: what a clean machine does",
                hour.records, hour.changed, hour.label, hour.expected()
            ),
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
        let mut groups: HashMap<(String, i64), Vec<usize>> = HashMap::new();
        for &k in &members {
            let r = &recs[k];
            if installed[k] || r.flags.is_empty() {
                continue;
            }
            let Some(c) = r.change else { continue };
            let flags = anomaly::parse_column(&r.flags);
            if anomaly::set_rate(&flags, r.kind != Kind::Unix).is_none() {
                continue;
            }
            groups.entry((r.flags.clone(), hour_of(c))).or_default().push(k);
        }
        let mut bursts = 0;
        let mut folded = 0;
        let mut chance = 0;
        for ((flags, hour), mut group) in groups {
            let rate = anomaly::set_rate(&anomaly::parse_column(&flags), kind != Kind::Unix).unwrap_or(1.0);
            let changed = per_hour.get(&hour).copied().unwrap_or(group.len()).max(group.len());
            let expected = rate * changed as f64;
            let what = Arc::new(Hour { label: hour_label(hour), changed, records: group.len(), expected });
            if poisson_tail(group.len(), expected) > alpha {
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
            if group.len() > 1 {
                let rest = Arc::new(Context::Burst { leader: false, leader_meta: leader, hour: what });
                for &k in &group[1..] {
                    contexts[k] = Some(rest.clone());
                }
                bursts += 1;
                folded += group.len() - 1;
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

    #[test]
    fn the_hour_judges_both_ways() {
        let mut t = volume();
        // the first boot, a week later: 300 records changed, 120 with b_after_c
        let boot = BIRTH + 8 * 86_400;
        for i in 0..300u64 {
            let c = boot + (i as i64) * 7;
            let b = if i < 120 { c + 30 } else { c - 1 };
            t.push(ntfs(7, 9000 + i, c, b, &format!("C:\\boot{}", i)));
        }
        // two b_after_c among fifty changed in an ordinary hour: the clean
        // rate (one in 25) gives two, so they are what a clean machine does
        let later = boot + 3 * 86_400;
        for i in 0..50u64 {
            let c = later + (i as i64) * 11;
            let b = if i < 2 { c + 99 } else { c - 1 };
            t.push(ntfs(7, 12_000 + i, c, b, &format!("C:\\Users\\bob\\d{}", i)));
        }
        // one b_after_c in a quiet hour where only it changed: more than the rate gives
        let quiet = later + 86_400;
        t.push(ntfs(7, 13_000, quiet, quiet + 99, "C:\\Users\\bob\\lone.txt"));
        let s = attach(&mut t, 0.05);
        assert_eq!((s[0].bursts, s[0].folded, s[0].chance), (1, 119, 2));
        let leader = t.iter().find(|e| e.meta == "9000").unwrap();
        let row = format_csv_row(leader);
        assert!(row.ends_with(",candidate,14,rule b_after_c (medium): $SI creation after the record change time; burst: 120 of the 205 records changed in 2026-11-03T03 carry these rules; the clean rate gives 8.07 (the others habitual),,"), "{}", row);
        let member = t.iter().find(|e| e.meta == "9119").unwrap();
        let row = format_csv_row(member);
        assert!(row.ends_with(",habitual,0,rule b_after_c (medium): $SI creation after the record change time; same burst as record 9000 (120 of the 205 records changed in 2026-11-03T03 carry these rules),,"), "{}", row);
        for m in ["12000", "12001"] {
            let e = t.iter().find(|e| e.meta == m).unwrap();
            assert!(matches!(e.context.as_deref(), Some(Context::Chance(_))), "{:?}", e.context);
            let row = format_csv_row(e);
            assert!(row.ends_with(",habitual,0,rule b_after_c (medium): $SI creation after the record change time; 2 of the 50 records changed in 2026-11-06T03 carry these rules; the clean rate gives 1.97: what a clean machine does,,"), "{}", row);
        }
        let lone = t.iter().find(|e| e.meta == "13000").unwrap();
        let row = format_csv_row(lone);
        assert!(row.ends_with(",candidate,14,rule b_after_c (medium): $SI creation after the record change time; the only record with these rules among the 1 changed in 2026-11-07T03; the clean rate gives 0.04,,"), "{}", row);
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
        assert!(matches!(later.context.as_deref(), Some(Context::Burst { leader: true, .. })), "alone in its hour: more than one in 42 gives: {:?}", later.context);
        assert!(format_csv_row(later).contains(",significant,16,rule usn_basic_info (high)"), "{}", format_csv_row(later));
    }

    #[test]
    fn no_birth_no_window() {
        let mut t = volume();
        t.retain(|e| e.meta != "0");
        let s = attach(&mut t, 0.05);
        assert!(s[0].install.is_none());
        // without a window the installation itself is one burst
        assert_eq!(s[0].bursts, 2, "the 399 b_after_c records fall in two hours");
        assert_eq!(s[0].chance, 0);
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
