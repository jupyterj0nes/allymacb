//! Anti-forensics indicators: the static rules of allymacb, reported in the
//! analysis tail (`hunt`, `hunt_score`, `hunt_why`).
//!
//! None of these is proof on its own. They point at records whose timestamps
//! or names do not look like the filesystem wrote them, so the analyst checks
//! those first. Each indicator is a short fixed token, which is also the rule
//! id in `hunt_why`. Inside the program a record keeps them as `WARN: a+b` /
//! `ALERT: a+b` ([`column`]); [`Rules::of`] turns that into the tail.

use mft::attribute::x30::FileNameAttr;
use mft::StandardInfoAttr;

/// `$STANDARD_INFORMATION` creation time earlier than the `$FILE_NAME` one.
/// NTFS writes both at the same instant when a file is created and only the
/// first can be changed from user mode, so an earlier `$SI` was set after the
/// fact. Copies that preserve timestamps (robocopy, 7-Zip, `cp -p` on SMB)
/// produce the same pattern.
pub const SI_BEFORE_FN: &str = "si_before_fn";
/// `$SI` modified and created have no sub-second part while the `$FILE_NAME`
/// copies do: the values were written with a whole-second API such as
/// `SetFileTime` from PowerShell, Python or timestomp.
pub const SI_SUBSEC_ZERO: &str = "si_subsec_zero";
/// `$SI` created later than `$SI` MFT-modified. The record change time moves
/// with every creation, so a creation after it was set by hand or into the future.
pub const B_AFTER_C: &str = "b_after_c";
/// A timestamp more than a day after the moment the timeline was built.
pub const FUTURE: &str = "future";
/// A non-zero timestamp before 1980-01-01, older than any filesystem that could
/// have written it (FAT epoch; NTFS appeared in 1993).
pub const PRE_1980: &str = "pre_1980";
/// Unix: modified before created. `touch -d`, or a copy / package install that
/// kept the original modification time.
pub const M_BEFORE_B: &str = "m_before_b";
/// Unix: modified after the inode change time. `ctime` cannot be set from user
/// mode and moves with every change, so an `mtime` beyond it was set by hand.
pub const M_AFTER_C: &str = "m_after_c";
/// A USN record whose only reasons are a basic-info change and close: the
/// timestamps or attributes were changed without touching the data.
pub const USN_BASIC_INFO: &str = "usn_basic_info";
/// Carving found an older state of this record with a later creation or
/// modification time than the live one: the timestamps were moved backwards.
pub const BACKDATED: &str = "backdated";
/// The name contains a right-to-left override (U+202E) or other bidi control.
pub const RTLO_NAME: &str = "rtlo_name";
/// The name contains zero-width or other invisible characters.
pub const INVISIBLE_NAME: &str = "invisible_name";
/// A document-like extension followed by an executable one (`invoice.pdf.exe`).
pub const DOUBLE_EXT: &str = "double_ext";

/// 1980-01-01T00:00:00Z.
const UNIX_1980: i64 = 315_532_800;
/// Tolerance for comparisons between timestamps the OS writes together.
const SLACK_SECS: i64 = 1;
const FUTURE_SLACK_SECS: i64 = 86_400;

fn ts(t: &mft::Timestamp) -> (i64, i32) {
    (t.as_second(), t.subsec_nanosecond())
}

fn push(flags: &mut Vec<&'static str>, f: &'static str) {
    if !flags.contains(&f) {
        flags.push(f);
    }
}

/// Indicators for one NTFS record. `now` is the current Unix time.
pub fn ntfs_flags(si: Option<&StandardInfoAttr>, fns: &[FileNameAttr], now: i64) -> Vec<&'static str> {
    let mut flags = Vec::new();
    let Some(si) = si else { return flags };
    let (b, m, c, a) = (ts(&si.created), ts(&si.modified), ts(&si.mft_modified), ts(&si.accessed));

    for (secs, _) in [b, m, c, a] {
        if secs > now + FUTURE_SLACK_SECS {
            push(&mut flags, FUTURE);
        }
        // FILETIME 0 is "unset", not a date.
        if secs < UNIX_1980 && secs != -crate::timefmt::SECS_BETWEEN_1601_AND_1970 {
            push(&mut flags, PRE_1980);
        }
    }
    if b.0 > c.0 + SLACK_SECS {
        push(&mut flags, B_AFTER_C);
    }
    for f in fns {
        let fb = ts(&f.created);
        if b.0 + SLACK_SECS < fb.0 {
            push(&mut flags, SI_BEFORE_FN);
        }
        let fm = ts(&f.modified);
        if b.1 == 0 && m.1 == 0 && (fb.1 != 0 || fm.1 != 0) {
            push(&mut flags, SI_SUBSEC_ZERO);
        }
    }
    flags
}

/// Indicators for a Unix-style set of timestamps (seconds); `None` = unknown.
pub fn unix_flags(modified: Option<i64>, changed: Option<i64>, created: Option<i64>, now: i64) -> Vec<&'static str> {
    let mut flags = Vec::new();
    for t in [modified, changed, created].into_iter().flatten() {
        if t > now + FUTURE_SLACK_SECS {
            push(&mut flags, FUTURE);
        }
        if t != 0 && t < UNIX_1980 {
            push(&mut flags, PRE_1980);
        }
    }
    if let (Some(m), Some(b)) = (modified, created) {
        if b != 0 && m + SLACK_SECS < b {
            push(&mut flags, M_BEFORE_B);
        }
    }
    if let (Some(m), Some(c)) = (modified, changed) {
        if c != 0 && m > c + SLACK_SECS {
            push(&mut flags, M_AFTER_C);
        }
    }
    flags
}

/// Indicators in a file name (the last path component is enough, but a full
/// path works too).
pub fn name_flags(name: &str) -> Vec<&'static str> {
    let mut flags = Vec::new();
    for ch in name.chars() {
        match ch {
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => push(&mut flags, RTLO_NAME),
            '\u{200B}'..='\u{200F}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}' | '\u{180E}' => push(&mut flags, INVISIBLE_NAME),
            _ => {}
        }
    }
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name).to_ascii_lowercase();
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() >= 3 {
        let last = parts[parts.len() - 1];
        let prev = parts[parts.len() - 2];
        // `.lnk` is left out on purpose: `Readme.txt.lnk` is how Windows names
        // a shortcut to Readme.txt.
        const EXEC: [&str; 11] = ["exe", "scr", "com", "bat", "cmd", "ps1", "js", "jse", "vbs", "vbe", "hta"];
        const DOC: [&str; 14] = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "zip", "rtf"];
        if EXEC.contains(&last) && DOC.contains(&prev) {
            push(&mut flags, DOUBLE_EXT);
        }
    }
    flags
}

/// USN reason flags that mean "only metadata changed".
pub fn usn_flags(reason: u32) -> Vec<&'static str> {
    const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
    const CLOSE: u32 = 0x8000_0000;
    let mut flags = Vec::new();
    if reason & BASIC_INFO_CHANGE != 0 && reason & !(BASIC_INFO_CHANGE | CLOSE) == 0 {
        push(&mut flags, USN_BASIC_INFO);
    }
    flags
}

/// How much weight a set of indicators carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Patterns that legitimate software also produces (preserved copies,
    /// installers): worth a look, not an alarm on their own.
    Warn,
    /// Patterns with no ordinary explanation, or the classic combination of
    /// `$SI` earlier than `$FN` with whole-second `$SI` values.
    Alert,
}

/// Indicators that are an alert on their own.
const STRONG: [&str; 8] = [BACKDATED, FUTURE, PRE_1980, M_AFTER_C, USN_BASIC_INFO, RTLO_NAME, INVISIBLE_NAME, DOUBLE_EXT];

/// Severity of a set of indicators; `None` when there are none.
pub fn severity(flags: &[&str]) -> Option<Severity> {
    if flags.is_empty() {
        return None;
    }
    let strong = flags.iter().any(|f| STRONG.contains(f))
        || (flags.contains(&SI_BEFORE_FN) && flags.contains(&SI_SUBSEC_ZERO));
    Some(if strong { Severity::Alert } else { Severity::Warn })
}

/// Text of the `flags` column: empty, `WARN: a+b` or `ALERT: a+b`.
pub fn column(flags: &[&str]) -> String {
    match severity(flags) {
        None => String::new(),
        Some(Severity::Alert) => format!("ALERT: {}", flags.join("+")),
        Some(Severity::Warn) => format!("WARN: {}", flags.join("+")),
    }
}

/// Splits a `flags` column back into its indicators.
pub fn parse_column(column: &str) -> Vec<&str> {
    let body = column.strip_prefix("ALERT: ").or_else(|| column.strip_prefix("WARN: ")).unwrap_or(column);
    body.split('+').filter(|f| !f.is_empty()).collect()
}

/// Adds one indicator to an existing `flags` column value.
pub fn add_to_column(column: &str, flag: &'static str) -> String {
    let mut flags: Vec<&str> = parse_column(column);
    if !flags.contains(&flag) {
        flags.push(flag);
    }
    self::column(&flags)
}

/// What one indicator means, in the words `hunt_why` gives after its id.
pub fn describe(flag: &str) -> &'static str {
    match flag {
        SI_BEFORE_FN => "$SI creation before the $FILE_NAME creation",
        SI_SUBSEC_ZERO => "$SI times in whole seconds, the $FILE_NAME ones not",
        B_AFTER_C => "$SI creation after the record change time",
        FUTURE => "a timestamp more than a day after the timeline was built",
        PRE_1980 => "a timestamp before 1980",
        M_BEFORE_B => "modification before creation",
        M_AFTER_C => "modification after the inode change time",
        USN_BASIC_INFO => "USN record of a timestamp or attribute change alone",
        BACKDATED => "an older carved copy of the record has later times",
        RTLO_NAME => "right-to-left override in the name",
        INVISIBLE_NAME => "invisible characters in the name",
        DOUBLE_EXT => "a document extension followed by an executable one",
        _ => "",
    }
}

/// Level of one indicator among the others of its record: an indicator in
/// [`STRONG`], or `$SI` before `$FN` together with whole-second `$SI` times,
/// is an alert; anything else a warning.
fn level(flag: &str, flags: &[&str]) -> Severity {
    let pair = flags.contains(&SI_BEFORE_FN) && flags.contains(&SI_SUBSEC_ZERO);
    if STRONG.contains(&flag) || (pair && (flag == SI_BEFORE_FN || flag == SI_SUBSEC_ZERO)) {
        Severity::Alert
    } else {
        Severity::Warn
    }
}

/// Records of the NTFS reference volume the rule rarities were measured on:
/// the `$MFT` of a clean Windows Server 2016 lab host (PTR-SRV01, SQL Server
/// Express and IIS, RangeForge, read from the live volume on 2026-11-03),
/// one record per file, the 403 records of the collection itself left out.
const MEASURED_ON: f64 = 431_153.0;

/// USN records of the same host's `$UsnJrnl:$J` (37 MB allocated), the
/// reference of the USN rules.
const MEASURED_ON_USN: f64 = 273_208.0;

/// Inodes of the Unix reference: the whole ext4 root of a clean Ubuntu 22.04
/// lab host (LEO-LNX01, RangeForge, 2026-11-03), a bodyfile with birth times
/// written by `stat` over `find / -xdev`, one record per inode.
const MEASURED_ON_UNIX: f64 = 77_881.0;

/// Points of a pattern that fired `hits` times on `records` reference
/// records, the scale of the four tools: `10 · log10(records / hits)`. A
/// pattern that never fired gets the bound the corpus gives, one in
/// `records + 1` (56 on the NTFS reference, 54 on the USN one, 49 on the
/// Unix one).
/// A rule measured below this many points fires on more than one clean
/// record in ten: noise on that kind of record, it gives no state and no
/// points, only its clause (the convention of the four tools).
pub const NOISE_BELOW: u32 = 10;

fn rarity(hits: f64, records: f64) -> u32 {
    let (h, n) = if hits <= 0.0 { (1.0, records + 1.0) } else { (hits, records) };
    (10.0 * (n / h).log10()).round().max(0.0) as u32
}

/// `hunt_score` points of an indicator, masstin's scale measured, not
/// chosen: `10 · log10(records / records that fire)` on the reference of the
/// record's kind (NTFS: the Server 2016 `$MFT`, its `$J` for the USN rule;
/// Unix: the Ubuntu root). `None` where it is not measured yet (`backdated`,
/// which needs carving, `m_before_b` on NTFS, and the names on Unix).
///
/// | rule | NTFS, of 431,153 | points | Unix, of 77,881 | points |
/// |---|---|---|---|---|
/// | `si_before_fn` | 103,104 (files laid down from the install image keep the image's `$SI` times, the `$FN` ones are the install's) | 6, noise | | |
/// | `si_subsec_zero` | 2,073 | 23 | | |
/// | `si_before_fn` with `si_subsec_zero` | 2,061 | 23 for the pair | | |
/// | `b_after_c` | 16,964 | 14 | | |
/// | `usn_basic_info` | 6,520 of 273,208 USN records | 16 | | |
/// | `m_before_b` | | | 71,982 (package files keep their build mtime, older than the install's crtime) | 0, noise |
/// | `future`, `pre_1980` | none | 56 | none | 49 |
/// | `m_after_c` | | | none | 49 |
/// | names | none | 56 | | |
fn points(flag: &str, ntfs: bool) -> Option<u32> {
    if !ntfs {
        let fired = match flag {
            M_BEFORE_B => 71_982.0,
            FUTURE | PRE_1980 | M_AFTER_C => 0.0,
            _ => return None,
        };
        return Some(rarity(fired, MEASURED_ON_UNIX));
    }
    if flag == USN_BASIC_INFO {
        return Some(rarity(6_520.0, MEASURED_ON_USN));
    }
    let fired = match flag {
        SI_BEFORE_FN => 103_104.0,
        SI_SUBSEC_ZERO => 2_073.0,
        B_AFTER_C => 16_964.0,
        FUTURE | PRE_1980 | RTLO_NAME | INVISIBLE_NAME | DOUBLE_EXT => 0.0,
        _ => return None,
    };
    Some(rarity(fired, MEASURED_ON))
}

/// Points of `$SI` before `$FN` with whole-second `$SI` times: measured as a
/// pair (2,061 records of 431,153), not the sum of the two. `si_before_fn`
/// alone is noise on a modern Windows; the pair is not.
const PAIR_POINTS: u32 = 23;

/// What the rules of one record put in the tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    /// The strongest level among the indicators that count: a rule measured
    /// common (below `NOISE_BELOW` points) gives no level. None when every
    /// indicator of the record is noise.
    pub severity: Option<Severity>,
    /// `hunt_score` points, 0 where none is measured.
    pub points: u32,
    /// One clause per indicator, strongest first, separated by `; `:
    /// `rule si_before_fn (high): $SI creation before the $FILE_NAME creation`.
    pub why: String,
}

/// Rule ids with their level, strongest first, `+`-joined: the `rules`
/// column of the hunt's findings table (`future (high)+b_after_c (medium)`).
pub fn ids(flags: &[&str]) -> String {
    let mut sorted: Vec<(Severity, &str)> = flags.iter().map(|f| (level(f, flags), *f)).collect();
    sorted.sort_by_key(|s| std::cmp::Reverse(s.0));
    let words: Vec<String> = sorted.iter().map(|(l, f)| format!("{} ({})", f, if *l == Severity::Alert { "high" } else { "medium" })).collect();
    words.join("+")
}

impl Rules {
    /// The rules of a record from its internal `WARN: a+b` / `ALERT: a+b`
    /// value; `ntfs` when the record is an NTFS one (the rarities are measured
    /// on NTFS only). `None` when there is no indicator.
    pub fn of(column: &str, ntfs: bool) -> Option<Rules> {
        let flags = parse_column(column);
        severity(&flags)?;
        let mut sorted: Vec<(Severity, &str)> = flags.iter().map(|f| (level(f, &flags), *f)).collect();
        sorted.sort_by_key(|s| std::cmp::Reverse(s.0));
        let pair = ntfs && flags.contains(&SI_BEFORE_FN) && flags.contains(&SI_SUBSEC_ZERO);
        let mut total = if pair { PAIR_POINTS } else { 0 };
        let mut severity: Option<Severity> = None;
        let mut why = Vec::with_capacity(sorted.len());
        for (lvl, f) in sorted {
            let word = if lvl == Severity::Alert { "high" } else { "medium" };
            let text = describe(f);
            let text = if text.is_empty() { f } else { text };
            let p = points(f, ntfs);
            // measured common: no level, no points, the clause only
            let counts = p.is_none_or(|p| p >= NOISE_BELOW) || (pair && (f == SI_BEFORE_FN || f == SI_SUBSEC_ZERO));
            if counts {
                severity = Some(severity.map_or(lvl, |s| s.max(lvl)));
            }
            match p {
                Some(p) => {
                    if counts && !(pair && (f == SI_BEFORE_FN || f == SI_SUBSEC_ZERO)) {
                        total += p;
                    }
                    why.push(format!("rule {f} ({word}): {text}"));
                }
                None => why.push(format!("rule {f} ({word}): {text}, rarity not measured")),
            }
        }
        Some(Rules { severity, points: total, why: why.join("; ") })
    }
}

/// Current Unix time in seconds.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_indicators() {
        let now = 1_800_000_000;
        assert_eq!(unix_flags(Some(100), Some(200), Some(150), now), vec![PRE_1980, M_BEFORE_B]);
        assert_eq!(unix_flags(Some(1_700_000_000), Some(1_690_000_000), None, now), vec![M_AFTER_C]);
        assert_eq!(unix_flags(Some(now + 2 * 86_400), None, None, now), vec![FUTURE]);
        assert!(unix_flags(Some(1_700_000_000), Some(1_700_000_000), Some(1_700_000_000), now).is_empty());
        assert!(unix_flags(Some(1_700_000_000), Some(0), Some(0), now).is_empty(), "0 means unset");
    }

    #[test]
    fn name_indicators() {
        assert_eq!(name_flags("C:\\Users\\x\\invoice.pdf.exe"), vec![DOUBLE_EXT]);
        assert_eq!(name_flags("report\u{202E}fdp.exe"), vec![RTLO_NAME]);
        assert_eq!(name_flags("pass\u{200B}word.txt"), vec![INVISIBLE_NAME]);
        assert!(name_flags("archive.tar.gz").is_empty());
        assert!(name_flags("setup.exe").is_empty());
        assert!(name_flags("\u{5831}\u{544A}\u{66F8} 2026.txt").is_empty(), "CJK is not suspicious");
    }

    #[test]
    fn severity_and_column_text() {
        assert_eq!(column(&[]), "");
        assert_eq!(column(&[SI_BEFORE_FN]), "WARN: si_before_fn");
        assert_eq!(column(&[SI_BEFORE_FN, SI_SUBSEC_ZERO]), "ALERT: si_before_fn+si_subsec_zero");
        assert_eq!(column(&[M_BEFORE_B, PRE_1980]), "ALERT: m_before_b+pre_1980");
        assert_eq!(parse_column("ALERT: a+b"), vec!["a", "b"]);
        assert_eq!(parse_column(""), Vec::<&str>::new());
        assert_eq!(add_to_column("WARN: si_before_fn", BACKDATED), "ALERT: si_before_fn+backdated");
        assert_eq!(add_to_column("", BACKDATED), "ALERT: backdated");
    }

    #[test]
    fn rules_in_the_tail() {
        assert_eq!(Rules::of("", true), None);
        // si_before_fn alone fires on 24 % of a clean Server 2016: noise, no level, no points, the clause.
        let r = Rules::of("WARN: si_before_fn", true).unwrap();
        assert_eq!(r, Rules { severity: None, points: 0, why: "rule si_before_fn (medium): $SI creation before the $FILE_NAME creation".into() });
        let r = Rules::of("WARN: si_subsec_zero", true).unwrap();
        assert_eq!((r.severity, r.points), (Some(Severity::Warn), 23));
        let r = Rules::of("ALERT: si_before_fn+si_subsec_zero", true).unwrap();
        assert_eq!(r.severity, Some(Severity::Alert), "the pair is the timestomp signature and counts");
        assert_eq!(r.points, 23, "the pair is measured as one pattern");
        assert!(r.why.starts_with("rule si_before_fn (high): ") && r.why.contains("; rule si_subsec_zero (high): "), "{}", r.why);
        // Strongest first; points add.
        let r = Rules::of("ALERT: b_after_c+future", true).unwrap();
        assert_eq!(r.points, 14 + 56);
        assert!(r.why.starts_with("rule future (high): ") && r.why.ends_with("; rule b_after_c (medium): $SI creation after the record change time"), "{}", r.why);
        // Unix: m_before_b fires on 97 % of a stock ext4 volume: noise, no level, no points.
        let r = Rules::of("WARN: m_before_b", false).unwrap();
        assert_eq!(r, Rules { severity: None, points: 0, why: "rule m_before_b (medium): modification before creation".into() });
        let r = Rules::of("ALERT: m_before_b+future", false).unwrap();
        assert_eq!((r.severity, r.points), (Some(Severity::Alert), 49), "the bound 77,881 inodes give; the noise adds nothing");
        assert!(r.why.starts_with("rule future (high): ") && r.why.ends_with("; rule m_before_b (medium): modification before creation"), "{}", r.why);
        assert_eq!(rarity(0.0, 12_183.0), 41);
        assert_eq!(rarity(1.0, 128.0), 21);
        assert_eq!(rarity(71_982.0, 77_881.0), 0);
        assert_eq!(rarity(103_104.0, 431_153.0), 6);
        assert_eq!(rarity(0.0, MEASURED_ON), 56);
        // USN: measured on the journal of the same host.
        let r = Rules::of("ALERT: usn_basic_info", true).unwrap();
        assert_eq!((r.severity, r.points), (Some(Severity::Alert), 16));
        assert_eq!(Rules::of("ALERT: m_after_c", false).unwrap().points, 49, "never fired on the Unix root");
        // Not measured: no points, and the clause says so.
        let r = Rules::of("ALERT: backdated", true).unwrap();
        assert_eq!((r.severity, r.points), (Some(Severity::Alert), 0), "unmeasured is not noise: it keeps its level");
        assert!(r.why.ends_with(", rarity not measured"), "{}", r.why);
        assert_eq!(ids(&[B_AFTER_C, FUTURE]), "future (high)+b_after_c (medium)");
        assert_eq!(ids(&[]), "");
        for f in [SI_BEFORE_FN, SI_SUBSEC_ZERO, B_AFTER_C, FUTURE, PRE_1980, M_BEFORE_B, M_AFTER_C, USN_BASIC_INFO, BACKDATED, RTLO_NAME, INVISIBLE_NAME, DOUBLE_EXT] {
            assert!(!describe(f).is_empty(), "{f}");
        }
    }

    #[test]
    fn usn_indicators() {
        assert_eq!(usn_flags(0x8000_8000), vec![USN_BASIC_INFO]);
        assert_eq!(usn_flags(0x0000_8000), vec![USN_BASIC_INFO]);
        assert!(usn_flags(0x8000_8001).is_empty(), "data overwrite + basic info is a normal write");
        assert!(usn_flags(0x8000_0100).is_empty());
    }
}
