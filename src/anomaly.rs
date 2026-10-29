//! Anti-forensics indicators, reported in the `flags` column.
//!
//! None of these is proof on its own. They point at records whose timestamps
//! or names do not look like the filesystem wrote them, so the analyst checks
//! those first. Each indicator is a short fixed token; a row carries several
//! joined with `+`, most rows carry none.

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
    fn usn_indicators() {
        assert_eq!(usn_flags(0x8000_8000), vec![USN_BASIC_INFO]);
        assert_eq!(usn_flags(0x0000_8000), vec![USN_BASIC_INFO]);
        assert!(usn_flags(0x8000_8001).is_empty(), "data overwrite + basic info is a normal write");
        assert!(usn_flags(0x8000_0100).is_empty());
    }
}
