//! Statistical hunt (`--investigation-from`): synthetic volumes with a
//! baseline of ordinary irregularities (preserved-timestamp copies) and a
//! window holding timestomped records.

use std::collections::HashMap;
use std::io::Cursor;

use allymacb::hunt::{self, Evidence, HuntOptions, Macb};
use allymacb::parsers::mft::{parse_mft_reader, MftParseOptions};
use allymacb::timeline::{source, TimelineEntry};

mod common;
use common::*;

/// 2023-11-14T22:13:20Z, start of the synthetic baseline.
const BASE: i64 = 1_700_000_000;
const DAY: i64 = 86_400;
/// Ten baseline days, then the window.
const CUTOFF: i64 = BASE + 10 * DAY;
/// 2015-06-01T00:00:00Z, the date the attacker picks.
const OLD: i64 = 1_433_116_800;

fn ft(secs: i64, ticks: u64) -> u64 {
    (secs + 11_644_473_600) as u64 * 10_000_000 + ticks
}

fn si4(b: u64, m: u64, c: u64, a: u64) -> Attr {
    let mut body = Vec::new();
    for t in [b, m, c, a] {
        body.extend_from_slice(&le64(t));
    }
    body.extend_from_slice(&le32(0x20));
    body.extend_from_slice(&[0u8; 12]);
    body.extend_from_slice(&[0u8; 24]);
    Attr { ty: 0x10, name: "", body, non_resident: None }
}

fn opts() -> MftParseOptions {
    MftParseOptions { quiet: true, ..Default::default() }
}

fn hunt_opts() -> HuntOptions {
    HuntOptions { from: CUTOFF, alpha: 0.05 }
}

/// A `$MFT` with 200 baseline files over ten days (every fourth one a copy
/// that kept a modification time a year older) and the window records the
/// test asks for, numbered after them.
fn volume(window: &[(&str, [u64; 4], u64)]) -> Vec<u8> {
    let mut m = Vec::new();
    for i in 0..24u64 {
        let t = ft(BASE - DAY, 1_000 + i);
        m.extend(record(i, 1, &[si4(t, t, t, t), fname(5, &format!("$Meta{}", i), 0, t)]));
    }
    for i in 0..200u64 {
        let created = ft(BASE + (i as i64 / 20) * DAY + i as i64 * 60, 3_000_001 + i * 7);
        let modified = if i % 4 == 0 { ft(BASE - 365 * DAY + i as i64, 1_234_567) } else { created };
        let name = format!("base{}.txt", i);
        m.extend(record(24 + i, 1, &[si4(created, modified, created, created), fname(5, &name, 10, created)]));
    }
    for (k, (name, [b, mo, c, a], fn_time)) in window.iter().enumerate() {
        m.extend(record(224 + k as u64, 1, &[si4(*b, *mo, *c, *a), fname(5, name, 10, *fn_time)]));
    }
    m
}

fn findings_by_name(rows: &[TimelineEntry]) -> HashMap<String, hunt::Finding> {
    let rep = hunt::run(rows, &hunt_opts());
    rep.findings
        .into_iter()
        .map(|f| (f.file_name.rsplit('\\').next().unwrap_or("").to_string(), f))
        .collect()
}

#[test]
fn stomped_records_stand_out_against_the_baseline() {
    let now = ft(CUTOFF + 3_600, 4_242_421);
    // A year older, as the baseline copies are.
    let copy_m = ft(CUTOFF - 360 * DAY, 7_654_321);
    let old = ft(OLD, 0);
    let mft = volume(&[
        // An ordinary copy in the window: the same pattern as the baseline's.
        ("copied.txt", [now, copy_m, now, now], now),
        // SetFileTime from PowerShell: B, M and A in whole seconds, C moved to "now".
        ("stomped.exe", [old, old, now + 10, old], now),
        // $SI set, file moved, $SI set again: $FILE_NAME carries the old values too.
        ("moved.dll", [old, old, old, old], old),
        // Untouched window file: nothing irregular, not a test.
        ("plain.txt", [now + 50, now + 50, now + 50, now + 50], now + 50),
    ]);
    let (rows, _) = parse_mft_reader(Cursor::new(mft), &opts()).unwrap();
    let f = findings_by_name(&rows);

    assert!(f["stomped.exe"].significant, "{}", f["stomped.exe"].why);
    assert!(f["stomped.exe"].evidence.contains("$SI creation before the $FILE_NAME creation by"), "{}", f["stomped.exe"].evidence);
    // Every timestamp of moved.dll is in 2015; the record allocated just
    // before it puts it in the window, and its $FILE_NAME gives it away.
    assert!(f["moved.dll"].significant, "{}", f["moved.dll"].why);
    assert!(f["moved.dll"].evidence.contains("record allocated just before it by"), "{}", f["moved.dll"].evidence);
    assert!(f["moved.dll"].evidence.contains("$FILE_NAME times in whole seconds"), "{}", f["moved.dll"].evidence);

    assert!(!f["copied.txt"].significant, "a copy like fifty baseline ones: {}", f["copied.txt"].why);
    assert!(f["copied.txt"].p > 0.1);
    assert!(!f.contains_key("plain.txt"), "regular records are not tests");
    // Significant rows come first.
    let rep = hunt::run(&rows, &hunt_opts());
    assert!(rep.findings[0].significant && rep.findings[1].significant && !rep.findings[2].significant);
}

#[test]
fn calibration_window_without_stomps_has_no_finding() {
    // The window repeats the baseline's habits: copies and plain files.
    let mut window = Vec::new();
    for i in 0..20u64 {
        let now = ft(CUTOFF + i as i64 * 600, 5_000_003 + i);
        let m = if i % 4 == 0 { ft(CUTOFF - 300 * DAY + i as i64, 4_444_444) } else { now };
        window.push((format!("w{}.txt", i), [now, m, now, now], now));
    }
    let named: Vec<(&str, [u64; 4], u64)> = window.iter().map(|(n, a, t)| (n.as_str(), *a, *t)).collect();
    let (rows, _) = parse_mft_reader(Cursor::new(volume(&named)), &opts()).unwrap();
    let rep = hunt::run(&rows, &hunt_opts());
    assert_eq!(rep.findings.len(), 5, "the five copies are tested");
    assert!(rep.findings.iter().all(|f| !f.significant), "{:?}", rep.findings.iter().map(|f| &f.evidence).collect::<Vec<_>>());
}

#[test]
fn no_baseline_means_not_evaluated() {
    let now = ft(CUTOFF + 60, 1);
    let old = ft(OLD, 0);
    let mut m = Vec::new();
    m.extend(record(24, 1, &[si4(old, old, now, old), fname(5, "stomped.exe", 10, now)]));
    let (rows, _) = parse_mft_reader(Cursor::new(m), &opts()).unwrap();
    let rep = hunt::run(&rows, &hunt_opts());
    assert_eq!(rep.findings.len(), 1);
    let f = &rep.findings[0];
    assert_eq!(f.state, hunt::State::NotEvaluated, "an empty null is no evidence");
    assert!(f.p.is_nan() && !f.significant);
    assert!(f.evidence.contains("no irregular baseline record"), "{}", f.evidence);
    let mark = rows.iter().find_map(|e| e.hunt.as_deref().and_then(|h| rep.mark(h))).unwrap();
    assert_eq!((mark.state, mark.score), (hunt::State::NotEvaluated, None));
    assert!(rep.notes.iter().any(|n| n.contains("not evaluated, nothing to compare them with")), "{:?}", rep.notes);
}

fn unix_row(volume: u32, inode: u64, name: &str, t: Macb) -> TimelineEntry {
    let secs = t.c.map(|c| c.0).unwrap_or(0);
    TimelineEntry::new(String::new(), secs, 0, 1, "..c.".into(), "-rw-r--r--".into(), 0, 0, inode.to_string(), name.into())
        .with_source(source::EXT4)
        .with_hunt(Some(hunt::record(volume, Evidence::Unix { inode, t, root: inode == 2 })))
}

#[test]
fn unix_mtime_after_ctime_is_a_contradiction() {
    let vol = hunt::new_volume();
    let mut rows = Vec::new();
    for i in 0..100u64 {
        // cp -p / tar: modification older than creation, change time = creation.
        let b = (BASE + (i as i64 % 10) * DAY + i as i64, 123_456_789);
        let m = (BASE - 200 * DAY + i as i64, 987_654_321);
        rows.push(unix_row(vol, 1_000 + i, &format!("/srv/base{}", i), Macb { m: Some(m), a: Some(b), c: Some(b), b: Some(b) }));
    }
    // touch -m -d "+1 day": mtime ahead of ctime, whole seconds.
    let c = (CUTOFF + 3_600, 555_000_111);
    let m = (CUTOFF + 3_600 + DAY, 0);
    rows.push(unix_row(vol, 5_000, "/srv/touched", Macb { m: Some(m), a: Some(c), c: Some(c), b: Some(c) }));
    // cp -p in the window: like the baseline.
    let b = (CUTOFF + 7_200, 1);
    rows.push(unix_row(vol, 5_001, "/srv/copied", Macb { m: Some((BASE - 50 * DAY, 3)), a: Some(b), c: Some(b), b: Some(b) }));

    let rep = hunt::run(&rows, &hunt_opts());
    let by: HashMap<&str, &hunt::Finding> = rep.findings.iter().map(|f| (f.file_name.as_str(), f)).collect();
    assert!(by["/srv/touched"].significant, "{}", by["/srv/touched"].why);
    assert_eq!(by["/srv/touched"].signature, hunt::Signature::Contradiction);
    assert!(!by["/srv/copied"].significant);
}

#[test]
fn ntfs_modified_after_change_is_not_a_test() {
    // Registry hives and other mapped files: $SI M ahead of C on every write.
    let mut window = Vec::new();
    let c = ft(CUTOFF + 60, 11);
    let m = ft(CUTOFF + 6_000, 22);
    window.push(("SYSTEM", [c, m, c, c], c));
    let (rows, _) = parse_mft_reader(Cursor::new(volume(&window)), &opts()).unwrap();
    let rep = hunt::run(&rows, &hunt_opts());
    assert!(rep.findings.iter().all(|f| !f.file_name.ends_with("SYSTEM")));
}

#[test]
fn usn_journal_joins_the_volume_and_dates_the_creation() {
    let now = ft(CUTOFF + 3_600, 4_242_421);
    let old = ft(OLD, 0);
    // $FILE_NAME and $SI both in 2015, but the journal saw the file created in the window.
    let (mut rows, _) = parse_mft_reader(Cursor::new(volume(&[("tool.exe", [old, old, now, old], old)])), &opts()).unwrap();
    let usn_vol = hunt::new_volume();
    let usn = |entry: u64, reason: u32, secs: i64| {
        TimelineEntry::new(String::new(), secs, 0, 0, "....".into(), String::new(), 0, 0, entry.to_string(), "x".into())
            .with_source(source::USN)
            .with_hunt(Some(hunt::record(usn_vol, Evidence::Usn { entry, seq: 1, reason, time: (secs, 0) })))
    };
    // Journal from the middle of the baseline: base files were created there too.
    for i in 100..200u64 {
        rows.push(usn(24 + i, 0x100, BASE + (i as i64 / 20) * DAY + i as i64 * 60));
    }
    rows.push(usn(224, 0x100, CUTOFF + 3_000));
    rows.push(usn(224, 0x8000_8000, CUTOFF + 3_500));

    let rep = hunt::run(&rows, &hunt_opts());
    let f = rep.findings.iter().find(|f| f.file_name.ends_with("tool.exe")).expect("tool.exe tested");
    assert!(f.evidence.contains("before the journal's create record by"), "{}", f.evidence);
    assert!(f.evidence.contains("change only timestamps or attributes (1)"), "{}", f.evidence);
    assert!(f.significant, "{}", f.why);
    assert!(rep.notes.iter().any(|n| n.contains("inside the USN journal's span")), "{:?}", rep.notes);
}

#[test]
fn usn_journal_after_the_cutoff_is_switched_off() {
    let (mut rows, _) = parse_mft_reader(Cursor::new(volume(&[])), &opts()).unwrap();
    let v = hunt::new_volume();
    rows.push(
        TimelineEntry::new(String::new(), 0, 0, 0, "....".into(), String::new(), 0, 0, "30".into(), "x".into())
            .with_hunt(Some(hunt::record(v, Evidence::Usn { entry: 30, seq: 1, reason: 0x100, time: (CUTOFF + 10, 0) }))),
    );
    let rep = hunt::run(&rows, &hunt_opts());
    assert!(rep.notes.iter().any(|n| n.contains("after the cutoff")), "{:?}", rep.notes);
}

#[test]
fn hunt_csv_has_one_row_per_tested_record() {
    let now = ft(CUTOFF + 3_600, 4_242_421);
    let old = ft(OLD, 0);
    let (rows, _) = parse_mft_reader(Cursor::new(volume(&[("stomped.exe", [old, old, now + 10, old], now)])), &opts()).unwrap();
    let rep = hunt::run(&rows, &hunt_opts());
    let path = std::env::temp_dir().join(format!("allymacb_hunt_{}.csv", std::process::id()));
    hunt::write_csv(&rep, &path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(hunt::HUNT_HEADER));
    let first = lines.next().unwrap();
    assert!(first.starts_with("1,yes,"), "{}", first);
    assert!(first.contains("stomped.exe"));
    assert!(first.ends_with(&format!(",meta={}", rep.findings[0].meta)), "{}", first);
    assert_eq!(hunt::HUNT_HEADER.split(',').count(), 19, "masstin's findings table");
    assert_eq!(text.lines().count(), rep.findings.len() + 1);
}

fn bodyfile_case() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("allymacb_hunt_cli_{}_{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut body = String::new();
    // Baseline: copies that kept a modification time a month older.
    for i in 0..60i64 {
        let t = BASE + i * 3_600;
        body.push_str(&format!("0|/srv/base{}|{}|-rw-r--r--|0|0|9|{}|{}|{}|{}\n", i, 100 + i, t, t - 30 * DAY, t, t));
    }
    let t = CUTOFF + 100;
    // touch -m into tomorrow: modified after the change time.
    body.push_str(&format!("0|/srv/touched|900|-rw-r--r--|0|0|9|{}|{}|{}|{}\n", t, t + DAY, t, t));
    // An ordinary copy in the window.
    body.push_str(&format!("0|/srv/copied|901|-rw-r--r--|0|0|9|{}|{}|{}|{}\n", t, t - 30 * DAY, t, t));
    let path = dir.join("bodyfile.txt");
    std::fs::write(&path, body).unwrap();
    path
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(0)
}

#[test]
fn cli_marks_significant_records_and_writes_the_hunt_csv() {
    let body = bodyfile_case();
    let hunt_csv = body.with_file_name("hunt.csv");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_allymacb"))
        .args(["-q", "--investigation-from", "2023-11-24 22:13:20", "--hunt-out"])
        .arg(&hunt_csv)
        .arg("-f")
        .arg(&body)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[ALERT] Hunt: 1 of 2 tested record(s) significant"), "{}", stderr);
    assert!(stderr.contains("/srv/touched"), "{}", stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("time_created,host,action,type,source,uid,gid,volume,size,mode,deleted,meta,file_name,evidence,hunt,hunt_score,hunt_why,verdict,notes"));
    let touched: Vec<&str> = stdout.lines().filter(|l| l.contains("/srv/touched")).collect();
    assert!(!touched.is_empty() && touched.iter().all(|l| l.contains(",significant,") && l.ends_with(",,")), "{:?}", touched);
    assert!(touched.iter().all(|l| !l.contains("hunt")), "the verdict is in the tail, not in flags: {:?}", touched);
    // A copy with an older modification: tested, not significant; its medium
    // rule makes it a candidate and speaks first, the test's words follow.
    let rule = "rule m_before_b (medium): modification before creation";
    assert!(stdout.lines().filter(|l| l.contains("/srv/copied")).all(|l| l.contains(",candidate,") && l.contains(&format!("{rule}; modification before creation"))), "{}", stdout);
    // Baseline copies: reference, not judged; their only rule is noise on Unix, so it no longer overrides `baseline`.
    assert!(stdout.lines().filter(|l| l.contains("/srv/base")).all(|l| l.ends_with(&format!(",baseline,,{rule},,"))), "{}", stdout);
    // Only masstin's six words in the hunt column.
    for l in stdout.lines().skip(1) {
        let hunt = l.rsplit(',').nth(4).unwrap_or("");
        assert!(["significant", "candidate", "habitual", "not_evaluated", "baseline", ""].contains(&hunt) || l.contains('"'), "{}", l);
    }
    let csv = std::fs::read_to_string(&hunt_csv).unwrap();
    assert_eq!(csv.lines().count(), 3, "{}", csv);
    let row = csv.lines().nth(1).unwrap();
    assert!(row.starts_with("1,yes,") && row.contains("/srv/touched,0,"), "{}", row);
    let _ = std::fs::remove_dir_all(body.parent().unwrap());
}

#[test]
fn cli_rejects_bad_hunt_arguments() {
    let body = bodyfile_case();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_allymacb")).args(["-q", "-f"]).arg(&body).args(args).output().unwrap()
    };
    let out = run(&["--investigation-from", "last tuesday"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read 'last tuesday'"));
    assert_eq!(run(&["--hunt-out", "x.csv"]).status.code(), Some(1));
    assert_eq!(run(&["--investigation-from", "2023-11-24", "--alpha", "1.5"]).status.code(), Some(1));
    let _ = std::fs::remove_dir_all(body.parent().unwrap());
}
