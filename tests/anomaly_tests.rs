//! Anti-forensics indicators in the `flags` column, on synthetic `$MFT`
//! records and bodyfile lines, and the stderr summary of the binary.

use std::fs;
use std::io::Cursor;
use std::process::Command;

use allymacb::anomaly;
use allymacb::parsers::bodyfile::parse_bodyfile_stream;
use allymacb::parsers::mft::{parse_mft_reader, MftParseOptions};

mod common;
use common::*;

/// FILETIME one day after FT.
const FT_LATER: u64 = FT + 86_400 * 10_000_000;
/// FILETIME for 1975-06-15T12:00:00Z.
const FT_1975: u64 = (171_979_200u64 + 11_644_473_600) * 10_000_000;
/// FILETIME far in the future (2099-01-01).
const FT_2099: u64 = (4_070_908_800u64 + 11_644_473_600) * 10_000_000;

fn si_full(b: u64, m: u64, c: u64, a: u64) -> Attr {
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
    MftParseOptions { include_file_name_timestamps: false, resident_dir: None, resident_report: None, drive_letter: Some('C'), quiet: true, carve: false }
}

fn mft_with(extra: Vec<Vec<u8>>) -> Vec<u8> {
    let mut m = Vec::new();
    for i in 0..5u64 {
        m.extend(record(i, 1, &[si(FT), fname(5, &format!("$Sys{}", i), 0, FT)]));
    }
    m.extend(record(5, 3, &[si(FT), fname(5, ".", 0, FT)]));
    for r in extra {
        m.extend(r);
    }
    m
}

fn flags_of(mft: Vec<u8>, name: &str) -> String {
    let (rows, _) = parse_mft_reader(Cursor::new(mft), &opts()).unwrap();
    let r = rows.iter().find(|r| r.file_name.ends_with(name)).unwrap_or_else(|| panic!("no row for {}", name));
    r.flags.clone()
}

#[test]
fn untouched_record_has_no_flags() {
    // Sub-second part present on both $SI and $FN, same instant.
    let ts = FT + 1_234_567;
    let m = mft_with(vec![record(6, 1, &[si_full(ts, ts, ts, ts), fname(5, "clean.txt", 10, ts)])]);
    assert_eq!(flags_of(m, "clean.txt"), "");
}

#[test]
fn si_earlier_than_fn_and_whole_seconds_is_timestomping() {
    // $FN keeps the real creation (with a fraction: 70 FILETIME ticks = 7 µs,
    // the parser keeps microseconds); $SI was set to a round 1975 date.
    let m = mft_with(vec![record(6, 1, &[si_full(FT_1975, FT_1975, FT + 70, FT_1975), fname(5, "stomped.txt", 10, FT + 70)])]);
    let f = flags_of(m, "stomped.txt");
    assert!(f.contains(anomaly::SI_BEFORE_FN), "{}", f);
    assert!(f.contains(anomaly::SI_SUBSEC_ZERO), "{}", f);
    assert!(f.contains(anomaly::PRE_1980), "{}", f);
}

#[test]
fn created_after_record_change_and_future_dates() {
    let m = mft_with(vec![record(6, 1, &[si_full(FT_LATER + 1, FT + 1, FT + 1, FT + 1), fname(5, "fwd.txt", 10, FT + 1)])]);
    let f = flags_of(m, "fwd.txt");
    assert!(f.contains(anomaly::B_AFTER_C), "{}", f);
    let m = mft_with(vec![record(7, 1, &[si_full(FT + 1, FT_2099 + 1, FT_2099 + 1, FT + 1), fname(5, "future.txt", 10, FT + 1)])]);
    assert!(flags_of(m, "future.txt").contains(anomaly::FUTURE));
}

#[test]
fn name_tricks_are_flagged_on_mft_rows() {
    let m = mft_with(vec![
        record(6, 1, &[si(FT), fname(5, "invoice.pdf.exe", 10, FT)]),
        record(7, 1, &[si(FT), fname(5, "report\u{202E}fdp.exe", 10, FT)]),
    ]);
    assert_eq!(flags_of(m.clone(), "invoice.pdf.exe"), format!("ALERT: {}", anomaly::DOUBLE_EXT));
    let (rows, _) = parse_mft_reader(Cursor::new(m), &opts()).unwrap();
    let r = rows.iter().find(|r| r.file_name.contains('\u{202E}')).unwrap();
    assert_eq!(r.flags, format!("ALERT: {}", anomaly::RTLO_NAME));
}

#[test]
fn bodyfile_mtime_after_ctime_or_before_crtime() {
    // mtime 1_800_000_000 > ctime 1_700_000_000: set by hand.
    let body = "0|/home/u/touched|1|-rw-r--r--|0|0|9|1700000000|1750000000|1700000000|1600000000\n\
                0|/home/u/normal|2|-rw-r--r--|0|0|9|1700000000|1700000000|1700000005|1690000000\n";
    let rows = parse_bodyfile_stream(Cursor::new(body), None);
    let touched = rows.iter().find(|r| r.file_name.ends_with("touched")).unwrap();
    assert!(touched.flags.contains(anomaly::M_AFTER_C), "{}", touched.flags);
    let normal = rows.iter().find(|r| r.file_name.ends_with("normal")).unwrap();
    assert_eq!(normal.flags, "");
    // mtime before crtime (touch -d, or a preserved copy)
    let body = "0|/opt/x|3|-rw-r--r--|0|0|9|1700000000|1600000000|1700000005|1690000000\n";
    let rows = parse_bodyfile_stream(Cursor::new(body), None);
    assert!(rows[0].flags.contains(anomaly::M_BEFORE_B), "{}", rows[0].flags);
}

#[test]
fn cli_reports_indicator_counts_on_stderr() {
    let dir = std::env::temp_dir().join(format!("allymacb_anomaly_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let body = dir.join("bodyfile.txt");
    fs::write(&body, "0|/home/u/touched|1|-rw-r--r--|0|0|9|1700000000|1750000000|1700000000|1600000000\n0|/home/u/ok.pdf.exe|2|-rw-r--r--|0|0|9|1700000000|1700000000|1700000005|1690000000\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).arg("-q").arg("-f").arg(&body).output().unwrap();
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[ALERT] 2 file(s)"), "{}", stderr);
    assert!(stderr.contains("[ALERT]   m_after_c") && stderr.contains("/home/u/touched"), "{}", stderr);
    assert!(stderr.contains("[ALERT]   double_ext") && stderr.contains("ok.pdf.exe"), "{}", stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l.ends_with(",bodyfile,ALERT: m_after_c")), "{}", stdout);
    let _ = fs::remove_dir_all(&dir);
}
