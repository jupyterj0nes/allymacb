//! Synthetic $MFT records (1024-byte, fixups applied) exercising the parser
//! fixes from the full code review: parent cycles, non-resident $DATA sizes,
//! ADS MACB flags, resident-extraction path traversal and deleted/live
//! collisions, and damaged first records.

use std::io::Cursor;
use std::path::PathBuf;

use allymacb::parsers::mft::{parse_mft_reader, MftParseOptions};

mod common;
use common::*;

fn opts(res: Option<PathBuf>) -> MftParseOptions {
    MftParseOptions {
        include_file_name_timestamps: false,
        resident_dir: res,
        resident_report: None,
        drive_letter: Some('C'),
        quiet: true,
        carve: false,
    }
}

fn base_records() -> Vec<u8> {
    let mut m = record(0, 1, &[si(FT), fname(5, "$MFT", 1024, FT), data("", b"x")]);
    for i in 1..5 {
        m.extend(record(i, 1, &[si(FT), fname(5, &format!("$Sys{}", i), 0, FT)]));
    }
    m.extend(record(5, 3, &[si(FT), fname(5, ".", 0, FT)]));
    m
}

#[test]
fn parent_cycle_does_not_overflow_the_stack() {
    // entry 6's parent is 7, entry 7's parent is 6 (both directories)
    let mut m = base_records();
    m.extend(record(6, 3, &[si(FT), fname(7, "A", 0, FT)]));
    m.extend(record(7, 3, &[si(FT), fname(6, "B", 0, FT)]));
    m.extend(record(8, 1, &[si(FT), fname(6, "inside.txt", 10, FT)]));
    let (t, _) = parse_mft_reader(Cursor::new(m), &opts(None)).unwrap();
    let names: Vec<&str> = t.iter().map(|e| e.file_name.as_str()).collect();
    assert!(names.iter().any(|n| n.contains("[CYCLE]") && n.ends_with("inside.txt")), "{:?}", names);
    assert_eq!(t.iter().filter(|e| e.meta == "8").count(), 1);
}

#[test]
fn stale_parent_sequence_is_reported_as_orphan() {
    let mut m = base_records();
    m.extend(record(6, 3, &[si(FT), fname(5, "Dir", 0, FT)]));
    // record 7 claims parent 6 with sequence 9, but record 6 has sequence 1 and is live
    m.extend(record(7, 1, &[si(FT), fname_seq(6, 9, "stale.txt", 1, FT)]));
    m.extend(record(8, 1, &[si(FT), fname_seq(6, 1, "fresh.txt", 1, FT)]));
    let (t, _) = parse_mft_reader(Cursor::new(m), &opts(None)).unwrap();
    let stale = t.iter().find(|e| e.meta == "7").unwrap();
    assert_eq!(stale.file_name, "C:\\[ORPHAN]\\stale.txt");
    let fresh = t.iter().find(|e| e.meta == "8").unwrap();
    assert_eq!(fresh.file_name, "C:\\Dir\\fresh.txt");
}

#[test]
fn non_resident_data_size_and_ads_are_reported() {
    let mut m = base_records();
    m.extend(record(6, 1, &[
        si(FT),
        fname(5, "big.bin", 0, FT),
        data_nonres("", 123_456),
        data_nonres("Zone.Identifier", 777),
    ]));
    let (t, _) = parse_mft_reader(Cursor::new(m), &opts(None)).unwrap();
    let host = t.iter().find(|e| e.file_name == "C:\\big.bin").expect("host row");
    assert_eq!(host.size, 123_456);
    let ads = t.iter().find(|e| e.file_name == "C:\\big.bin:Zone.Identifier").expect("ADS row");
    assert_eq!(ads.size, 777);
}

#[test]
fn ads_rows_carry_the_host_macb_flags() {
    let mut m = base_records();
    m.extend(record(6, 1, &[si(FT), fname(5, "host.txt", 0, FT), data("", b"hello"), data("evil", b"payload!")]));
    let (t, _) = parse_mft_reader(Cursor::new(m), &opts(None)).unwrap();
    let host = t.iter().find(|e| e.file_name == "C:\\host.txt").unwrap();
    let ads = t.iter().find(|e| e.file_name == "C:\\host.txt:evil").unwrap();
    assert_eq!(host.macb, "macb");
    assert_eq!(ads.macb, "macb");
    assert_eq!(ads.size, 8);
}

#[test]
fn resident_extraction_refuses_path_traversal() {
    let base = std::env::temp_dir().join(format!("allymacb_trav_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let out = base.join("out").join("deep");
    std::fs::create_dir_all(&out).unwrap();
    let mut m = base_records();
    m.extend(record(6, 1, &[si(FT), fname(5, "..\\..\\pwn.txt", 0, FT), data("", b"owned")]));
    m.extend(record(7, 1, &[si(FT), fname(5, "ok.txt", 0, FT), data("", b"fine")]));
    let (_t, st) = parse_mft_reader(Cursor::new(m), &opts(Some(out.clone()))).unwrap();
    assert_eq!(st.total_unsafe_paths, 1);
    assert!(!base.join("pwn.txt").exists());
    assert!(!base.join("out").join("pwn.txt").exists());
    assert_eq!(std::fs::read_to_string(out.join("ok.txt")).unwrap(), "fine");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn deleted_record_never_overwrites_live_file_with_same_path() {
    let base = std::env::temp_dir().join(format!("allymacb_dup_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let mut m = base_records();
    m.extend(record(6, 0, &[si(FT), fname(5, "dup.txt", 0, FT), data("", b"OLD-DELETED-CONTENT")])); // unallocated
    m.extend(record(7, 1, &[si(FT), fname(5, "dup.txt", 0, FT), data("", b"NEW")]));
    let (_t, st) = parse_mft_reader(Cursor::new(m), &opts(Some(base.clone()))).unwrap();
    assert_eq!(st.total_extracted, 3); // $MFT "x" + both dup.txt variants
    assert_eq!(std::fs::read_to_string(base.join("dup.txt")).unwrap(), "NEW");
    assert_eq!(std::fs::read_to_string(base.join("dup.txt.deleted_rec6")).unwrap(), "OLD-DELETED-CONTENT");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn damaged_first_records_are_skipped_and_numbering_preserved() {
    // Records 0 and 1 zeroed; the rest intact. Record 7 must still be numbered 7.
    let mut m = vec![0u8; 2048];
    m.extend(record(2, 1, &[si(FT), fname(5, "$LogFile", 0, FT)]));
    for i in 3..5 {
        m.extend(record(i, 1, &[si(FT), fname(5, &format!("$Sys{}", i), 0, FT)]));
    }
    m.extend(record(5, 3, &[si(FT), fname(5, ".", 0, FT)]));
    m.extend(record(6, 3, &[si(FT), fname(5, "Dir", 0, FT)]));
    m.extend(record(7, 1, &[si(FT), fname(6, "file.txt", 5, FT)]));
    let (t, _) = parse_mft_reader(Cursor::new(m), &opts(None)).unwrap();
    let f = t.iter().find(|e| e.meta == "7").expect("record 7 present");
    assert_eq!(f.file_name, "C:\\Dir\\file.txt");
}
