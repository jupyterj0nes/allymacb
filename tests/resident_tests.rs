//! The resident dump: off unless `-r <DIR>` names a new or empty folder,
//! never overwrites a file, whoever wrote it first, and one report per run.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use allymacb::parsers::mft::{parse_mft_reader, MftParseOptions};

mod common;
use common::*;

fn opts(res: Option<PathBuf>) -> MftParseOptions {
    MftParseOptions { include_file_name_timestamps: false, resident_dir: res, resident_report: None, drive_letter: Some('C'), quiet: true, carve: false }
}

/// A small table: $MFT, four system records, the root, and two resident files.
fn table(content: &str) -> Vec<u8> {
    let mut m = record(0, 1, &[si(FT), fname(5, "$MFT", 1024, FT), data("", b"x")]);
    for i in 1..5 {
        m.extend(record(i, 1, &[si(FT), fname(5, &format!("$Sys{}", i), 0, FT)]));
    }
    m.extend(record(5, 3, &[si(FT), fname(5, ".", 0, FT)]));
    m.extend(record(6, 1, &[si(FT), fname(5, "note.txt", 0, FT), data("", content.as_bytes())]));
    m.extend(record(7, 0, &[si(FT), fname(5, "gone.txt", 0, FT), data("", content.as_bytes())]));
    m
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("allymacb_res_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Every file under `dir`, relative path and content, sorted.
fn listing(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(dir).into_iter().flatten().filter(|e| e.file_type().is_file()) {
        let rel = e.path().strip_prefix(dir).unwrap().to_string_lossy().replace('\\', "/");
        out.push((rel, String::from_utf8_lossy(&std::fs::read(e.path()).unwrap()).into_owned()));
    }
    out.sort();
    out
}

#[test]
fn two_sources_with_the_same_paths_and_records_both_survive() {
    let dir = scratch("two");
    parse_mft_reader(Cursor::new(table("FIRST")), &opts(Some(dir.clone()))).unwrap();
    let (_, st) = parse_mft_reader(Cursor::new(table("SECOND")), &opts(Some(dir.clone()))).unwrap();
    assert_eq!(st.total_extracted, 3);
    assert_eq!(st.total_failed, 0);
    let files = listing(&dir);
    let get = |p: &str| files.iter().find(|(n, _)| n == p).map(|(_, c)| c.as_str());
    assert_eq!(get("note.txt"), Some("FIRST"));
    assert_eq!(get("note.txt.rec6"), Some("SECOND"));
    assert_eq!(get("gone.txt.deleted_rec7"), Some("FIRST"));
    assert_eq!(get("gone.txt.deleted_rec7.rec7"), Some("SECOND"));
    // A third source still finds a free name.
    parse_mft_reader(Cursor::new(table("THIRD")), &opts(Some(dir.clone()))).unwrap();
    assert_eq!(listing(&dir).iter().find(|(n, _)| n == "note.txt.rec6_2").map(|(_, c)| c.as_str()), Some("THIRD"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn many_threads_dumping_to_one_folder_lose_nothing() {
    let dir = scratch("threads");
    let n = 8;
    std::thread::scope(|s| {
        for k in 0..n {
            let dir = dir.clone();
            s.spawn(move || {
                let (_, st) = parse_mft_reader(Cursor::new(table(&format!("SOURCE{k}"))), &opts(Some(dir))).unwrap();
                assert_eq!(st.total_failed, 0);
            });
        }
    });
    let files = listing(&dir);
    assert_eq!(files.len(), 3 * n, "{files:?}");
    // Each source's content is there once for each of its three streams.
    for k in 0..n {
        let c = format!("SOURCE{k}");
        assert_eq!(files.iter().filter(|(_, v)| *v == c).count(), 2, "{c}: {files:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_allymacb"))
}

fn mft_file(tag: &str, content: &str) -> PathBuf {
    let d = scratch(tag);
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("$MFT");
    std::fs::write(&p, table(content)).unwrap();
    p
}

#[test]
fn nothing_is_dumped_unless_asked() {
    let mft = mft_file("default", "X");
    let before = listing(mft.parent().unwrap());
    let out = bin().args(["-q", "-f"]).arg(&mft).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(listing(mft.parent().unwrap()), before);
    let _ = std::fs::remove_dir_all(mft.parent().unwrap());
}

#[test]
fn the_folder_must_be_new_or_empty() {
    let mft = mft_file("busy", "X");
    let dest = scratch("busy_dest");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("keep.txt"), "analyst's").unwrap();
    let out = bin().args(["-q", "-f"]).arg(&mft).arg("-r").arg(&dest).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not empty"));
    assert_eq!(listing(&dest), vec![("keep.txt".to_string(), "analyst's".to_string())]);
    // `-r` alone is a usage error: the folder is always named.
    let out = bin().args(["-q", "-f"]).arg(&mft).arg("-r").output().unwrap();
    assert!(!out.status.success());
    // A report without a dump makes no sense.
    let out = bin().args(["-q", "-f"]).arg(&mft).arg("--resident-report").arg(dest.join("r.txt")).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!dest.join("r.txt").exists());
    let _ = std::fs::remove_dir_all(&dest);
    let _ = std::fs::remove_dir_all(mft.parent().unwrap());
}

#[test]
fn one_report_for_every_source_and_never_over_a_file() {
    let a = mft_file("rep_a", "AAA");
    let b = mft_file("rep_b", "BBB");
    let dest = scratch("rep_dest");
    let rep = scratch("rep_file").with_extension("txt");
    let _ = std::fs::remove_file(&rep);
    let out = bin().args(["-q", "-f"]).arg(&a).arg(&b).arg("-r").arg(&dest).arg("--resident-report").arg(&rep).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = std::fs::read_to_string(&rep).unwrap();
    assert!(text.contains("Total resident files extracted: 6"), "{text}");
    assert_eq!(listing(&dest).len(), 6);
    // Asking for the same report again is refused before anything is read.
    let out = bin().args(["-q", "-f"]).arg(&a).arg("-r").arg(scratch("rep_dest2")).arg("--resident-report").arg(&rep).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(std::fs::read_to_string(&rep).unwrap(), text);
    for p in [a.parent().unwrap(), b.parent().unwrap(), &dest] {
        let _ = std::fs::remove_dir_all(p);
    }
    let _ = std::fs::remove_file(&rep);
}
