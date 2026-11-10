//! A USN journal given with the `$MFT` of its volume is read with that `$MFT`'s paths: its
//! rows name the real folder (`C:\Users\Public\tool.exe`) instead of `C:\[UNKNOWN]\tool.exe`.
//! Pairing works for `-f $MFT -f $J` under every usual journal name, for a `-d` folder
//! (`$MFT` beside `$Extend\$J`), and leaves a lone journal as it was.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::*;

/// 2026-11-10T08:32:43Z as a FILETIME.
const T: u64 = (1_762_763_563 + 11_644_473_600) * 10_000_000;

/// A small `$MFT`: system records 0..29, then `Users` (30, a folder under the root),
/// `Public` (31, under `Users`) and `tool.exe` (32, under `Public`).
fn mft() -> Vec<u8> {
    let mut m = Vec::new();
    for i in 0..30u64 {
        m.extend(record(i, 1, &[si(T - 1_000_000_000), fname(5, &format!("$Meta{i}"), 0, T - 1_000_000_000)]));
    }
    m.extend(record(30, 3, &[si(T - 500_000_000), fname(5, "Users", 0, T - 500_000_000)]));
    m.extend(record(31, 3, &[si(T - 400_000_000), fname(30, "Public", 0, T - 400_000_000)]));
    m.extend(record(32, 1, &[si(T), fname(31, "tool.exe", 4096, T)]));
    m
}

/// A V2 USN record of `entry` under `parent` (sequence 1 in both references).
fn usn_v2(entry: u64, parent: u64, filetime: u64, reason: u32, name: &str) -> Vec<u8> {
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let len = (60 + utf16.len() * 2).div_ceil(8) * 8;
    let mut b = Vec::new();
    b.extend_from_slice(&(len as u32).to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&(entry | (1u64 << 48)).to_le_bytes());
    b.extend_from_slice(&(parent | (1u64 << 48)).to_le_bytes());
    b.extend_from_slice(&4096i64.to_le_bytes());
    b.extend_from_slice(&filetime.to_le_bytes());
    b.extend_from_slice(&reason.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0x20u32.to_le_bytes());
    b.extend_from_slice(&((utf16.len() * 2) as u16).to_le_bytes());
    b.extend_from_slice(&60u16.to_le_bytes());
    for c in utf16 {
        b.extend_from_slice(&c.to_le_bytes());
    }
    b.resize(len, 0);
    b
}

fn journal() -> Vec<u8> {
    let mut j = vec![0u8; 8192]; // the zeros of a journal's discarded head
    j.extend(usn_v2(32, 31, T, 0x100, "tool.exe"));
    j.extend(usn_v2(32, 31, T + 10_000_000, 0x2 | 0x8000_0000, "tool.exe"));
    j
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("allymacb_usnpair_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The file names of the USN rows of a run.
fn usn_names(args: &[&std::ffi::OsStr]) -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).arg("-q").args(args).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().unwrap().split(',').collect();
    let src = header.iter().position(|c| *c == "source").unwrap();
    let name = header.iter().position(|c| *c == "file_name").unwrap();
    lines
        .map(|l| l.split(',').map(str::to_string).collect::<Vec<_>>())
        .filter(|f| f[src] == "usn")
        .map(|f| f[name].trim_matches('"').split(" (USN:").next().unwrap_or("").to_string())
        .collect()
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn a_journal_given_with_its_mft_names_real_folders_under_every_name() {
    for (k, journal_rel) in ["$Extend/$UsnJrnl__$J", "$Extend/$J", "$UsnJrnl_$J", "$Extend/$UsnJrnl%3A$J", "UsnJrnl_J"].iter().enumerate() {
        let d = tmpdir(&format!("f{k}"));
        let m = d.join("$MFT");
        let j = d.join(journal_rel);
        write(&m, &mft());
        write(&j, &journal());
        let names = usn_names(&["-f".as_ref(), m.as_os_str(), "-f".as_ref(), j.as_os_str()]);
        assert_eq!(names.len(), 2, "{journal_rel}: {names:?}");
        assert!(names.iter().all(|n| n == r"C:\Users\Public\tool.exe"), "{journal_rel}: {names:?}");
        // The journal first on the command line: the same.
        let names = usn_names(&["-f".as_ref(), j.as_os_str(), "-f".as_ref(), m.as_os_str()]);
        assert!(names.iter().all(|n| n == r"C:\Users\Public\tool.exe"), "{journal_rel} first: {names:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
fn a_folder_pairs_the_journal_with_the_mft_of_its_volume() {
    let d = tmpdir("dir");
    write(&d.join("C").join("$MFT"), &mft());
    write(&d.join("C").join("$Extend").join("$UsnJrnl%3A$J"), &journal());
    let names = usn_names(&["-d".as_ref(), d.as_os_str()]);
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.iter().all(|n| n == r"C:\Users\Public\tool.exe"), "{names:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_lone_journal_keeps_unknown_parents() {
    let d = tmpdir("lone");
    let j = d.join("$Extend").join("$J");
    write(&j, &journal());
    let names = usn_names(&["-f".as_ref(), j.as_os_str()]);
    assert_eq!(names.len(), 2);
    assert!(names.iter().all(|n| n == r"C:\[UNKNOWN]\tool.exe"), "{names:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn two_volumes_are_not_crossed() {
    // C/$MFT knows record 32; D/$MFT does not: D's journal must not borrow C's paths.
    let d = tmpdir("two");
    write(&d.join("C").join("$MFT"), &mft());
    let mut other = Vec::new();
    for i in 0..33u64 {
        other.extend(record(i, 1, &[si(T), fname(5, &format!("other{i}"), 0, T)]));
    }
    write(&d.join("D").join("$MFT"), &other);
    write(&d.join("D").join("$Extend").join("$J"), &journal());
    let names = usn_names(&["-d".as_ref(), d.as_os_str()]);
    assert_eq!(names.len(), 2);
    assert!(names.iter().all(|n| !n.contains(r"Users\Public")), "D's journal took C's paths: {names:?}");
    let _ = std::fs::remove_dir_all(&d);
}
