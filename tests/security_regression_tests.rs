//! Regression tests for the security and evidence-loss findings of the
//! full code review: archive path traversal, CSV formula injection, status
//! output polluting stdout, silent failures returning exit code 0, and
//! archives without artifacts being timelined with host timestamps.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use allymacb::ingest::archive::{extract_archive_with_report, process_archive_fast};
use allymacb::parsers::mft::MftParseOptions;
use allymacb::timeline::{TimelineEntry, TimelineWriter, CSV_HEADER};

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("allymacb_sec_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Builds a minimal ustar header + data block for one regular file.
fn tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
    let mut hdr = vec![0u8; 512];
    hdr[..name.len()].copy_from_slice(name.as_bytes());
    hdr[100..107].copy_from_slice(b"0000644");
    hdr[108..115].copy_from_slice(b"0000000");
    hdr[116..123].copy_from_slice(b"0000000");
    hdr[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    hdr[136..147].copy_from_slice(b"10000000000");
    hdr[156] = b'0';
    hdr[257..262].copy_from_slice(b"ustar");
    hdr[263..265].copy_from_slice(b"00");
    // checksum: computed with the field filled with spaces
    hdr[148..156].copy_from_slice(b"        ");
    let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
    hdr[148..155].copy_from_slice(format!("{:06o}\0", sum).as_bytes());
    let mut out = hdr;
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}

fn write_tar(path: &Path, entries: &[(&str, &[u8])]) {
    let mut f = fs::File::create(path).unwrap();
    for (name, data) in entries {
        f.write_all(&tar_entry(name, data)).unwrap();
    }
    f.write_all(&[0u8; 1024]).unwrap();
}

#[test]
fn tar_entries_escaping_the_extraction_dir_are_refused() {
    let dir = scratch("tarslip");
    let tar_path = dir.join("evil.tar");
    write_tar(
        &tar_path,
        &[
            ("../../ALLYMACB_ESCAPE_MARKER.txt", b"owned"),
            ("safe/inside.txt", b"fine"),
        ],
    );
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();

    let report = extract_archive_with_report(&tar_path, &out).unwrap();
    assert_eq!(report.unsafe_entries, 1, "the traversal entry must be refused");
    assert_eq!(report.files.len(), 1);
    assert!(out.join("safe").join("inside.txt").exists());
    assert!(!dir.join("ALLYMACB_ESCAPE_MARKER.txt").exists());
    assert!(!dir.parent().unwrap().join("ALLYMACB_ESCAPE_MARKER.txt").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn csv_writer_neutralises_formula_filenames_and_escapes_every_column() {
    let dir = scratch("csvinj");
    let out = dir.join("t.csv");
    let mut entries = vec![
        TimelineEntry::new(
            "2024-01-01T00:00:00Z".into(), 1_704_067_200, 0, 10, "m...".into(), "-rw-r--r--".into(), 0, 0,
            "4230,evil".into(), "=cmd|' /C calc'!A0".into(),
        ),
        TimelineEntry::new(
            "2024-01-01T00:00:01Z".into(), 1_704_067_201, 0, 10, "m...".into(), "-rw-r--r--".into(), 0, 0,
            "1".into(), "@SUM(A1:A9)".into(),
        ),
    ];
    TimelineWriter::write_entries(&mut entries, Some(&out)).unwrap();
    let text = fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], CSV_HEADER);
    assert_eq!(lines[1], "2024-01-01T00:00:00Z,10,m...,-rw-r--r--,0,0,\"4230,evil\",\"'=cmd|' /C calc'!A0\",unknown,");
    assert_eq!(lines[2], "2024-01-01T00:00:01Z,10,m...,-rw-r--r--,0,0,1,\"'@SUM(A1:A9)\",unknown,");
    let _ = fs::remove_dir_all(&dir);
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_allymacb"))
}

const BODY: &str = "0|/etc/passwd|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|0\n0|/tmp/=evil|1|-rw-r--r--|0|0|1|1700000000|1700000000|1700000000|0\n";

#[test]
fn cli_stdout_is_pure_csv_without_quiet_flag() {
    let dir = scratch("cli_stdout");
    let body = dir.join("bodyfile.txt");
    fs::write(&body, BODY).unwrap();

    let out = bin().arg("-f").arg(&body).output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert_eq!(first, CSV_HEADER, "stdout must start with the CSV header, got: {:?}", first);
    assert!(stdout.lines().all(|l| l.split(',').count() >= 8), "every stdout line is a CSV row");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Summary"), "status output goes to stderr");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_exit_code_2_when_nothing_parsed() {
    let dir = scratch("cli_nothing");
    let out = bin().arg("-q").arg("-f").arg(dir.join("does_not_exist.bin")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "no CSV must be written when nothing parsed");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_exit_code_3_on_partial_failure() {
    let dir = scratch("cli_partial");
    let body = dir.join("bodyfile.txt");
    fs::write(&body, BODY).unwrap();
    let bad = dir.join("bad.E01");
    fs::write(&bad, b"garbage").unwrap();

    let out = bin().arg("-q").arg("-f").arg(&body).arg(&bad).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().next().unwrap_or(""), CSV_HEADER);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bad.E01"), "the failed source is named on stderr: {}", stderr);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_sniffs_bodyfile_content_from_unnamed_file() {
    let dir = scratch("cli_sniff");
    let f = dir.join("collection.dat");
    fs::write(&f, BODY).unwrap();
    let out = bin().arg("-q").arg("-f").arg(&f).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/etc/passwd"));
    assert!(!stdout.contains("collection.dat"), "must not fall back to host metadata of the file");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn directory_scan_picks_up_loose_bodyfile_and_usn() {
    let dir = scratch("dir_scan");
    fs::create_dir_all(dir.join("uac").join("bodyfile")).unwrap();
    fs::write(dir.join("uac").join("bodyfile").join("bodyfile.txt"), BODY).unwrap();
    let out = bin().arg("-q").arg("-d").arg(&dir).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("/etc/passwd"), "{}", stdout);
    assert!(!stdout.contains("bodyfile.txt"), "the bodyfile itself must not be timelined as a loose file");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn archive_without_artifacts_uses_archive_mtimes_only_and_no_temp_root_rows() {
    let dir = scratch("zip_fallback");
    let zip_path = dir.join("loose.zip");
    {
        let f = fs::File::create(&zip_path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let dt = zip::DateTime::from_date_and_time(2001, 9, 9, 1, 46, 40).unwrap();
        let opts = zip::write::SimpleFileOptions::default().last_modified_time(dt);
        zw.start_file("docs/old.txt", opts).unwrap();
        zw.write_all(b"12345678").unwrap();
        zw.finish().unwrap();
    }
    let staging = dir.join("staging");
    fs::create_dir_all(&staging).unwrap();
    let opts = MftParseOptions { quiet: true, ..Default::default() };
    assert!(process_archive_fast(&zip_path, &opts, &staging).unwrap().is_none());

    let out = bin().arg("-q").arg("-f").arg(&zip_path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let rows: Vec<&str> = stdout.lines().skip(1).collect();
    assert!(!rows.is_empty());
    for r in &rows {
        assert!(r.contains("[loose.zip]\\docs"), "only archive members, no temp-dir root rows: {}", r);
        assert!(r.contains(",m...,"), "only modification-time rows from the archive: {}", r);
    }
    assert!(rows.iter().any(|r| r.starts_with("2001-09-09T01:46:40Z")), "mtime comes from the zip entry: {:?}", rows);
    let _ = fs::remove_dir_all(&dir);
}
