//! Carving (`--carve`): NTFS `FILE` records and `$I30` index entries found
//! at arbitrary sector offsets of a blob or image, deduplicated against the
//! live `$MFT`, resolved through carved directories and tagged `carved`.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;

use allymacb::ingest::carve::{carve_blob, carve_stream, file_record_size, parse_indx_block, VolumeContext};
use allymacb::parsers::mft::MftParseOptions;
use allymacb::timeline::{source, TimelineEntry, CSV_HEADER};

mod common;
use common::*;

/// FILETIME for 2023-06-01T00:00:00Z, a different state of the same records.
const FT2: u64 = (1685577600u64 + 11_644_473_600) * 10_000_000;

fn opts(include_fn: bool) -> MftParseOptions {
    MftParseOptions {
        include_file_name_timestamps: include_fn,
        resident_dir: None,
        resident_report: None,
        drive_letter: Some('C'),
        quiet: true,
        carve: true,
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("allymacb_carve_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Deterministic junk that never contains a valid record.
fn junk(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x & 0xFF) as u8
        })
        .collect()
}

fn place(blob: &mut [u8], off: usize, bytes: &[u8]) {
    blob[off..off + bytes.len()].copy_from_slice(bytes);
}

/// $STANDARD_INFORMATION with created/accessed/mft_modified at `ts` and modified at `mts`.
fn si_mixed(ts: u64, mts: u64) -> Attr {
    let mut b = Vec::new();
    for t in [ts, mts, ts, ts] {
        b.extend_from_slice(&le64(t));
    }
    b.extend_from_slice(&le32(0x20));
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&[0u8; 24]);
    Attr { ty: 0x10, name: "", body: b, non_resident: None }
}

/// root (5) -> dir A (6) -> file f.txt (7)
fn sample_records(ts: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root = record(5, 3, &[si(ts), fname(5, ".", 0, ts)]);
    let dir_a = record(6, 3, &[si(ts), fname(5, "A", 0, ts)]);
    let file = record(7, 1, &[si(ts), fname(6, "f.txt", 42, ts), data("", b"hello")]);
    (root, dir_a, file)
}

/// Builds one 4 KiB `$I30` block with fixups: a live chain holding
/// `live` entries, then `slack` entries after the LAST marker.
fn indx_block(live: &[(u64, u16, Attr)], slack: &[(u64, u16, Attr)]) -> Vec<u8> {
    let size = 4096usize;
    let mut b = vec![0u8; size];
    b[0..4].copy_from_slice(b"INDX");
    b[4..6].copy_from_slice(&le16(0x28));
    b[6..8].copy_from_slice(&le16(9)); // 8 sectors + usn
    let entries_start = 0x40usize;
    let mut pos = entries_start;
    let push = |b: &mut Vec<u8>, pos: &mut usize, file_ref: u64, seq: u16, fn_attr: &Attr, flags: u32| {
        let fn_len = fn_attr.body.len();
        let len = (16 + fn_len + 7) & !7;
        b[*pos..*pos + 8].copy_from_slice(&le64(file_ref | ((seq as u64) << 48)));
        b[*pos + 8..*pos + 10].copy_from_slice(&le16(len as u16));
        b[*pos + 10..*pos + 12].copy_from_slice(&le16(fn_len as u16));
        b[*pos + 12..*pos + 16].copy_from_slice(&le32(flags));
        b[*pos + 16..*pos + 16 + fn_len].copy_from_slice(&fn_attr.body);
        *pos += len;
    };
    for (r, s, a) in live {
        push(&mut b, &mut pos, *r, *s, a, 0);
    }
    // LAST entry: 16 bytes, flags = 2
    b[pos + 8..pos + 10].copy_from_slice(&le16(16));
    b[pos + 12..pos + 16].copy_from_slice(&le32(2));
    pos += 16;
    let index_size = pos - 0x18;
    for (r, s, a) in slack {
        push(&mut b, &mut pos, *r, *s, a, 0);
    }
    b[24..28].copy_from_slice(&le32((entries_start - 0x18) as u32));
    b[28..32].copy_from_slice(&le32(index_size as u32));
    b[32..36].copy_from_slice(&le32((size - 0x18) as u32));
    // fixups: usn 0x0007, keep the real sector-end bytes in the array
    b[0x28..0x2A].copy_from_slice(&le16(7));
    for i in 1..9 {
        let end = i * 512;
        let orig = [b[end - 2], b[end - 1]];
        b[0x28 + i * 2..0x28 + i * 2 + 2].copy_from_slice(&orig);
        b[end - 2..end].copy_from_slice(&le16(7));
    }
    b
}

fn names(rows: &[TimelineEntry]) -> Vec<String> {
    let mut v: Vec<String> = rows.iter().map(|r| r.file_name.clone()).collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn records_scattered_in_a_blob_are_found_and_paths_rebuilt_from_carved_dirs() {
    let (root, dir_a, file) = sample_records(FT);
    let mut blob = junk(2 * 1024 * 1024, 1);
    // Not record-aligned on purpose: only sector alignment is assumed.
    place(&mut blob, 0x1000, &root);
    place(&mut blob, 0x8_0200, &dir_a);
    place(&mut blob, 0x12_3E00, &file);
    // Decoys: a bare signature, and a record whose fixups do not match.
    place(&mut blob, 0x3000, b"FILE");
    let mut broken = file.clone();
    broken[510] ^= 0xFF;
    place(&mut blob, 0x1F_0000, &broken);

    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[], &opts(false), "blob", &[]).unwrap();
    assert_eq!(stats.file_records, 3, "only the three intact records are valid");
    assert_eq!(stats.file_records_new, 3);
    assert!(rows.iter().all(|r| r.source == source::CARVED));
    assert_eq!(
        names(&rows),
        vec![
            "C:\\ (carved @0x1000)".to_string(),
            "C:\\A (carved @0x80200)".to_string(),
            "C:\\A\\f.txt (carved @0x123E00)".to_string(),
        ]
    );
    let f = rows.iter().find(|r| r.file_name.contains("f.txt")).unwrap();
    assert_eq!(f.size, 5, "resident $DATA size");
    assert_eq!(f.meta, "7");
    assert_eq!(f.mode, "-/-rwxrwxrwx");
    let a = rows.iter().find(|r| r.file_name.starts_with("C:\\A (")).unwrap();
    assert_eq!(a.mode, "d/drwxrwxrwx");
}

#[test]
fn record_straddling_the_read_block_boundary_is_seen_whole() {
    let (_, dir_a, file) = sample_records(FT);
    let block = 4 * 1024 * 1024;
    let mut blob = junk(block + 256 * 1024, 2);
    place(&mut blob, block - 512, &file); // crosses the 4 MiB boundary
    place(&mut blob, block - 64 * 1024, &dir_a); // inside the carry-over window
    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[], &opts(false), "blob", &[]).unwrap();
    assert_eq!(stats.file_records, 2);
    assert!(names(&rows).iter().any(|n| n == "C:\\A\\f.txt (carved @0x3FFE00)"), "{:?}", names(&rows));
}

#[test]
fn identical_copies_collapse_but_older_states_survive() {
    let (root, dir_a, file) = sample_records(FT);
    let (_, _, older) = sample_records(FT2);
    let mut blob = junk(1024 * 1024, 3);
    place(&mut blob, 0x1000, &root);
    place(&mut blob, 0x2000, &dir_a);
    place(&mut blob, 0x3000, &file);
    place(&mut blob, 0x4000, &file); // VSS-style duplicate
    place(&mut blob, 0x5000, &older); // same record, different timestamps
    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[], &opts(false), "blob", &[]).unwrap();
    assert_eq!(stats.file_records, 5);
    assert_eq!(stats.file_records_new, 4);
    let f: Vec<&TimelineEntry> = rows.iter().filter(|r| r.file_name.contains("f.txt")).collect();
    let offsets: Vec<&str> = f.iter().map(|r| r.file_name.rsplit('@').next().unwrap()).collect();
    assert!(offsets.contains(&"0x3000)") && offsets.contains(&"0x5000)") && !offsets.contains(&"0x4000)"), "{:?}", offsets);
}

#[test]
fn live_mft_records_are_not_reported_as_carved() {
    let dir = scratch("live");
    let (root, dir_a, file) = sample_records(FT);
    let (_, _, older) = sample_records(FT2);
    // Live $MFT: records 0..=7 (0..=4 are placeholders).
    let mut mft = Vec::new();
    for i in 0..5u64 {
        mft.extend(record(i, 1, &[si(FT), fname(5, &format!("$Sys{}", i), 0, FT)]));
    }
    mft.extend(&root);
    mft.extend(&dir_a);
    mft.extend(&file);
    let mft_path = dir.join("mft.bin");
    fs::write(&mft_path, &mft).unwrap();

    // Image: the live table itself plus an older copy of record 7 elsewhere.
    let mut blob = junk(1024 * 1024, 4);
    place(&mut blob, 0x1_0000, &mft);
    place(&mut blob, 0x8_0000, &older);
    let vol = VolumeContext { start: 0, end: blob.len() as u64, live_mft: Some(mft_path), free_ranges: vec![], free_known: false };
    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[vol], &opts(true), "img", &[]).unwrap();
    assert_eq!(stats.file_records, 9);
    assert_eq!(stats.file_records_new, 1, "only the older state is new");
    // Parent resolved through the live $MFT, with both SI and FN rows.
    assert_eq!(
        names(&rows),
        vec![
            "C:\\A\\f.txt ($FILE_NAME: f.txt) (carved @0x80000)".to_string(),
            "C:\\A\\f.txt (carved @0x80000)".to_string()
        ]
    );
    assert!(rows.iter().all(|r| r.timestamp.starts_with("2023-06-01")));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn indx_slack_entries_of_deleted_files_are_recovered() {
    let dir = scratch("indx");
    let (root, dir_a, file) = sample_records(FT);
    let mut mft = Vec::new();
    for i in 0..5u64 {
        mft.extend(record(i, 1, &[si(FT), fname(5, &format!("$Sys{}", i), 0, FT)]));
    }
    mft.extend(&root);
    mft.extend(&dir_a);
    mft.extend(&file);
    let mft_path = dir.join("mft.bin");
    fs::write(&mft_path, &mft).unwrap();

    // $I30 of directory A: live entry f.txt (record 7), slack entry gone.txt
    // (record 8, which the live table does not have).
    let block = indx_block(
        &[(7, 1, fname(6, "f.txt", 42, FT))],
        &[(8, 1, fname(6, "gone.txt", 1234, FT2))],
    );
    let mut blob = junk(512 * 1024, 5);
    place(&mut blob, 0x1_0000, &mft);
    place(&mut blob, 0x4_0000, &block);

    let (size, entries) = parse_indx_block(&block).expect("valid INDX block");
    assert_eq!(size, 4096);
    assert_eq!(entries.len(), 2);

    let vol = VolumeContext { start: 0, end: blob.len() as u64, live_mft: Some(mft_path), free_ranges: vec![], free_known: false };
    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[vol], &opts(false), "img", &[]).unwrap();
    assert_eq!(stats.indx_blocks, 1);
    assert_eq!(stats.indx_entries, 2);
    assert_eq!(stats.indx_entries_new, 1, "f.txt is live, gone.txt is not");
    // First entry at 0x40, the f.txt entry is 0x60 long, the LAST marker 0x10: slack starts at 0xB0.
    assert_eq!(names(&rows), vec!["C:\\A\\gone.txt ($I30) (carved @0x400B0)".to_string()]);
    let g = &rows[0];
    assert_eq!(g.size, 1234);
    assert_eq!(g.meta, "8");
    assert_eq!(g.macb, "macb");
    assert!(g.timestamp.starts_with("2023-06-01"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rows_identical_to_live_rows_are_not_repeated() {
    // An older state of record 7 that differs from the live one only in its
    // modification time: the creation row says what the live row says.
    let (root, dir_a, file) = sample_records(FT);
    let older = record(7, 1, &[si_mixed(FT, FT2), fname(6, "f.txt", 42, FT), data("", b"hello")]);
    let mut blob = junk(512 * 1024, 11);
    place(&mut blob, 0x1000, &root);
    place(&mut blob, 0x2000, &dir_a);
    place(&mut blob, 0x3000, &older);
    // Pretend the live timeline already has the current state of f.txt.
    let live = {
        let mut live_blob = junk(64 * 1024, 12);
        place(&mut live_blob, 0x1000, &root);
        place(&mut live_blob, 0x2000, &dir_a);
        place(&mut live_blob, 0x3000, &file);
        let (rows, _) = carve_stream(&mut Cursor::new(&live_blob), live_blob.len() as u64, &[], &opts(false), "live", &[]).unwrap();
        rows.into_iter()
            .map(|mut r| {
                let i = r.file_name.rfind(" (carved").unwrap();
                r.file_name.truncate(i);
                r.with_source(source::MFT)
            })
            .collect::<Vec<_>>()
    };
    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[], &opts(false), "blob", &live).unwrap();
    // The live row at FT is `macb`; the older state has `.acb` there (its
    // modification time moved), so both of its rows say something new.
    let mut f: Vec<(String, String)> = rows.iter().filter(|r| r.file_name.contains("f.txt")).map(|r| (r.macb.clone(), r.timestamp[..10].to_string())).collect();
    f.sort();
    assert_eq!(f, vec![(".acb".to_string(), "2024-02-04".to_string()), ("m...".to_string(), "2023-06-01".to_string())]);
    assert_eq!(stats.rows_duplicate, 2, "root and A each repeat one live row");
    // Root and A repeat the live rows exactly: nothing from them.
    assert!(rows.iter().all(|r| r.file_name.contains("f.txt")), "{:?}", names(&rows));
}

#[test]
fn log_lines_and_utmp_records_are_carved_from_free_space_only() {
    let mut blob = junk(512 * 1024, 21);
    // Log lines start after a newline, as in a file; the junk before them is not a line start.
    let syslog = b"\n2026-10-28T20:38:02.123456+00:00 LEO-LNX01 sshd[1234]: Accepted password for bob from 10.0.0.5\nOct 28 20:39:00 LEO-LNX01 sudo: bob : COMMAND=/bin/rm -rf /var/log/auth.log\n";
    place(&mut blob, 0x1_00FF, syslog); // inside the free range
    place(&mut blob, 0x4_00FF, b"\n2026-10-28T21:00:00Z LEO-LNX01 cron[9]: allocated line, must not appear\n"); // allocated
    let mut utmp = vec![0u8; 384];
    utmp[0] = 7;
    utmp[4..8].copy_from_slice(&4321i32.to_le_bytes());
    utmp[8..13].copy_from_slice(b"pts/1");
    utmp[44..49].copy_from_slice(b"alice");
    utmp[76..85].copy_from_slice(b"10.0.0.77");
    utmp[340..344].copy_from_slice(&1_793_220_000i32.to_le_bytes());
    place(&mut blob, 0x1_2000, &utmp);

    // Whole blob free (no volume information): everything is found.
    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[], &opts(false), "blob", &[]).unwrap();
    assert_eq!(stats.text_lines, 3, "{:?}", names(&rows));
    assert_eq!(stats.utmp_records, 1);
    assert!(rows.iter().any(|r| r.file_name.starts_with("[syslog] 2026-10-28T20:38:02.123456+00:00 LEO-LNX01 sshd[1234]") && r.file_name.ends_with("(carved @0x10100)")));
    assert!(rows.iter().any(|r| r.file_name.contains("[utmp] USER_PROCESS user=alice line=pts/1 host=10.0.0.77 pid=4321")));
    let sudo = rows.iter().find(|r| r.file_name.contains("COMMAND=/bin/rm")).unwrap();
    assert_eq!(sudo.timestamp, "2026-10-28T20:39:00Z");
    assert_eq!(sudo.source, source::CARVED);

    // A volume covering the blob whose free space is only 0x10000..0x20000.
    let vol = VolumeContext { start: 0, end: blob.len() as u64, live_mft: None, free_ranges: vec![(0x1_0000, 0x1_0000)], free_known: true };
    let (rows, stats) = carve_stream(&mut Cursor::new(&blob), blob.len() as u64, &[vol], &opts(false), "img", &[]).unwrap();
    assert_eq!(stats.text_lines, 2);
    assert_eq!(stats.utmp_records, 1);
    assert!(!rows.iter().any(|r| r.file_name.contains("allocated line")));
    assert_eq!(stats.free_bytes_scanned, 0x1_0000);
}

#[test]
fn validators_reject_garbage() {
    assert_eq!(file_record_size(&junk(4096, 9)), None);
    assert!(parse_indx_block(&junk(8192, 10)).is_none());
    let (_, _, file) = sample_records(FT);
    assert_eq!(file_record_size(&file), Some(1024));
    assert_eq!(file_record_size(&file[..1000]), None, "truncated record");
}

#[test]
fn carve_blob_reads_a_file_and_unaligned_junk_is_ignored() {
    let dir = scratch("blobfile");
    let (root, dir_a, file) = sample_records(FT);
    let mut blob = junk(300 * 1024, 6);
    place(&mut blob, 0x200, &root);
    place(&mut blob, 0x800, &dir_a);
    place(&mut blob, 0xC00, &file);
    place(&mut blob, 0x1234, &file); // not sector aligned: not a candidate
    let p = dir.join("unknown.bin");
    fs::write(&p, &blob).unwrap();
    let (rows, stats) = carve_blob(&p, &opts(false)).unwrap();
    assert_eq!(stats.file_records, 3);
    assert!(names(&rows).contains(&"C:\\A\\f.txt (carved @0xC00)".to_string()), "{:?}", names(&rows));
    let _ = fs::remove_dir_all(&dir);
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_allymacb"))
}

#[test]
fn cli_carving_is_opt_in_and_rows_say_carved() {
    let dir = scratch("cli");
    let (root, dir_a, file) = sample_records(FT);
    let mut blob = junk(256 * 1024, 7);
    place(&mut blob, 0x200, &root);
    place(&mut blob, 0x800, &dir_a);
    place(&mut blob, 0xC00, &file);
    let p = dir.join("pagefile.sys");
    fs::write(&p, &blob).unwrap();

    // Without --carve the blob is an unrecognised file: host metadata only.
    let out = bin().arg("-q").arg("-f").arg(&p).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains(",carved"), "no carving unless asked: {}", stdout);
    assert!(stdout.lines().skip(1).all(|l| l.contains(",fs,")), "{}", stdout);

    // With --carve the records inside are timelined and tagged.
    let out = bin().arg("-q").arg("--carve").arg("-f").arg(&p).output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().next().unwrap(), CSV_HEADER);
    let carved: Vec<&str> = stdout.lines().filter(|l| l.contains(",carved,")).collect();
    assert_eq!(carved.len(), 3, "{}", stdout);
    assert!(carved.iter().any(|l| l.contains("C:\\A\\f.txt (carved @0xC00)")), "{}", stdout);
    assert!(stdout.lines().skip(1).all(|l| l.contains(",carved,")));
    let _ = fs::remove_dir_all(&dir);
}
