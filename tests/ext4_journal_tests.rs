//! The raw ext4 reader on a small real filesystem (tests/data/ext4_journal.img.gz,
//! 8 MiB, 1 KiB blocks, built on Ubuntu 22.04): live tree with inode numbers
//! and ctime, inodes marked deleted, and the jbd2 journal giving names and
//! older states with `--carve`.
//!
//! What was done on the volume: docs/alive.txt, docs/gone.txt, keep/old.txt
//! (400 bytes), keep/renamed_before.txt, docs/stomp.txt and deep/a/b/deep.txt
//! were created; then stomp.txt got `touch -d 1975`, old.txt grew to 650
//! bytes, renamed_before.txt became renamed_after.txt, gone.txt was removed
//! and the deep tree deleted whole.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use allymacb::anomaly;
use allymacb::parsers::ext4raw::parse_ext4_raw;
use allymacb::timeline::{source, TimelineEntry};

/// One decompressed copy per test: the tests run in parallel.
fn fixture(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("allymacb_ext4_fixture_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let img = dir.join(format!("ext4_journal_{}.img", tag));
    let gz = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ext4_journal.img.gz")).unwrap();
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut raw).unwrap();
    assert_eq!(raw.len(), 8 * 1024 * 1024);
    std::fs::write(&img, raw).unwrap();
    img
}

fn rows(carve: bool) -> Vec<TimelineEntry> {
    let f = File::open(fixture(if carve { "carve" } else { "live" })).unwrap();
    let (rows, _) = parse_ext4_raw(f, 0, carve).unwrap();
    rows
}

fn find<'a>(rows: &'a [TimelineEntry], name: &str, src: &str) -> Vec<&'a TimelineEntry> {
    rows.iter().filter(|r| r.file_name.starts_with(name) && r.source == src).collect()
}

#[test]
fn live_tree_has_inode_numbers_ctime_and_deleted_inodes() {
    let rows = rows(false);
    assert!(rows.iter().all(|r| r.source == source::EXT4));
    let alive = find(&rows, "/docs/alive.txt", source::EXT4);
    assert!(!alive.is_empty());
    assert_eq!(alive[0].meta, "17", "inode number in meta");
    assert_eq!(alive[0].size, 120);
    assert!(alive.iter().any(|r| r.macb.contains('c')), "ctime row present");
    assert_eq!(alive[0].mode, "-rw-r--r--");
    // keep/old.txt is 650 bytes now; the deleted gone.txt has no name without the journal
    assert_eq!(find(&rows, "/keep/old.txt", source::EXT4)[0].size, 650);
    assert!(!find(&rows, "/[UNKNOWN]/inode_18 (deleted)", source::EXT4).is_empty());
    assert!(find(&rows, "/docs/gone.txt", source::EXT4).is_empty());
    let stomp = find(&rows, "/docs/stomp.txt", source::EXT4);
    assert!(stomp.iter().any(|r| r.timestamp.starts_with("1975-06-15") && r.macb.starts_with("ma")));
    assert!(stomp[0].flags.contains(anomaly::PRE_1980) && stomp[0].flags.contains(anomaly::M_BEFORE_B), "{}", stomp[0].flags);
}

#[test]
fn journal_names_deleted_files_and_recovers_older_states() {
    let rows = rows(true);
    // The deleted inode is named through a journal copy of its directory.
    assert!(!find(&rows, "/docs/gone.txt (deleted)", source::EXT4).is_empty());
    assert!(find(&rows, "/[UNKNOWN]/inode_18", source::EXT4).is_empty());
    // Its pre-deletion state (400 bytes) is a carved row.
    let gone = find(&rows, "/docs/gone.txt (carved @0x", source::CARVED);
    assert!(gone.iter().any(|r| r.size == 400), "{:?}", gone);
    // old.txt before it grew, renamed_before.txt before the rename.
    assert!(find(&rows, "/keep/old.txt (carved @0x", source::CARVED).iter().any(|r| r.size == 400));
    assert!(!find(&rows, "/keep/renamed_before.txt (carved @0x", source::CARVED).is_empty());
    // The whole deleted tree gets its path back, parents included.
    assert!(!find(&rows, "/deep/a/b/deep.txt (deleted)", source::EXT4).is_empty());
    assert!(!find(&rows, "/deep/a (deleted)", source::EXT4).is_empty());
    // stomp.txt: the journal still has the state before `touch -d 1975`, so the live
    // rows and the carved one say backdated.
    let live = find(&rows, "/docs/stomp.txt", source::EXT4);
    assert!(live[0].flags.contains(anomaly::BACKDATED), "{}", live[0].flags);
    let old = find(&rows, "/docs/stomp.txt (carved @0x", source::CARVED);
    assert!(old.iter().any(|r| r.timestamp.starts_with("2026-10-28") && r.flags.contains(anomaly::BACKDATED)), "{:?}", old);
    // Carved rows never repeat a live row.
    let strip = |n: &str| n.rfind(" (carved @0x").map_or(n.to_string(), |i| n[..i].to_string());
    let live_keys: std::collections::HashSet<_> = rows.iter().filter(|r| r.source != source::CARVED).map(|r| (r.timestamp_secs, r.timestamp_nanos, r.macb.clone(), r.size, r.meta.clone(), r.file_name.clone())).collect();
    for r in rows.iter().filter(|r| r.source == source::CARVED) {
        assert!(!live_keys.contains(&(r.timestamp_secs, r.timestamp_nanos, r.macb.clone(), r.size, r.meta.clone(), strip(&r.file_name))), "duplicate: {:?}", r);
    }
    assert!(rows.iter().filter(|r| r.source == source::CARVED).all(|r| !r.file_name.starts_with(" (")), "root carved rows are named '/'");
}

#[test]
fn cli_reads_a_bare_ext4_image_and_carves_its_journal() {
    let img = fixture("cli");
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).arg("--carve").arg("-f").arg(&img).output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l.contains("/docs/gone.txt (deleted),ext4,")), "{}", stdout);
    assert!(stdout.lines().any(|l| l.contains("/keep/renamed_before.txt (carved @0x") && l.contains(",carved,")), "{}", stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("[ALERT]") && stderr.contains("backdated"), "{}", stderr);
    assert!(stderr.contains("journal:"), "{}", stderr);
}
