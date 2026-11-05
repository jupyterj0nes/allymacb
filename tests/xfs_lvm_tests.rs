//! XFS and LVM on disk images built on a real Linux host by faramir's
//! `scripts/linux_disk_lab.sh` (the same fixtures faramir tests with):
//!
//! * `gpt_xfs.img`: 64 MiB, GPT, one XFS partition (v5, with `crtime`).
//! * `mbr_lvm_xfs.img`: 80 MiB, MBR type 0x8e, VG `vg_xfs`, LV `root`, XFS.
//! * `mbr_lvm_ext4.img`: 48 MiB, MBR type 0x8e, VG `vg_lab`, LV `root`, ext4.
//!
//! Each volume holds a small root (`/etc/hostname`, cron, systemd, sudoers,
//! `/home/bob/.ssh`, `/lib` and `/bin` as symlinks into `/usr`), and three
//! files that were created and removed again: `/etc/cron.d/gone`,
//! `/etc/systemd/system/gone.service` and `/home/bob/.ssh/authorized_keys2`.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

/// One decompressed copy per test: the tests run in parallel.
fn fixture(name: &str, tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("allymacb_xfs_{}_{}", std::process::id(), tag));
    let _ = std::fs::create_dir_all(&dir);
    let img = dir.join(format!("{name}.img"));
    let gz = File::open(format!("{}/tests/data/{name}.img.gz", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut raw).unwrap();
    std::fs::write(&img, raw).unwrap();
    img
}

/// Splits one CSV line, quotes included.
fn fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Runs the binary and returns the rows as column name -> value.
fn run(name: &str, tag: &str, extra: &[&str]) -> Vec<HashMap<String, String>> {
    let img = fixture(name, tag);
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).arg("-q").arg("-f").arg(&img).args(extra).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.lines();
    let header = fields(lines.next().unwrap());
    assert_eq!(header.len(), 19);
    let rows: Vec<HashMap<String, String>> = lines
        .map(|l| {
            let f = fields(l);
            assert_eq!(f.len(), 19, "{l}");
            header.iter().cloned().zip(f).collect()
        })
        .collect();
    let _ = std::fs::remove_dir_all(img.parent().unwrap());
    rows
}

fn named<'a>(rows: &'a [HashMap<String, String>], name: &str) -> Vec<&'a HashMap<String, String>> {
    rows.iter().filter(|r| r["file_name"] == name).collect()
}

#[test]
fn xfs_partition_gives_the_tree_with_four_times() {
    let rows = run("gpt_xfs", "gpt", &[]);
    assert!(rows.iter().all(|r| r["source"] == "xfs" && r["volume"] == "p1" && r["evidence"] == "gpt_xfs.img:p1"));
    let hostname = named(&rows, "/etc/hostname");
    assert!(!hostname.is_empty());
    assert_eq!(hostname[0]["mode"], "-rw-r--r--");
    assert!(hostname.iter().any(|r| r["type"].contains('b')), "crtime of a v5 inode");
    assert!(hostname.iter().any(|r| r["type"].contains('c')), "ctime");
    assert!(hostname[0]["time_created"].contains('.'), "nanoseconds: {}", hostname[0]["time_created"]);
    assert_eq!(named(&rows, "/lib")[0]["mode"], "lrwxrwxrwx");
    assert_eq!(named(&rows, "/")[0]["meta"], "128", "the superblock's root inode");
    for gone in ["/etc/cron.d/gone", "/etc/systemd/system/gone.service", "/home/bob/.ssh/authorized_keys2"] {
        assert!(named(&rows, gone).is_empty(), "{gone} is not in the live tree");
    }
    // A freed inode keeps its creation time and the time of its deletion.
    let freed: Vec<_> = rows.iter().filter(|r| r["deleted"] == "unallocated").collect();
    assert!(!freed.is_empty());
    assert!(freed.iter().all(|r| r["file_name"].starts_with("/[UNKNOWN]/inode_")));
    assert!(freed.iter().any(|r| r["type"].contains('b')));
}

#[test]
fn xfs_in_lvm_is_read_through_the_logical_volume() {
    let rows = run("mbr_lvm_xfs", "lvm", &[]);
    assert!(rows.iter().all(|r| r["source"] == "xfs" && r["volume"] == "p1:vg_xfs/root"));
    assert!(rows.iter().all(|r| r["evidence"] == "mbr_lvm_xfs.img:p1:vg_xfs/root"));
    assert!(!named(&rows, "/etc/cron.d/lab").is_empty());
    assert!(!named(&rows, "/home/bob/.ssh/authorized_keys").is_empty());
    let freed: BTreeSet<&str> = rows.iter().filter(|r| r["deleted"] == "unallocated").map(|r| r["meta"].as_str()).collect();
    assert_eq!(freed.len(), 4, "{freed:?}");
    // The removal changed /etc/cron.d at the instant the freed inodes last changed.
    let cron_d_m: BTreeSet<&str> = named(&rows, "/etc/cron.d").iter().filter(|r| r["type"].starts_with('m')).map(|r| r["time_created"].as_str()).collect();
    let freed_c: BTreeSet<&str> = rows.iter().filter(|r| r["deleted"] == "unallocated" && r["type"].contains('c')).map(|r| r["time_created"].as_str()).collect();
    assert!(cron_d_m.intersection(&freed_c).next().is_some(), "{cron_d_m:?} {freed_c:?}");
}

#[test]
fn ext4_in_lvm_with_its_journal() {
    let rows = run("mbr_lvm_ext4", "ext4", &[]);
    assert!(rows.iter().all(|r| r["source"] == "ext4" && r["volume"] == "p1:vg_lab/root"));
    let deleted: BTreeSet<&str> = rows.iter().filter(|r| !r["deleted"].is_empty()).map(|r| r["meta"].as_str()).collect();
    assert!(deleted.len() >= 3, "{deleted:?}");
    // With --carve the journal, read through the logical volume, names the three removed files.
    let rows = run("mbr_lvm_ext4", "ext4carve", &["--carve"]);
    for gone in ["/etc/cron.d/gone", "/etc/systemd/system/gone.service", "/home/bob/.ssh/authorized_keys2"] {
        assert!(rows.iter().any(|r| r["file_name"].starts_with(gone)), "{gone}");
    }
}
