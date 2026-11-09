//! Forensically strict: nothing the run does shows in the timeline, and the
//! run leaves no trace on the evidence.
//!
//! * An extracted archive is timelined from the times the archive gives,
//!   never from the copy the extraction writes: no row for a folder the
//!   extraction made, no rule fired by the copy's own creation time.
//! * A folder of the host is timelined from the metadata it had before the
//!   run read it, and reading it writes no access time on it.

use std::fs::{self, File, FileTimes};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("allymacb_strict_{}_{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&std::ffi::OsStr]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).arg("-q").args(args).output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// (time, type, file_name, hunt_why) of every `fs` row.
fn fs_rows(csv: &str) -> Vec<(String, String, String, String)> {
    csv.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (f.len() >= 19 && f[4] == "fs").then(|| (f[0].to_string(), f[3].to_string(), f[12].to_string(), f[16].to_string()))
        })
        .collect()
}

const T0: u64 = 1_000_000_000; // 2001-09-09T01:46:40Z
const T1: u64 = 1_100_000_000; // 2004-11-09T11:33:20Z

fn tar_gz(path: &Path, members: &[(&str, Option<&[u8]>, u64)]) {
    let f = File::create(path).unwrap();
    let mut t = tar::Builder::new(flate2::write::GzEncoder::new(f, flate2::Compression::fast()));
    for (name, data, mtime) in members {
        let mut h = tar::Header::new_gnu();
        h.set_mtime(*mtime);
        match data {
            Some(d) => {
                h.set_size(d.len() as u64);
                h.set_mode(0o644);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_cksum();
                t.append_data(&mut h, name, &d[..]).unwrap();
            }
            None => {
                h.set_size(0);
                h.set_mode(0o755);
                h.set_entry_type(tar::EntryType::Directory);
                h.set_cksum();
                t.append_data(&mut h, name, &[][..]).unwrap();
            }
        }
    }
    t.into_inner().unwrap().finish().unwrap();
}

#[test]
fn an_archive_is_timelined_from_its_own_times_only() {
    let dir = scratch("archive");
    let a = dir.join("loose.tar.gz");
    // `etc/` is an entry with a time; `home/` and `home/bob/` exist only because a file is in them.
    tar_gz(&a, &[("etc/", None, T1), ("etc/hosts", Some(b"127.0.0.1 x\n"), T0), ("home/bob/notes.txt", Some(b"n"), T1)]);
    let (code, csv, err) = run(&["-f".as_ref(), a.as_os_str()]);
    assert_eq!(code, Some(0), "{err}");
    let rows = fs_rows(&csv);
    let names: Vec<&str> = rows.iter().map(|r| r.2.as_str()).collect();
    let sep = std::path::MAIN_SEPARATOR;
    assert_eq!(names.len(), 3, "{rows:?}");
    assert!(names.contains(&"etc"), "{rows:?}");
    assert!(names.contains(&format!("etc{sep}hosts").as_str()), "{rows:?}");
    assert!(names.contains(&format!("home{sep}bob{sep}notes.txt").as_str()), "{rows:?}");
    assert!(!names.iter().any(|n| *n == "home" || *n == format!("home{sep}bob")), "no row for a folder the extraction made: {rows:?}");
    for (t, macb, name, why) in &rows {
        assert_eq!(macb, "m...", "{name}: only the time the archive gives");
        assert!(t == "2001-09-09T01:46:40Z" || t == "2004-11-09T11:33:20Z", "{name}: the archive's time, got {t}");
        assert!(why.is_empty(), "{name}: no rule from the copy's own times: {why}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_gzip_member_without_a_time_has_no_row() {
    let dir = scratch("gz");
    let write = |name: &str, mtime: u32| {
        let p = dir.join(name);
        let f = File::create(&p).unwrap();
        let mut gz = flate2::GzBuilder::new().mtime(mtime).write(f, flate2::Compression::fast());
        gz.write_all(b"just some text, not evidence of any known kind\n").unwrap();
        gz.finish().unwrap();
        p
    };
    let none = write("notes.txt.gz", 0);
    let some = write("dated.txt.gz", T0 as u32);
    let (_, csv, err) = run(&["-f".as_ref(), none.as_os_str(), some.as_os_str()]);
    let rows = fs_rows(&csv);
    assert_eq!(rows.len(), 1, "{rows:?} {err}");
    assert_eq!(rows[0].0, "2001-09-09T01:46:40Z");
    assert!(rows[0].2.ends_with("dated.txt"), "{rows:?}");
    let _ = fs::remove_dir_all(&dir);
}

/// Sets access and modification time; a directory needs its own flag on Windows.
fn age(p: &Path, t: u64) {
    let mut o = fs::OpenOptions::new();
    o.write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        if p.is_dir() {
            o.custom_flags(0x0200_0000); // FILE_FLAG_BACKUP_SEMANTICS
        }
    }
    #[cfg(unix)]
    if p.is_dir() {
        // A directory cannot be opened for writing on Unix; `File::open` is enough to set times.
        let f = File::open(p).unwrap();
        f.set_times(FileTimes::new().set_accessed(UNIX_EPOCH + Duration::from_secs(t)).set_modified(UNIX_EPOCH + Duration::from_secs(t))).unwrap();
        return;
    }
    let f = o.open(p).unwrap();
    let when = UNIX_EPOCH + Duration::from_secs(t);
    f.set_times(FileTimes::new().set_accessed(when).set_modified(when)).unwrap();
}

/// Access and modification time of every path, read without listing anything.
fn times(paths: &[PathBuf]) -> Vec<(SystemTime, SystemTime)> {
    paths.iter().map(|p| {
        let m = fs::symlink_metadata(p).unwrap();
        (m.accessed().unwrap(), m.modified().unwrap())
    }).collect()
}

#[test]
fn a_host_folder_is_read_without_a_trace_and_timelined_as_found() {
    let dir = scratch("host");
    let root = dir.join("case");
    fs::create_dir_all(root.join("docs").join("old")).unwrap();
    let files = [root.join("readme.txt"), root.join("docs").join("plan.txt"), root.join("docs").join("old").join("notes.txt"), root.join("blob.bin")];
    for f in &files {
        fs::write(f, vec![b'x'; 70_000]).unwrap();
    }
    fs::write(&files[3], (0..70_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect::<Vec<u8>>()).unwrap();
    let mut paths: Vec<PathBuf> = files.to_vec();
    paths.extend([root.join("docs").join("old"), root.join("docs"), root.clone()]);
    for p in &paths {
        age(p, T0);
    }
    let before = times(&paths);
    let started = chrono::Utc::now();

    // The folder walked, twice, and an unrecognised file given on its own (it is read to be recognised).
    let (c1, csv1, e1) = run(&["-d".as_ref(), root.as_os_str()]);
    let (c2, csv2, _) = run(&["-d".as_ref(), root.as_os_str()]);
    let (c3, csv3, e3) = run(&["-f".as_ref(), files[3].as_os_str()]);
    assert_eq!((c1, c2, c3), (Some(0), Some(0), Some(0)), "{e1} {e3}");
    assert!(!e1.contains("without their access time frozen"), "{e1}");

    assert_eq!(times(&paths), before, "the runs wrote no time on the evidence");
    assert_eq!(csv1, csv2, "a second run sees what the first saw");
    for csv in [&csv1, &csv3] {
        let rows = fs_rows(csv);
        assert!(!rows.is_empty());
        for (t, macb, name, _) in &rows {
            let when = chrono::DateTime::parse_from_rfc3339(t).unwrap();
            assert!(when < started, "{name} {macb}: a time of the run itself: {t}");
        }
        // The access time as found, before any reading.
        assert!(rows.iter().any(|(t, macb, _, _)| macb.contains('a') && t == "2001-09-09T01:46:40Z"), "{rows:?}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn evidence_read_through_every_parser_keeps_its_times() {
    // A `$MFT`, an archive, a bodyfile and a disk image in one folder, each read by its parser.
    let dir = scratch("parsers");
    let root = dir.join("triage");
    fs::create_dir_all(root.join("C")).unwrap();
    let img = root.join("disk.img");
    let gz = File::open(format!("{}/tests/data/gpt_xfs.img.gz", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut raw).unwrap();
    fs::write(&img, raw).unwrap();
    fs::write(root.join("bodyfile.txt"), "0|/etc/passwd|2|-rw-r--r--|0|0|10|1000000000|1000000000|1000000000|0\n").unwrap();
    tar_gz(&root.join("kape.tar.gz"), &[("etc/hosts", Some(b"h"), T0)]);
    let paths = vec![img.clone(), root.join("bodyfile.txt"), root.join("kape.tar.gz"), root.join("C"), root.clone()];
    for p in &paths {
        age(p, T0);
    }
    let before = times(&paths);
    let (code, _, err) = run(&["-d".as_ref(), root.as_os_str(), "--carve".as_ref()]);
    assert_eq!(code, Some(0), "{err}");
    let (code, _, err) = run(&["-f".as_ref(), img.as_os_str(), root.join("kape.tar.gz").as_os_str(), root.join("bodyfile.txt").as_os_str(), "--carve".as_ref()]);
    assert_eq!(code, Some(0), "{err}");
    assert!(!err.contains("without their access time frozen"), "{err}");
    assert_eq!(times(&paths), before, "image, archive, bodyfile and folders keep every time");
    let _ = fs::remove_dir_all(&dir);
}
