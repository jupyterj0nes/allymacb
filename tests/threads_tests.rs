//! The number of threads never shows in the output: every fixture, alone,
//! together, in a directory, carved and hunted, gives byte for byte the same
//! CSV, stderr and exit code on 1, 2, 3 and 8 threads.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::*;

/// The fixtures of `tests/data`, decompressed, and two small `$MFT`s, in a
/// directory of their own.
fn corpus(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("allymacb_threads_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["ext4_journal", "gpt_xfs", "mbr_lvm_xfs", "mbr_lvm_ext4"] {
        let gz = File::open(format!("{}/tests/data/{name}.img.gz", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let mut raw = Vec::new();
        flate2::read::GzDecoder::new(gz).read_to_end(&mut raw).unwrap();
        std::fs::write(dir.join(format!("{name}.img")), raw).unwrap();
    }
    for (host, content) in [("hostA", "first"), ("hostB", "second")] {
        std::fs::create_dir_all(dir.join(host)).unwrap();
        let mut m = record(0, 1, &[si(FT), fname(5, "$MFT", 1024, FT), data("", b"x")]);
        for i in 1..5 {
            m.extend(record(i, 1, &[si(FT), fname(5, &format!("$Sys{}", i), 0, FT)]));
        }
        m.extend(record(5, 3, &[si(FT), fname(5, ".", 0, FT)]));
        m.extend(record(6, 1, &[si(FT + 10_000_000), fname(5, "same.txt", 0, FT), data("", content.as_bytes())]));
        m.extend(record(7, 0, &[si(FT), fname(5, "gone.txt", 0, FT), data("", content.as_bytes())]));
        std::fs::write(dir.join(host).join("$MFT"), m).unwrap();
    }
    // Archives: one holding a `$MFT` (streamed), one with plain files (extracted
    // to a temporary folder, whose name is printed).
    let tgz = |name: &str, members: &[(&str, Vec<u8>)]| {
        let f = File::create(dir.join(name)).unwrap();
        let mut t = tar::Builder::new(flate2::write::GzEncoder::new(f, flate2::Compression::fast()));
        for (path, data) in members {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(1_700_000_000);
            h.set_cksum();
            t.append_data(&mut h, path, &data[..]).unwrap();
        }
        t.into_inner().unwrap().finish().unwrap();
    };
    tgz("kape.tar.gz", &[("C/$MFT", std::fs::read(dir.join("hostA").join("$MFT")).unwrap())]);
    tgz("loose.tar.gz", &[("etc/hosts", b"127.0.0.1 localhost\n".to_vec()), ("home/bob/notes.txt", b"x".to_vec())]);
    dir
}

/// The run's workspace is named after its process id (`allymacb_<pid>_0`):
/// the one part of a temporary path two runs cannot share.
fn without_pid(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(i) = rest.find("allymacb_") {
        out.push_str(&rest[..i + 9]);
        rest = &rest[i + 9..];
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits > 0 && rest[digits..].starts_with('_') {
            out.push_str("PID");
            rest = &rest[digits..];
        }
    }
    out.push_str(rest);
    out
}

/// Exit code, stdout and stderr, the elapsed time and thread count left out.
fn run(args: &[&std::ffi::OsStr], threads: usize) -> (Option<i32>, Vec<u8>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).args(args).arg("--threads").arg(threads.to_string()).output().unwrap();
    let err: String = String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| !l.contains("Elapsed time") && !l.trim_start().starts_with("Threads "))
        .map(|l| format!("{}\n", without_pid(l)))
        .collect();
    (out.status.code(), out.stdout, err)
}

fn same_on_every_thread_count(args: Vec<std::ffi::OsString>) {
    let args: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
    let one = run(&args, 1);
    assert!(one.1.len() > 200, "the run produced a timeline: {}", one.2);
    for threads in [2, 3, 8] {
        let other = run(&args, threads);
        assert_eq!(other.0, one.0, "exit code with {threads} threads");
        assert!(other.1 == one.1, "CSV with {threads} threads differs from 1 thread ({args:?})");
        assert_eq!(other.2, one.2, "stderr with {threads} threads");
    }
}

fn os(p: &Path) -> std::ffi::OsString {
    p.as_os_str().to_owned()
}

#[test]
fn every_fixture_on_its_own() {
    let dir = corpus("alone");
    for name in ["ext4_journal", "gpt_xfs", "mbr_lvm_xfs", "mbr_lvm_ext4"] {
        same_on_every_thread_count(vec!["-f".into(), os(&dir.join(format!("{name}.img"))), "--carve".into()]);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn all_fixtures_given_together_and_hunted() {
    let dir = corpus("together");
    let mut args: Vec<std::ffi::OsString> = vec!["-f".into()];
    for name in ["mbr_lvm_ext4", "gpt_xfs", "ext4_journal", "mbr_lvm_xfs"] {
        args.push(os(&dir.join(format!("{name}.img"))));
    }
    args.push(os(&dir.join("hostA").join("$MFT")));
    args.push(os(&dir.join("missing.img")));
    args.push(os(&dir.join("hostB").join("$MFT")));
    args.push(os(&dir.join("loose.tar.gz")));
    args.push(os(&dir.join("kape.tar.gz")));
    args.push(os(&dir.join("loose.tar.gz")));
    args.extend(["--carve".into(), "--investigation-from".into(), "2020-01-01".into(), "-n".into()]);
    same_on_every_thread_count(args);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_directory_of_evidence_with_messages() {
    let dir = corpus("dir");
    // Without -q: every informational line, in order.
    same_on_every_thread_count(vec!["-d".into(), os(&dir), "--carve".into()]);
    same_on_every_thread_count(vec!["-q".into(), "-d".into(), os(&dir), os(&dir.join("hostA")), "--investigation-from".into(), "2020-01-01".into()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_resident_dump_of_several_sources_is_the_same_too() {
    let dir = corpus("resident");
    let listing = |root: &Path| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = walkdir::WalkDir::new(root)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .map(|e| (e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read(e.path()).unwrap()))
            .collect();
        v.sort();
        v
    };
    let mut first = None;
    for threads in [1, 2, 8] {
        let out = dir.join(format!("res{threads}"));
        let args: Vec<std::ffi::OsString> =
            vec!["-q".into(), "-f".into(), os(&dir.join("hostA").join("$MFT")), os(&dir.join("hostB").join("$MFT")), os(&dir.join("hostA").join("$MFT")), "-r".into(), os(&out)];
        let args: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
        let (code, _, err) = run(&args, threads);
        assert_eq!(code, Some(0), "{err}");
        let l = listing(&out);
        assert_eq!(l.len(), 9, "three sources, three streams each, none lost");
        // The plain name goes to the first source given, `.rec<N>` to the next ones, in order.
        let get = |p: &str| l.iter().find(|(n, _)| n == p).map(|(_, c)| c.clone());
        assert_eq!(get("same.txt").as_deref(), Some(&b"first"[..]));
        assert_eq!(get("same.txt.rec6").as_deref(), Some(&b"second"[..]));
        assert_eq!(get("same.txt.rec6_2").as_deref(), Some(&b"first"[..]));
        match &first {
            None => first = Some(l),
            Some(f) => assert_eq!(&l, f, "the dump with {threads} threads"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
