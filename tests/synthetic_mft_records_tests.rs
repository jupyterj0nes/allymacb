//! Synthetic $MFT records (1024-byte, fixups applied) exercising the parser
//! fixes from the full code review: parent cycles, non-resident $DATA sizes,
//! ADS MACB flags, resident-extraction path traversal and deleted/live
//! collisions, and damaged first records.

use std::io::Cursor;
use std::path::PathBuf;

use allymacb::parsers::mft::{parse_mft_reader, MftParseOptions};

pub struct Attr {
    pub ty: u32,
    pub name: &'static str,
    pub body: Vec<u8>,
    pub non_resident: Option<u64>,
}

fn le16(v: u16) -> [u8; 2] { v.to_le_bytes() }
fn le32(v: u32) -> [u8; 4] { v.to_le_bytes() }
fn le64(v: u64) -> [u8; 8] { v.to_le_bytes() }

/// FILETIME for 2024-02-04T12:35:00Z
const FT: u64 = (1707050100u64 + 11_644_473_600) * 10_000_000;

fn si(ts: u64) -> Attr {
    let mut b = Vec::new();
    for _ in 0..4 { b.extend_from_slice(&le64(ts)); }
    b.extend_from_slice(&le32(0x20));
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&[0u8; 24]);
    Attr { ty: 0x10, name: "", body: b, non_resident: None }
}

fn fname_seq(parent: u64, parent_seq: u16, name: &str, logical: u64, ts: u64) -> Attr {
    let mut b = Vec::new();
    b.extend_from_slice(&le64(parent | ((parent_seq as u64) << 48)));
    for _ in 0..4 { b.extend_from_slice(&le64(ts)); }
    b.extend_from_slice(&le64(logical));
    b.extend_from_slice(&le64(logical));
    b.extend_from_slice(&le32(0x20));
    b.extend_from_slice(&le32(0));
    let u: Vec<u16> = name.encode_utf16().collect();
    b.push(u.len() as u8);
    b.push(0); // POSIX namespace: any character allowed
    for c in u { b.extend_from_slice(&le16(c)); }
    Attr { ty: 0x30, name: "", body: b, non_resident: None }
}

fn fname(parent: u64, name: &str, logical: u64, ts: u64) -> Attr {
    fname_seq(parent, 1, name, logical, ts)
}

fn data(name: &'static str, content: &[u8]) -> Attr {
    Attr { ty: 0x80, name, body: content.to_vec(), non_resident: None }
}

fn data_nonres(name: &'static str, file_size: u64) -> Attr {
    Attr { ty: 0x80, name, body: vec![0x11, 0x01, 0x20, 0x00, 0, 0, 0, 0], non_resident: Some(file_size) }
}

/// flags: 1 = in use, 2 = directory
fn record(rec_no: u64, flags: u16, attrs: &[Attr]) -> Vec<u8> {
    let mut r = vec![0u8; 1024];
    r[0..4].copy_from_slice(b"FILE");
    r[4..6].copy_from_slice(&le16(48));
    r[6..8].copy_from_slice(&le16(3));
    r[16..18].copy_from_slice(&le16(1)); // sequence
    r[18..20].copy_from_slice(&le16(1));
    r[20..22].copy_from_slice(&le16(56));
    r[22..24].copy_from_slice(&le16(flags));
    r[28..32].copy_from_slice(&le32(1024));
    r[40..42].copy_from_slice(&le16(10));
    r[44..48].copy_from_slice(&le32(rec_no as u32));
    r[48..50].copy_from_slice(&le16(1));
    let mut off = 56usize;
    for (i, a) in attrs.iter().enumerate() {
        let name_u: Vec<u16> = a.name.encode_utf16().collect();
        let name_len = name_u.len();
        let mut buf = Vec::new();
        match a.non_resident {
            None => {
                let name_off = 24u16;
                let data_off = ((24 + name_len * 2 + 7) / 8 * 8) as u16;
                let total = ((data_off as usize + a.body.len() + 7) / 8 * 8) as u32;
                buf.extend_from_slice(&le32(a.ty));
                buf.extend_from_slice(&le32(total));
                buf.push(0);
                buf.push(name_len as u8);
                buf.extend_from_slice(&le16(name_off));
                buf.extend_from_slice(&le16(0));
                buf.extend_from_slice(&le16(i as u16));
                buf.extend_from_slice(&le32(a.body.len() as u32));
                buf.extend_from_slice(&le16(data_off));
                buf.push(0);
                buf.push(0);
                for c in &name_u { buf.extend_from_slice(&le16(*c)); }
                while buf.len() < data_off as usize { buf.push(0); }
                buf.extend_from_slice(&a.body);
                while buf.len() < total as usize { buf.push(0); }
            }
            Some(fsz) => {
                let name_off = 64u16;
                let run_off = ((64 + name_len * 2 + 7) / 8 * 8) as u16;
                let total = ((run_off as usize + a.body.len() + 7) / 8 * 8) as u32;
                buf.extend_from_slice(&le32(a.ty));
                buf.extend_from_slice(&le32(total));
                buf.push(1);
                buf.push(name_len as u8);
                buf.extend_from_slice(&le16(name_off));
                buf.extend_from_slice(&le16(0));
                buf.extend_from_slice(&le16(i as u16));
                buf.extend_from_slice(&le64(0));
                buf.extend_from_slice(&le64(0));
                buf.extend_from_slice(&le16(run_off));
                buf.extend_from_slice(&le16(0));
                buf.extend_from_slice(&le32(0));
                buf.extend_from_slice(&le64(4096));
                buf.extend_from_slice(&le64(fsz));
                buf.extend_from_slice(&le64(fsz));
                for c in &name_u { buf.extend_from_slice(&le16(*c)); }
                while buf.len() < run_off as usize { buf.push(0); }
                buf.extend_from_slice(&a.body);
                while buf.len() < total as usize { buf.push(0); }
            }
        }
        r[off..off + buf.len()].copy_from_slice(&buf);
        off += buf.len();
    }
    r[off..off + 4].copy_from_slice(&[0xFF; 4]);
    off += 8;
    r[24..28].copy_from_slice(&le32(off as u32));
    r[510..512].copy_from_slice(&le16(1));
    r[1022..1024].copy_from_slice(&le16(1));
    r
}

fn opts(res: Option<PathBuf>) -> MftParseOptions {
    MftParseOptions {
        include_file_name_timestamps: false,
        resident_dir: res,
        resident_report: None,
        drive_letter: Some('C'),
        quiet: true,
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
