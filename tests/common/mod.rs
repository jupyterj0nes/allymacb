//! Synthetic NTFS structures shared by the integration tests: 1 KiB `FILE`
//! records with fixups applied, and the attribute builders that go in them.
#![allow(dead_code)]

pub struct Attr {
    pub ty: u32,
    pub name: &'static str,
    pub body: Vec<u8>,
    pub non_resident: Option<u64>,
}

pub fn le16(v: u16) -> [u8; 2] { v.to_le_bytes() }
pub fn le32(v: u32) -> [u8; 4] { v.to_le_bytes() }
pub fn le64(v: u64) -> [u8; 8] { v.to_le_bytes() }

/// FILETIME for 2024-02-04T12:35:00Z
pub const FT: u64 = (1707050100u64 + 11_644_473_600) * 10_000_000;

pub fn si(ts: u64) -> Attr {
    let mut b = Vec::new();
    for _ in 0..4 { b.extend_from_slice(&le64(ts)); }
    b.extend_from_slice(&le32(0x20));
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&[0u8; 24]);
    Attr { ty: 0x10, name: "", body: b, non_resident: None }
}

pub fn fname_seq(parent: u64, parent_seq: u16, name: &str, logical: u64, ts: u64) -> Attr {
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

pub fn fname(parent: u64, name: &str, logical: u64, ts: u64) -> Attr {
    fname_seq(parent, 1, name, logical, ts)
}

pub fn data(name: &'static str, content: &[u8]) -> Attr {
    Attr { ty: 0x80, name, body: content.to_vec(), non_resident: None }
}

pub fn data_nonres(name: &'static str, file_size: u64) -> Attr {
    Attr { ty: 0x80, name, body: vec![0x11, 0x01, 0x20, 0x00, 0, 0, 0, 0], non_resident: Some(file_size) }
}

/// flags: 1 = in use, 2 = directory
pub fn record(rec_no: u64, flags: u16, attrs: &[Attr]) -> Vec<u8> {
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
