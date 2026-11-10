//! Virtual disks: the repository's raw fixtures (`gpt_xfs.img`, `mbr_lvm_ext4.img`) wrapped
//! in every container allymacb decodes (VMDK monolithic sparse, VMDK streamOptimized, VMDK
//! descriptor with a flat extent, dynamic VHD, VHDX) must give exactly the rows of the raw
//! image, the evidence name aside. Then the refusals (differencing disks, missing extents,
//! QCOW) with their exit code and error code, and two lab images (skipped where absent).

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::write::ZlibEncoder;
use flate2::Compression;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("allymacb_vdisk_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn raw_fixture(name: &str) -> Vec<u8> {
    let gz = File::open(format!("{}/tests/data/{name}.img.gz", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut raw).unwrap();
    raw
}

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

/// Runs allymacb on `img` and returns (exit code, rows with the evidence's file name cut
/// off, stderr).
fn run(img: &Path) -> (i32, Vec<Vec<String>>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).arg("-q").arg("-f").arg(img).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut lines = text.lines();
    let mut rows = Vec::new();
    if let Some(h) = lines.next() {
        let header = fields(h);
        let ev = header.iter().position(|c| c == "evidence");
        for l in lines {
            let mut f = fields(l);
            if let Some(i) = ev {
                // "<file>:p1" -> ":p1": the container's name differs, the volume does not.
                f[i] = f[i].split_once(':').map(|(_, v)| format!(":{v}")).unwrap_or_default();
            }
            rows.push(f);
        }
    }
    (out.status.code().unwrap_or(-1), rows, stderr)
}

// ── builders ────────────────────────────────────────────────────────────────

const KDMV: u32 = 0x564D_444B;

fn pad(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(512) {
        v.push(0);
    }
}

fn vmdk_header(capacity: u64, grain: u64, gtes: u32, gd_offset: u64, compressed: bool) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[0..4].copy_from_slice(&KDMV.to_le_bytes());
    h[4..8].copy_from_slice(&(if compressed { 3u32 } else { 1 }).to_le_bytes());
    h[8..12].copy_from_slice(&(if compressed { 0x3_0000u32 } else { 0 }).to_le_bytes());
    h[12..20].copy_from_slice(&capacity.to_le_bytes());
    h[20..28].copy_from_slice(&grain.to_le_bytes());
    h[44..48].copy_from_slice(&gtes.to_le_bytes());
    h[56..64].copy_from_slice(&gd_offset.to_le_bytes());
    h
}

/// A VMDK sparse extent (uncompressed) or streamOptimized (compressed) holding `raw`; grains
/// of 64 KB that are all zeros are left unallocated.
fn vmdk(raw: &[u8], compressed: bool) -> Vec<u8> {
    let grain = 128u64;
    let gtes = 512u32;
    let gb = (grain * 512) as usize;
    let capacity = (raw.len() as u64).div_ceil(512);
    let n_grains = (raw.len()).div_ceil(gb);
    let n_gd = capacity.div_ceil(u64::from(gtes) * grain) as usize;
    let mut gts = vec![vec![0u32; gtes as usize]; n_gd];
    let grain_of = |i: usize| {
        let mut g = raw[i * gb..((i + 1) * gb).min(raw.len())].to_vec();
        g.resize(gb, 0);
        g
    };
    if !compressed {
        let gd_sectors = ((n_gd * 4) as u64).div_ceil(512);
        let gt_sectors = (u64::from(gtes) * 4).div_ceil(512);
        let first_gt = 1 + gd_sectors;
        let mut next = first_gt + gt_sectors * n_gd as u64;
        let mut data = Vec::new();
        for i in 0..n_grains {
            let g = grain_of(i);
            if g.iter().all(|b| *b == 0) {
                continue;
            }
            gts[i / gtes as usize][i % gtes as usize] = next as u32;
            data.extend_from_slice(&g);
            next += grain;
        }
        let mut img = vmdk_header(capacity, grain, gtes, 1, false);
        for i in 0..n_gd {
            img.extend_from_slice(&((first_gt + gt_sectors * i as u64) as u32).to_le_bytes());
        }
        pad(&mut img);
        for gt in &gts {
            for e in gt {
                img.extend_from_slice(&e.to_le_bytes());
            }
            pad(&mut img);
        }
        img.extend_from_slice(&data);
        img
    } else {
        let mut img = vmdk_header(capacity, grain, gtes, u64::MAX, true);
        img.resize(64 * 1024, 0); // header area: a grain table entry of 1 means a zeroed grain
        for i in 0..n_grains {
            let g = grain_of(i);
            if g.iter().all(|b| *b == 0) {
                continue;
            }
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(&g).unwrap();
            let packed = enc.finish().unwrap();
            gts[i / gtes as usize][i % gtes as usize] = (img.len() / 512) as u32;
            img.extend_from_slice(&((i as u64) * grain).to_le_bytes());
            img.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            img.extend_from_slice(&packed);
            pad(&mut img);
        }
        let mut gt_at = Vec::new();
        for gt in &gts {
            gt_at.push((img.len() / 512) as u32);
            for e in gt {
                img.extend_from_slice(&e.to_le_bytes());
            }
            pad(&mut img);
        }
        let gd_sector = (img.len() / 512) as u64;
        for s in &gt_at {
            img.extend_from_slice(&s.to_le_bytes());
        }
        pad(&mut img);
        img.extend_from_slice(&vmdk_header(capacity, grain, gtes, gd_sector, true));
        img.extend_from_slice(&[0u8; 512]);
        img
    }
}

fn vhd_footer(size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[..8].copy_from_slice(b"conectix");
    f[16..24].copy_from_slice(&data_offset.to_be_bytes());
    f[40..48].copy_from_slice(&size.to_be_bytes());
    f[48..56].copy_from_slice(&size.to_be_bytes());
    f[60..64].copy_from_slice(&disk_type.to_be_bytes());
    f
}

/// A dynamic VHD holding `raw`, 2 MB blocks, all-zero blocks unallocated.
fn dynamic_vhd(raw: &[u8]) -> Vec<u8> {
    let block = 2u64 << 20;
    let n = (raw.len() as u64).div_ceil(block) as usize;
    let size = raw.len() as u64;
    let mut img = vhd_footer(size, 3, 512).to_vec();
    let bat_at = 1536u64;
    let mut hdr = vec![0u8; 1024];
    hdr[..8].copy_from_slice(b"cxsparse");
    hdr[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    hdr[16..24].copy_from_slice(&bat_at.to_be_bytes());
    hdr[28..32].copy_from_slice(&(n as u32).to_be_bytes());
    hdr[32..36].copy_from_slice(&(block as u32).to_be_bytes());
    img.extend_from_slice(&hdr);
    let bat_bytes = ((n * 4) as u64).div_ceil(512) * 512;
    let bitmap = 512u64;
    let mut bat = vec![0u8; bat_bytes as usize];
    let mut next = bat_at + bat_bytes;
    let mut blocks = Vec::new();
    for i in 0..n {
        let mut b = raw[(i as u64 * block) as usize..(((i + 1) as u64 * block) as usize).min(raw.len())].to_vec();
        b.resize(block as usize, 0);
        if b.iter().all(|x| *x == 0) {
            bat[i * 4..i * 4 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            continue;
        }
        bat[i * 4..i * 4 + 4].copy_from_slice(&((next / 512) as u32).to_be_bytes());
        blocks.extend(std::iter::repeat_n(0xFFu8, bitmap as usize));
        blocks.extend_from_slice(&b);
        next += bitmap + block;
    }
    img.extend_from_slice(&bat);
    img.extend_from_slice(&blocks);
    img.extend_from_slice(&vhd_footer(size, 3, 512));
    img
}

const GUID_BAT: [u8; 16] = [0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08];
const GUID_METADATA: [u8; 16] = [0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E];
const GUID_FILE_PARAMETERS: [u8; 16] = [0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B];
const GUID_VIRTUAL_DISK_SIZE: [u8; 16] = [0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8];
const GUID_LOGICAL_SECTOR_SIZE: [u8; 16] = [0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F];

/// A VHDX holding `raw`, 1 MB blocks, all-zero blocks absent; `with_parent` marks it a
/// differencing disk.
fn vhdx(raw: &[u8], with_parent: bool) -> Vec<u8> {
    let block = 1u64 << 20;
    let n = (raw.len() as u64).div_ceil(block) as usize;
    let bat_off = 1u64 << 20;
    let meta_off = 2u64 << 20;
    let mut data_off = 3u64 << 20;
    let mut img = vec![0u8; data_off as usize];
    img[..8].copy_from_slice(b"vhdxfile");
    img[64 * 1024..64 * 1024 + 4].copy_from_slice(b"head");
    let rt = 192 * 1024;
    img[rt..rt + 4].copy_from_slice(b"regi");
    img[rt + 8..rt + 12].copy_from_slice(&2u32.to_le_bytes());
    let e0 = rt + 16;
    img[e0..e0 + 16].copy_from_slice(&GUID_BAT);
    img[e0 + 16..e0 + 24].copy_from_slice(&bat_off.to_le_bytes());
    img[e0 + 24..e0 + 28].copy_from_slice(&(1u32 << 20).to_le_bytes());
    let e1 = e0 + 32;
    img[e1..e1 + 16].copy_from_slice(&GUID_METADATA);
    img[e1 + 16..e1 + 24].copy_from_slice(&meta_off.to_le_bytes());
    img[e1 + 24..e1 + 28].copy_from_slice(&(64u32 * 1024).to_le_bytes());
    let m = meta_off as usize;
    img[m..m + 8].copy_from_slice(b"metadata");
    img[m + 10..m + 12].copy_from_slice(&3u16.to_le_bytes());
    let items: [([u8; 16], Vec<u8>); 3] = [
        (GUID_FILE_PARAMETERS, [(block as u32).to_le_bytes(), (if with_parent { 2u32 } else { 0 }).to_le_bytes()].concat()),
        (GUID_VIRTUAL_DISK_SIZE, (raw.len() as u64).to_le_bytes().to_vec()),
        (GUID_LOGICAL_SECTOR_SIZE, 512u32.to_le_bytes().to_vec()),
    ];
    let mut item_off = 4096u32;
    for (i, (g, bytes)) in items.iter().enumerate() {
        let e = m + 32 + i * 32;
        img[e..e + 16].copy_from_slice(g);
        img[e + 16..e + 20].copy_from_slice(&item_off.to_le_bytes());
        img[e + 20..e + 24].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        let at = m + item_off as usize;
        img[at..at + bytes.len()].copy_from_slice(bytes);
        item_off += 64;
    }
    // Chunk ratio for 1 MB blocks and 512-byte sectors is 4096: no bitmap entry for < 4096 blocks.
    for i in 0..n {
        let mut b = raw[(i as u64 * block) as usize..(((i + 1) as u64 * block) as usize).min(raw.len())].to_vec();
        b.resize(block as usize, 0);
        if b.iter().all(|x| *x == 0) {
            continue;
        }
        let e = bat_off as usize + i * 8;
        img[e..e + 8].copy_from_slice(&(data_off | 6).to_le_bytes());
        img.extend_from_slice(&b);
        data_off += block;
    }
    img
}

// ── tests ───────────────────────────────────────────────────────────────────

fn same_rows_in_every_container(name: &str, tag: &str) {
    let raw = raw_fixture(name);
    let d = tmpdir(tag);
    let raw_path = d.join(format!("{name}.img"));
    std::fs::write(&raw_path, &raw).unwrap();
    let (code, want, err) = run(&raw_path);
    assert_eq!(code, 0, "{err}");
    assert!(want.len() > 20, "{} rows from the raw image", want.len());

    // Every container in its own folder under the raw image's own name: same host, same volume.
    let sub = |k: &str| {
        let s = d.join(k);
        std::fs::create_dir_all(&s).unwrap();
        s
    };
    let sparse = sub("sparse").join(format!("{name}.vmdk"));
    std::fs::write(&sparse, vmdk(&raw, false)).unwrap();
    let stream = sub("stream").join(format!("{name}.vmdk"));
    std::fs::write(&stream, vmdk(&raw, true)).unwrap();
    let desc_dir = sub("desc");
    std::fs::write(desc_dir.join(format!("{name}-flat.vmdk")), &raw).unwrap();
    let desc = desc_dir.join(format!("{name}.vmdk"));
    std::fs::write(&desc, format!("# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType=\"monolithicFlat\"

# Extent description
RW {} FLAT \"{name}-flat.vmdk\" 0
", raw.len() / 512)).unwrap();
    let dyn_vhd = sub("dyn").join(format!("{name}.vhd"));
    std::fs::write(&dyn_vhd, dynamic_vhd(&raw)).unwrap();
    let vx = sub("vhdx").join(format!("{name}.vhdx"));
    std::fs::write(&vx, vhdx(&raw, false)).unwrap();
    for p in [&sparse, &stream, &desc, &dyn_vhd, &vx] {
        let (code, rows, err) = run(p);
        assert_eq!(code, 0, "{}: {err}", p.display());
        assert_eq!(rows.len(), want.len(), "{}: row count", p.display());
        assert_eq!(rows, want, "{}: the same rows as the raw image", p.display());
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn gpt_xfs_in_every_container_gives_the_raw_rows() {
    same_rows_in_every_container("gpt_xfs", "xfs");
}

#[test]
fn lvm_ext4_in_every_container_gives_the_raw_rows() {
    same_rows_in_every_container("mbr_lvm_ext4", "lvm");
}

#[test]
fn refusals_exit_2_with_their_codes() {
    let raw = raw_fixture("gpt_xfs");
    let d = tmpdir("refuse");
    let cases: Vec<(PathBuf, Vec<u8>, &str)> = vec![
        (d.join("diff.vhdx"), vhdx(&raw[..4 << 20], true), "ERR_IMAGE_HAS_PARENT_6005"),
        (d.join("diff.vhd"), vhd_footer(4096, 4, 512).to_vec(), "ERR_IMAGE_HAS_PARENT_6005"),
        (d.join("cut.vmdk"), {
            let v = vmdk(&raw, true);
            v[..v.len() - 4096].to_vec()
        }, "ERR_IMAGE_CONTAINER_DAMAGED_6004"),
        (d.join("lost.vmdk"), b"# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\nRW 8 FLAT \"lost-flat.vmdk\" 0\n".to_vec(), "ERR_IMAGE_EXTENT_MISSING_6006"),
        (d.join("delta.vmdk"), b"# Disk DescriptorFile\nparentCID=1234abcd\nparentFileNameHint=\"base.vmdk\"\ncreateType=\"monolithicSparse\"\nRW 8 SPARSE \"x.vmdk\"\n".to_vec(), "ERR_IMAGE_HAS_PARENT_6005"),
        (d.join("disk.img"), { let mut q = b"QFI\xfb".to_vec(); q.resize(4096, 0); q }, "ERR_IMAGE_UNSUPPORTED_6003"),
    ];
    for (p, bytes, code) in cases {
        std::fs::write(&p, bytes).unwrap();
        let (exit, rows, err) = run(&p);
        assert_eq!(exit, 2, "{}: {err}", p.display());
        assert!(rows.is_empty(), "{}", p.display());
        assert!(err.contains(code), "{}: {code} not in {err}", p.display());
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The fixed VHD of the lab (raw disk plus footer) still reads as before.
#[test]
fn lab_fixed_vhd_still_reads() {
    let p = Path::new(r"D:\evidence\mixed-intake\carvelab.vhd");
    if !p.is_file() {
        return;
    }
    let (code, rows, err) = run(p);
    assert_eq!(code, 0, "{err}");
    assert!(rows.len() > 50, "{}", rows.len());
}

/// The 50 GB sparse VMDK exported from GCP of the 2026-11-10 RangeForge lab's
/// DEV-SRV01: the NTFS volume is found and the planted files are there with their times.
/// About ten minutes and a few GB of memory: run with `--ignored`.
#[test]
#[ignore]
fn lab_gcp_exported_vmdk_has_the_planted_files() {
    let p = Path::new(r"D:\evidence\rangeforge-20261110\DEV-SRV01-disk\rf-1a1a0fd2c8e-dev-srv01-snap-1794300692-img-1794311754.vmdk");
    if !p.is_file() {
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_allymacb")).arg("-q").arg("-f").arg(p).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let header = fields(lines.next().unwrap());
    let col = |n: &str| header.iter().position(|c| c == n).unwrap();
    let (t, name, ty) = (col("time_created"), col("file_name"), col("type"));
    let rows: Vec<Vec<String>> = lines.map(fields).collect();
    let has = |path: &str, when: &str, macb: char| {
        rows.iter().any(|r| r[name].eq_ignore_ascii_case(path) && r[t].starts_with(when) && r[ty].contains(macb))
    };
    assert!(has(r"C:\Users\Public\mimikatz.exe", "2026-11-10T08:32:43", 'b'), "mimikatz.exe born at 08:32:43");
    assert!(has(r"C:\inetpub\wwwroot\upload\cmd.aspx", "2026-11-10T08:22:44", 'b'), "cmd.aspx born at 08:22:44");
    assert!(rows.iter().any(|r| r[name].eq_ignore_ascii_case(r"C:\ProgramData\svch0st.exe")), "svch0st.exe");
    // The journal of the same volume resolves its parents through the $MFT.
    let usn_unknown = rows.iter().filter(|r| r[name].contains("[UNKNOWN]") && r[name].contains("mimikatz")).count();
    assert_eq!(usn_unknown, 0, "USN rows of mimikatz.exe without a parent path");
    let mut by_count: HashMap<String, usize> = HashMap::new();
    for r in &rows {
        *by_count.entry(r[name].clone()).or_default() += 1;
    }
    assert!(by_count.len() > 100_000, "{} distinct paths", by_count.len());
}
