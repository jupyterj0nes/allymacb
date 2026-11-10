//! Readers for Microsoft virtual disks as `Read + Seek`: VHD (fixed and dynamic) and VHDX
//! (fixed and dynamic), fed to the same partition walker as a raw image. Ported from masstin
//! (`src/vhd.rs`).
//!
//! VHD (Connectix `conectix`): the last 512 bytes are the footer with the disk type and the
//! virtual size; a dynamic disk keeps a copy of it at offset 0 and a `cxsparse` header
//! pointing at a block allocation table (BAT) of big-endian sector numbers, one per block
//! (2 MB by default); each allocated block starts with a sector bitmap whose clear bits read
//! as zeros. A fixed VHD is the raw disk followed by its footer and needs no reader.
//!
//! VHDX (`vhdxfile`): two region tables at 192 KB and 256 KB naming the BAT and the metadata
//! regions; the metadata gives the block size, the logical sector size and the virtual size;
//! BAT entries are little-endian u64, state in the low 3 bits and the file offset in the
//! upper bits (MB-aligned), and after every `chunk_ratio` payload entries comes one
//! sector-bitmap entry, which is skipped. Blocks not present read as zeros.
//!
//! A differencing disk (VHD type 4, a VHDX with a parent, partially present VHDX blocks)
//! holds only the changes over its parent and is refused with E6005. Neither reader applies
//! the VHDX log: a disk detached cleanly has an empty log, and evidence is never written.
//! Files are opened through [`crate::evidence::open`]: reading leaves no access time.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::vdisk::{be32, be64, le32, le64, open_evidence, read_at, seek_to, DiskError};

// ───────────────────────────── VHD ─────────────────────────────

const VHD_FOOTER: usize = 512;
pub const VHD_FIXED: u32 = 2;
pub const VHD_DYNAMIC: u32 = 3;
pub const VHD_DIFFERENCING: u32 = 4;

enum VhdLayout {
    Fixed,
    Dynamic {
        /// File offset of each block's data (after its bitmap), or None when never allocated.
        blocks: Vec<Option<u64>>,
        block_size: u64,
        bitmap_bytes: u64,
    },
}

pub struct VhdReader {
    file: File,
    layout: VhdLayout,
    total_size: u64,
    position: u64,
}

impl VhdReader {
    pub fn open(path: &Path) -> Result<Self, DiskError> {
        let mut file = open_evidence(path).map_err(|e| DiskError::read(format!("cannot open VHD: {e}")))?;
        let len = file.metadata().map_err(|e| DiskError::read(e.to_string()))?.len();
        if len < VHD_FOOTER as u64 {
            return Err(DiskError::damaged("VHD too small to hold a footer"));
        }
        let mut footer = [0u8; VHD_FOOTER];
        read_at(&mut file, len - VHD_FOOTER as u64, &mut footer).map_err(|e| DiskError::read(e.to_string()))?;
        if &footer[..8] != b"conectix" {
            // Some writers leave a truncated trailing footer; a dynamic disk keeps a copy at 0.
            read_at(&mut file, 0, &mut footer).map_err(|e| DiskError::read(e.to_string()))?;
            if &footer[..8] != b"conectix" {
                return Err(DiskError::damaged("not a VHD: no conectix footer at the end or the start"));
            }
        }
        let data_offset = be64(&footer, 16);
        let current_size = be64(&footer, 48);
        let layout = match be32(&footer, 60) {
            VHD_FIXED => VhdLayout::Fixed,
            VHD_DYNAMIC => {
                let mut hdr = [0u8; 1024];
                read_at(&mut file, data_offset, &mut hdr).map_err(|e| DiskError::damaged(format!("dynamic VHD header at {data_offset}: {e}")))?;
                if &hdr[..8] != b"cxsparse" {
                    return Err(DiskError::damaged("dynamic VHD without its cxsparse header"));
                }
                let table_offset = be64(&hdr, 16);
                let max_entries = be32(&hdr, 28) as usize;
                let block_size = u64::from(be32(&hdr, 32));
                if block_size == 0 || block_size % 512 != 0 {
                    return Err(DiskError::damaged(format!("dynamic VHD with an invalid block size {block_size}")));
                }
                if (max_entries as u64) * 4 > len {
                    return Err(DiskError::damaged(format!("dynamic VHD with a BAT of {max_entries} entries in a {len}-byte file")));
                }
                let sectors = block_size / 512;
                let bitmap_bytes = (sectors.div_ceil(8)).div_ceil(512) * 512;
                let mut bat = vec![0u8; max_entries * 4];
                read_at(&mut file, table_offset, &mut bat).map_err(|e| DiskError::damaged(format!("dynamic VHD BAT: {e}")))?;
                let blocks = (0..max_entries)
                    .map(|i| {
                        let s = be32(&bat, i * 4);
                        if s == 0xFFFF_FFFF { None } else { Some(u64::from(s) * 512) }
                    })
                    .collect();
                VhdLayout::Dynamic { blocks, block_size, bitmap_bytes }
            }
            VHD_DIFFERENCING => return Err(DiskError::has_parent("differencing VHD: it holds only the changes over its parent; give the merged disk")),
            t => return Err(DiskError::damaged(format!("unknown VHD disk type {t}"))),
        };
        Ok(VhdReader { file, layout, total_size: current_size, position: 0 })
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(self.layout, VhdLayout::Dynamic { .. })
    }
}

impl Read for VhdReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let want = buf.len().min((self.total_size - self.position) as usize);
        let pos = self.position;
        let n = match &self.layout {
            VhdLayout::Fixed => {
                self.file.seek(SeekFrom::Start(pos))?;
                self.file.read(&mut buf[..want])?
            }
            VhdLayout::Dynamic { blocks, block_size, bitmap_bytes } => {
                let bi = (pos / block_size) as usize;
                let in_block = pos % block_size;
                let n = want.min((block_size - in_block) as usize);
                match blocks.get(bi).copied().flatten() {
                    None => buf[..n].fill(0),
                    Some(start) => {
                        // A clear bit of the sector bitmap is a zero sector.
                        let first = in_block / 512;
                        let last = (in_block + n as u64 - 1) / 512;
                        let mut bitmap = vec![0u8; ((last / 8) - (first / 8) + 1) as usize];
                        read_at(&mut self.file, start + first / 8, &mut bitmap)?;
                        read_at(&mut self.file, start + bitmap_bytes + in_block, &mut buf[..n])?;
                        for s in first..=last {
                            let byte = bitmap[(s / 8 - first / 8) as usize];
                            if byte & (0x80 >> (s % 8)) == 0 {
                                let a = (s * 512).saturating_sub(in_block) as usize;
                                let b = (((s + 1) * 512).saturating_sub(in_block) as usize).min(n);
                                if a < b {
                                    buf[a..b].fill(0);
                                }
                            }
                        }
                    }
                }
                n
            }
        };
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VhdReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        seek_to(&mut self.position, self.total_size, pos)
    }
}

// ───────────────────────────── VHDX ─────────────────────────────

/// GUIDs as stored on disk (first three fields little-endian).
pub const GUID_BAT: [u8; 16] = [0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08];
pub const GUID_METADATA: [u8; 16] = [0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E];
pub const GUID_FILE_PARAMETERS: [u8; 16] = [0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B];
pub const GUID_VIRTUAL_DISK_SIZE: [u8; 16] = [0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8];
pub const GUID_LOGICAL_SECTOR_SIZE: [u8; 16] = [0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F];

const VHDX_STATE_MASK: u64 = 0x7;
pub const VHDX_FULLY_PRESENT: u64 = 6;
const VHDX_PARTIALLY_PRESENT: u64 = 7;

pub struct VhdxReader {
    file: File,
    blocks: Vec<Option<u64>>,
    block_size: u64,
    total_size: u64,
    position: u64,
}

/// Index of payload block `i` in the BAT: one sector-bitmap entry after every `ratio` blocks.
pub fn bat_index(i: usize, ratio: usize) -> usize {
    i + i / ratio.max(1)
}

impl VhdxReader {
    pub fn open(path: &Path) -> Result<Self, DiskError> {
        let mut file = open_evidence(path).map_err(|e| DiskError::read(format!("cannot open VHDX: {e}")))?;
        let mut id = [0u8; 8];
        read_at(&mut file, 0, &mut id).map_err(|e| DiskError::read(e.to_string()))?;
        if &id != b"vhdxfile" {
            return Err(DiskError::damaged("not a VHDX: no vhdxfile identifier"));
        }
        let mut regions: Option<Vec<([u8; 16], u64, u32)>> = None;
        for off in [192 * 1024u64, 256 * 1024] {
            let mut tbl = vec![0u8; 64 * 1024];
            if read_at(&mut file, off, &mut tbl).is_err() || &tbl[..4] != b"regi" {
                continue;
            }
            let count = le32(&tbl, 8) as usize;
            if count > 2047 {
                continue;
            }
            let mut v = Vec::with_capacity(count);
            for i in 0..count {
                let e = 16 + i * 32;
                let mut g = [0u8; 16];
                g.copy_from_slice(&tbl[e..e + 16]);
                v.push((g, le64(&tbl, e + 16), le32(&tbl, e + 24)));
            }
            regions = Some(v);
            break;
        }
        let regions = regions.ok_or_else(|| DiskError::damaged("VHDX without a readable region table"))?;
        let (bat_off, bat_len) = regions.iter().find(|r| r.0 == GUID_BAT).map(|r| (r.1, r.2)).ok_or_else(|| DiskError::damaged("VHDX without a BAT region"))?;
        let meta_off = regions.iter().find(|r| r.0 == GUID_METADATA).map(|r| r.1).ok_or_else(|| DiskError::damaged("VHDX without a metadata region"))?;
        let mut mt = vec![0u8; 64 * 1024];
        read_at(&mut file, meta_off, &mut mt).map_err(|e| DiskError::damaged(format!("VHDX metadata: {e}")))?;
        if &mt[..8] != b"metadata" {
            return Err(DiskError::damaged("VHDX metadata table without its signature"));
        }
        let n_items = u16::from_le_bytes([mt[10], mt[11]]) as usize;
        let (mut block_size, mut has_parent, mut virtual_size, mut sector_size) = (0u64, false, 0u64, 512u64);
        for i in 0..n_items.min(2047) {
            let e = 32 + i * 32;
            if e + 32 > mt.len() {
                break;
            }
            let gid = &mt[e..e + 16];
            let off = u64::from(le32(&mt, e + 16));
            let len = le32(&mt, e + 20) as usize;
            if len > 1 << 20 {
                continue;
            }
            let mut item = vec![0u8; len];
            if read_at(&mut file, meta_off + off, &mut item).is_err() {
                continue;
            }
            if gid == GUID_FILE_PARAMETERS && len >= 8 {
                block_size = u64::from(le32(&item, 0));
                has_parent = le32(&item, 4) & 0x2 != 0;
            } else if gid == GUID_VIRTUAL_DISK_SIZE && len >= 8 {
                virtual_size = le64(&item, 0);
            } else if gid == GUID_LOGICAL_SECTOR_SIZE && len >= 4 {
                sector_size = u64::from(le32(&item, 0));
            }
        }
        if has_parent {
            return Err(DiskError::has_parent("differencing VHDX: it holds only the changes over its parent; give the merged disk"));
        }
        if block_size == 0 || virtual_size == 0 {
            return Err(DiskError::damaged("VHDX metadata without a block size or a virtual size"));
        }
        if !block_size.is_power_of_two() || !(1 << 20..=256 << 20).contains(&block_size) || (sector_size != 512 && sector_size != 4096) || virtual_size > 64u64 << 40 {
            return Err(DiskError::damaged(format!("damaged VHDX metadata: block size {block_size}, sector size {sector_size}, virtual size {virtual_size}")));
        }
        let ratio = ((1u64 << 23) * sector_size / block_size).max(1) as usize;
        let n_blocks = virtual_size.div_ceil(block_size) as usize;
        let n_entries = n_blocks + n_blocks / ratio + 1;
        let mut bat = vec![0u8; (n_entries * 8).min(bat_len as usize)];
        read_at(&mut file, bat_off, &mut bat).map_err(|e| DiskError::damaged(format!("VHDX BAT: {e}")))?;
        let mut blocks = Vec::with_capacity(n_blocks);
        for i in 0..n_blocks {
            let idx = bat_index(i, ratio);
            if idx * 8 + 8 > bat.len() {
                blocks.push(None);
                continue;
            }
            let entry = le64(&bat, idx * 8);
            let offset = entry & !0xF_FFFF;
            blocks.push(match entry & VHDX_STATE_MASK {
                VHDX_FULLY_PRESENT if offset != 0 => Some(offset),
                VHDX_PARTIALLY_PRESENT => return Err(DiskError::has_parent("VHDX block partially present: a differencing disk; give the merged disk")),
                _ => None,
            });
        }
        Ok(VhdxReader { file, blocks, block_size, total_size: virtual_size, position: 0 })
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }
}

impl Read for VhdxReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let want = buf.len().min((self.total_size - self.position) as usize);
        let bi = (self.position / self.block_size) as usize;
        let in_block = self.position % self.block_size;
        let n = want.min((self.block_size - in_block) as usize);
        match self.blocks.get(bi).copied().flatten() {
            None => buf[..n].fill(0),
            Some(start) => read_at(&mut self.file, start + in_block, &mut buf[..n])?,
        }
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VhdxReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        seek_to(&mut self.position, self.total_size, pos)
    }
}

/// Test builders: VHD footers, a dynamic VHD and a VHDX with given blocks.
#[cfg(test)]
pub mod build {
    use super::*;

    pub fn vhd_footer(size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
        let mut f = [0u8; 512];
        f[..8].copy_from_slice(b"conectix");
        f[16..24].copy_from_slice(&data_offset.to_be_bytes());
        f[40..48].copy_from_slice(&size.to_be_bytes());
        f[48..56].copy_from_slice(&size.to_be_bytes());
        f[60..64].copy_from_slice(&disk_type.to_be_bytes());
        f
    }

    /// A dynamic VHD of `n_blocks` blocks of `block` bytes; `data[i]` fills block `i` when Some.
    pub fn dynamic_vhd(block: u64, data: &[Option<Vec<u8>>]) -> Vec<u8> {
        let size = block * data.len() as u64;
        let mut img = Vec::new();
        img.extend_from_slice(&vhd_footer(size, VHD_DYNAMIC, 512));
        let bat_at = 1536u64;
        let mut hdr = vec![0u8; 1024];
        hdr[..8].copy_from_slice(b"cxsparse");
        hdr[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        hdr[16..24].copy_from_slice(&bat_at.to_be_bytes());
        hdr[28..32].copy_from_slice(&(data.len() as u32).to_be_bytes());
        hdr[32..36].copy_from_slice(&(block as u32).to_be_bytes());
        img.extend_from_slice(&hdr);
        let bat_bytes = ((data.len() * 4) as u64).div_ceil(512) * 512;
        let bitmap = ((block / 512).div_ceil(8)).div_ceil(512) * 512;
        let mut bat = vec![0u8; bat_bytes as usize];
        let mut next = bat_at + bat_bytes;
        let mut blocks = Vec::new();
        for (i, d) in data.iter().enumerate() {
            match d {
                None => bat[i * 4..i * 4 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes()),
                Some(bytes) => {
                    bat[i * 4..i * 4 + 4].copy_from_slice(&((next / 512) as u32).to_be_bytes());
                    blocks.extend(std::iter::repeat_n(0xFFu8, bitmap as usize));
                    let mut b = bytes.clone();
                    b.resize(block as usize, 0);
                    blocks.extend_from_slice(&b);
                    next += bitmap + block;
                }
            }
        }
        img.extend_from_slice(&bat);
        img.extend_from_slice(&blocks);
        img.extend_from_slice(&vhd_footer(size, VHD_DYNAMIC, 512));
        img
    }

    /// A VHDX of two 1 MB blocks: block 0 present filled with `pattern`, block 1 absent.
    pub fn vhdx(pattern: u8, with_parent: bool) -> Vec<u8> {
        let block: u64 = 1 << 20;
        let virtual_size = 2 * block;
        let bat_off: u64 = 1 << 20;
        let meta_off: u64 = bat_off + 64 * 1024;
        let data_off: u64 = 2 << 20;
        let mut img = vec![0u8; (data_off + block) as usize];
        img[..8].copy_from_slice(b"vhdxfile");
        img[64 * 1024..64 * 1024 + 4].copy_from_slice(b"head");
        let rt = 192 * 1024;
        img[rt..rt + 4].copy_from_slice(b"regi");
        img[rt + 8..rt + 12].copy_from_slice(&2u32.to_le_bytes());
        let e0 = rt + 16;
        img[e0..e0 + 16].copy_from_slice(&GUID_BAT);
        img[e0 + 16..e0 + 24].copy_from_slice(&bat_off.to_le_bytes());
        img[e0 + 24..e0 + 28].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        let e1 = e0 + 32;
        img[e1..e1 + 16].copy_from_slice(&GUID_METADATA);
        img[e1 + 16..e1 + 24].copy_from_slice(&meta_off.to_le_bytes());
        img[e1 + 24..e1 + 28].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        let m = meta_off as usize;
        img[m..m + 8].copy_from_slice(b"metadata");
        img[m + 10..m + 12].copy_from_slice(&3u16.to_le_bytes());
        let items: [([u8; 16], Vec<u8>); 3] = [
            (GUID_FILE_PARAMETERS, [(block as u32).to_le_bytes(), (if with_parent { 2u32 } else { 0 }).to_le_bytes()].concat()),
            (GUID_VIRTUAL_DISK_SIZE, virtual_size.to_le_bytes().to_vec()),
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
        let b = bat_off as usize;
        img[b..b + 8].copy_from_slice(&(data_off | VHDX_FULLY_PRESENT).to_le_bytes());
        for x in &mut img[data_off as usize..] {
            *x = pattern;
        }
        img
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("allymacb-vhd-{}-{}", std::process::id(), name))
    }

    #[test]
    fn fixed_vhd_is_raw_plus_footer() {
        let p = tmp("fixed.vhd");
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let mut f = File::create(&p).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&build::vhd_footer(4096, VHD_FIXED, u64::MAX)).unwrap();
        drop(f);
        let mut r = VhdReader::open(&p).unwrap();
        assert!(!r.is_dynamic());
        assert_eq!(r.total_size(), 4096);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn dynamic_vhd_reads_allocated_blocks_bitmap_and_holes() {
        let p = tmp("dyn.vhd");
        let block = 4096u64;
        let d0: Vec<u8> = (0..block as usize).map(|i| (i % 7 + 1) as u8).collect();
        let d2: Vec<u8> = (0..block as usize).map(|i| (i % 5 + 10) as u8).collect();
        let mut img = build::dynamic_vhd(block, &[Some(d0.clone()), None, Some(d2.clone())]);
        // Clear the bitmap bit of sector 3 of block 0: that sector reads as zeros.
        let bat_at = 1536usize;
        let b0 = u32::from_be_bytes(img[bat_at..bat_at + 4].try_into().unwrap()) as usize * 512;
        img[b0] = 0b1110_1111;
        std::fs::write(&p, &img).unwrap();
        let mut r = VhdReader::open(&p).unwrap();
        assert!(r.is_dynamic());
        assert_eq!(r.total_size(), 3 * block);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(&out[..1536], &d0[..1536]);
        assert!(out[1536..2048].iter().all(|b| *b == 0), "sector 3 of block 0 is a zero sector");
        assert_eq!(&out[2048..4096], &d0[2048..]);
        assert!(out[4096..8192].iter().all(|b| *b == 0), "unallocated block");
        assert_eq!(&out[8192..], &d2[..]);
        r.seek(SeekFrom::Start(8192 + 100)).unwrap();
        let mut b = [0u8; 4];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b, &d2[100..104]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn vhd_refusals_carry_their_codes() {
        use crate::error::ErrorCode;
        let p = tmp("diff.vhd");
        std::fs::write(&p, build::vhd_footer(4096, VHD_DIFFERENCING, 512)).unwrap();
        assert_eq!(VhdReader::open(&p).err().unwrap().code, ErrorCode::ImageHasParent);
        std::fs::write(&p, [0u8; 100]).unwrap();
        assert_eq!(VhdReader::open(&p).err().unwrap().code, ErrorCode::ImageContainerDamaged, "too small");
        std::fs::write(&p, [0u8; 2048]).unwrap();
        assert_eq!(VhdReader::open(&p).err().unwrap().code, ErrorCode::ImageContainerDamaged, "no footer");
        std::fs::write(&p, build::vhd_footer(4096, 9, 512)).unwrap();
        assert_eq!(VhdReader::open(&p).err().unwrap().code, ErrorCode::ImageContainerDamaged, "unknown type");
        // A dynamic footer pointing at no cxsparse header.
        let mut img = build::vhd_footer(4096, VHD_DYNAMIC, 512).to_vec();
        img.extend_from_slice(&[0u8; 1024]);
        img.extend_from_slice(&build::vhd_footer(4096, VHD_DYNAMIC, 512));
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdReader::open(&p).err().unwrap().code, ErrorCode::ImageContainerDamaged);
        assert_eq!(VhdReader::open(&tmp("missing.vhd")).err().unwrap().code, ErrorCode::ImageReadFailed);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn vhdx_bat_index_skips_bitmap_entries() {
        assert_eq!((0..6).map(|i| bat_index(i, 4)).collect::<Vec<_>>(), vec![0, 1, 2, 3, 5, 6]);
        assert_eq!(bat_index(3, 0), 6, "a zero ratio is taken as one");
    }

    #[test]
    fn vhdx_reads_present_block_and_zero_absent_block() {
        let p = tmp("ok.vhdx");
        std::fs::write(&p, build::vhdx(0xAB, false)).unwrap();
        let mut r = VhdxReader::open(&p).unwrap();
        assert_eq!(r.total_size(), 2 << 20);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert!(out[..1 << 20].iter().all(|b| *b == 0xAB));
        assert!(out[1 << 20..].iter().all(|b| *b == 0));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn vhdx_refusals_carry_their_codes() {
        use crate::error::ErrorCode;
        let p = tmp("parent.vhdx");
        std::fs::write(&p, build::vhdx(1, true)).unwrap();
        assert_eq!(VhdxReader::open(&p).err().unwrap().code, ErrorCode::ImageHasParent);
        let mut img = build::vhdx(1, false);
        img[192 * 1024..192 * 1024 + 4].copy_from_slice(b"xxxx");
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdxReader::open(&p).err().unwrap().code, ErrorCode::ImageContainerDamaged, "no region table");
        let mut img = build::vhdx(1, false);
        let m = (1usize << 20) + 64 * 1024;
        img[m..m + 8].copy_from_slice(b"xxxxxxxx");
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdxReader::open(&p).err().unwrap().code, ErrorCode::ImageContainerDamaged, "no metadata signature");
        let mut img = build::vhdx(1, false);
        let b = 1usize << 20;
        img[b..b + 8].copy_from_slice(&((2u64 << 20) | VHDX_PARTIALLY_PRESENT).to_le_bytes());
        std::fs::write(&p, &img).unwrap();
        assert_eq!(VhdxReader::open(&p).err().unwrap().code, ErrorCode::ImageHasParent, "partially present block");
        std::fs::write(&p, b"notvhdx!").unwrap();
        assert_eq!(VhdxReader::open(&p).err().unwrap().code, ErrorCode::ImageContainerDamaged);
        std::fs::remove_file(&p).ok();
    }
}
