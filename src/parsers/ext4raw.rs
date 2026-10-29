//! ext2/ext3/ext4 read directly from the on-disk structures.
//!
//! `ext4-view` gives a clean view of the live tree but hides what a forensic
//! timeline needs: inode numbers, `ctime`, inodes marked deleted, inodes it
//! refuses (timestamps past 2038), and the jbd2 journal. This module reads
//! the superblock, the group descriptors, the inode tables, the extent trees
//! (or the ext2/3 block maps), the directory blocks and the journal itself.
//!
//! * The **live timeline** comes from a walk of the directory tree starting
//!   at inode 2, plus every inode in the tables that carries a `dtime`
//!   (deleted, name gone from the directories) as a `(deleted)` row.
//! * The **journal** keeps copies of metadata blocks as they were before each
//!   transaction. Copies of inode-table blocks are older states of inodes
//!   (sizes, timestamps before a `touch`, files before they were deleted);
//!   copies of directory blocks hold the names and inode numbers of entries
//!   that the live directory no longer has. Modern kernels zero a directory
//!   entry when it is removed, so the journal is the only place a deleted
//!   name survives. That is what `--carve` reads on ext4.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

use crate::anomaly;
use crate::error::{AllyError, ErrorCode, Result};
use crate::parsers::ext4::mode_bits_to_string;
use crate::timefmt::format_unix_timestamp;
use crate::timeline::{join_macb_flags, source, TimelineEntry};

const EXT4_MAGIC: u16 = 0xEF53;
const ROOT_INODE: u32 = 2;
const EXTENT_MAGIC: u16 = 0xF30A;
const JBD2_MAGIC: u32 = 0xC03B_3998;
/// Feature bits.
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INODE_FLAG_EXTENTS: u32 = 0x0008_0000;
const INODE_FLAG_INLINE_DATA: u32 = 0x1000_0000;
const BG_INODE_UNINIT: u16 = 0x0001;
/// Directory nesting followed before a subtree is abandoned.
const MAX_DIR_DEPTH: usize = 256;
/// Blocks of one file we are willing to map (directories and the journal only).
const MAX_FILE_BLOCKS: usize = 1 << 20;
/// Largest inode table slice read at once.
const MAX_INODE_TABLE_BYTES: u64 = 1 << 30;

/// Seconds and nanoseconds, as ext4 stores them (34-bit seconds since the
/// extra field, so dates past 2038 are real).
pub type Ts = (i64, u32);

#[derive(Debug, Clone)]
pub struct Superblock {
    pub block_size: u64,
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub inodes_per_group: u32,
    pub blocks_per_group: u32,
    pub inode_size: u16,
    pub first_data_block: u32,
    pub desc_size: u16,
    pub journal_inum: u32,
    pub incompat: u32,
    pub first_ino: u32,
}

#[derive(Debug, Clone)]
struct GroupDesc {
    block_bitmap: u64,
    inode_table: u64,
    flags: u16,
    itable_unused: u32,
}
const BG_BLOCK_UNINIT: u16 = 0x0002;

/// One inode as stored on disk (the fields a timeline needs).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Inode {
    pub num: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    pub flags: u32,
    pub atime: Ts,
    pub ctime: Ts,
    pub mtime: Ts,
    pub crtime: Option<Ts>,
    /// Deletion time, 0 when the inode is in use.
    pub dtime: u32,
    i_block: [u8; 60],
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }
    /// A record that was ever used: a type in the mode bits.
    pub fn is_used(&self) -> bool {
        matches!(self.mode & 0xF000, 0x1000 | 0x2000 | 0x4000 | 0x6000 | 0x8000 | 0xA000 | 0xC000)
    }
    pub fn is_deleted(&self) -> bool {
        self.is_used() && (self.dtime != 0 || self.links == 0)
    }
    /// `ls -l` style mode with the type character.
    pub fn mode_string(&self) -> String {
        let t = match self.mode & 0xF000 {
            0x4000 => 'd',
            0xA000 => 'l',
            0x2000 => 'c',
            0x6000 => 'b',
            0x1000 => 'p',
            0xC000 => 's',
            _ => '-',
        };
        format!("{}{}", t, mode_bits_to_string(self.mode & 0o7777))
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Decodes an ext4 timestamp: the 32-bit seconds plus the extra field, whose
/// low two bits extend the epoch and whose upper 30 bits are nanoseconds.
fn decode_ts(secs: u32, extra: Option<u32>) -> Ts {
    let mut s = i64::from(secs as i32);
    let mut nanos = 0u32;
    if let Some(x) = extra {
        s += i64::from(x & 3) << 32;
        nanos = x >> 2;
    }
    (s, nanos.min(999_999_999))
}

/// Parses one raw inode record. `num` is only recorded, not derived.
pub fn parse_inode(raw: &[u8], num: u32) -> Option<Inode> {
    if raw.len() < 128 {
        return None;
    }
    let mode = u16le(raw, 0);
    let uid_lo = u16le(raw, 2);
    let size_lo = u32le(raw, 4);
    let atime = u32le(raw, 8);
    let ctime = u32le(raw, 12);
    let mtime = u32le(raw, 16);
    let dtime = u32le(raw, 20);
    let gid_lo = u16le(raw, 24);
    let links = u16le(raw, 26);
    let flags = u32le(raw, 32);
    let size_hi = u32le(raw, 0x6C);
    let uid_hi = u16le(raw, 0x78);
    let gid_hi = u16le(raw, 0x7A);
    let extra_isize = if raw.len() >= 130 { u16le(raw, 0x80) as usize } else { 0 };
    let has_extra = |end: usize| raw.len() >= 128 + extra_isize && 128 + extra_isize >= end && raw.len() >= end;
    let ctime_extra = has_extra(0x88).then(|| u32le(raw, 0x84));
    let mtime_extra = has_extra(0x8C).then(|| u32le(raw, 0x88));
    let atime_extra = has_extra(0x90).then(|| u32le(raw, 0x8C));
    let crtime = has_extra(0x94).then(|| u32le(raw, 0x90));
    let crtime_extra = has_extra(0x98).then(|| u32le(raw, 0x94));
    let mut i_block = [0u8; 60];
    i_block.copy_from_slice(&raw[0x28..0x28 + 60]);
    Some(Inode {
        num,
        mode,
        uid: u32::from(uid_lo) | (u32::from(uid_hi) << 16),
        gid: u32::from(gid_lo) | (u32::from(gid_hi) << 16),
        size: u64::from(size_lo) | (u64::from(size_hi) << 32),
        links,
        flags,
        atime: decode_ts(atime, atime_extra),
        ctime: decode_ts(ctime, ctime_extra),
        mtime: decode_ts(mtime, mtime_extra),
        crtime: crtime.map(|c| decode_ts(c, crtime_extra)),
        dtime,
        i_block,
    })
}

/// Plausibility of an inode read from a journal copy or carved bytes.
fn plausible(i: &Inode) -> bool {
    if !i.is_used() || i.links > 65_000 {
        return false;
    }
    let ok = |t: Ts| t.0 == 0 || (-2_000_000_000..=10_000_000_000).contains(&t.0);
    ok(i.atime) && ok(i.ctime) && ok(i.mtime) && i.crtime.map_or(true, ok)
}

/// A directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub inode: u32,
    pub name: String,
    pub file_type: u8,
}

/// Parses the entries of one directory block (linear leaves of an htree
/// included: dx nodes come out as entries with inode 0 and are skipped).
pub fn parse_dir_block(block: &[u8]) -> Vec<DirEntry> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= block.len() {
        let inode = u32le(block, pos);
        let rec_len = u16le(block, pos + 4) as usize;
        let name_len = block[pos + 6] as usize;
        let file_type = block[pos + 7];
        if rec_len < 8 || pos + rec_len > block.len() {
            break;
        }
        if inode != 0 && name_len > 0 && pos + 8 + name_len <= block.len() {
            let name = String::from_utf8_lossy(&block[pos + 8..pos + 8 + name_len]).into_owned();
            out.push(DirEntry { inode, name, file_type });
        }
        pos += rec_len;
    }
    out
}

/// A directory block parses cleanly when its records cover the block exactly.
fn dir_block_is_whole(block: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos + 8 <= block.len() {
        let rec_len = u16le(block, pos + 4) as usize;
        if rec_len < 8 || rec_len % 4 != 0 || pos + rec_len > block.len() {
            return false;
        }
        pos += rec_len;
    }
    pos == block.len()
}

/// A copy of a filesystem block found in the journal.
pub struct JournalCopy {
    /// Transaction sequence number: order of the states.
    pub seq: u32,
    /// Filesystem block the copy belongs to.
    pub fs_block: u64,
    /// Absolute offset of the copy in the image.
    pub offset: u64,
    pub data: Vec<u8>,
}

pub struct Ext4Raw<R: Read + Seek> {
    reader: R,
    base: u64,
    pub sb: Superblock,
    groups: Vec<GroupDesc>,
    /// group -> bytes of the used part of its inode table
    itables: HashMap<u32, Vec<u8>>,
}

impl<R: Read + Seek> Ext4Raw<R> {
    /// Opens the filesystem whose first byte is at `base`.
    pub fn open(mut reader: R, base: u64) -> Result<Self> {
        let err = |m: String| AllyError::Ext4 { code: ErrorCode::Ext4SuperblockInvalid, message: m };
        let mut sbraw = vec![0u8; 1024];
        reader.seek(SeekFrom::Start(base + 1024)).and_then(|_| reader.read_exact(&mut sbraw)).map_err(|e| err(format!("superblock unreadable: {}", e)))?;
        if u16le(&sbraw, 0x38) != EXT4_MAGIC {
            return Err(err("no ext4 magic".into()));
        }
        let log_block_size = u32le(&sbraw, 0x18);
        if log_block_size > 6 {
            return Err(err(format!("block size exponent {} out of range", log_block_size)));
        }
        let incompat = u32le(&sbraw, 0x60);
        if incompat & INCOMPAT_META_BG != 0 {
            return Err(err("meta_bg layout is not supported by the raw reader".into()));
        }
        let rev = u32le(&sbraw, 0x4C);
        let inode_size = if rev == 0 { 128 } else { u16le(&sbraw, 0x58) };
        if !(128..=4096).contains(&inode_size) || !inode_size.is_power_of_two() {
            return Err(err(format!("inode size {} out of range", inode_size)));
        }
        let is64 = incompat & INCOMPAT_64BIT != 0;
        let desc_size = if is64 { u16le(&sbraw, 0xFE).max(64) } else { 32 };
        let sb = Superblock {
            block_size: 1024u64 << log_block_size,
            inodes_count: u32le(&sbraw, 0),
            blocks_count: u64::from(u32le(&sbraw, 4)) | if is64 { u64::from(u32le(&sbraw, 0x150)) << 32 } else { 0 },
            inodes_per_group: u32le(&sbraw, 0x28),
            blocks_per_group: u32le(&sbraw, 0x20),
            inode_size,
            first_data_block: u32le(&sbraw, 0x14),
            desc_size,
            journal_inum: u32le(&sbraw, 0xE0),
            incompat,
            first_ino: if rev == 0 { 11 } else { u32le(&sbraw, 0x54) },
        };
        if sb.inodes_per_group == 0 || sb.blocks_per_group == 0 || sb.inodes_count == 0 {
            return Err(err("zero inodes or blocks per group".into()));
        }
        let groups_n = sb.inodes_count.div_ceil(sb.inodes_per_group) as usize;
        if groups_n > 1 << 20 {
            return Err(err(format!("{} block groups: refusing", groups_n)));
        }
        let gdt_off = base + u64::from(sb.first_data_block + 1) * sb.block_size;
        let mut gd = vec![0u8; groups_n * sb.desc_size as usize];
        reader.seek(SeekFrom::Start(gdt_off)).and_then(|_| reader.read_exact(&mut gd)).map_err(|e| err(format!("group descriptors unreadable: {}", e)))?;
        let mut groups = Vec::with_capacity(groups_n);
        for g in 0..groups_n {
            let d = &gd[g * sb.desc_size as usize..(g + 1) * sb.desc_size as usize];
            let lo = u64::from(u32le(d, 8));
            let hi = if sb.desc_size >= 64 { u64::from(u32le(d, 0x28)) << 32 } else { 0 };
            let bb = u64::from(u32le(d, 0)) | if sb.desc_size >= 64 { u64::from(u32le(d, 0x20)) << 32 } else { 0 };
            let unused = u32::from(u16le(d, 0x1C)) | if sb.desc_size >= 64 { u32::from(u16le(d, 0x32)) << 16 } else { 0 };
            groups.push(GroupDesc { block_bitmap: bb, inode_table: lo | hi, flags: u16le(d, 0x12), itable_unused: unused });
        }
        Ok(Self { reader, base, sb, groups, itables: HashMap::new() })
    }

    pub fn read_block(&mut self, block: u64) -> Option<Vec<u8>> {
        if block >= self.sb.blocks_count {
            return None;
        }
        let mut buf = vec![0u8; self.sb.block_size as usize];
        self.reader.seek(SeekFrom::Start(self.base + block * self.sb.block_size)).ok()?;
        self.reader.read_exact(&mut buf).ok()?;
        Some(buf)
    }

    /// Absolute image offset of a filesystem block.
    pub fn block_offset(&self, block: u64) -> u64 {
        self.base + block * self.sb.block_size
    }

    /// Byte range of the whole filesystem in the image.
    pub fn extent(&self) -> (u64, u64) {
        (self.base, self.base + self.sb.blocks_count * self.sb.block_size)
    }

    /// Unallocated space as absolute byte ranges `(start, len)`, from the
    /// block bitmaps. A group whose bitmap was never initialised counts as
    /// free in full.
    pub fn free_ranges(&mut self) -> Vec<(u64, u64)> {
        let bs = self.sb.block_size;
        let bpg = u64::from(self.sb.blocks_per_group);
        let first = u64::from(self.sb.first_data_block);
        let mut out: Vec<(u64, u64)> = Vec::new();
        let push = |out: &mut Vec<(u64, u64)>, start: u64, len: u64| {
            if len == 0 {
                return;
            }
            if let Some(last) = out.last_mut() {
                if last.0 + last.1 == start {
                    last.1 += len;
                    return;
                }
            }
            out.push((start, len));
        };
        let groups = self.groups.clone();
        for (g, d) in groups.iter().enumerate() {
            let gstart = first + g as u64 * bpg;
            let gblocks = bpg.min(self.sb.blocks_count.saturating_sub(gstart));
            if gblocks == 0 {
                break;
            }
            let bitmap = if d.flags & BG_BLOCK_UNINIT != 0 { None } else { self.read_block(d.block_bitmap) };
            match bitmap {
                None => push(&mut out, self.block_offset(gstart), gblocks * bs),
                Some(bm) => {
                    let mut b = 0u64;
                    while b < gblocks {
                        let byte = bm.get((b / 8) as usize).copied().unwrap_or(0xFF);
                        if byte == 0xFF {
                            b = (b / 8 + 1) * 8;
                            continue;
                        }
                        if byte & (1 << (b % 8)) == 0 {
                            push(&mut out, self.block_offset(gstart + b), bs);
                        }
                        b += 1;
                    }
                }
            }
        }
        out
    }

    /// Inodes of group `g` that may have been used (tables of uninitialised
    /// groups are never read).
    fn used_inodes_in_group(&self, g: u32) -> u32 {
        let d = &self.groups[g as usize];
        if d.flags & BG_INODE_UNINIT != 0 {
            return 0;
        }
        self.sb.inodes_per_group.saturating_sub(d.itable_unused.min(self.sb.inodes_per_group))
    }

    fn load_group(&mut self, g: u32) -> Option<&Vec<u8>> {
        if !self.itables.contains_key(&g) {
            let n = self.used_inodes_in_group(g);
            let bytes = (u64::from(n) * u64::from(self.sb.inode_size)).min(MAX_INODE_TABLE_BYTES);
            let mut buf = vec![0u8; bytes as usize];
            if bytes > 0 {
                let off = self.base + self.groups[g as usize].inode_table * self.sb.block_size;
                if self.reader.seek(SeekFrom::Start(off)).is_err() || self.reader.read_exact(&mut buf).is_err() {
                    buf.clear();
                }
            }
            self.itables.insert(g, buf);
        }
        self.itables.get(&g)
    }

    /// The inode `num` (1-based), `None` when outside the used tables.
    pub fn inode(&mut self, num: u32) -> Option<Inode> {
        if num == 0 || num > self.sb.inodes_count {
            return None;
        }
        let g = (num - 1) / self.sb.inodes_per_group;
        let idx = ((num - 1) % self.sb.inodes_per_group) as usize;
        let isz = self.sb.inode_size as usize;
        let table = self.load_group(g)?;
        let raw = table.get(idx * isz..(idx + 1) * isz)?;
        parse_inode(raw, num)
    }

    /// Every inode in the used parts of the tables.
    pub fn all_inodes(&mut self) -> Vec<Inode> {
        let mut out = Vec::new();
        let groups = self.groups.len() as u32;
        let isz = self.sb.inode_size as usize;
        for g in 0..groups {
            let first = g * self.sb.inodes_per_group + 1;
            let Some(table) = self.load_group(g) else { continue };
            for (k, raw) in table.chunks_exact(isz).enumerate() {
                if let Some(i) = parse_inode(raw, first + k as u32) {
                    if i.is_used() {
                        out.push(i);
                    }
                }
            }
        }
        out
    }

    /// Filesystem blocks of an inode's data, in file order (holes skipped).
    pub fn blocks_of(&mut self, inode: &Inode) -> Vec<u64> {
        let mut out = Vec::new();
        if inode.flags & INODE_FLAG_INLINE_DATA != 0 {
            return out;
        }
        if inode.flags & INODE_FLAG_EXTENTS != 0 {
            let root = inode.i_block.to_vec();
            self.extent_blocks(&root, 0, &mut out);
        } else {
            self.blockmap_blocks(&inode.i_block, &mut out);
        }
        out
    }

    fn extent_blocks(&mut self, node: &[u8], depth_guard: u32, out: &mut Vec<u64>) {
        if node.len() < 12 || u16le(node, 0) != EXTENT_MAGIC || depth_guard > 5 || out.len() >= MAX_FILE_BLOCKS {
            return;
        }
        let entries = u16le(node, 2) as usize;
        let depth = u16le(node, 6);
        let max = (node.len() - 12) / 12;
        for k in 0..entries.min(max) {
            let e = &node[12 + k * 12..24 + k * 12];
            if depth == 0 {
                let len = u16le(e, 4);
                let len = if len > 32768 { len - 32768 } else { len } as u64; // uninitialised extents
                let start = u64::from(u32le(e, 8)) | (u64::from(u16le(e, 6)) << 32);
                for b in 0..len {
                    if out.len() >= MAX_FILE_BLOCKS {
                        return;
                    }
                    out.push(start + b);
                }
            } else {
                let leaf = u64::from(u32le(e, 4)) | (u64::from(u16le(e, 8)) << 32);
                if let Some(child) = self.read_block(leaf) {
                    self.extent_blocks(&child, depth_guard + 1, out);
                }
            }
        }
    }

    fn blockmap_blocks(&mut self, i_block: &[u8], out: &mut Vec<u64>) {
        for k in 0..12 {
            let b = u32le(i_block, k * 4);
            if b != 0 {
                out.push(u64::from(b));
            }
        }
        let ind = [u32le(i_block, 48), u32le(i_block, 52), u32le(i_block, 56)];
        for (level, &b) in ind.iter().enumerate() {
            if b != 0 {
                self.indirect(u64::from(b), level as u32, out);
            }
        }
    }

    fn indirect(&mut self, block: u64, level: u32, out: &mut Vec<u64>) {
        if out.len() >= MAX_FILE_BLOCKS {
            return;
        }
        let Some(data) = self.read_block(block) else { return };
        for k in 0..data.len() / 4 {
            let b = u64::from(u32le(&data, k * 4));
            if b == 0 {
                continue;
            }
            if level == 0 {
                out.push(b);
                if out.len() >= MAX_FILE_BLOCKS {
                    return;
                }
            } else {
                self.indirect(b, level - 1, out);
            }
        }
    }

    /// Entries of a directory inode, reading every block.
    pub fn dir_entries(&mut self, dir: &Inode) -> Vec<DirEntry> {
        let mut out = Vec::new();
        for b in self.blocks_of(dir) {
            if let Some(data) = self.read_block(b) {
                out.extend(parse_dir_block(&data));
            }
        }
        out
    }

    /// Walks the live tree: (inode number, full path) for every reachable
    /// entry, hard links included. Directories end without a slash; the root
    /// is "/".
    pub fn walk(&mut self) -> Result<Vec<(u32, String)>> {
        let root = self.inode(ROOT_INODE).filter(|i| i.is_dir()).ok_or_else(|| AllyError::Ext4 {
            code: ErrorCode::Ext4DirectoryTraversalFailed,
            message: "root inode is not a readable directory".to_string(),
        })?;
        if root.flags & INODE_FLAG_INLINE_DATA != 0 || self.sb.incompat & INCOMPAT_INLINE_DATA != 0 && root.size < self.sb.block_size {
            return Err(AllyError::Ext4 {
                code: ErrorCode::Ext4DirectoryTraversalFailed,
                message: "inline-data directories are not supported by the raw reader".to_string(),
            });
        }
        let mut out = vec![(ROOT_INODE, "/".to_string())];
        let mut visited: HashSet<u32> = HashSet::new();
        let mut stack: Vec<(Inode, String, usize)> = vec![(root, String::new(), 0)];
        while let Some((dir, path, depth)) = stack.pop() {
            if !visited.insert(dir.num) || depth > MAX_DIR_DEPTH {
                continue;
            }
            for e in self.dir_entries(&dir) {
                if e.name == "." || e.name == ".." {
                    continue;
                }
                let full = format!("{}/{}", path, e.name);
                out.push((e.inode, full.clone()));
                let is_dir = if self.sb.incompat & INCOMPAT_FILETYPE != 0 { e.file_type == 2 } else { self.inode(e.inode).map_or(false, |i| i.is_dir()) };
                if is_dir {
                    if let Some(child) = self.inode(e.inode) {
                        if child.is_dir() {
                            stack.push((child, full, depth + 1));
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Every block copy the journal still holds, oldest transaction first.
    pub fn journal_copies(&mut self) -> Vec<JournalCopy> {
        let mut out = Vec::new();
        let Some(jinode) = self.inode(self.sb.journal_inum).filter(|i| i.is_used()) else { return out };
        let jblocks = self.blocks_of(&jinode);
        if jblocks.is_empty() {
            return out;
        }
        let Some(jsb) = self.read_block(jblocks[0]) else { return out };
        if u32be(&jsb, 0) != JBD2_MAGIC || !matches!(u32be(&jsb, 4), 3 | 4) {
            return out;
        }
        let jbs = u32be(&jsb, 12) as usize;
        let maxlen = (u32be(&jsb, 16) as usize).min(jblocks.len());
        let first = u32be(&jsb, 20) as usize;
        let jincompat = u32be(&jsb, 0x28);
        let csum_v3 = jincompat & 0x10 != 0;
        let is64 = jincompat & 0x2 != 0;
        let tag_size = if csum_v3 { 16 } else if is64 { 12 } else { 8 };
        if jbs != self.sb.block_size as usize || maxlen == 0 || first >= maxlen {
            return out;
        }
        let read_j = |me: &mut Self, lb: usize| -> Option<Vec<u8>> { jblocks.get(lb).and_then(|&b| me.read_block(b)) };
        let mut lb = first.max(1);
        while lb < maxlen {
            let Some(hdr) = read_j(self, lb) else { lb += 1; continue };
            if u32be(&hdr, 0) != JBD2_MAGIC || u32be(&hdr, 4) != 1 {
                lb += 1;
                continue;
            }
            let seq = u32be(&hdr, 8);
            let mut pos = 12;
            let mut data_lb = lb + 1;
            loop {
                if pos + tag_size > jbs {
                    break;
                }
                let blocknr_lo = u64::from(u32be(&hdr, pos));
                let (flags, blocknr_hi) = if csum_v3 {
                    (u32be(&hdr, pos + 4), u64::from(u32be(&hdr, pos + 8)))
                } else {
                    (u32::from(u16::from_be_bytes([hdr[pos + 6], hdr[pos + 7]])), if is64 { u64::from(u32be(&hdr, pos + 8)) } else { 0 })
                };
                pos += tag_size;
                if flags & 0x2 == 0 {
                    pos += 16; // UUID follows the tag
                }
                if data_lb >= maxlen {
                    data_lb = first.max(1);
                }
                if let Some(mut data) = read_j(self, data_lb) {
                    if flags & 0x1 != 0 {
                        data[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes()); // escaped block
                    }
                    let fs_block = blocknr_lo | (blocknr_hi << 32);
                    if fs_block < self.sb.blocks_count {
                        out.push(JournalCopy { seq, fs_block, offset: self.block_offset(jblocks[data_lb]), data });
                    }
                }
                data_lb += 1;
                if flags & 0x8 != 0 {
                    break; // last tag
                }
            }
            lb = data_lb.max(lb + 1);
        }
        out.sort_by_key(|c| c.seq);
        out
    }

    /// Inode table block -> (group, first inode number held by that block).
    fn inode_table_block(&self, block: u64) -> Option<u32> {
        let per_block = (self.sb.block_size / u64::from(self.sb.inode_size)) as u32;
        for (g, d) in self.groups.iter().enumerate() {
            let len = u64::from(self.sb.inodes_per_group) * u64::from(self.sb.inode_size) / self.sb.block_size;
            if block >= d.inode_table && block < d.inode_table + len {
                let idx = (block - d.inode_table) as u32;
                return Some(g as u32 * self.sb.inodes_per_group + idx * per_block + 1);
            }
        }
        None
    }
}

/// Rows for one inode state; `name` is the full path with tags, `suffix`
/// goes after it.
fn rows_for(i: &Inode, name: &str, src: &'static str, flags: &str, out: &mut Vec<TimelineEntry>) {
    let mut ts_map: HashMap<Ts, String> = HashMap::new();
    for (t, f) in [(i.mtime, 'm'), (i.atime, 'a'), (i.ctime, 'c')] {
        if t != (0, 0) {
            let cur = ts_map.entry(t).or_insert_with(|| "....".to_string());
            *cur = join_macb_flags(cur, f);
        }
    }
    if let Some(b) = i.crtime {
        if b != (0, 0) {
            let cur = ts_map.entry(b).or_insert_with(|| "....".to_string());
            *cur = join_macb_flags(cur, 'b');
        }
    }
    let mode = i.mode_string();
    for ((secs, nanos), macb) in ts_map {
        if let Some(iso) = format_unix_timestamp(secs, nanos) {
            out.push(
                TimelineEntry::new(iso, secs, nanos, i.size, macb, mode.clone(), i.uid, i.gid, i.num.to_string(), name.to_string())
                    .with_source(src)
                    .with_flags(flags.to_string()),
            );
        }
    }
}

fn indicators(i: &Inode, name: &str, extra: &[&'static str]) -> String {
    let mut f = anomaly::unix_flags(Some(i.mtime.0), Some(i.ctime.0), i.crtime.map(|c| c.0), anomaly::now_secs());
    for x in anomaly::name_flags(name) {
        if !f.contains(&x) {
            f.push(x);
        }
    }
    for x in extra {
        if !f.contains(x) {
            f.push(x);
        }
    }
    anomaly::column(&f)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ext4RawReport {
    pub live_entries: usize,
    pub deleted_inodes: usize,
    pub journal_copies: usize,
    pub journal_inode_states: usize,
    pub journal_states_new: usize,
    pub journal_names: usize,
    pub rows_duplicate: usize,
    pub backdated: usize,
}

/// Live timeline of an ext4 filesystem: the directory tree plus the inodes
/// marked deleted in the tables. With `carve`, the journal's older states
/// are added as `carved` rows.
pub fn parse_ext4_raw<R: Read + Seek>(reader: R, base: u64, carve: bool) -> Result<(Vec<TimelineEntry>, Ext4RawReport)> {
    let mut fs = Ext4Raw::open(reader, base)?;
    let mut report = Ext4RawReport::default();
    let mut out = Vec::new();

    // --- live tree ----------------------------------------------------------
    let live = fs.walk()?;
    let mut live_paths: HashMap<u32, Vec<String>> = HashMap::new();
    for (ino, path) in &live {
        live_paths.entry(*ino).or_default().push(path.clone());
    }
    let mut live_inodes: HashMap<u32, Inode> = HashMap::new();
    for (ino, path) in &live {
        let Some(i) = live_inodes.get(ino).cloned().or_else(|| fs.inode(*ino)) else { continue };
        live_inodes.entry(*ino).or_insert_with(|| i.clone());
        rows_for(&i, path, source::EXT4, &indicators(&i, path, &[]), &mut out);
        report.live_entries += 1;
    }

    // --- inodes marked deleted in the tables ---------------------------------
    let all = fs.all_inodes();
    let mut deleted: Vec<Inode> = all.iter().filter(|i| i.is_deleted() && !live_paths.contains_key(&i.num)).cloned().collect();
    deleted.sort_by_key(|i| i.num);
    report.deleted_inodes = deleted.len();

    if !carve {
        for i in &deleted {
            let name = format!("/[UNKNOWN]/inode_{} (deleted)", i.num);
            rows_for(i, &name, source::EXT4, &indicators(i, &name, &[]), &mut out);
        }
        return Ok((out, report));
    }

    // --- journal: names and older states -------------------------------------
    let copies = fs.journal_copies();
    report.journal_copies = copies.len();
    // child inode -> [(seq, parent dir inode, name)]
    let mut jnames: HashMap<u32, Vec<(u32, u32, String)>> = HashMap::new();
    // dir block -> owning dir inode, from the live tree and from `.` entries
    let mut block_owner: HashMap<u64, u32> = HashMap::new();
    for (ino, i) in &live_inodes {
        if i.is_dir() {
            for b in fs.blocks_of(i) {
                block_owner.insert(b, *ino);
            }
        }
    }
    let mut states: Vec<(u32, u64, Inode)> = Vec::new(); // (seq, offset, inode)
    for c in &copies {
        if let Some(first_ino) = fs.inode_table_block(c.fs_block) {
            let isz = fs.sb.inode_size as usize;
            for (k, raw) in c.data.chunks_exact(isz).enumerate() {
                if let Some(i) = parse_inode(raw, first_ino + k as u32) {
                    if plausible(&i) {
                        states.push((c.seq, c.offset + (k * isz) as u64, i));
                    }
                }
            }
        } else if dir_block_is_whole(&c.data) {
            let entries = parse_dir_block(&c.data);
            let owner = entries.iter().find(|e| e.name == ".").map(|e| e.inode).or_else(|| block_owner.get(&c.fs_block).copied());
            if let Some(dir) = owner {
                block_owner.entry(c.fs_block).or_insert(dir);
                for e in entries {
                    if e.name == "." || e.name == ".." {
                        continue;
                    }
                    jnames.entry(e.inode).or_default().push((c.seq, dir, e.name));
                }
            }
        }
    }
    report.journal_inode_states = states.len();
    report.journal_names = jnames.values().map(|v| v.len()).sum();

    // Name of inode `ino` as of transaction `seq`: the latest journal entry not
    // newer than `seq`, then the live path, then unknown.
    fn name_at(ino: u32, seq: u32, jnames: &HashMap<u32, Vec<(u32, u32, String)>>, live_paths: &HashMap<u32, Vec<String>>, depth: usize, visiting: &mut HashSet<u32>) -> Option<String> {
        if ino == ROOT_INODE {
            return Some(String::new());
        }
        if depth > MAX_DIR_DEPTH || !visiting.insert(ino) {
            return None;
        }
        let from_journal = jnames.get(&ino).and_then(|v| v.iter().filter(|(s, _, _)| *s <= seq).max_by_key(|(s, _, _)| *s).or_else(|| v.iter().min_by_key(|(s, _, _)| *s)));
        let r = match from_journal {
            Some((s, parent, name)) => name_at(*parent, *s, jnames, live_paths, depth + 1, visiting)
                .or_else(|| live_paths.get(parent).and_then(|p| p.first()).map(|p| p.trim_end_matches('/').to_string()))
                .map(|p| format!("{}/{}", p, name)),
            None => live_paths.get(&ino).and_then(|p| p.first()).map(|p| if p == "/" { String::new() } else { p.clone() }),
        };
        visiting.remove(&ino);
        r
    }

    let mut rows = Vec::new();
    for i in &deleted {
        let path = name_at(i.num, u32::MAX, &jnames, &live_paths, 0, &mut HashSet::new()).unwrap_or_else(|| format!("/[UNKNOWN]/inode_{}", i.num));
        let name = format!("{} (deleted)", path);
        rows_for(i, &name, source::EXT4, &indicators(i, &name, &[]), &mut rows);
    }

    // Older states: dedupe against the live inode and across copies.
    let mut seen: HashSet<Inode> = live_inodes.values().cloned().collect();
    seen.extend(deleted.iter().cloned());
    let mut backdated: HashSet<u32> = HashSet::new();
    for (seq, offset, st) in &states {
        if !seen.insert(st.clone()) {
            continue;
        }
        report.journal_states_new += 1;
        let mut extra = Vec::new();
        if let Some(live_i) = live_inodes.get(&st.num) {
            // Same incarnation (creation time agrees) and the older copy is later: moved back.
            let same_file = st.crtime.is_some() && st.crtime == live_i.crtime;
            if same_file && st.ctime.0 <= live_i.ctime.0 && (st.mtime.0 > live_i.mtime.0 + 1) {
                extra.push(anomaly::BACKDATED);
                backdated.insert(st.num);
            }
        }
        let mut path = name_at(st.num, *seq, &jnames, &live_paths, 0, &mut HashSet::new()).unwrap_or_else(|| format!("/[UNKNOWN]/inode_{}", st.num));
        if path.is_empty() {
            path = "/".to_string();
        }
        let status = if st.is_deleted() { " (deleted)" } else { "" };
        let name = format!("{}{} (carved @0x{:X})", path, status, offset);
        rows_for(st, &name, source::CARVED, &indicators(st, &name, &extra), &mut rows);
    }
    report.backdated = backdated.len();
    for e in out.iter_mut() {
        if let Ok(n) = e.meta.parse::<u32>() {
            if backdated.contains(&n) {
                e.flags = anomaly::add_to_column(&e.flags, anomaly::BACKDATED);
            }
        }
    }

    // Row-level dedupe: a carved row that repeats a live row says nothing new.
    let key = |e: &TimelineEntry| {
        let n = e.file_name.rfind(" (carved @0x").map_or(e.file_name.as_str(), |i| &e.file_name[..i]);
        (e.timestamp_secs, e.timestamp_nanos, e.macb.clone(), e.size, e.meta.clone(), n.to_string())
    };
    let mut seen_rows: HashSet<_> = out.iter().map(key).collect();
    for r in rows {
        if seen_rows.insert(key(&r)) {
            out.push(r);
        } else {
            report.rows_duplicate += 1;
        }
    }
    Ok((out, report))
}

/// Byte extent of the filesystem at `base` and its free space, for the carver.
pub fn free_space<R: Read + Seek>(reader: R, base: u64) -> Option<((u64, u64), Vec<(u64, u64)>)> {
    let mut fs = Ext4Raw::open(reader, base).ok()?;
    let extent = fs.extent();
    Some((extent, fs.free_ranges()))
}

/// One-line summary for stderr.
pub fn describe(r: &Ext4RawReport, carve: bool) -> String {
    let mut s = format!("{} live entries, {} deleted inode(s) still in the tables", r.live_entries, r.deleted_inodes);
    if carve {
        s.push_str(&format!(
            "; journal: {} block copies, {} inode states of which {} not live, {} names; {} row(s) identical to live rows dropped",
            r.journal_copies, r.journal_inode_states, r.journal_states_new, r.journal_names, r.rows_duplicate
        ));
        if r.backdated > 0 {
            s.push_str(&format!("; {} inode(s) BACKDATED", r.backdated));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_decoding_extends_the_epoch() {
        assert_eq!(decode_ts(1_700_000_000, None), (1_700_000_000, 0));
        // 2050-01-01: the low 32 bits read as a negative i32, so the kernel
        // stores epoch bits = 1 to land in 2038..2106.
        let secs = 2_524_608_000i64;
        let lo = (secs & 0xFFFF_FFFF) as u32;
        let epoch = ((secs - i64::from(lo as i32)) >> 32) as u32;
        assert_eq!(epoch, 1);
        let extra = epoch | (123_456_789u32 << 2);
        assert_eq!(decode_ts(lo, Some(extra)), (secs, 123_456_789));
        // pre-1970 with no extra field: sign-extended
        assert_eq!(decode_ts((-100i32) as u32, None), (-100, 0));
    }

    #[test]
    fn dir_block_parsing_skips_tails_and_dx_nodes() {
        let mut b = vec![0u8; 64];
        // "." -> inode 2, rec_len 12
        b[0..4].copy_from_slice(&2u32.to_le_bytes());
        b[4..6].copy_from_slice(&12u16.to_le_bytes());
        b[6] = 1;
        b[7] = 2;
        b[8] = b'.';
        // "x.txt" -> inode 12, rec_len 40 (covers the rest minus the tail)
        b[12..16].copy_from_slice(&12u32.to_le_bytes());
        b[16..18].copy_from_slice(&40u16.to_le_bytes());
        b[18] = 5;
        b[19] = 1;
        b[20..25].copy_from_slice(b"x.txt");
        // csum tail: inode 0, rec_len 12
        b[52..56].copy_from_slice(&0u32.to_le_bytes());
        b[56..58].copy_from_slice(&12u16.to_le_bytes());
        b[59] = 0xDE;
        let e = parse_dir_block(&b);
        assert_eq!(e.len(), 2);
        assert_eq!((e[1].inode, e[1].name.as_str()), (12, "x.txt"));
        assert!(dir_block_is_whole(&b));
        assert!(!dir_block_is_whole(&vec![0xFFu8; 64]));
    }

    #[test]
    fn inode_parsing_reads_extra_fields() {
        let mut raw = vec![0u8; 256];
        raw[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
        raw[4..8].copy_from_slice(&1234u32.to_le_bytes());
        raw[12..16].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // ctime
        raw[16..20].copy_from_slice(&1_600_000_000u32.to_le_bytes()); // mtime
        raw[26..28].copy_from_slice(&1u16.to_le_bytes());
        raw[0x80..0x82].copy_from_slice(&32u16.to_le_bytes());
        raw[0x90..0x94].copy_from_slice(&1_500_000_000u32.to_le_bytes()); // crtime
        raw[0x94..0x98].copy_from_slice(&(7u32 << 2).to_le_bytes());
        let i = parse_inode(&raw, 42).unwrap();
        assert_eq!(i.num, 42);
        assert_eq!(i.size, 1234);
        assert_eq!(i.mtime, (1_600_000_000, 0));
        assert_eq!(i.crtime, Some((1_500_000_000, 7)));
        assert!(!i.is_deleted());
        assert_eq!(i.mode_string(), "-rw-r--r--");
        raw[20..24].copy_from_slice(&1_700_000_100u32.to_le_bytes()); // dtime
        raw[26..28].copy_from_slice(&0u16.to_le_bytes());
        assert!(parse_inode(&raw, 42).unwrap().is_deleted());
    }
}
