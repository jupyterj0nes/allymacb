//! XFS, the default filesystem of RHEL, Rocky, Alma, Oracle Linux and
//! CentOS, read through the `rust-fs-xfs` driver (the one faramir uses).
//!
//! * The **live timeline** comes from a walk of the directory tree from the
//!   superblock's root inode. Every inode carries four times with
//!   nanoseconds: `mtime`, `atime`, `ctime` and, on v5 filesystems (the
//!   default since RHEL 7.3), the creation time `crtime`.
//! * **Every inode the allocation groups know** is read from their inode
//!   B+trees, used or free. A used inode no path reaches is reported under
//!   `/[UNKNOWN]`. A free inode that was once used keeps its creation time
//!   and the times of its last change, usually the deletion: XFS clears the
//!   mode and the extents of a freed inode but not its timestamps.
//! * **Names of deleted files** survive in the directory blocks. Removing an
//!   entry only overwrites its first four bytes with a free tag and a length;
//!   the low half of the inode number, the name length and the name stay
//!   until the space is reused. A free inode whose number matches such a
//!   remnant gets its path back, tagged `(dir slack)`. Short-form
//!   directories (a handful of entries, kept inside the inode) are compacted
//!   on removal and keep nothing.
//!
//! The log holds logical operations, not block copies, so there is no
//! equivalent of the ext4 journal's older inode states.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use fs_core::BlockRead;
use fs_xfs::inode::{Format, Inode};
use fs_xfs::inode_btree::Trees;
use fs_xfs::{Filesystem, Superblock};

use crate::anomaly;
use crate::error::{AllyError, ErrorCode, Result};
use crate::hunt::{self, HuntRecord};
use crate::parsers::ext4::mode_bits_to_string;
use crate::timefmt::format_unix_timestamp;
use crate::timeline::{deleted, join_macb_flags, source, TimelineEntry};

/// XFS superblock magic, at byte 0 of the volume.
pub const XFS_MAGIC: &[u8; 4] = b"XFSB";
/// Directory nesting followed before a subtree is abandoned.
const MAX_DIR_DEPTH: usize = 256;
/// Directory data we read from one directory to look for removed names.
const MAX_DIR_BYTES: u64 = 64 << 20;
/// Directory data blocks live below this byte offset of the directory; the
/// leaf and free-index blocks sit above it.
const DIR_LEAF_OFFSET: u64 = 32 << 30;
/// Freed-entry tag of a directory data block.
const DIR_FREE_TAG: u16 = 0xFFFF;
const DIR_DATA_MAGIC_V5: &[u8; 4] = b"XDD3";
const DIR_BLOCK_MAGIC_V5: &[u8; 4] = b"XDB3";
const DIR_DATA_MAGIC_V4: &[u8; 4] = b"XD2D";
const DIR_BLOCK_MAGIC_V4: &[u8; 4] = b"XD2B";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct XfsReport {
    pub live_entries: usize,
    pub unreachable: usize,
    pub deleted_inodes: usize,
    pub named_from_slack: usize,
    pub unreadable_inodes: usize,
}

/// One-line summary for stderr.
pub fn describe(r: &XfsReport) -> String {
    let mut s = format!(
        "{} live entries, {} freed inode(s) with their times, {} named again from directory slack",
        r.live_entries, r.deleted_inodes, r.named_from_slack
    );
    if r.unreachable > 0 {
        s.push_str(&format!(", {} in-use inode(s) no path reaches", r.unreachable));
    }
    if r.unreadable_inodes > 0 {
        s.push_str(&format!(", {} inode(s) unreadable", r.unreadable_inodes));
    }
    s
}

/// Seconds and nanoseconds.
type Ts = (i64, u32);

fn ts(t: &fs_xfs::inode::Timestamp) -> Ts {
    (t.sec, t.nsec)
}

/// The four times of an inode; `crtime` only where the format has it.
struct Times {
    m: Ts,
    a: Ts,
    c: Ts,
    b: Option<Ts>,
}

fn times(i: &Inode) -> Times {
    Times { m: ts(&i.mtime), a: ts(&i.atime), c: ts(&i.ctime), b: (i.version == 3 && i.crtime.sec != 0).then(|| ts(&i.crtime)) }
}

/// `ls -l` style mode; `ftype` stands in for the type a freed inode lost.
fn mode_string(mode: u16, ftype: Option<char>) -> String {
    let t = match mode & 0xF000 {
        0x4000 => 'd',
        0xA000 => 'l',
        0x2000 => 'c',
        0x6000 => 'b',
        0x1000 => 'p',
        0xC000 => 's',
        0x8000 => '-',
        _ => ftype.unwrap_or('-'),
    };
    format!("{}{}", t, mode_bits_to_string(mode & 0o7777))
}

/// Type character of a directory entry's file type byte.
fn ftype_char(raw: u8) -> Option<char> {
    match raw {
        1 => Some('-'),
        2 => Some('d'),
        3 => Some('c'),
        4 => Some('b'),
        5 => Some('p'),
        6 => Some('s'),
        7 => Some('l'),
        _ => None,
    }
}

struct Rows<'a> {
    volume: u32,
    rootino: u64,
    out: &'a mut Vec<TimelineEntry>,
}

impl Rows<'_> {
    fn push(&mut self, ino: u64, i: &Inode, name: &str, mode: &str, deleted_kind: &'static str, hunt: &Option<Arc<HuntRecord>>) {
        let t = times(i);
        let mut f = anomaly::unix_flags(Some(t.m.0), Some(t.c.0), t.b.map(|b| b.0), anomaly::now_secs());
        for x in anomaly::name_flags(name) {
            if !f.contains(&x) {
                f.push(x);
            }
        }
        let flags = anomaly::column(&f);
        let mut by_time: HashMap<Ts, String> = HashMap::new();
        for (v, c) in [(Some(t.m), 'm'), (Some(t.a), 'a'), (Some(t.c), 'c'), (t.b, 'b')] {
            if let Some(v) = v.filter(|v| *v != (0, 0)) {
                let cur = by_time.entry(v).or_insert_with(|| "....".to_string());
                *cur = join_macb_flags(cur, c);
            }
        }
        for ((secs, nanos), macb) in by_time {
            if let Some(iso) = format_unix_timestamp(secs, nanos) {
                self.out.push(
                    TimelineEntry::new(iso, secs, nanos, i.size, macb, mode.to_string(), i.uid, i.gid, ino.to_string(), name.to_string())
                        .with_source(source::XFS)
                        .with_flags(flags.clone())
                        .with_deleted(deleted_kind)
                        .with_hunt(hunt.clone()),
                );
            }
        }
    }

    fn hunt(&self, ino: u64, i: &Inode) -> Option<Arc<HuntRecord>> {
        let t = times(i);
        let macb = hunt::Macb { m: hunt::unix_ts(t.m), a: hunt::unix_ts(t.a), c: hunt::unix_ts(t.c), b: t.b.and_then(hunt::unix_ts) };
        Some(hunt::record(self.volume, hunt::Evidence::Unix { inode: ino, t: macb, root: ino == self.rootino }))
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Absolute inode number of inode `n` of a chunk in allocation group `agno`.
fn ino_of(sb: &Superblock, agno: u32, agino: u32) -> u64 {
    (u64::from(agno) << (u32::from(sb.agblklog) + u32::from(sb.inopblog))) | u64::from(agino)
}

/// Byte offset of a filesystem block number (allocation group in the high bits).
fn fsb_to_byte(sb: &Superblock, fsb: u64) -> u64 {
    let agno = fsb >> sb.agblklog;
    let agbno = fsb & ((1u64 << sb.agblklog) - 1);
    (agno * u64::from(sb.agblocks) + agbno) * u64::from(sb.blocksize)
}

/// Inodes the filesystem keeps for itself (quota, realtime), not files.
fn internal(sb: &Superblock, ino: u64) -> bool {
    ino != 0 && [sb.rbmino, sb.rsumino, sb.uquotino, sb.gquotino, sb.pquotino].contains(&ino)
}

/// A name left in the free space of a directory data block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackName {
    /// Low 32 bits of the inode number: the high half was overwritten.
    pub ino_lo: u32,
    pub name: String,
    pub ftype: Option<char>,
}

/// Names of removed entries in one directory data block. `header` is the
/// size of the block header, `end` where the entries stop (the leaf area of
/// a single-block directory).
pub fn slack_names(block: &[u8], header: usize, end: usize, has_ftype: bool) -> Vec<SlackName> {
    let be16 = |o: usize| u16::from_be_bytes([block[o], block[o + 1]]);
    let entry_len = |namelen: usize| (8 + 1 + namelen + usize::from(has_ftype) + 2).div_ceil(8) * 8;
    let end = end.min(block.len());
    let mut out = Vec::new();
    let mut off = header;
    while off + 4 <= end {
        if be16(off) == DIR_FREE_TAG {
            let len = usize::from(be16(off + 2));
            if len < 8 || len % 8 != 0 || off + len > end {
                break;
            }
            // Removed entries merged into this free run, one after another:
            // the first one starts with the tag, the next ones are whole.
            let region = &block[off..off + len];
            let mut o = 0usize;
            while o + 12 <= region.len() {
                let ino_lo = u32::from_be_bytes([region[o + 4], region[o + 5], region[o + 6], region[o + 7]]);
                let namelen = usize::from(region[o + 8]);
                let size = entry_len(namelen);
                if namelen == 0 || o + size > region.len() {
                    break;
                }
                let raw = &region[o + 9..o + 9 + namelen];
                let ok = ino_lo != 0 && raw.iter().all(|&b| b != 0 && b != b'/') && raw != b"." && raw != b"..";
                if !ok {
                    break;
                }
                let ftype = if has_ftype { ftype_char(region[o + 9 + namelen]) } else { None };
                out.push(SlackName { ino_lo, name: String::from_utf8_lossy(raw).into_owned(), ftype });
                o += size;
            }
            off += len;
        } else {
            // A live entry: inode number, name length, name, file type, tag.
            if off + 9 > end {
                break;
            }
            let namelen = usize::from(block[off + 8]);
            if namelen == 0 {
                break;
            }
            off += entry_len(namelen);
        }
    }
    out
}

/// Removed names found in the data blocks of one directory.
fn dir_slack(fs: &Filesystem, dev: &dyn BlockRead, i: &Inode, raw: &[u8]) -> Vec<SlackName> {
    let sb = fs.superblock();
    if !matches!(i.format, Format::Extents | Format::Btree) {
        return Vec::new();
    }
    let Ok(extents) = fs.data_extents(i, raw) else { return Vec::new() };
    let bs = u64::from(sb.blocksize);
    let dbs = bs << sb.dirblklog;
    let v5 = sb.is_v5();
    let has_ftype = sb.has_ftype();
    let mut out = Vec::new();
    let mut read = 0u64;
    for e in extents {
        if e.unwritten || e.startoff * bs >= DIR_LEAF_OFFSET {
            continue;
        }
        let bytes = (e.blockcount * bs).min(DIR_LEAF_OFFSET - e.startoff * bs);
        let start = fsb_to_byte(sb, e.startblock);
        let mut pos = 0u64;
        while pos + dbs <= bytes && read < MAX_DIR_BYTES {
            let mut block = vec![0u8; dbs as usize];
            if dev.read_at(start + pos, &mut block).is_err() {
                break;
            }
            read += dbs;
            pos += dbs;
            let magic = &block[0..4];
            let header = if v5 { 64 } else { 16 };
            let end = if magic == DIR_BLOCK_MAGIC_V5 || magic == DIR_BLOCK_MAGIC_V4 {
                // Single-block directory: the leaf entries and a tail of
                // (count, stale) sit at the end of the block.
                let n = block.len();
                let count = u32::from_be_bytes([block[n - 8], block[n - 7], block[n - 6], block[n - 5]]) as usize;
                n.saturating_sub(8 + count * 8)
            } else if magic == DIR_DATA_MAGIC_V5 || magic == DIR_DATA_MAGIC_V4 {
                block.len()
            } else {
                continue;
            };
            out.extend(slack_names(&block, header, end, has_ftype));
        }
    }
    out
}

/// Timeline of an XFS filesystem on `device`.
pub fn parse_xfs(device: Arc<dyn BlockRead>) -> Result<(Vec<TimelineEntry>, XfsReport)> {
    let fs = Filesystem::mount(Arc::clone(&device)).map_err(|e| AllyError::Ext4 { code: ErrorCode::XfsSuperblockInvalid, message: format!("XFS: {e}") })?;
    let sb = fs.superblock().clone();
    let dev: &dyn BlockRead = device.as_ref();
    let mut report = XfsReport::default();
    let mut out = Vec::new();
    let mut rows = Rows { volume: hunt::new_volume(), rootino: sb.rootino, out: &mut out };
    fs.read_inode_raw(sb.rootino).map_err(|e| AllyError::Ext4 { code: ErrorCode::XfsMetadataReadFailed, message: format!("XFS root directory (inode {}): {e}", sb.rootino) })?;

    // --- live tree ----------------------------------------------------------
    let mut paths: HashMap<u64, Vec<String>> = HashMap::new();
    let mut dirs: Vec<(u64, String)> = Vec::new();
    let mut seen_dirs: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(u64, String, usize)> = VecDeque::new();
    paths.entry(sb.rootino).or_default().push("/".to_string());
    queue.push_back((sb.rootino, "/".to_string(), 0));
    seen_dirs.insert(sb.rootino);
    while let Some((ino, path, depth)) = queue.pop_front() {
        let Ok((dir, raw)) = fs.read_inode_raw(ino) else {
            report.unreadable_inodes += 1;
            continue;
        };
        if !dir.is_dir() {
            continue;
        }
        dirs.push((ino, path.clone()));
        let Ok(entries) = fs.read_dir(&dir, &raw) else {
            report.unreadable_inodes += 1;
            continue;
        };
        for e in entries {
            if e.name == b"." || e.name == b".." || e.ino == 0 {
                continue;
            }
            let child = join(&path, &String::from_utf8_lossy(&e.name));
            paths.entry(e.ino).or_default().push(child.clone());
            let is_dir = match e.ftype {
                Some(t) => t == fs_xfs::inode::FileType::Directory,
                None => fs.read_inode(e.ino).map(|i| i.is_dir()).unwrap_or(false),
            };
            if is_dir && depth < MAX_DIR_DEPTH && seen_dirs.insert(e.ino) {
                queue.push_back((e.ino, child, depth + 1));
            }
        }
    }

    // --- names left in directory slack ----------------------------------------
    let mut slack: HashMap<u32, Vec<(String, Option<char>)>> = HashMap::new();
    for (ino, path) in &dirs {
        if let Ok((i, raw)) = fs.read_inode_raw(*ino) {
            for s in dir_slack(&fs, dev, &i, &raw) {
                slack.entry(s.ino_lo).or_default().push((join(path, &s.name), s.ftype));
            }
        }
    }

    // --- every inode of every allocation group -------------------------------
    let mut deleted_seen = 0usize;
    for agno in 0..sb.agcount {
        let Ok(trees) = Trees::open(&sb, dev, agno) else {
            report.unreadable_inodes += 1;
            continue;
        };
        let isize = usize::from(sb.inodesize);
        for chunk in trees.chunks() {
            // The 64 inodes of a chunk sit side by side: one read for all.
            let first = ino_of(&sb, agno, chunk.startino);
            let mut buf = vec![0u8; 64 * isize];
            let whole = fs.inode_offset(first).is_ok_and(|off| dev.read_at(off, &mut buf).is_ok());
            for n in 0..64u8 {
                if !chunk.exists(n) {
                    continue;
                }
                let ino = ino_of(&sb, agno, chunk.startino + u32::from(n));
                if internal(&sb, ino) {
                    continue;
                }
                let parsed = if whole {
                    Inode::parse(&buf[usize::from(n) * isize..(usize::from(n) + 1) * isize], &sb, ino)
                } else {
                    fs.read_inode(ino)
                };
                let Ok(i) = parsed else {
                    if !chunk.is_free(n) {
                        report.unreadable_inodes += 1;
                    }
                    continue;
                };
                let h = rows.hunt(ino, &i);
                if !chunk.is_free(n) {
                    let mode = mode_string(i.mode, None);
                    let gone = if i.nlink == 0 { deleted::UNALLOCATED } else { "" };
                    match paths.get(&ino) {
                        Some(ps) => {
                            for p in ps {
                                rows.push(ino, &i, p, &mode, gone, &h);
                                report.live_entries += 1;
                            }
                        }
                        None => {
                            rows.push(ino, &i, &format!("/[UNKNOWN]/inode_{ino}"), &mode, gone, &h);
                            report.unreachable += 1;
                        }
                    }
                    continue;
                }
                // A free inode that was never used has no times at all.
                let t = times(&i);
                if t.m == (0, 0) && t.c == (0, 0) && t.a == (0, 0) && t.b.is_none() {
                    continue;
                }
                deleted_seen += 1;
                let named = slack.get(&(ino as u32)).filter(|v| !v.is_empty());
                match named {
                    Some(names) => {
                        report.named_from_slack += 1;
                        for (p, ft) in names {
                            rows.push(ino, &i, &format!("{p} (dir slack)"), &mode_string(i.mode, *ft), deleted::UNALLOCATED, &h);
                        }
                    }
                    None => rows.push(ino, &i, &format!("/[UNKNOWN]/inode_{ino}"), &mode_string(i.mode, None), deleted::UNALLOCATED, &h),
                }
            }
        }
    }
    report.deleted_inodes = deleted_seen;
    Ok((out, report))
}

/// Free space of the filesystem as `(start, len)` byte ranges relative to
/// the volume, for the log carver; `None` when the free-space trees cannot
/// be read.
pub fn free_ranges(device: Arc<dyn BlockRead>) -> Option<(u64, Vec<(u64, u64)>)> {
    let fs = Filesystem::mount(device).ok()?;
    let sb = fs.superblock().clone();
    let bs = u64::from(sb.blocksize);
    let mut out = Vec::new();
    for agno in 0..sb.agcount {
        for e in fs.free_extents(agno).ok()? {
            let start = (u64::from(agno) * u64::from(sb.agblocks) + u64::from(e.startblock)) * bs;
            out.push((start, u64::from(e.blockcount) * bs));
        }
    }
    out.sort_unstable();
    Some((sb.dblocks * bs, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A v5 data block (64-byte header) with one live entry, then a free run
    /// holding two removed entries.
    fn block() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0..4].copy_from_slice(DIR_DATA_MAGIC_V5);
        // live: ino 131, "keep.txt", ftype 1, tag
        let mut o = 64;
        b[o..o + 8].copy_from_slice(&131u64.to_be_bytes());
        b[o + 8] = 8;
        b[o + 9..o + 17].copy_from_slice(b"keep.txt");
        b[o + 17] = 1;
        o += 24; // 8 + 1 + 8 + 1 + 2 = 20, rounded to 24
        // A free run with two removed entries: "gone" (8 + 1 + 4 + 1 + 2 = 16
        // bytes) then "gone.service" (24 bytes). Removal overwrote the first
        // four bytes of the first one with the tag and the run's length.
        let first = o;
        b[first..first + 8].copy_from_slice(&0x85u64.to_be_bytes());
        b[first + 8] = 4;
        b[first + 9..first + 13].copy_from_slice(b"gone");
        b[first + 13] = 1;
        let second = first + 16;
        b[second..second + 8].copy_from_slice(&0x86u64.to_be_bytes());
        b[second + 8] = 12;
        b[second + 9..second + 21].copy_from_slice(b"gone.service");
        b[second + 21] = 1;
        b[first..first + 2].copy_from_slice(&DIR_FREE_TAG.to_be_bytes());
        b[first + 2..first + 4].copy_from_slice(&40u16.to_be_bytes());
        // the rest of the block is one more free run with nothing in it
        let rest = first + 40;
        b[rest..rest + 2].copy_from_slice(&DIR_FREE_TAG.to_be_bytes());
        b[rest + 2..rest + 4].copy_from_slice(&((512 - rest) as u16).to_be_bytes());
        b
    }

    #[test]
    fn removed_names_come_back_from_the_free_runs() {
        let names = slack_names(&block(), 64, 512, true);
        assert_eq!(
            names,
            vec![
                SlackName { ino_lo: 0x85, name: "gone".into(), ftype: Some('-') },
                SlackName { ino_lo: 0x86, name: "gone.service".into(), ftype: Some('-') },
            ]
        );
    }

    #[test]
    fn modes_keep_the_type_a_freed_inode_lost() {
        assert_eq!(mode_string(0o100644, None), "-rw-r--r--");
        assert_eq!(mode_string(0o040755, None), "drwxr-xr-x");
        assert_eq!(mode_string(0, Some('d')), "d---------");
    }
}
