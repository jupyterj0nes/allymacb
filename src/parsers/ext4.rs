use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use ext4_view::{Ext4, Ext4Read, FileType, PathBuf as Ext4PathBuf};

use crate::error::{AllyError, ErrorCode, Result};
use crate::timefmt::format_unix_timestamp;
use crate::anomaly;
use crate::timeline::{join_macb_flags, source, TimelineEntry};

/// Maximum directory nesting followed before a subtree is abandoned. Protects
/// against crafted images whose directory entries point back at an ancestor
/// (ext4-view resolves by path and has no loop detection of its own).
pub const MAX_DIR_DEPTH: usize = 256;

pub struct PartitionReader<R: Read + Seek> {
    inner: Arc<Mutex<R>>,
    offset: u64,
}

impl<R: Read + Seek> PartitionReader<R> {
    pub fn new(inner: Arc<Mutex<R>>, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<R: Read + Seek + Send + 'static> Ext4Read for PartitionReader<R> {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn core::error::Error + Send + Sync + 'static>> {
        let mut guard = self.inner.lock().map_err(|_| "Mutex poisoned")?;
        guard.seek(SeekFrom::Start(self.offset + start_byte))?;
        guard.read_exact(dst)?;
        Ok(())
    }
}

/// Renders the 12 permission bits (rwx for user/group/other plus setuid,
/// setgid and sticky) in `ls -l` notation. Nine characters, no type prefix.
pub fn mode_bits_to_string(mode: u16) -> String {
    let suid = mode & 0o4000 != 0;
    let sgid = mode & 0o2000 != 0;
    let sticky = mode & 0o1000 != 0;

    let user_r = if mode & 0o400 != 0 { 'r' } else { '-' };
    let user_w = if mode & 0o200 != 0 { 'w' } else { '-' };
    let user_x = match (mode & 0o100 != 0, suid) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    };

    let group_r = if mode & 0o040 != 0 { 'r' } else { '-' };
    let group_w = if mode & 0o020 != 0 { 'w' } else { '-' };
    let group_x = match (mode & 0o010 != 0, sgid) {
        (true, true) => 's',
        (false, true) => 'S',
        (true, false) => 'x',
        (false, false) => '-',
    };

    let other_r = if mode & 0o004 != 0 { 'r' } else { '-' };
    let other_w = if mode & 0o002 != 0 { 'w' } else { '-' };
    let other_x = match (mode & 0o001 != 0, sticky) {
        (true, true) => 't',
        (false, true) => 'T',
        (true, false) => 'x',
        (false, false) => '-',
    };

    format!("{user_r}{user_w}{user_x}{group_r}{group_w}{group_x}{other_r}{other_w}{other_x}")
}

/// `ls -l` type character for an ext4 file type.
pub fn file_type_char(ft: FileType) -> char {
    match ft {
        FileType::Directory => 'd',
        FileType::Symlink => 'l',
        FileType::BlockDevice => 'b',
        FileType::CharacterDevice => 'c',
        FileType::Fifo => 'p',
        FileType::Socket => 's',
        _ => '-',
    }
}

pub fn mode_to_string(mode: u16, is_dir: bool, is_symlink: bool) -> String {
    let file_char = if is_dir {
        'd'
    } else if is_symlink {
        'l'
    } else {
        '-'
    };
    format!("{}{}", file_char, mode_bits_to_string(mode))
}

/// Statistics about what could not be read, so the caller can tell the
/// analyst that the timeline is incomplete instead of silently omitting data.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ext4WalkReport {
    pub entries_ok: usize,
    /// Inodes whose metadata could not be decoded (ext4-view rejects
    /// timestamps with the high bit set, i.e. pre-1970 or post-2038 values).
    pub metadata_failed: usize,
    pub dirs_failed: usize,
    pub depth_limited: usize,
    pub sample_errors: Vec<String>,
}

const MAX_SAMPLE_ERRORS: usize = 5;

impl Ext4WalkReport {
    fn note(&mut self, msg: String) {
        if self.sample_errors.len() < MAX_SAMPLE_ERRORS {
            self.sample_errors.push(msg);
        }
    }
}

pub fn parse_ext4_partition<R: Read + Seek + Send + 'static>(
    reader: Arc<Mutex<R>>,
    partition_offset: u64,
) -> Result<Vec<TimelineEntry>> {
    let (timeline, report) = parse_ext4_partition_with_report(reader, partition_offset)?;
    if report.metadata_failed > 0 || report.dirs_failed > 0 || report.depth_limited > 0 {
        eprintln!(
            "[!] ext4 @0x{:X}: {} entries timelined, {} inodes unreadable, {} directories unreadable, {} subtrees cut at depth {}",
            partition_offset,
            report.entries_ok,
            report.metadata_failed,
            report.dirs_failed,
            report.depth_limited,
            MAX_DIR_DEPTH
        );
        for msg in &report.sample_errors {
            eprintln!("    {}", msg);
        }
    }
    Ok(timeline)
}

pub fn parse_ext4_partition_with_report<R: Read + Seek + Send + 'static>(
    reader: Arc<Mutex<R>>,
    partition_offset: u64,
) -> Result<(Vec<TimelineEntry>, Ext4WalkReport)> {
    let part_reader = PartitionReader::new(reader, partition_offset);
    let fs = Ext4::load(Box::new(part_reader)).map_err(|e| AllyError::Ext4 {
        code: ErrorCode::Ext4SuperblockInvalid,
        message: format!("Failed loading ext4 filesystem at offset 0x{:X}: {:?}", partition_offset, e),
    })?;

    let mut timeline = Vec::new();
    let mut report = Ext4WalkReport::default();

    // Stack of (raw byte path, depth). Paths are kept as raw bytes so that
    // directories whose names are not valid UTF-8 can still be re-opened.
    let root = Ext4PathBuf::try_from("/").map_err(|e| AllyError::Ext4 {
        code: ErrorCode::Ext4DirectoryTraversalFailed,
        message: format!("Invalid root path: {:?}", e),
    })?;
    let mut stack: Vec<(Ext4PathBuf, usize)> = vec![(root, 0)];

    while let Some((current_path, depth)) = stack.pop() {
        let read_dir = match fs.read_dir(&current_path) {
            Ok(rd) => rd,
            Err(e) => {
                report.dirs_failed += 1;
                report.note(format!("read_dir {} failed: {:?}", current_path.display(), e));
                continue;
            }
        };

        for entry_res in read_dir {
            let entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    report.dirs_failed += 1;
                    report.note(format!("dir entry under {} unreadable: {:?}", current_path.display(), e));
                    continue;
                }
            };

            let name = entry.file_name();
            let name_bytes: &[u8] = name.as_ref();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }

            let entry_path = entry.path();
            let display_path = entry_path.display().to_string();
            let entry_type = entry.file_type().ok();
            let is_dir = entry_type == Some(FileType::Directory);

            let meta = match entry.metadata() {
                Ok(m) => Some(m),
                Err(e) => {
                    report.metadata_failed += 1;
                    report.note(format!("inode metadata for {} unreadable: {:?}", display_path, e));
                    None
                }
            };

            if let Some(meta) = meta {
                let ft = meta.file_type();
                let size = meta.len();
                let mode_str = format!("{}{}", file_type_char(ft), mode_bits_to_string(meta.mode()));
                let uid = meta.uid();
                let gid = meta.gid();

                let mut ts_map: HashMap<(i64, u32), String> = HashMap::new();

                // Note: ext4-view 1.0 exposes no accessor for ctime (inode change
                // time) nor for the inode number, so 'c' rows and the meta column
                // cannot be populated from this crate.
                let m_ts = meta.modified();
                let key = (m_ts.seconds(), m_ts.nanoseconds());
                let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'm');

                let a_ts = meta.accessed();
                let key = (a_ts.seconds(), a_ts.nanoseconds());
                let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'a');

                if let Some(c_ts) = meta.created() {
                    let key = (c_ts.seconds(), c_ts.nanoseconds());
                    let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
                    *current = join_macb_flags(current, 'b');
                }

                let flags = anomaly::column(
                    &[
                        anomaly::unix_flags(Some(m_ts.seconds()), None, meta.created().map(|c| c.seconds()), anomaly::now_secs()),
                        anomaly::name_flags(&display_path),
                    ]
                    .concat(),
                );

                for ((secs, nanos), macb) in ts_map {
                    // 0 means "never set" on ext4; negative values are real
                    // (pre-1970) and are a timestomping indicator, so keep them.
                    if secs == 0 && nanos == 0 {
                        continue;
                    }
                    if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
                        timeline.push(TimelineEntry::new(
                            ts_iso,
                            secs,
                            nanos,
                            size,
                            macb,
                            mode_str.clone(),
                            uid,
                            gid,
                            "0".to_string(),
                            display_path.clone(),
                        ).with_source(source::EXT4).with_flags(flags.clone()));
                    }
                }
                report.entries_ok += 1;
            }

            // Recurse into directories even when their inode metadata could not
            // be decoded: the children are still reachable through the dir entry.
            if is_dir {
                if depth + 1 > MAX_DIR_DEPTH {
                    report.depth_limited += 1;
                    report.note(format!("subtree {} exceeds depth limit", display_path));
                } else {
                    stack.push((entry_path, depth + 1));
                }
            }
        }
    }

    Ok((timeline, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_bits() {
        assert_eq!(mode_bits_to_string(0o4755), "rwsr-xr-x");
        assert_eq!(mode_bits_to_string(0o4644), "rwSr--r--");
        assert_eq!(mode_bits_to_string(0o2755), "rwxr-sr-x");
        assert_eq!(mode_bits_to_string(0o1777), "rwxrwxrwt");
        assert_eq!(mode_bits_to_string(0o1776), "rwxrwxrwT");
    }

    #[test]
    fn test_file_type_chars() {
        assert_eq!(file_type_char(FileType::BlockDevice), 'b');
        assert_eq!(file_type_char(FileType::CharacterDevice), 'c');
        assert_eq!(file_type_char(FileType::Fifo), 'p');
        assert_eq!(file_type_char(FileType::Socket), 's');
        assert_eq!(file_type_char(FileType::Directory), 'd');
        assert_eq!(file_type_char(FileType::Symlink), 'l');
        assert_eq!(file_type_char(FileType::Regular), '-');
    }
}
