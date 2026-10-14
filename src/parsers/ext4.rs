use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use ext4_view::{Ext4, Ext4Read};

use crate::error::{AllyError, ErrorCode, Result};
use crate::timefmt::format_unix_timestamp;
use crate::timeline::{join_macb_flags, TimelineEntry};

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

pub fn mode_to_string(mode: u16, is_dir: bool, is_symlink: bool) -> String {
    let file_char = if is_dir {
        'd'
    } else if is_symlink {
        'l'
    } else {
        '-'
    };

    let user_r = if mode & 0o400 != 0 { 'r' } else { '-' };
    let user_w = if mode & 0o200 != 0 { 'w' } else { '-' };
    let user_x = if mode & 0o100 != 0 { 'x' } else { '-' };

    let group_r = if mode & 0o040 != 0 { 'r' } else { '-' };
    let group_w = if mode & 0o020 != 0 { 'w' } else { '-' };
    let group_x = if mode & 0o010 != 0 { 'x' } else { '-' };

    let other_r = if mode & 0o004 != 0 { 'r' } else { '-' };
    let other_w = if mode & 0o002 != 0 { 'w' } else { '-' };
    let other_x = if mode & 0o001 != 0 { 'x' } else { '-' };

    format!("{file_char}{user_r}{user_w}{user_x}{group_r}{group_w}{group_x}{other_r}{other_w}{other_x}")
}

pub fn parse_ext4_partition<R: Read + Seek + Send + 'static>(
    reader: Arc<Mutex<R>>,
    partition_offset: u64,
) -> Result<Vec<TimelineEntry>> {
    let part_reader = PartitionReader::new(reader, partition_offset);
    let fs = Ext4::load(Box::new(part_reader)).map_err(|e| AllyError::Ext4 {
        code: ErrorCode::Ext4SuperblockInvalid,
        message: format!("Failed loading ext4 filesystem at offset 0x{:X}: {:?}", partition_offset, e),
    })?;

    let mut timeline = Vec::new();
    let mut stack = vec!["/".to_string()];

    while let Some(current_path) = stack.pop() {
        let read_dir = match fs.read_dir(&current_path) {
            Ok(rd) => rd,
            Err(_) => continue,
        };

        for entry_res in read_dir {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name = entry.file_name();
            let name_str = String::from_utf8_lossy(name.as_ref()).to_string();

            if name_str == "." || name_str == ".." {
                continue;
            }

            let entry_path = if current_path == "/" {
                format!("/{}", name_str)
            } else {
                format!("{}/{}", current_path, name_str)
            };

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let is_dir = meta.is_dir();
            let is_symlink = meta.is_symlink();
            let size = meta.len();
            let mode_str = mode_to_string(meta.mode(), is_dir, is_symlink);
            let uid = meta.uid();
            let gid = meta.gid();

            let mut ts_map: HashMap<(i64, u32), String> = HashMap::new();

            let m_ts = meta.modified();
            let m_secs = m_ts.seconds();
            let m_nanos = m_ts.nanoseconds();
            if m_secs > 0 {
                let current = ts_map.entry((m_secs, m_nanos)).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'm');
            }

            let a_ts = meta.accessed();
            let a_secs = a_ts.seconds();
            let a_nanos = a_ts.nanoseconds();
            if a_secs > 0 {
                let current = ts_map.entry((a_secs, a_nanos)).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'a');
            }

            if let Some(c_ts) = meta.created() {
                let c_secs = c_ts.seconds();
                let c_nanos = c_ts.nanoseconds();
                if c_secs > 0 {
                    let current = ts_map.entry((c_secs, c_nanos)).or_insert_with(|| "....".to_string());
                    *current = join_macb_flags(current, 'b');
                }
            }

            for ((secs, nanos), macb) in ts_map {
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
                        entry_path.clone(),
                    ));
                }
            }

            if is_dir {
                stack.push(entry_path);
            }
        }
    }

    Ok(timeline)
}
