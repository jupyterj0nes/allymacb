use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

use crate::timefmt::format_unix_timestamp;
use crate::anomaly;
use crate::timeline::{join_macb_flags, source, TimelineEntry};

/// Options controlling how a live/extracted directory tree is timelined.
#[derive(Debug, Clone, Default)]
pub struct WalkOptions {
    /// Do not emit a row for the root directory itself (useful when the root
    /// is a temporary extraction folder that is not evidence).
    pub skip_root: bool,
    /// Emit only modification-time rows. Used for archives that were
    /// extracted to disk: the archive preserves mtime but access/birth/change
    /// times would be the analyst machine's extraction time.
    pub mtime_only: bool,
}

/// Converts a `SystemTime` to (secs, nanos), supporting pre-1970 values.
pub fn system_time_to_unix(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            // Before the epoch: negative seconds. Normalise so nanos stay in [0, 1e9).
            let d = e.duration();
            let secs = -(d.as_secs() as i64);
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                (secs, 0)
            } else {
                (secs - 1, 1_000_000_000 - nanos)
            }
        }
    }
}

#[cfg(unix)]
fn mode_from_metadata(meta: &Metadata) -> (String, u32, u32, Option<(i64, u32)>, String) {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    let perm = crate::parsers::ext4::mode_bits_to_string((mode & 0o7777) as u16);
    let ft = meta.file_type();
    let kind = if ft.is_dir() {
        'd'
    } else if ft.is_symlink() {
        'l'
    } else {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_block_device() {
            'b'
        } else if ft.is_char_device() {
            'c'
        } else if ft.is_fifo() {
            'p'
        } else if ft.is_socket() {
            's'
        } else {
            '-'
        }
    };
    let ctime = Some((meta.ctime(), meta.ctime_nsec().clamp(0, 999_999_999) as u32));
    (
        format!("{}{}", kind, perm),
        meta.uid(),
        meta.gid(),
        ctime,
        meta.ino().to_string(),
    )
}

#[cfg(not(unix))]
fn mode_from_metadata(meta: &Metadata) -> (String, u32, u32, Option<(i64, u32)>, String) {
    // Windows has no Unix mode/uid/gid; mactime convention for NTFS is
    // "-/-rwxrwxrwx". We only vary the type character and the read-only bit.
    let ft = meta.file_type();
    let kind = if ft.is_dir() {
        'd'
    } else if ft.is_symlink() {
        'l'
    } else {
        '-'
    };
    let perm = if meta.permissions().readonly() {
        "r-xr-xr-x"
    } else {
        "rwxrwxrwx"
    };
    (format!("{}/{}{}", kind, kind, perm), 0, 0, None, "0".to_string())
}

pub fn walk_directory_timeline(
    root_dir: &Path,
) -> Result<Vec<TimelineEntry>, Box<dyn std::error::Error + Send + Sync>> {
    walk_directory_timeline_with(root_dir, &WalkOptions::default())
}

pub fn walk_directory_timeline_with(
    root_dir: &Path,
    opts: &WalkOptions,
) -> Result<Vec<TimelineEntry>, Box<dyn std::error::Error + Send + Sync>> {
    let mut timeline = Vec::new();
    let mut skipped = 0usize;

    for entry_res in WalkDir::new(root_dir).follow_links(false) {
        let entry = match entry_res {
            Ok(e) => e,
            Err(e) => {
                skipped += 1;
                if skipped <= 5 {
                    eprintln!("[!] Skipping unreadable path: {}", e);
                }
                continue;
            }
        };
        let path = entry.path();
        if opts.skip_root && entry.depth() == 0 {
            continue;
        }
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                skipped += 1;
                if skipped <= 5 {
                    eprintln!("[!] Skipping {}: {}", path.display(), e);
                }
                continue;
            }
        };

        let size = meta.len();
        let display_path = path.to_string_lossy().to_string();
        let (mode_str, uid, gid, ctime, inode) = mode_from_metadata(&meta);

        let mut ts_map: HashMap<(i64, u32), String> = HashMap::new();

        // Modified time ('m')
        if let Ok(mtime) = meta.modified() {
            let key = system_time_to_unix(mtime);
            let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
            *current = join_macb_flags(current, 'm');
        }

        if !opts.mtime_only {
            // Accessed time ('a')
            if let Ok(atime) = meta.accessed() {
                let key = system_time_to_unix(atime);
                let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'a');
            }

            // Inode change time ('c'), Unix only
            if let Some(key) = ctime {
                let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'c');
            }

            // Created / Birth time ('b')
            if let Ok(btime) = meta.created() {
                let key = system_time_to_unix(btime);
                let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'b');
            }
        }

        let flags = anomaly::column(
            &[
                anomaly::unix_flags(
                    meta.modified().ok().map(|t| system_time_to_unix(t).0),
                    ctime.map(|c| c.0),
                    meta.created().ok().map(|t| system_time_to_unix(t).0),
                    anomaly::now_secs(),
                ),
                anomaly::name_flags(&display_path),
            ]
            .concat(),
        );

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
                    inode.clone(),
                    display_path.clone(),
                ).with_source(source::FS).with_flags(flags.clone()));
            }
        }
    }

    if skipped > 5 {
        eprintln!("[!] {} paths skipped in total under {}", skipped, root_dir.display());
    }

    Ok(timeline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_system_time_before_epoch() {
        let t = UNIX_EPOCH - Duration::from_secs(86_400);
        assert_eq!(system_time_to_unix(t), (-86_400, 0));
        let t = UNIX_EPOCH - Duration::new(0, 250_000_000);
        assert_eq!(system_time_to_unix(t), (-1, 750_000_000));
    }

    #[test]
    fn test_system_time_after_epoch() {
        let t = UNIX_EPOCH + Duration::new(1_700_000_000, 500);
        assert_eq!(system_time_to_unix(t), (1_700_000_000, 500));
    }
}
