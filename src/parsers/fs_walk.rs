use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// What the host filesystem says about one path, read before anything of
/// the run opens it: these are the times of the evidence as found, not of
/// the analysis.
#[derive(Debug, Clone)]
pub struct HostMeta {
    size: u64,
    mode: String,
    uid: u32,
    gid: u32,
    inode: String,
    m: Option<(i64, u32)>,
    a: Option<(i64, u32)>,
    c: Option<(i64, u32)>,
    b: Option<(i64, u32)>,
}

impl HostMeta {
    fn of(meta: &Metadata) -> Self {
        let (mode, uid, gid, c, inode) = mode_from_metadata(meta);
        HostMeta {
            size: meta.len(),
            mode,
            uid,
            gid,
            inode,
            m: meta.modified().ok().map(system_time_to_unix),
            a: meta.accessed().ok().map(system_time_to_unix),
            c,
            b: meta.created().ok().map(system_time_to_unix),
        }
    }
}

/// The metadata of a tree, taken before the run reads it.
///
/// Reading a file sets its access time, listing a directory sets the
/// directory's; on many systems both are written back. Every path is
/// therefore stat'ed before it is opened: a directory before it is listed,
/// a file before any parser reads it. The walk then works from this
/// picture, so nothing the run does shows in its rows.
#[derive(Debug, Clone, Default)]
pub struct TreeSnapshot {
    /// Every path in walk order (a directory before what it holds, names
    /// sorted), with its metadata or why it could not be read.
    items: Vec<(PathBuf, std::result::Result<HostMeta, String>)>,
}

impl TreeSnapshot {
    /// Every path of the picture that could be read, in walk order.
    pub fn paths(&self) -> Vec<PathBuf> {
        self.items.iter().filter(|(_, m)| m.is_ok()).map(|(p, _)| p.clone()).collect()
    }

    /// Takes the picture of `root` and, when it is a directory, of
    /// everything under it. Symbolic links are not followed.
    pub fn take(root: &Path) -> Self {
        let mut snap = TreeSnapshot::default();
        match fs::symlink_metadata(root) {
            Ok(meta) => {
                let is_dir = meta.file_type().is_dir();
                snap.items.push((root.to_path_buf(), Ok(HostMeta::of(&meta))));
                if is_dir {
                    snap.descend(root);
                }
            }
            Err(e) => snap.items.push((root.to_path_buf(), Err(format!("{}: {}", root.display(), e)))),
        }
        snap
    }

    fn descend(&mut self, dir: &Path) {
        // Listed with its access time frozen: the listing leaves no trace.
        let children: Vec<PathBuf> = match crate::evidence::list_dir(dir) {
            Ok(v) => v,
            Err(e) => {
                self.items.push((dir.to_path_buf(), Err(format!("{}: {}", dir.display(), e))));
                return;
            }
        };
        // Every child is stat'ed before any of them is listed.
        let stated: Vec<(PathBuf, std::io::Result<Metadata>)> = children.into_iter().map(|c| {
            let m = fs::symlink_metadata(&c);
            (c, m)
        }).collect();
        for (child, meta) in stated {
            match meta {
                Ok(meta) => {
                    let is_dir = meta.file_type().is_dir();
                    self.items.push((child.clone(), Ok(HostMeta::of(&meta))));
                    if is_dir {
                        self.descend(&child);
                    }
                }
                Err(e) => self.items.push((child.clone(), Err(format!("{}: {}", child.display(), e)))),
            }
        }
    }
}

/// The rows of an extracted archive: one `m...` row per entry, at the time
/// the archive gives it. An entry the archive gives no time has no row, and
/// neither has a folder the extraction made for a file. Size and mode are
/// those of the extracted copy; no time of the copy is used, by the rows or
/// by the rules.
pub fn timeline_from_archive(members: &[crate::ingest::archive::ArchiveMember]) -> Vec<TimelineEntry> {
    // A path written twice keeps the time of the last write, as the extraction does.
    let mut last: std::collections::BTreeMap<&Path, Option<(i64, u32)>> = std::collections::BTreeMap::new();
    for m in members {
        last.insert(m.path.as_path(), m.mtime);
    }
    let mut timeline = Vec::new();
    for (path, mtime) in last {
        let (Some((secs, nanos)), Ok(meta)) = (mtime, fs::symlink_metadata(path)) else { continue };
        let (mode, uid, gid, _, inode) = mode_from_metadata(&meta);
        let display_path = path.to_string_lossy().to_string();
        let flags = anomaly::column(&[anomaly::unix_flags(Some(secs), None, None, anomaly::now_secs()), anomaly::name_flags(&display_path)].concat());
        if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
            timeline.push(
                TimelineEntry::new(ts_iso, secs, nanos, meta.len(), "m...".to_string(), mode, uid, gid, inode, display_path)
                    .with_source(source::FS)
                    .with_flags(flags),
            );
        }
    }
    timeline
}

pub fn walk_directory_timeline(
    root_dir: &Path,
) -> Result<Vec<TimelineEntry>, Box<dyn std::error::Error + Send + Sync>> {
    walk_directory_timeline_with(root_dir, &WalkOptions::default())
}

/// Walks `root_dir` as it is now.
pub fn walk_directory_timeline_with(
    root_dir: &Path,
    opts: &WalkOptions,
) -> Result<Vec<TimelineEntry>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(timeline_from_snapshot(&TreeSnapshot::take(root_dir), root_dir, opts))
}

/// The rows of a tree from its picture (see [`TreeSnapshot`]).
pub fn timeline_from_snapshot(snap: &TreeSnapshot, root_dir: &Path, opts: &WalkOptions) -> Vec<TimelineEntry> {
    let mut timeline = Vec::new();
    let mut skipped = 0usize;

    for (k, (path, meta)) in snap.items.iter().enumerate() {
        let meta = match meta {
            Ok(m) => m,
            Err(e) => {
                skipped += 1;
                if skipped <= 5 {
                    crate::say!("[!] Skipping unreadable path: {}", e);
                }
                continue;
            }
        };
        if opts.skip_root && k == 0 {
            continue;
        }
        let display_path = path.to_string_lossy().to_string();
        let mut ts_map: std::collections::BTreeMap<(i64, u32), String> = std::collections::BTreeMap::new();
        let mut add = |t: Option<(i64, u32)>, flag: char| {
            if let Some(key) = t {
                let current = ts_map.entry(key).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, flag);
            }
        };
        add(meta.m, 'm');
        if !opts.mtime_only {
            add(meta.a, 'a');
            add(meta.c, 'c');
            add(meta.b, 'b');
        }
        // The rules see only the times the rows show.
        let (c, b) = if opts.mtime_only { (None, None) } else { (meta.c.map(|c| c.0), meta.b.map(|b| b.0)) };
        let flags = anomaly::column(&[anomaly::unix_flags(meta.m.map(|t| t.0), c, b, anomaly::now_secs()), anomaly::name_flags(&display_path)].concat());

        for ((secs, nanos), macb) in ts_map {
            if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
                timeline.push(
                    TimelineEntry::new(ts_iso, secs, nanos, meta.size, macb, meta.mode.clone(), meta.uid, meta.gid, meta.inode.clone(), display_path.clone())
                        .with_source(source::FS)
                        .with_flags(flags.clone()),
                );
            }
        }
    }

    if skipped > 5 {
        crate::say!("[!] {} paths skipped in total under {}", skipped, root_dir.display());
    }
    timeline
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
