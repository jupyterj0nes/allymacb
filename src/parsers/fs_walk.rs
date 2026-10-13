use std::collections::HashMap;
use std::fs;
use std::path::Path;

use walkdir::WalkDir;

use crate::timefmt::format_unix_timestamp;
use crate::timeline::{join_macb_flags, TimelineEntry};

pub fn walk_directory_timeline(
    root_dir: &Path,
) -> Result<Vec<TimelineEntry>, Box<dyn std::error::Error + Send + Sync>> {
    let mut timeline = Vec::new();

    for entry_res in WalkDir::new(root_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry_res.path();
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let is_dir = meta.is_dir();
        let is_symlink = meta.file_type().is_symlink();
        let size = meta.len();

        let display_path = path.to_string_lossy().to_string();

        let mode_str = if is_dir {
            "d/drwxrwxrwx".to_string()
        } else if is_symlink {
            "l/lrwxrwxrwx".to_string()
        } else {
            "-/-rwxrwxrwx".to_string()
        };

        let mut ts_map: HashMap<(i64, u32), String> = HashMap::new();

        // Modified time ('m')
        if let Ok(mtime) = meta.modified() {
            if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
                let secs = dur.as_secs() as i64;
                let nanos = dur.subsec_nanos();
                let current = ts_map.entry((secs, nanos)).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'm');
            }
        }

        // Accessed time ('a')
        if let Ok(atime) = meta.accessed() {
            if let Ok(dur) = atime.duration_since(std::time::UNIX_EPOCH) {
                let secs = dur.as_secs() as i64;
                let nanos = dur.subsec_nanos();
                let current = ts_map.entry((secs, nanos)).or_insert_with(|| "....".to_string());
                *current = join_macb_flags(current, 'a');
            }
        }

        // Created / Birth time ('b')
        if let Ok(btime) = meta.created() {
            if let Ok(dur) = btime.duration_since(std::time::UNIX_EPOCH) {
                let secs = dur.as_secs() as i64;
                let nanos = dur.subsec_nanos();
                let current = ts_map.entry((secs, nanos)).or_insert_with(|| "....".to_string());
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
                    0,
                    0,
                    "0".to_string(),
                    display_path.clone(),
                ));
            }
        }
    }

    Ok(timeline)
}
