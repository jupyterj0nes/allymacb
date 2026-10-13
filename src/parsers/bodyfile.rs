use std::collections::HashMap;
use std::io::BufRead;

use crate::timefmt::format_unix_timestamp;
use crate::timeline::{join_macb_flags, TimelineEntry};

pub fn parse_bodyfile_stream<R: BufRead>(
    reader: R,
    prefix: Option<&str>,
) -> Vec<TimelineEntry> {
    let mut timeline = Vec::new();

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Bodyfile format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
        let parts: Vec<&str> = trimmed.split('|').collect();
        if parts.len() < 11 {
            continue;
        }

        let raw_path = parts[1];
        let inode = parts[2];
        let mode = parts[3];
        let uid: u32 = parts[4].parse().unwrap_or(0);
        let gid: u32 = parts[5].parse().unwrap_or(0);
        let size: u64 = parts[6].parse().unwrap_or(0);
        let atime: i64 = parts[7].parse().unwrap_or(0);
        let mtime: i64 = parts[8].parse().unwrap_or(0);
        let ctime: i64 = parts[9].parse().unwrap_or(0);
        let crtime: i64 = parts[10].parse().unwrap_or(0);

        let full_path = if let Some(p) = prefix {
            format!("[{}] {}", p, raw_path)
        } else {
            raw_path.to_string()
        };

        // Group timestamps: (secs, nanos=0) -> macb string
        let mut ts_map: HashMap<i64, String> = HashMap::new();

        if mtime > 0 {
            let cur = ts_map.entry(mtime).or_insert_with(|| "....".to_string());
            *cur = join_macb_flags(cur, 'm');
        }
        if atime > 0 {
            let cur = ts_map.entry(atime).or_insert_with(|| "....".to_string());
            *cur = join_macb_flags(cur, 'a');
        }
        if ctime > 0 {
            let cur = ts_map.entry(ctime).or_insert_with(|| "....".to_string());
            *cur = join_macb_flags(cur, 'c');
        }
        if crtime > 0 {
            let cur = ts_map.entry(crtime).or_insert_with(|| "....".to_string());
            *cur = join_macb_flags(cur, 'b');
        }

        for (secs, macb) in ts_map {
            if let Some(ts_iso) = format_unix_timestamp(secs, 0) {
                timeline.push(TimelineEntry::new(
                    ts_iso,
                    secs,
                    0,
                    size,
                    macb,
                    mode.to_string(),
                    uid,
                    gid,
                    inode.to_string(),
                    full_path.clone(),
                ));
            }
        }
    }

    timeline
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_bodyfile_stream() {
        let sample = "0|/etc/passwd-|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|0\n";
        let cursor = Cursor::new(sample.as_bytes());
        let entries = parse_bodyfile_stream(cursor, Some("server01"));

        assert_eq!(entries.len(), 2); // Two distinct timestamps: 1710234798 (m+a) and 1710247956 (c)
        let ma_entry = entries.iter().find(|e| e.macb == "ma..").unwrap();
        assert_eq!(ma_entry.file_name, "[server01] /etc/passwd-");
        assert_eq!(ma_entry.size, 2323);
        assert_eq!(ma_entry.meta, "4230");
        assert_eq!(ma_entry.mode, "-rw-r--r--");

        let c_entry = entries.iter().find(|e| e.macb == "..c.").unwrap();
        assert_eq!(c_entry.file_name, "[server01] /etc/passwd-");
    }
}
