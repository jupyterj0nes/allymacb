use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;

use allymacb::parsers::bodyfile::parse_bodyfile_stream;
use allymacb::parsers::mft::{parse_mft_reader, MftParseOptions};
use allymacb::timeline::{TimelineEntry, TimelineWriter};

#[test]
fn test_mft_parsing_real_sample() {
    let mut sample_path = PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default());
    sample_path.push(r".cargo\registry\src\index.crates.io-1949cf8c6b5b557f\mft-0.7.0\samples\MFT");

    if sample_path.exists() {
        let file = File::open(&sample_path).expect("Failed to open sample MFT");
        let reader = BufReader::new(file);

        let temp_dir = std::env::temp_dir().join("allymacb_test_residents");
        let _ = std::fs::create_dir_all(&temp_dir);

        let options = MftParseOptions {
            include_file_name_timestamps: true,
            resident_dir: Some(temp_dir.clone()),
            resident_report: None,
            drive_letter: Some('C'),
            quiet: true,
        };

        let (timeline, resident_stats) = parse_mft_reader(reader, &options).expect("Failed to parse MFT");

        assert!(!timeline.is_empty(), "Timeline should not be empty");
        assert!(resident_stats.total_extracted > 0, "Should have extracted resident files");
        assert!(resident_stats.total_bytes > 0, "Extracted bytes should be > 0");

        // Verify that entries contain valid UTC timestamps ending in 'Z'
        for entry in timeline.iter().take(50) {
            assert!(
                entry.timestamp.ends_with('Z'),
                "Timestamp must end in Z: {}",
                entry.timestamp
            );
            assert!(entry.timestamp.contains('T'), "Timestamp must be ISO 8601 with T");
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

#[test]
fn test_bodyfile_parser_full_macb() {
    let raw = "0|/usr/bin/bash|1234|-rwxr-xr-x|0|0|1024|1700000000|1700000000|1700000000|1700000000\n";
    let cursor = Cursor::new(raw.as_bytes());
    let entries = parse_bodyfile_stream(cursor, Some("my_host"));

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].macb, "macb");
    assert_eq!(entries[0].file_name, "[my_host] /usr/bin/bash");
    assert_eq!(entries[0].mode, "-rwxr-xr-x");
    assert_eq!(entries[0].size, 1024);
    assert_eq!(entries[0].meta, "1234");
    assert_eq!(entries[0].timestamp, "2023-11-14T22:13:20Z");
}

#[test]
fn test_bodyfile_parser_distinct_macb() {
    // atime=1700000001, mtime=1700000002, ctime=1700000003, crtime=1700000004
    let raw = "0|/etc/shadow|999|-rw-------|0|0|500|1700000001|1700000002|1700000003|1700000004\n";
    let cursor = Cursor::new(raw.as_bytes());
    let entries = parse_bodyfile_stream(cursor, None);

    assert_eq!(entries.len(), 4);
    let mut flags: Vec<String> = entries.iter().map(|e| e.macb.clone()).collect();
    flags.sort();
    assert_eq!(flags, vec!["...b", "..c.", ".a..", "m..."]);
}

#[test]
fn test_csv_timeline_writer_sorting_and_escaping() {
    let mut entries = vec![
        TimelineEntry::new(
            "2026-04-13T09:15:00Z".to_string(),
            1776071700,
            0,
            200,
            "macb".to_string(),
            "-rw-r--r--".to_string(),
            0,
            0,
            "2".to_string(),
            "file,with,comma.txt".to_string(),
        ),
        TimelineEntry::new(
            "2020-01-01T00:00:00Z".to_string(),
            1577836800,
            0,
            100,
            "m...".to_string(),
            "-rw-r--r--".to_string(),
            0,
            0,
            "1".to_string(),
            "first_file.txt".to_string(),
        ),
    ];

    let temp_out = std::env::temp_dir().join("allymacb_test_sort.csv");
    let count = TimelineWriter::write_entries(&mut entries, Some(&temp_out)).unwrap();
    assert_eq!(count, 2);

    let content = std::fs::read_to_string(&temp_out).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    assert_eq!(lines[0], "Date,Size,Type,Mode,UID,GID,Meta,File Name");
    // Line 1 should be the older file (2020)
    assert!(lines[1].starts_with("2020-01-01T00:00:00Z,100,m..."));
    // Line 2 should be the newer file (2026) and properly escaped with quotes
    assert!(lines[2].contains("\"file,with,comma.txt\""));

    let _ = std::fs::remove_file(temp_out);
}
