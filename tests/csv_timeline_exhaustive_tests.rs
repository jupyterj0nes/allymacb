use allymacb::timeline::{escape_csv, TimelineEntry, TimelineWriter, CSV_HEADER};

#[test]
fn test_escape_plain_text() {
    assert_eq!(escape_csv(""), "");
    assert_eq!(escape_csv("filename.txt"), "filename.txt");
    assert_eq!(escape_csv("path/to/file.ext"), "path/to/file.ext");
    assert_eq!(escape_csv("C:\\Windows\\System32\\cmd.exe"), "C:\\Windows\\System32\\cmd.exe");
}

#[test]
fn test_escape_with_commas() {
    assert_eq!(escape_csv("file,with,commas.txt"), "\"file,with,commas.txt\"");
    assert_eq!(escape_csv(",leading.txt"), "\",leading.txt\"");
    assert_eq!(escape_csv("trailing.txt,"), "\"trailing.txt,\"");
    assert_eq!(escape_csv(","), "\",\"");
}

#[test]
fn test_escape_with_quotes() {
    assert_eq!(escape_csv("file \"quoted\".txt"), "\"file \"\"quoted\"\".txt\"");
    assert_eq!(escape_csv("\"all_quoted\""), "\"\"\"all_quoted\"\"\"");
    assert_eq!(escape_csv("\""), "\"\"\"\"");
}

#[test]
fn test_escape_with_newlines() {
    assert_eq!(escape_csv("line1\nline2"), "\"line1\nline2\"");
    assert_eq!(escape_csv("line1\r\nline2"), "\"line1\r\nline2\"");
}

#[test]
fn test_escape_combined_special_chars() {
    let tricky = "file, with \"quotes\" and \n newline.txt";
    let escaped = escape_csv(tricky);
    assert!(escaped.starts_with('"'));
    assert!(escaped.ends_with('"'));
    assert!(escaped.contains("\"\"quotes\"\""));
}

#[test]
fn test_timeline_writer_sorting_strict_chronological() {
    let mut entries = Vec::new();
    // Insert 50 entries in reverse chronological order
    for i in (1..=50).rev() {
        entries.push(TimelineEntry::new(
            format!("2024-01-01T00:00:{:02}Z", i),
            1704067200 + i,
            0,
            i as u64 * 100,
            "macb".to_string(),
            "-rw-r--r--".to_string(),
            0,
            0,
            i.to_string(),
            format!("file_{:02}.txt", i),
        ));
    }

    let temp_file = std::env::temp_dir().join("test_sort_strict.csv");
    let written = TimelineWriter::write_entries(&mut entries, Some(&temp_file)).unwrap();
    assert_eq!(written, 50);

    let content = std::fs::read_to_string(&temp_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    // Check header
    // Literal on purpose: this pins the documented header (README) independently of the constant.
    assert_eq!(lines[0], "time_created,size,type,mode,uid,gid,meta,file_name,source,flags");
    assert_eq!(lines[0], CSV_HEADER);

    // Line 1 should be file_01 (timestamp 1704067201)
    assert!(lines[1].starts_with("2024-01-01T00:00:01Z"));
    // Line 50 should be file_50 (timestamp 1704067250)
    assert!(lines[50].starts_with("2024-01-01T00:00:50Z"));

    let _ = std::fs::remove_file(temp_file);
}

#[test]
fn test_timeline_writer_subsecond_sorting() {
    let mut entries = vec![
        TimelineEntry::new("2024-01-01T00:00:00.999Z".to_string(), 1704067200, 999_000_000, 10, "m...".to_string(), "-".to_string(), 0, 0, "3".to_string(), "third.txt".to_string()),
        TimelineEntry::new("2024-01-01T00:00:00.100Z".to_string(), 1704067200, 100_000_000, 10, "m...".to_string(), "-".to_string(), 0, 0, "1".to_string(), "first.txt".to_string()),
        TimelineEntry::new("2024-01-01T00:00:00.500Z".to_string(), 1704067200, 500_000_000, 10, "m...".to_string(), "-".to_string(), 0, 0, "2".to_string(), "second.txt".to_string()),
    ];

    let temp_file = std::env::temp_dir().join("test_sort_subseconds.csv");
    TimelineWriter::write_entries(&mut entries, Some(&temp_file)).unwrap();

    let content = std::fs::read_to_string(&temp_file).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    assert!(lines[1].contains("first.txt"));
    assert!(lines[2].contains("second.txt"));
    assert!(lines[3].contains("third.txt"));

    let _ = std::fs::remove_file(temp_file);
}

// Generate tests for escaping various file extension names
macro_rules! generate_filename_escape_tests {
    ($($fn_name:ident: $input:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                assert_eq!(escape_csv($input), $expected);
            }
        )*
    };
}

generate_filename_escape_tests! {
    test_esc_ext_1: "test,1.exe" => "\"test,1.exe\"",
    test_esc_ext_2: "test,2.dll" => "\"test,2.dll\"",
    test_esc_ext_3: "test,3.sys" => "\"test,3.sys\"",
    test_esc_ext_4: "test,4.log" => "\"test,4.log\"",
    test_esc_ext_5: "test,5.evtx" => "\"test,5.evtx\"",
    test_esc_ext_6: "test,6.pcap" => "\"test,6.pcap\"",
    test_esc_ext_7: "test,7.reg" => "\"test,7.reg\"",
    test_esc_ext_8: "test,8.ps1" => "\"test,8.ps1\"",
    test_esc_ext_9: "test,9.sh" => "\"test,9.sh\"",
    test_esc_ext_10: "test,10.py" => "\"test,10.py\"",
    test_esc_ext_11: "test,11.tar.gz" => "\"test,11.tar.gz\"",
    test_esc_ext_12: "test,12.zip" => "\"test,12.zip\"",
}
