use allymacb::parsers::usn::{decode_usn_file_attributes, decode_usn_reason, parse_usn_reader, UsnParseOptions};
use std::io::Cursor;

#[test]
fn test_usn_attributes_directory() {
    assert_eq!(decode_usn_file_attributes(0x10), "d/drwxrwxrwx");
    assert_eq!(decode_usn_file_attributes(0x11), "d/drwxrwxrwx");
    assert_eq!(decode_usn_file_attributes(0x10 | 0x20), "d/drwxrwxrwx");
}

#[test]
fn test_usn_attributes_file() {
    assert_eq!(decode_usn_file_attributes(0x20), "-/-rwxrwxrwx");
    assert_eq!(decode_usn_file_attributes(0x80), "-/-rwxrwxrwx");
    assert_eq!(decode_usn_file_attributes(0x0), "-/-rwxrwxrwx");
}

#[test]
fn test_usn_reason_single_bits() {
    assert_eq!(decode_usn_reason(0x00000001), "DATA_OVERWRITE");
    assert_eq!(decode_usn_reason(0x00000002), "DATA_EXTEND");
    assert_eq!(decode_usn_reason(0x00000004), "DATA_TRUNCATION");
    assert_eq!(decode_usn_reason(0x00000010), "NAMED_DATA_OVERWRITE");
    assert_eq!(decode_usn_reason(0x00000020), "NAMED_DATA_EXTEND");
    assert_eq!(decode_usn_reason(0x00000040), "NAMED_DATA_TRUNCATION");
    assert_eq!(decode_usn_reason(0x00000100), "FILE_CREATE");
    assert_eq!(decode_usn_reason(0x00000200), "FILE_DELETE");
    assert_eq!(decode_usn_reason(0x00000400), "EA_CHANGE");
    assert_eq!(decode_usn_reason(0x00000800), "SECURITY_CHANGE");
    assert_eq!(decode_usn_reason(0x00001000), "RENAME_OLD_NAME");
    assert_eq!(decode_usn_reason(0x00002000), "RENAME_NEW_NAME");
    assert_eq!(decode_usn_reason(0x00004000), "INDEXABLE_CHANGE");
    assert_eq!(decode_usn_reason(0x00008000), "BASIC_INFO_CHANGE");
    assert_eq!(decode_usn_reason(0x00010000), "HARD_LINK_CHANGE");
    assert_eq!(decode_usn_reason(0x00020000), "COMPRESSION_CHANGE");
    assert_eq!(decode_usn_reason(0x00040000), "ENCRYPTION_CHANGE");
    assert_eq!(decode_usn_reason(0x00080000), "OBJECT_ID_CHANGE");
    assert_eq!(decode_usn_reason(0x00100000), "REPARSE_POINT_CHANGE");
    assert_eq!(decode_usn_reason(0x00200000), "STREAM_CHANGE");
    assert_eq!(decode_usn_reason(0x00400000), "TRANSACTED_CHANGE");
    assert_eq!(decode_usn_reason(0x00800000), "INTEGRITY_CHANGE");
    assert_eq!(decode_usn_reason(0x80000000), "CLOSE");
}

#[test]
fn test_usn_reason_combinations() {
    // FILE_CREATE + CLOSE
    assert_eq!(decode_usn_reason(0x00000100 | 0x80000000), "FILE_CREATE+CLOSE");
    // DATA_EXTEND + CLOSE
    assert_eq!(decode_usn_reason(0x00000002 | 0x80000000), "DATA_EXTEND+CLOSE");
    // FILE_CREATE + DATA_EXTEND + CLOSE
    assert_eq!(decode_usn_reason(0x00000102 | 0x80000000), "DATA_EXTEND+FILE_CREATE+CLOSE");
    // RENAME_NEW_NAME + CLOSE
    assert_eq!(decode_usn_reason(0x00002000 | 0x80000000), "RENAME_NEW_NAME+CLOSE");
}

#[test]
fn test_usn_reason_unknown() {
    assert_eq!(decode_usn_reason(0), "0x00000000");
}

// Generate test records with synthetic buffer
fn create_synthetic_usn_record(
    record_len: u32,
    major_ver: u16,
    minor_ver: u16,
    entry_id: u64,
    filetime: u64,
    reason: u32,
    file_name: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record_len.to_le_bytes()); // 0..4
    buf.extend_from_slice(&major_ver.to_le_bytes());  // 4..6
    buf.extend_from_slice(&minor_ver.to_le_bytes());  // 6..8
    buf.extend_from_slice(&entry_id.to_le_bytes());   // 8..16 (file_ref)
    buf.extend_from_slice(&5u64.to_le_bytes());       // 16..24 (parent_ref)
    buf.extend_from_slice(&100i64.to_le_bytes());     // 24..32 (usn)
    buf.extend_from_slice(&filetime.to_le_bytes());   // 32..40 (filetime)
    buf.extend_from_slice(&reason.to_le_bytes());     // 40..44 (reason)
    buf.extend_from_slice(&0u32.to_le_bytes());       // 44..48 (source_info)
    buf.extend_from_slice(&0u32.to_le_bytes());       // 48..52 (sec_id)
    buf.extend_from_slice(&0x20u32.to_le_bytes());    // 52..56 (attrs: ARCHIVE)

    let utf16: Vec<u16> = file_name.encode_utf16().collect();
    let name_len = (utf16.len() * 2) as u16;
    let name_offset = 60u16;

    buf.extend_from_slice(&name_len.to_le_bytes());    // 56..58
    buf.extend_from_slice(&name_offset.to_le_bytes()); // 58..60

    for ch in utf16 {
        buf.extend_from_slice(&ch.to_le_bytes());
    }

    // Pad to record_len
    while buf.len() < record_len as usize {
        buf.push(0);
    }

    buf
}

#[test]
fn test_parse_usn_reader_valid_v2() {
    let ft: u64 = 133515045000000000; // 2024-02-04 12:35:00 UTC
    let rec = create_synthetic_usn_record(80, 2, 0, 1024, ft, 0x100 | 0x80000000, "malware.exe");

    let cursor = Cursor::new(rec);
    let options = UsnParseOptions {
        drive_letter: Some('C'),
        quiet: true,
        mft_path_cache: None,
    };

    let entries = parse_usn_reader(cursor, 80, &options).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].meta, "1024");
    assert_eq!(entries[0].timestamp, "2024-02-04T07:15:00Z");
    assert!(entries[0].file_name.contains("malware.exe"));
    assert!(entries[0].file_name.contains("(USN: FILE_CREATE+CLOSE)"));
}

#[test]
fn test_parse_usn_reader_valid_v3() {
    let ft: u64 = 133515045000000000;
    let rec = create_synthetic_usn_record(88, 3, 0, 2048, ft, 0x02, "script.ps1");

    let cursor = Cursor::new(rec);
    let options = UsnParseOptions {
        drive_letter: Some('D'),
        quiet: true,
        mft_path_cache: None,
    };

    let entries = parse_usn_reader(cursor, 88, &options).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].meta, "2048");
    assert!(entries[0].file_name.contains("D:\\[UNKNOWN]\\script.ps1"));
    assert!(entries[0].file_name.contains("(USN: DATA_EXTEND)"));
}

#[test]
fn test_parse_usn_reader_with_null_padding() {
    let ft: u64 = 133515045000000000;
    let rec = create_synthetic_usn_record(80, 2, 0, 999, ft, 0x1, "test.txt");

    // Prepend 16 bytes of null padding
    let mut data = vec![0u8; 16];
    data.extend_from_slice(&rec);

    let total_size = data.len() as u64;
    let cursor = Cursor::new(data);
    let options = UsnParseOptions {
        drive_letter: Some('C'),
        quiet: true,
        mft_path_cache: None,
    };

    let entries = parse_usn_reader(cursor, total_size, &options).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].meta, "999");
}

#[test]
fn test_parse_usn_reader_multiple_records() {
    let ft: u64 = 133515045000000000;
    let mut data = Vec::new();

    for i in 1..=20 {
        let rec = create_synthetic_usn_record(128, 2, 0, i, ft + i * 10_000_000, 0x100, &format!("file_{}.bin", i));
        data.extend_from_slice(&rec);
    }

    let total_size = data.len() as u64;
    let cursor = Cursor::new(data);
    let options = UsnParseOptions {
        drive_letter: Some('C'),
        quiet: true,
        mft_path_cache: None,
    };

    let entries = parse_usn_reader(cursor, total_size, &options).unwrap();
    assert_eq!(entries.len(), 20);
}
