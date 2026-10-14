use allymacb::error::ErrorCode;
use allymacb::parsers::bodyfile::{parse_bodyfile_line, parse_bodyfile_stream};
use std::io::Cursor;

#[test]
fn test_bodyfile_comment_and_empty_lines() {
    assert!(parse_bodyfile_line("", 1, None).unwrap().is_empty());
    assert!(parse_bodyfile_line("   ", 1, None).unwrap().is_empty());
    assert!(parse_bodyfile_line("# This is a comment", 1, None).unwrap().is_empty());
    assert!(parse_bodyfile_line("   # Indented comment", 1, None).unwrap().is_empty());
}

#[test]
fn test_bodyfile_field_count_validation() {
    // 1 to 10 fields (should all fail with BodyfileInvalidFieldCount)
    for count in 1..11 {
        let line = vec!["val"; count].join("|");
        let err = parse_bodyfile_line(&line, count + 1, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::BodyfileInvalidFieldCount);
    }
}

#[test]
fn test_bodyfile_invalid_numeric_fields() {
    let base = "0|/path|1|drwxr-xr-x|0|0|100|";
    // Bad atime
    let err = parse_bodyfile_line(&format!("{}xyz|100|100|0", base), 1, None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BodyfileTimestampInvalid);

    // Bad mtime
    let err = parse_bodyfile_line(&format!("{}100|xyz|100|0", base), 1, None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BodyfileTimestampInvalid);

    // Bad ctime
    let err = parse_bodyfile_line(&format!("{}100|100|xyz|0", base), 1, None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BodyfileTimestampInvalid);

    // Bad crtime
    let err = parse_bodyfile_line(&format!("{}100|100|100|xyz", base), 1, None).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BodyfileTimestampInvalid);
}

#[test]
fn test_bodyfile_hostname_prefixing() {
    let line = "0|/var/log/syslog|500|-rw-r--r--|0|0|1024|1700000000|1700000000|1700000000|0";
    let entries = parse_bodyfile_line(line, 1, Some("srv-web01")).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name, "[srv-web01] /var/log/syslog");

    let no_prefix = parse_bodyfile_line(line, 1, None).unwrap();
    assert_eq!(no_prefix[0].file_name, "/var/log/syslog");
}

#[test]
fn test_bodyfile_special_paths() {
    let paths = [
        "/",
        "/etc/passwd",
        "/var/log/audit/audit.log",
        "/home/user with spaces/file.txt",
        "/opt/Renfe/cercanías/config.xml",
        "/usr/local/bin/test-tool_v1.0.tar.gz",
        "/mnt/sysroot/proc/1/cmdline",
        "/var/run/docker.sock",
    ];

    for path in paths {
        let line = format!("0|{}|123|-rw-r--r--|1000|1000|512|1700000000|1700000000|1700000000|0", path);
        let entries = parse_bodyfile_line(&line, 1, None).unwrap();
        assert_eq!(entries[0].file_name, path);
    }
}

// Generate tests for all 16 MACB configurations from bodyfile timestamps
macro_rules! generate_macb_bodyfile_tests {
    ($($fn_name:ident: atime=$a:expr, mtime=$m:expr, ctime=$c:expr, crtime=$b:expr => expected_flags=$exp:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let line = format!("0|/test|1|-rw-r--r--|0|0|100|{}|{}|{}|{}", $a, $m, $c, $b);
                let entries = parse_bodyfile_line(&line, 1, None).unwrap();
                let actual_flags: Vec<&str> = entries.iter().map(|e| e.macb.as_str()).collect();
                assert_eq!(actual_flags, $exp);
            }
        )*
    };
}

generate_macb_bodyfile_tests! {
    test_bf_flag_all_same: atime=1000, mtime=1000, ctime=1000, crtime=1000 => expected_flags=["macb"],
    test_bf_flag_mac_b0: atime=1000, mtime=1000, ctime=1000, crtime=0 => expected_flags=["mac."],
    test_bf_flag_m_only: atime=0, mtime=1000, ctime=0, crtime=0 => expected_flags=["m..."],
    test_bf_flag_a_only: atime=1000, mtime=0, ctime=0, crtime=0 => expected_flags=[".a.."],
    test_bf_flag_c_only: atime=0, mtime=0, ctime=1000, crtime=0 => expected_flags=["..c."],
    test_bf_flag_b_only: atime=0, mtime=0, ctime=0, crtime=1000 => expected_flags=["...b"],
    test_bf_flag_ma_same: atime=1000, mtime=1000, ctime=0, crtime=0 => expected_flags=["ma.."],
    test_bf_flag_mc_same: atime=0, mtime=1000, ctime=1000, crtime=0 => expected_flags=["m.c."],
    test_bf_flag_mb_same: atime=0, mtime=1000, ctime=0, crtime=1000 => expected_flags=["m..b"],
    test_bf_flag_ac_same: atime=1000, mtime=0, ctime=1000, crtime=0 => expected_flags=[".ac."],
    test_bf_flag_ab_same: atime=1000, mtime=0, ctime=0, crtime=1000 => expected_flags=[".a.b"],
    test_bf_flag_cb_same: atime=0, mtime=0, ctime=1000, crtime=1000 => expected_flags=["..cb"],
}

// Stream parsing tests with multiple records
#[test]
fn test_bodyfile_multi_line_stream() {
    let mut data = String::new();
    for i in 1..=50 {
        data.push_str(&format!(
            "0|/usr/lib/lib{}.so|{}|-rwxr-xr-x|0|0|{}|1700000000|1700000000|1700000000|0\n",
            i, i * 10, i * 1024
        ));
    }

    let cursor = Cursor::new(data.as_bytes());
    let entries = parse_bodyfile_stream(cursor, Some("server"));
    assert_eq!(entries.len(), 50);

    for (i, entry) in entries.iter().enumerate() {
        let expected_name = format!("[server] /usr/lib/lib{}.so", i + 1);
        assert_eq!(entry.file_name, expected_name);
        assert_eq!(entry.macb, "mac.");
        assert_eq!(entry.size, ((i + 1) * 1024) as u64);
        assert_eq!(entry.mode, "-rwxr-xr-x");
    }
}
