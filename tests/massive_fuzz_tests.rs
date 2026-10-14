use allymacb::parsers::bodyfile::parse_bodyfile_line;
use allymacb::parsers::usn::decode_usn_reason;
use allymacb::timefmt::format_unix_timestamp;
use allymacb::timeline::escape_csv;

// 1. Inode range boundary tests (30 tests)
macro_rules! test_inodes {
    ($($name:ident: $inode:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let line = format!("0|/file|{}|-rw-r--r--|0|0|100|1700000000|1700000000|1700000000|0", $inode);
                let entries = parse_bodyfile_line(&line, 1, None).unwrap();
                assert_eq!(entries[0].meta, $inode.to_string());
            }
        )*
    };
}

test_inodes! {
    test_inode_0: 0,
    test_inode_1: 1,
    test_inode_2: 2,
    test_inode_3: 3,
    test_inode_4: 4,
    test_inode_5: 5,
    test_inode_6: 6,
    test_inode_7: 7,
    test_inode_8: 8,
    test_inode_9: 9,
    test_inode_10: 10,
    test_inode_11: 11,
    test_inode_12: 12,
    test_inode_16: 16,
    test_inode_32: 32,
    test_inode_64: 64,
    test_inode_128: 128,
    test_inode_256: 256,
    test_inode_512: 512,
    test_inode_1024: 1024,
    test_inode_2048: 2048,
    test_inode_4096: 4096,
    test_inode_8192: 8192,
    test_inode_16384: 16384,
    test_inode_32768: 32768,
    test_inode_65535: 65535,
    test_inode_65536: 65536,
    test_inode_100000: 100000,
    test_inode_1000000: 1000000,
    test_inode_u32_max: 4294967295u32,
}

// 2. File size range tests (25 tests)
macro_rules! test_sizes {
    ($($name:ident: $size:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let line = format!("0|/file|100|-rw-r--r--|0|0|{}|1700000000|1700000000|1700000000|0", $size);
                let entries = parse_bodyfile_line(&line, 1, None).unwrap();
                assert_eq!(entries[0].size, $size);
            }
        )*
    };
}

test_sizes! {
    test_size_0: 0u64,
    test_size_1: 1u64,
    test_size_2: 2u64,
    test_size_16: 16u64,
    test_size_64: 64u64,
    test_size_128: 128u64,
    test_size_256: 256u64,
    test_size_512: 512u64,
    test_size_1024: 1024u64,
    test_size_2048: 2048u64,
    test_size_4096: 4096u64,
    test_size_8192: 8192u64,
    test_size_16384: 16384u64,
    test_size_32768: 32768u64,
    test_size_65536: 65536u64,
    test_size_1mb: 1_048_576u64,
    test_size_10mb: 10_485_760u64,
    test_size_100mb: 104_857_600u64,
    test_size_1gb: 1_073_741_824u64,
    test_size_10gb: 10_737_418_240u64,
    test_size_100gb: 107_374_182_400u64,
    test_size_1tb: 1_099_511_627_776u64,
    test_size_10tb: 10_995_116_277_760u64,
    test_size_1pb: 1_125_899_906_842_624u64,
    test_size_u64_max: 18_446_744_073_709_551_615u64,
}

// 3. User ID & Group ID range tests (25 tests)
macro_rules! test_uids {
    ($($name:ident: $uid:expr, $gid:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let line = format!("0|/file|100|-rw-r--r--|{}|{}|100|1700000000|1700000000|1700000000|0", $uid, $gid);
                let entries = parse_bodyfile_line(&line, 1, None).unwrap();
                assert_eq!(entries[0].uid, $uid);
                assert_eq!(entries[0].gid, $gid);
            }
        )*
    };
}

test_uids! {
    test_uid_root: 0, 0,
    test_uid_bin: 1, 1,
    test_uid_daemon: 2, 2,
    test_uid_sys: 3, 3,
    test_uid_adm: 4, 4,
    test_uid_tty: 5, 5,
    test_uid_disk: 6, 6,
    test_uid_lp: 7, 7,
    test_uid_mail: 8, 8,
    test_uid_news: 9, 9,
    test_uid_uucp: 10, 10,
    test_uid_man: 12, 12,
    test_uid_proxy: 13, 13,
    test_uid_kmem: 15, 15,
    test_uid_dialout: 20, 20,
    test_uid_fax: 21, 21,
    test_uid_voice: 22, 22,
    test_uid_cdrom: 24, 24,
    test_uid_floppy: 25, 25,
    test_uid_tape: 26, 26,
    test_uid_sudo: 27, 27,
    test_uid_audio: 29, 29,
    test_uid_user_1000: 1000, 1000,
    test_uid_user_1001: 1001, 1001,
    test_uid_nobody: 65534, 65534,
}

// 4. USN Reason Individual Bit Tests (24 tests)
macro_rules! test_usn_bits {
    ($($name:ident: $bit:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                assert_eq!(decode_usn_reason($bit), $expected);
            }
        )*
    };
}

test_usn_bits! {
    test_usn_bit_01: 0x00000001 => "DATA_OVERWRITE",
    test_usn_bit_02: 0x00000002 => "DATA_EXTEND",
    test_usn_bit_03: 0x00000004 => "DATA_TRUNCATION",
    test_usn_bit_04: 0x00000010 => "NAMED_DATA_OVERWRITE",
    test_usn_bit_05: 0x00000020 => "NAMED_DATA_EXTEND",
    test_usn_bit_06: 0x00000040 => "NAMED_DATA_TRUNCATION",
    test_usn_bit_07: 0x00000100 => "FILE_CREATE",
    test_usn_bit_08: 0x00000200 => "FILE_DELETE",
    test_usn_bit_09: 0x00000400 => "EA_CHANGE",
    test_usn_bit_10: 0x00000800 => "SECURITY_CHANGE",
    test_usn_bit_11: 0x00001000 => "RENAME_OLD_NAME",
    test_usn_bit_12: 0x00002000 => "RENAME_NEW_NAME",
    test_usn_bit_13: 0x00004000 => "INDEXABLE_CHANGE",
    test_usn_bit_14: 0x00008000 => "BASIC_INFO_CHANGE",
    test_usn_bit_15: 0x00010000 => "HARD_LINK_CHANGE",
    test_usn_bit_16: 0x00020000 => "COMPRESSION_CHANGE",
    test_usn_bit_17: 0x00040000 => "ENCRYPTION_CHANGE",
    test_usn_bit_18: 0x00080000 => "OBJECT_ID_CHANGE",
    test_usn_bit_19: 0x00100000 => "REPARSE_POINT_CHANGE",
    test_usn_bit_20: 0x00200000 => "STREAM_CHANGE",
    test_usn_bit_21: 0x00400000 => "TRANSACTED_CHANGE",
    test_usn_bit_22: 0x00800000 => "INTEGRITY_CHANGE",
    test_usn_bit_23: 0x80000000 => "CLOSE",
    test_usn_bit_24: 0x00000300 => "FILE_CREATE+FILE_DELETE",
}

// 5. Unix timestamp formatting variations (25 tests)
macro_rules! test_unix_times {
    ($($name:ident: $secs:expr => $expected_start:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let s = format_unix_timestamp($secs, 0).unwrap();
                assert!(s.starts_with($expected_start), "Expected to start with {}, got {}", $expected_start, s);
                assert!(s.ends_with('Z'));
            }
        )*
    };
}

test_unix_times! {
    test_t_1970: 0 => "1970-01-01T00:00:00",
    test_t_1975: 157766400 => "1975-01-01",
    test_t_1980: 315532800 => "1980-01-01",
    test_t_1985: 473385600 => "1985-01-01",
    test_t_1990: 631152000 => "1990-01-01",
    test_t_1995: 788918400 => "1995-01-01",
    test_t_2000: 946684800 => "2000-01-01",
    test_t_2005: 1104537600 => "2005-01-01",
    test_t_2010: 1262304000 => "2010-01-01",
    test_t_2015: 1420070400 => "2015-01-01",
    test_t_2020: 1577836800 => "2020-01-01",
    test_t_2021: 1609459200 => "2021-01-01",
    test_t_2022: 1640995200 => "2022-01-01",
    test_t_2023: 1672531200 => "2023-01-01",
    test_t_2024: 1704067200 => "2024-01-01",
    test_t_2025: 1735689600 => "2025-01-01",
    test_t_2026: 1767225600 => "2026-01-01",
    test_t_2027: 1798761600 => "2027-01-01",
    test_t_2028: 1830297600 => "2028-01-01",
    test_t_2029: 1861920000 => "2029-01-01",
    test_t_2030: 1893456000 => "2030-01-01",
    test_t_2031: 1924992000 => "2031-01-01",
    test_t_2032: 1956528000 => "2032-01-01",
    test_t_2035: 2051222400 => "2035-01-01",
    test_t_2038: 2145916800 => "2038-01-01",
}

// 6. CSV Escaping Stress Tests (25 tests)
macro_rules! test_escaping_stress {
    ($($name:ident: $input:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                assert_eq!(escape_csv($input), $expected);
            }
        )*
    };
}

test_escaping_stress! {
    test_esc_s1: "a,b" => "\"a,b\"",
    test_esc_s2: "a,b,c" => "\"a,b,c\"",
    test_esc_s3: "a,b,c,d" => "\"a,b,c,d\"",
    test_esc_s4: "\"hello\"" => "\"\"\"hello\"\"\"",
    test_esc_s5: "\"\"" => "\"\"\"\"\"\"",
    test_esc_s6: "a\nb" => "\"a\nb\"",
    test_esc_s7: "a\r\nb" => "\"a\r\nb\"",
    test_esc_s8: "a\rb" => "\"a\rb\"",
    test_esc_s9: ",," => "\",,\"",
    test_esc_s10: ",a," => "\",a,\"",
    test_esc_s11: "\"a,b\"" => "\"\"\"a,b\"\"\"",
    test_esc_s12: "a, \"b\"" => "\"a, \"\"b\"\"\"",
    test_esc_s13: "normal" => "normal",
    test_esc_s14: "with spaces" => "with spaces",
    test_esc_s15: "with-dash" => "with-dash",
    test_esc_s16: "with_underscore" => "with_underscore",
    test_esc_s17: "with.dot" => "with.dot",
    test_esc_s18: "with:colon" => "with:colon",
    test_esc_s19: "with;semicolon" => "with;semicolon",
    test_esc_s20: "with/slash" => "with/slash",
    test_esc_s21: "with\\backslash" => "with\\backslash",
    test_esc_s22: "with[bracket]" => "with[bracket]",
    test_esc_s23: "with(parentheses)" => "with(parentheses)",
    test_esc_s24: "with{brace}" => "with{brace}",
    test_esc_s25: "with=equals" => "with=equals",
}
