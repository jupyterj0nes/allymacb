use allymacb::parsers::ext4::mode_to_string;

#[test]
fn test_mode_to_string_basics() {
    assert_eq!(mode_to_string(0o755, true, false), "drwxr-xr-x");
    assert_eq!(mode_to_string(0o644, false, false), "-rw-r--r--");
    assert_eq!(mode_to_string(0o777, false, true), "lrwxrwxrwx");
    assert_eq!(mode_to_string(0o000, false, false), "----------");
}

#[test]
fn test_mode_to_string_common_permissions() {
    assert_eq!(mode_to_string(0o700, false, false), "-rwx------");
    assert_eq!(mode_to_string(0o600, false, false), "-rw-------");
    assert_eq!(mode_to_string(0o400, false, false), "-r--------");
    assert_eq!(mode_to_string(0o750, true, false), "drwxr-x---");
    assert_eq!(mode_to_string(0o770, true, false), "drwxrwx---");
    assert_eq!(mode_to_string(0o664, false, false), "-rw-rw-r--");
    assert_eq!(mode_to_string(0o660, false, false), "-rw-rw----");
    assert_eq!(mode_to_string(0o775, false, false), "-rwxrwxr-x");
}

// Generate tests for all 8 user permission values (0 to 7)
macro_rules! generate_octal_user_tests {
    ($($fn_name:ident: $val:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let s = mode_to_string($val << 6, false, false);
                assert_eq!(&s[1..4], $expected);
                assert_eq!(&s[4..10], "------");
            }
        )*
    };
}

generate_octal_user_tests! {
    test_octal_user_0: 0 => "---",
    test_octal_user_1: 1 => "--x",
    test_octal_user_2: 2 => "-w-",
    test_octal_user_3: 3 => "-wx",
    test_octal_user_4: 4 => "r--",
    test_octal_user_5: 5 => "r-x",
    test_octal_user_6: 6 => "rw-",
    test_octal_user_7: 7 => "rwx",
}

// Generate tests for all 8 group permission values (0 to 7)
macro_rules! generate_octal_group_tests {
    ($($fn_name:ident: $val:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let s = mode_to_string($val << 3, false, false);
                assert_eq!(&s[1..4], "---");
                assert_eq!(&s[4..7], $expected);
                assert_eq!(&s[7..10], "---");
            }
        )*
    };
}

generate_octal_group_tests! {
    test_octal_group_0: 0 => "---",
    test_octal_group_1: 1 => "--x",
    test_octal_group_2: 2 => "-w-",
    test_octal_group_3: 3 => "-wx",
    test_octal_group_4: 4 => "r--",
    test_octal_group_5: 5 => "r-x",
    test_octal_group_6: 6 => "rw-",
    test_octal_group_7: 7 => "rwx",
}

// Generate tests for all 8 other permission values (0 to 7)
macro_rules! generate_octal_other_tests {
    ($($fn_name:ident: $val:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let s = mode_to_string($val, false, false);
                assert_eq!(&s[1..7], "------");
                assert_eq!(&s[7..10], $expected);
            }
        )*
    };
}

generate_octal_other_tests! {
    test_octal_other_0: 0 => "---",
    test_octal_other_1: 1 => "--x",
    test_octal_other_2: 2 => "-w-",
    test_octal_other_3: 3 => "-wx",
    test_octal_other_4: 4 => "r--",
    test_octal_other_5: 5 => "r-x",
    test_octal_other_6: 6 => "rw-",
    test_octal_other_7: 7 => "rwx",
}

// Generate tests for combinations of user, group, other
macro_rules! generate_mode_combo_tests {
    ($($fn_name:ident: $mode:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                assert_eq!(mode_to_string($mode, false, false), $expected);
            }
        )*
    };
}

generate_mode_combo_tests! {
    test_combo_01: 0o111 => "---x--x--x",
    test_combo_02: 0o222 => "--w--w--w-",
    test_combo_03: 0o333 => "--wx-wx-wx",
    test_combo_04: 0o444 => "-r--r--r--",
    test_combo_05: 0o555 => "-r-xr-xr-x",
    test_combo_06: 0o666 => "-rw-rw-rw-",
    test_combo_07: 0o777 => "-rwxrwxrwx",
    test_combo_08: 0o711 => "-rwx--x--x",
    test_combo_09: 0o744 => "-rwxr--r--",
    test_combo_10: 0o754 => "-rwxr-xr--",
    test_combo_11: 0o640 => "-rw-r-----",
    test_combo_12: 0o604 => "-rw----r--",
    test_combo_13: 0o440 => "-r--r-----",
    test_combo_14: 0o404 => "-r-----r--",
    test_combo_15: 0o077 => "----rwxrwx",
    test_combo_16: 0o070 => "----rwx---",
}
