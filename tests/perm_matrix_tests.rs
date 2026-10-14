use allymacb::parsers::ext4::mode_to_string;

macro_rules! test_octals {
    ($($name:ident: $mode:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                assert_eq!(mode_to_string($mode, false, false), $expected);
            }
        )*
    };
}

test_octals! {
    test_oct_000: 0o000 => "----------",
    test_oct_001: 0o001 => "---------x",
    test_oct_002: 0o002 => "--------w-",
    test_oct_003: 0o003 => "--------wx",
    test_oct_004: 0o004 => "-------r--",
    test_oct_005: 0o005 => "-------r-x",
    test_oct_006: 0o006 => "-------rw-",
    test_oct_007: 0o007 => "-------rwx",

    test_oct_010: 0o010 => "------x---",
    test_oct_011: 0o011 => "------x--x",
    test_oct_012: 0o012 => "------x-w-",
    test_oct_013: 0o013 => "------x-wx",
    test_oct_014: 0o014 => "------xr--",
    test_oct_015: 0o015 => "------xr-x",
    test_oct_016: 0o016 => "------xrw-",
    test_oct_017: 0o017 => "------xrwx",

    test_oct_020: 0o020 => "-----w----",
    test_oct_021: 0o021 => "-----w---x",
    test_oct_022: 0o022 => "-----w--w-",
    test_oct_023: 0o023 => "-----w--wx",
    test_oct_024: 0o024 => "-----w-r--",
    test_oct_025: 0o025 => "-----w-r-x",
    test_oct_026: 0o026 => "-----w-rw-",
    test_oct_027: 0o027 => "-----w-rwx",

    test_oct_040: 0o040 => "----r-----",
    test_oct_041: 0o041 => "----r----x",
    test_oct_042: 0o042 => "----r---w-",
    test_oct_043: 0o043 => "----r---wx",
    test_oct_044: 0o044 => "----r--r--",
    test_oct_045: 0o045 => "----r--r-x",
    test_oct_046: 0o046 => "----r--rw-",
    test_oct_047: 0o047 => "----r--rwx",

    test_oct_100: 0o100 => "---x------",
    test_oct_101: 0o101 => "---x-----x",
    test_oct_102: 0o102 => "---x----w-",
    test_oct_103: 0o103 => "---x----wx",
    test_oct_104: 0o104 => "---x---r--",
    test_oct_105: 0o105 => "---x---r-x",
    test_oct_106: 0o106 => "---x---rw-",
    test_oct_107: 0o107 => "---x---rwx",

    test_oct_200: 0o200 => "--w-------",
    test_oct_201: 0o201 => "--w------x",
    test_oct_202: 0o202 => "--w-----w-",
    test_oct_203: 0o203 => "--w-----wx",
    test_oct_204: 0o204 => "--w----r--",
    test_oct_205: 0o205 => "--w----r-x",
    test_oct_206: 0o206 => "--w----rw-",
    test_oct_207: 0o207 => "--w----rwx",

    test_oct_400: 0o400 => "-r--------",
    test_oct_401: 0o401 => "-r-------x",
    test_oct_402: 0o402 => "-r------w-",
    test_oct_403: 0o403 => "-r------wx",
    test_oct_404: 0o404 => "-r-----r--",
    test_oct_405: 0o405 => "-r-----r-x",
    test_oct_406: 0o406 => "-r-----rw-",
    test_oct_407: 0o407 => "-r-----rwx",

    test_oct_700: 0o700 => "-rwx------",
    test_oct_701: 0o701 => "-rwx-----x",
    test_oct_702: 0o702 => "-rwx----w-",
    test_oct_703: 0o703 => "-rwx----wx",
    test_oct_704: 0o704 => "-rwx---r--",
    test_oct_705: 0o705 => "-rwx---r-x",
    test_oct_706: 0o706 => "-rwx---rw-",
    test_oct_707: 0o707 => "-rwx---rwx",
}
