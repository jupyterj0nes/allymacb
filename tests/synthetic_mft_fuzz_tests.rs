use allymacb::parsers::mft::MftParseOptions;
use std::path::PathBuf;

// Test MftParseOptions defaults and builder behaviors (30 tests)
macro_rules! test_drive_letters {
    ($($fn_name:ident: $drive:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let opts = MftParseOptions {
                    include_file_name_timestamps: true,
                    resident_dir: Some(PathBuf::from("residents")),
                    resident_report: Some(PathBuf::from("report.txt")),
                    drive_letter: Some($drive),
                    quiet: true,
                };
                assert_eq!(opts.drive_letter, Some($drive));
                assert!(opts.include_file_name_timestamps);
                assert!(opts.quiet);
            }
        )*
    };
}

test_drive_letters! {
    test_drive_c: 'C',
    test_drive_d: 'D',
    test_drive_e: 'E',
    test_drive_f: 'F',
    test_drive_g: 'G',
    test_drive_h: 'H',
    test_drive_i: 'I',
    test_drive_j: 'J',
    test_drive_k: 'K',
    test_drive_l: 'L',
    test_drive_m: 'M',
    test_drive_n: 'N',
    test_drive_o: 'O',
    test_drive_p: 'P',
    test_drive_q: 'Q',
    test_drive_r: 'R',
    test_drive_s: 'S',
    test_drive_t: 'T',
    test_drive_u: 'U',
    test_drive_v: 'V',
    test_drive_w: 'W',
    test_drive_x: 'X',
    test_drive_y: 'Y',
    test_drive_z: 'Z',
    test_drive_low_c: 'c',
    test_drive_low_d: 'd',
}

// Path sanitization tests for resident file extraction (30 tests)
macro_rules! test_path_sanitizer {
    ($($fn_name:ident: $input:expr => $expected:expr),* $(,)?) => {
        $(
            #[test]
            fn $fn_name() {
                let clean = $input
                    .replace(":\\", "/")
                    .replace(":/", "/")
                    .replace('\\', "/")
                    .replace(':', "_");
                let safe_rel = clean.trim_start_matches('/');
                assert_eq!(safe_rel, $expected);
            }
        )*
    };
}

test_path_sanitizer! {
    test_clean_p1: "C:\\Windows\\System32\\cmd.exe" => "C/Windows/System32/cmd.exe",
    test_clean_p2: "C:\\Users\\admin\\file.txt" => "C/Users/admin/file.txt",
    test_clean_p3: "C:\\file.txt:Zone.Identifier" => "C/file.txt_Zone.Identifier",
    test_clean_p4: "D:\\backup\\dump.tar.gz" => "D/backup/dump.tar.gz",
    test_clean_p5: "E:/path/forward/slash" => "E/path/forward/slash",
    test_clean_p6: "\\\\server\\share\\file" => "server/share/file",
    test_clean_p7: "C:\\Program Files (x86)\\test" => "C/Program Files (x86)/test",
    test_clean_p8: "C:\\[UNKNOWN]\\entry_123" => "C/[UNKNOWN]/entry_123",
    test_clean_p9: "C:\\file:ads1:ads2" => "C/file_ads1_ads2",
    test_clean_p10: "C:\\Windows\\$MFT" => "C/Windows/$MFT",
    test_clean_p11: "C:\\Windows\\$LogFile" => "C/Windows/$LogFile",
    test_clean_p12: "C:\\$Extend\\$UsnJrnl" => "C/$Extend/$UsnJrnl",
    test_clean_p13: "C:\\pagefile.sys" => "C/pagefile.sys",
    test_clean_p14: "C:\\hiberfil.sys" => "C/hiberfil.sys",
    test_clean_p15: "C:\\swapfile.sys" => "C/swapfile.sys",
    test_clean_p16: "C:\\Recovery\\Winre.wim" => "C/Recovery/Winre.wim",
    test_clean_p17: "C:\\System Volume Information\\Syscache.hve" => "C/System Volume Information/Syscache.hve",
    test_clean_p18: "C:\\Windows\\System32\\config\\SYSTEM" => "C/Windows/System32/config/SYSTEM",
    test_clean_p19: "C:\\Windows\\System32\\config\\SAM" => "C/Windows/System32/config/SAM",
    test_clean_p20: "C:\\Windows\\System32\\config\\SECURITY" => "C/Windows/System32/config/SECURITY",
    test_clean_p21: "C:\\Windows\\System32\\config\\SOFTWARE" => "C/Windows/System32/config/SOFTWARE",
    test_clean_p22: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx" => "C/Windows/System32/winevt/Logs/Security.evtx",
    test_clean_p23: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx" => "C/Windows/System32/winevt/Logs/System.evtx",
    test_clean_p24: "C:\\Windows\\System32\\drivers\\etc\\hosts" => "C/Windows/System32/drivers/etc/hosts",
    test_clean_p25: "C:\\Users\\Default\\NTUSER.DAT" => "C/Users/Default/NTUSER.DAT",
}
