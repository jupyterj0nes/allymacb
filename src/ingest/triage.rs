use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageType {
    WindowsMftTriage,
    LinuxTriage,
    GenericFolder,
}

pub fn detect_triage_type(dir: &Path) -> TriageType {
    let mut has_mft = false;
    let mut has_linux_structures = false;

    for entry_res in WalkDir::new(dir).max_depth(4).into_iter().filter_map(|e| e.ok()) {
        let fname = entry_res.file_name().to_string_lossy().to_lowercase();
        if fname == "$mft" || fname == "_mft" || fname.ends_with("$mft") {
            has_mft = true;
            break;
        }

        if fname == "etc" || fname == "var" || fname == "sys" || fname == "proc" || fname == "uac" {
            has_linux_structures = true;
        }
    }

    if has_mft {
        TriageType::WindowsMftTriage
    } else if has_linux_structures {
        TriageType::LinuxTriage
    } else {
        TriageType::GenericFolder
    }
}
