use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageType {
    WindowsMftTriage,
    LinuxTriage,
    GenericFolder,
}

pub fn detect_triage_type(dir: &Path) -> TriageType {
    let paths: Vec<std::path::PathBuf> = WalkDir::new(dir).max_depth(4).into_iter().filter_map(|e| e.ok()).map(|e| e.into_path()).collect();
    detect_triage_type_in(dir, &paths)
}

/// The same, from the paths of the tree already known (a picture taken
/// before the run read anything): no directory is listed again.
pub fn detect_triage_type_in(dir: &Path, paths: &[std::path::PathBuf]) -> TriageType {
    let mut has_mft = false;
    let mut has_linux_structures = false;

    for p in paths {
        let depth = p.strip_prefix(dir).map(|r| r.components().count()).unwrap_or(usize::MAX);
        if depth > 4 {
            continue;
        }
        let fname = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
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
