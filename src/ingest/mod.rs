pub mod archive;
pub mod carve;
pub mod carve_text;
pub mod image;
pub mod triage;

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use walkdir::WalkDir;

use crate::error::{AllyError, ErrorCode, Result};
use crate::parsers::bodyfile::parse_bodyfile_stream;
use crate::parsers::fs_walk::{walk_directory_timeline, walk_directory_timeline_with, WalkOptions};
use crate::parsers::mft::{parse_mft_file, MftParseOptions, ResidentStats};
use crate::parsers::usn::{parse_usn_file, UsnParseOptions};
use crate::timeline::TimelineEntry;
use archive::{extract_archive_with_report, process_archive_fast};
use image::parse_forensic_image;
use triage::{detect_triage_type, TriageType};

static WORKSPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct EvidenceWorkspace {
    temp_dir: PathBuf,
}

impl EvidenceWorkspace {
    pub fn new() -> Result<Self> {
        let unique_id = format!(
            "allymacb_{}_{}",
            std::process::id(),
            WORKSPACE_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let temp_dir = std::env::temp_dir().join(unique_id);
        fs::create_dir_all(&temp_dir).map_err(|e| AllyError::Io {
            code: ErrorCode::IoError,
            source: e,
            context: format!("Creating workspace directory {}", temp_dir.display()),
        })?;
        Ok(Self { temp_dir })
    }

    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }
}

impl Drop for EvidenceWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

pub fn is_image_extension(ext: &str) -> bool {
    matches!(
        ext,
        "dd" | "raw" | "img" | "001" | "e01" | "ex01" | "vmdk" | "vhd" | "vhdx"
    )
}

pub fn is_archive_extension(ext: &str) -> bool {
    matches!(ext, "zip" | "tar" | "tgz" | "gz")
}

/// `$MFT` as exported by KAPE/Velociraptor/UAC (`$MFT`, `_MFT`, `C__$MFT`, ...).
pub fn is_mft_name(base_lower: &str) -> bool {
    base_lower == "$mft" || base_lower == "_mft" || base_lower.ends_with("$mft")
}

/// `$UsnJrnl:$J` as exported by triage tools: the colon is encoded as `%3A`,
/// `_` or `-`, and some tools ship just `$J` under `$Extend`.
pub fn is_usn_name(path_lower: &str) -> bool {
    let p = path_lower.replace('\\', "/");
    let base = p.rsplit('/').next().unwrap_or(&p);
    base == "$usnjrnl%3a$j"
        || base == "$usnjrnl_$j"
        || base == "$usnjrnl-$j"
        || base == "$usnjrnl:$j"
        || base == "$usnjrnl$j"
        || base == "usnjrnl.$j"
        || base == "$j" && p.contains("$extend")
        || (base.contains("usnjrnl") && base.ends_with("$j"))
}

pub fn is_bodyfile_name(base_lower: &str) -> bool {
    base_lower == "bodyfile"
        || base_lower == "bodyfile.txt"
        || base_lower.ends_with(".body")
        || base_lower.ends_with(".bodyfile")
        || base_lower.ends_with("bodyfile.txt")
}

/// Heuristic for an unnamed stream: a TSK bodyfile line has exactly 10 pipes
/// (11 fields) and its last four fields are integers.
pub fn looks_like_bodyfile(first_line: &str) -> bool {
    let fields: Vec<&str> = first_line.trim().rsplitn(5, '|').collect();
    if fields.len() < 5 {
        return false;
    }
    fields[..4].iter().all(|f| f.trim().parse::<i64>().is_ok()) && first_line.matches('|').count() >= 10
}

/// Everything the CLI needs to decide the exit code and what to tell the analyst.
#[derive(Debug, Default)]
pub struct IngestReport {
    pub timeline: Vec<TimelineEntry>,
    pub resident_stats: ResidentStats,
    /// Evidence sources (files, archives, images, partitions, directories) parsed successfully.
    pub sources_ok: usize,
    /// Evidence sources that failed or were not found.
    pub sources_failed: usize,
    pub warnings: Vec<String>,
}

impl IngestReport {
    fn ok(&mut self, entries: Vec<TimelineEntry>, stats: ResidentStats) {
        self.timeline.extend(entries);
        self.resident_stats.total_extracted += stats.total_extracted;
        self.resident_stats.total_bytes += stats.total_bytes;
        self.resident_stats.total_failed += stats.total_failed;
        self.resident_stats.total_unsafe_paths += stats.total_unsafe_paths;
        self.sources_ok += 1;
    }

    fn fail(&mut self, msg: String) {
        eprintln!("[!] {}", msg);
        self.warnings.push(msg);
        self.sources_failed += 1;
    }

    fn warn(&mut self, msg: String) {
        eprintln!("[!] {}", msg);
        self.warnings.push(msg);
    }
}

fn info(quiet: bool, msg: String) {
    if !quiet {
        eprintln!("{}", msg);
    }
}

fn usn_options(mft_options: &MftParseOptions) -> UsnParseOptions {
    UsnParseOptions {
        drive_letter: mft_options.drive_letter,
        quiet: mft_options.quiet,
        mft_path_cache: None,
    }
}

fn parse_bodyfile_path(path: &Path) -> Result<Vec<TimelineEntry>> {
    let f = fs::File::open(path).map_err(|e| AllyError::io_with_context(e, format!("Opening bodyfile {}", path.display())))?;
    let prefix = path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string());
    Ok(parse_bodyfile_stream(BufReader::new(f), prefix.as_deref()))
}

/// Extracts an archive that holds no forensic artifact and timelines its
/// contents from the extracted files' modification times only (the only
/// timestamp an archive preserves).
fn timeline_extracted_archive(
    file_path: &Path,
    mft_options: &MftParseOptions,
    workspace: &EvidenceWorkspace,
    report: &mut IngestReport,
) {
    let extract_target = workspace.temp_dir().join(format!("arch_{}", WORKSPACE_COUNTER.fetch_add(1, Ordering::Relaxed)));
    if let Err(e) = fs::create_dir_all(&extract_target) {
        report.fail(format!("{}: cannot create extraction dir: {}", file_path.display(), e));
        return;
    }
    let extracted = match extract_archive_with_report(file_path, &extract_target) {
        Ok(r) => r,
        Err(e) => {
            report.fail(format!("{}: {}", file_path.display(), e));
            return;
        }
    };
    if extracted.unsafe_entries > 0 {
        report.warn(format!(
            "{}: {} entries refused because their path escaped the extraction directory",
            file_path.display(),
            extracted.unsafe_entries
        ));
    }
    if extracted.files.is_empty() {
        report.fail(format!("{}: archive contains no files", file_path.display()));
        return;
    }
    report.warn(format!(
        "{}: no $MFT, USN journal or bodyfile inside; timelining {} extracted file(s) from archive modification times only (type column shows m... only)",
        file_path.display(),
        extracted.files.len()
    ));

    // The extracted tree may itself contain MFTs/images/archives (nested evidence).
    let (mut entries, stats) = process_directory_internal(&extract_target, mft_options, workspace.temp_dir(), report, true);
    let target_prefix = extract_target.to_string_lossy().to_string();
    let archive_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("archive");
    for entry in &mut entries {
        if entry.file_name.starts_with(&target_prefix) {
            let rel = entry.file_name[target_prefix.len()..].trim_start_matches(['\\', '/']);
            entry.file_name = format!("[{}]\\{}", archive_name, rel);
        }
    }
    report.ok(entries, stats);
}

pub fn process_evidence_inputs(
    files: &[PathBuf],
    directories: &[PathBuf],
    usn_file: Option<&PathBuf>,
    mft_options: &MftParseOptions,
) -> Result<IngestReport> {
    let workspace = EvidenceWorkspace::new()?;
    let mut report = IngestReport::default();
    let quiet = mft_options.quiet;

    // 1. Process explicit individual files
    for file_path in files {
        if !file_path.exists() {
            report.fail(format!("File not found: {}", file_path.display()));
            continue;
        }

        let fname = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let fname_lower = fname.to_lowercase();
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if is_image_extension(&ext) {
            info(quiet, format!("[*] Processing forensic image: {}", file_path.display()));
            match parse_forensic_image(file_path, mft_options, workspace.temp_dir()) {
                Ok((entries, stats)) => report.ok(entries, stats),
                Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
            }
        } else if is_archive_extension(&ext) {
            info(quiet, format!("[*] Inspecting archive: {}", file_path.display()));
            match process_archive_fast(file_path, mft_options, workspace.temp_dir()) {
                Ok(Some((entries, stats))) => {
                    info(quiet, format!("    [+] {} timeline entries streamed directly from container", entries.len()));
                    report.ok(entries, stats);
                }
                Ok(None) => timeline_extracted_archive(file_path, mft_options, &workspace, &mut report),
                Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
            }
        } else if is_mft_name(&fname_lower) {
            info(quiet, format!("[*] Parsing MFT file: {}", file_path.display()));
            match parse_mft_file(file_path, mft_options) {
                Ok((entries, stats)) => report.ok(entries, stats),
                Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
            }
        } else if is_usn_name(&fname_lower) || fname_lower.contains("usnjrnl") {
            info(quiet, format!("[*] Parsing USN Journal file: {}", file_path.display()));
            match parse_usn_file(file_path, &usn_options(mft_options)) {
                Ok(entries) => report.ok(entries, ResidentStats::default()),
                Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
            }
        } else if is_bodyfile_name(&fname_lower) {
            info(quiet, format!("[*] Parsing bodyfile: {}", file_path.display()));
            match parse_bodyfile_path(file_path) {
                Ok(entries) => report.ok(entries, ResidentStats::default()),
                Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
            }
        } else {
            // Sniff the content.
            match sniff_file(file_path) {
                Ok(Sniffed::Mft) => {
                    info(quiet, format!("[*] Identified MFT signature in {}", file_path.display()));
                    match parse_mft_file(file_path, mft_options) {
                        Ok((entries, stats)) => report.ok(entries, stats),
                        Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
                    }
                }
                Ok(Sniffed::Bodyfile) => {
                    info(quiet, format!("[*] Identified bodyfile content in {}", file_path.display()));
                    match parse_bodyfile_path(file_path) {
                        Ok(entries) => report.ok(entries, ResidentStats::default()),
                        Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
                    }
                }
                Ok(Sniffed::Image) => {
                    info(quiet, format!("[*] Identified disk/volume image signature in {}", file_path.display()));
                    match parse_forensic_image(file_path, mft_options, workspace.temp_dir()) {
                        Ok((entries, stats)) => report.ok(entries, stats),
                        Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
                    }
                }
                Ok(Sniffed::Unknown) if mft_options.carve => {
                    info(quiet, format!("[*] Unrecognized file, carving it for NTFS records: {}", file_path.display()));
                    match carve::carve_blob(file_path, mft_options) {
                        Ok((entries, stats)) => {
                            info(quiet, format!("    [+] Carving: {}", carve::describe_stats(&stats)));
                            if entries.is_empty() {
                                report.fail(format!("{}: carving found no NTFS FILE records or $I30 entries", file_path.display()));
                            } else {
                                report.ok(entries, ResidentStats::default());
                            }
                        }
                        Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
                    }
                }
                Ok(Sniffed::Unknown) => {
                    report.warn(format!(
                        "{}: unrecognized evidence type; timelining the host filesystem metadata of this file only (use --carve to scan it for NTFS records)",
                        file_path.display()
                    ));
                    match walk_directory_timeline(file_path) {
                        Ok(entries) => report.ok(entries, ResidentStats::default()),
                        Err(e) => report.fail(format!("{}: {}", file_path.display(), e)),
                    }
                }
                Err(e) => report.fail(format!("{}: cannot read: {}", file_path.display(), e)),
            }
        }
    }

    // 2. Process specified directories / triages
    for dir_path in directories {
        if !dir_path.exists() {
            report.fail(format!("Directory not found: {}", dir_path.display()));
            continue;
        }

        info(quiet, format!("[*] Scanning evidence directory: {}", dir_path.display()));
        let before_ok = report.sources_ok;
        let before_failed = report.sources_failed;
        let (entries, stats) = process_directory_internal(dir_path, mft_options, workspace.temp_dir(), &mut report, false);
        if report.sources_ok == before_ok && report.sources_failed == before_failed && entries.is_empty() {
            report.fail(format!("{}: no evidence found", dir_path.display()));
        } else {
            report.timeline.extend(entries);
            report.resident_stats.total_extracted += stats.total_extracted;
            report.resident_stats.total_bytes += stats.total_bytes;
            report.resident_stats.total_failed += stats.total_failed;
            report.resident_stats.total_unsafe_paths += stats.total_unsafe_paths;
        }
    }

    // 3. Process standalone USN Journal file if supplied via CLI
    if let Some(usn_path) = usn_file {
        if usn_path.exists() {
            info(quiet, format!("[*] Parsing standalone USN Journal: {}", usn_path.display()));
            match parse_usn_file(usn_path, &usn_options(mft_options)) {
                Ok(entries) => report.ok(entries, ResidentStats::default()),
                Err(e) => report.fail(format!("{}: {}", usn_path.display(), e)),
            }
        } else {
            report.fail(format!("USN journal not found: {}", usn_path.display()));
        }
    }

    Ok(report)
}

/// Scans a directory for every supported artifact and parses each one.
/// Successes and failures are recorded in `report`; the returned entries are
/// *not* yet added to the report (the caller may need to rewrite paths).
fn process_directory_internal(
    dir_path: &Path,
    mft_options: &MftParseOptions,
    temp_dir: &Path,
    report: &mut IngestReport,
    from_archive: bool,
) -> (Vec<TimelineEntry>, ResidentStats) {
    let quiet = mft_options.quiet;
    let mut combined_timeline = Vec::new();
    let mut total_resident_stats = ResidentStats::default();

    let triage_type = detect_triage_type(dir_path);

    let mut mft_files = Vec::new();
    let mut usn_files = Vec::new();
    let mut body_files = Vec::new();
    let mut image_files = Vec::new();
    let mut archive_files = Vec::new();

    for entry_res in WalkDir::new(dir_path).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        let p = entry_res.path();
        if !p.is_file() {
            continue;
        }
        let fname_lower = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let rel_lower = p.strip_prefix(dir_path).unwrap_or(p).to_string_lossy().to_lowercase();

        if is_mft_name(&fname_lower) {
            mft_files.push(p.to_path_buf());
        } else if is_usn_name(&rel_lower) {
            usn_files.push(p.to_path_buf());
        } else if is_bodyfile_name(&fname_lower) {
            body_files.push(p.to_path_buf());
        } else if is_image_extension(&ext) {
            image_files.push(p.to_path_buf());
        } else if is_archive_extension(&ext) {
            archive_files.push(p.to_path_buf());
        }
    }

    fn merge(
        timeline: &mut Vec<TimelineEntry>,
        total: &mut ResidentStats,
        entries: Vec<TimelineEntry>,
        stats: ResidentStats,
        report: &mut IngestReport,
    ) {
        timeline.extend(entries);
        total.total_extracted += stats.total_extracted;
        total.total_bytes += stats.total_bytes;
        total.total_failed += stats.total_failed;
        total.total_unsafe_paths += stats.total_unsafe_paths;
        report.sources_ok += 1;
    }

    for mft_p in &mft_files {
        info(quiet, format!("[*] Found MFT in triage: {}", mft_p.display()));
        match parse_mft_file(mft_p, mft_options) {
            Ok((entries, stats)) => merge(&mut combined_timeline, &mut total_resident_stats, entries, stats, report),
            Err(e) => report.fail(format!("{}: {}", mft_p.display(), e)),
        }
    }

    for usn_p in &usn_files {
        info(quiet, format!("[*] Found USN journal in triage: {}", usn_p.display()));
        match parse_usn_file(usn_p, &usn_options(mft_options)) {
            Ok(entries) => merge(&mut combined_timeline, &mut total_resident_stats, entries, ResidentStats::default(), report),
            Err(e) => report.fail(format!("{}: {}", usn_p.display(), e)),
        }
    }

    for body_p in &body_files {
        info(quiet, format!("[*] Found bodyfile in triage: {}", body_p.display()));
        match parse_bodyfile_path(body_p) {
            Ok(entries) => merge(&mut combined_timeline, &mut total_resident_stats, entries, ResidentStats::default(), report),
            Err(e) => report.fail(format!("{}: {}", body_p.display(), e)),
        }
    }

    for img_p in &image_files {
        info(quiet, format!("[*] Found disk image in directory: {}", img_p.display()));
        match parse_forensic_image(img_p, mft_options, temp_dir) {
            Ok((entries, stats)) => merge(&mut combined_timeline, &mut total_resident_stats, entries, stats, report),
            Err(e) => report.fail(format!("{}: {}", img_p.display(), e)),
        }
    }

    // Archives in parallel; each result carries its own success/failure.
    if !archive_files.is_empty() {
        use rayon::prelude::*;
        info(quiet, format!("[*] Processing {} archive(s) in parallel...", archive_files.len()));

        let results: Vec<(PathBuf, Result<Option<(Vec<TimelineEntry>, ResidentStats)>>)> = archive_files
            .par_iter()
            .map(|arch_p| (arch_p.clone(), process_archive_fast(arch_p, mft_options, temp_dir)))
            .collect();

        for (arch_p, res) in results {
            match res {
                Ok(Some((entries, stats))) => merge(&mut combined_timeline, &mut total_resident_stats, entries, stats, report),
                Ok(None) => report.warn(format!(
                    "{}: no $MFT, USN journal or bodyfile inside (archives found via -d are not extracted; pass it with -f to timeline its contents)",
                    arch_p.display()
                )),
                Err(e) => report.fail(format!("{}: {}", arch_p.display(), e)),
            }
        }
    }

    let found_artifacts = !(mft_files.is_empty() && usn_files.is_empty() && body_files.is_empty() && image_files.is_empty() && archive_files.is_empty());

    // Plain directory tree (Linux triage, loose files, extracted archive): walk it.
    let should_walk = if from_archive {
        !found_artifacts
    } else {
        combined_timeline.is_empty()
            && (triage_type == TriageType::LinuxTriage || triage_type == TriageType::GenericFolder)
    };
    if should_walk {
        info(quiet, format!("[*] Processing filesystem structure from: {}", dir_path.display()));
        let opts = WalkOptions { skip_root: from_archive, mtime_only: from_archive };
        match walk_directory_timeline_with(dir_path, &opts) {
            Ok(entries) => {
                if !from_archive {
                    report.warn(format!(
                        "{}: timestamps come from the host filesystem metadata of the files in this directory",
                        dir_path.display()
                    ));
                }
                merge(&mut combined_timeline, &mut total_resident_stats, entries, ResidentStats::default(), report)
            }
            Err(e) => report.fail(format!("{}: {}", dir_path.display(), e)),
        }
    }

    (combined_timeline, total_resident_stats)
}

enum Sniffed {
    Mft,
    Bodyfile,
    /// Raw disk or volume image recognised by signature (boot sector, GPT, MBR).
    Image,
    Unknown,
}

fn sniff_file(path: &Path) -> std::io::Result<Sniffed> {
    let mut f = fs::File::open(path)?;
    let mut header = vec![0u8; 1024 + 8];
    let n = f.read(&mut header)?;
    header.truncate(n);
    if n >= 4 && (&header[0..4] == b"FILE" || &header[0..4] == b"BAAD") {
        return Ok(Sniffed::Mft);
    }
    if n >= 512 {
        let ntfs = &header[3..11] == b"NTFS    ";
        let gpt = n >= 520 && &header[512..520] == b"EFI PART";
        let boot_sig = header[510] == 0x55 && header[511] == 0xAA;
        // A boot signature alone is weak; require a plausible partition entry or a known filesystem.
        let mbr_entry = boot_sig && (446..=494).step_by(16).any(|o| header[o + 4] != 0 && u32::from_le_bytes([header[o + 8], header[o + 9], header[o + 10], header[o + 11]]) != 0);
        if ntfs || gpt || mbr_entry {
            return Ok(Sniffed::Image);
        }
    }
    // Text sniff: binary data is simply "unknown", not an error.
    let f = fs::File::open(path)?;
    let mut raw = Vec::new();
    let mut reader = BufReader::new(f).take(64 * 1024);
    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&raw);
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if looks_like_bodyfile(t) {
            return Ok(Sniffed::Bodyfile);
        }
        break;
    }
    Ok(Sniffed::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usn_names() {
        assert!(is_usn_name("c/$extend/$usnjrnl%3a$j"));
        assert!(is_usn_name("$usnjrnl_$j"));
        assert!(is_usn_name("C\\$Extend\\$J".to_lowercase().as_str()));
        assert!(!is_usn_name("c/users/x/$j"));
        assert!(!is_usn_name("$mft"));
    }

    #[test]
    fn test_bodyfile_sniff() {
        assert!(looks_like_bodyfile("0|/etc/passwd|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|0"));
        assert!(!looks_like_bodyfile("hello world"));
        assert!(!looks_like_bodyfile("a|b|c|d|e|f|g|h|i|j|k"));
    }
}
