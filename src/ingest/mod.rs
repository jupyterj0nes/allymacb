pub mod archive;
pub mod image;
pub mod triage;

use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::parsers::fs_walk::walk_directory_timeline;
use crate::parsers::mft::{parse_mft_file, MftParseOptions, ResidentStats};
use crate::parsers::usn::{parse_usn_file, UsnParseOptions};
use crate::timeline::TimelineEntry;
use archive::{extract_archive, process_archive_fast};
use image::parse_forensic_image;
use triage::{detect_triage_type, TriageType};

pub struct EvidenceWorkspace {
    temp_dir: PathBuf,
}

impl EvidenceWorkspace {
    pub fn new() -> std::io::Result<Self> {
        let unique_id = format!("allymacb_{}_{}", std::process::id(), uuid_or_random());
        let temp_dir = std::env::temp_dir().join(unique_id);
        fs::create_dir_all(&temp_dir)?;
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

pub fn process_evidence_inputs(
    files: &[PathBuf],
    directories: &[PathBuf],
    usn_file: Option<&PathBuf>,
    mft_options: &MftParseOptions,
) -> Result<(Vec<TimelineEntry>, ResidentStats), Box<dyn std::error::Error + Send + Sync>> {
    let workspace = EvidenceWorkspace::new()?;
    let mut combined_timeline = Vec::new();
    let mut total_resident_stats = ResidentStats::default();

    // 1. Process explicit individual files
    for file_path in files {
        if !file_path.exists() {
            eprintln!("[!] File not found: {}", file_path.display());
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
            if !mft_options.quiet {
                println!("[*] Processing forensic image: {}", file_path.display());
            }
            if let Ok((entries, stats)) = parse_forensic_image(file_path, mft_options, workspace.temp_dir()) {
                combined_timeline.extend(entries);
                total_resident_stats.total_extracted += stats.total_extracted;
                total_resident_stats.total_bytes += stats.total_bytes;
            }
        } else if is_archive_extension(&ext) {
            if !mft_options.quiet {
                println!("[*] Inspecting archive: {}", file_path.display());
            }
            if let Ok(Some((entries, stats))) = process_archive_fast(file_path, mft_options, workspace.temp_dir()) {
                if !mft_options.quiet {
                    println!("    [+] Fast-streamed {} timeline entries directly from container", entries.len());
                }
                combined_timeline.extend(entries);
                total_resident_stats.total_extracted += stats.total_extracted;
                total_resident_stats.total_bytes += stats.total_bytes;
            } else {
                let extract_target = workspace.temp_dir().join(format!("arch_{}", uuid_or_random()));
                let _ = fs::create_dir_all(&extract_target);
                if let Ok(_extracted) = extract_archive(file_path, &extract_target) {
                    let (mut entries, stats) = process_directory_internal(&extract_target, mft_options, workspace.temp_dir())?;
                    let target_prefix = extract_target.to_string_lossy().to_string();
                    let archive_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("archive");
                    for entry in &mut entries {
                        if entry.file_name.starts_with(&target_prefix) {
                            let rel = entry.file_name[target_prefix.len()..].trim_start_matches(['\\', '/']);
                            entry.file_name = format!("[{}]\\{}", archive_name, rel);
                        }
                    }
                    combined_timeline.extend(entries);
                    total_resident_stats.total_extracted += stats.total_extracted;
                    total_resident_stats.total_bytes += stats.total_bytes;
                }
            }
        } else if fname_lower == "$mft" || fname_lower == "_mft" || fname_lower.ends_with("$mft") {
            if !mft_options.quiet {
                println!("[*] Parsing MFT file: {}", file_path.display());
            }
            if let Ok((entries, stats)) = parse_mft_file(file_path, mft_options) {
                combined_timeline.extend(entries);
                total_resident_stats.total_extracted += stats.total_extracted;
                total_resident_stats.total_bytes += stats.total_bytes;
            }
        } else if fname_lower.contains("$usnjrnl") || fname_lower.contains("usnjrnl") {
            if !mft_options.quiet {
                println!("[*] Parsing USN Journal file: {}", file_path.display());
            }
            let usn_opts = UsnParseOptions {
                drive_letter: mft_options.drive_letter,
                quiet: mft_options.quiet,
                mft_path_cache: None,
            };
            if let Ok(entries) = parse_usn_file(file_path, &usn_opts) {
                combined_timeline.extend(entries);
            }
        } else {
            // Check file header signature
            if let Ok(file_type) = check_file_signature(file_path) {
                match file_type.as_str() {
                    "mft" => {
                        if !mft_options.quiet {
                            println!("[*] Identified MFT signature in {}", file_path.display());
                        }
                        if let Ok((entries, stats)) = parse_mft_file(file_path, mft_options) {
                            combined_timeline.extend(entries);
                            total_resident_stats.total_extracted += stats.total_extracted;
                            total_resident_stats.total_bytes += stats.total_bytes;
                        }
                    }
                    _ => {
                        // Attempt generic directory walk / single file timeline
                        if let Ok(entries) = walk_directory_timeline(file_path) {
                            combined_timeline.extend(entries);
                        }
                    }
                }
            }
        }
    }

    // 2. Process specified directories / triages
    for dir_path in directories {
        if !dir_path.exists() {
            eprintln!("[!] Directory not found: {}", dir_path.display());
            continue;
        }

        if !mft_options.quiet {
            println!("[*] Scanning evidence directory: {}", dir_path.display());
        }

        let (entries, stats) = process_directory_internal(dir_path, mft_options, workspace.temp_dir())?;
        combined_timeline.extend(entries);
        total_resident_stats.total_extracted += stats.total_extracted;
        total_resident_stats.total_bytes += stats.total_bytes;
    }

    // 3. Process standalone USN Journal file if supplied via CLI
    if let Some(usn_path) = usn_file {
        if usn_path.exists() {
            if !mft_options.quiet {
                println!("[*] Parsing standalone USN Journal: {}", usn_path.display());
            }
            let usn_opts = UsnParseOptions {
                drive_letter: mft_options.drive_letter,
                quiet: mft_options.quiet,
                mft_path_cache: None,
            };
            if let Ok(entries) = parse_usn_file(usn_path, &usn_opts) {
                combined_timeline.extend(entries);
            }
        }
    }

    Ok((combined_timeline, total_resident_stats))
}

fn process_directory_internal(
    dir_path: &Path,
    mft_options: &MftParseOptions,
    temp_dir: &Path,
) -> Result<(Vec<TimelineEntry>, ResidentStats), Box<dyn std::error::Error + Send + Sync>> {
    let mut combined_timeline = Vec::new();
    let mut total_resident_stats = ResidentStats::default();

    let triage_type = detect_triage_type(dir_path);

    // Scan directory for MFTs, disk images, and archives
    let mut mft_files = Vec::new();
    let mut image_files = Vec::new();
    let mut archive_files = Vec::new();

    for entry_res in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
        let p = entry_res.path();
        if p.is_file() {
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let fname_lower = fname.to_lowercase();
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

            if fname_lower == "$mft" || fname_lower == "_mft" || fname_lower.ends_with("$mft") {
                mft_files.push(p.to_path_buf());
            } else if is_image_extension(&ext) {
                image_files.push(p.to_path_buf());
            } else if is_archive_extension(&ext) {
                archive_files.push(p.to_path_buf());
            }
        }
    }

    // Process all discovered MFTs
    for mft_p in mft_files {
        if !mft_options.quiet {
            println!("[*] Found MFT in triage: {}", mft_p.display());
        }
        if let Ok((entries, stats)) = parse_mft_file(&mft_p, mft_options) {
            combined_timeline.extend(entries);
            total_resident_stats.total_extracted += stats.total_extracted;
            total_resident_stats.total_bytes += stats.total_bytes;
        }
    }

    // Process all discovered disk images
    for img_p in image_files {
        if !mft_options.quiet {
            println!("[*] Found disk image in directory: {}", img_p.display());
        }
        if let Ok((entries, stats)) = parse_forensic_image(&img_p, mft_options, temp_dir) {
            combined_timeline.extend(entries);
            total_resident_stats.total_extracted += stats.total_extracted;
            total_resident_stats.total_bytes += stats.total_bytes;
        }
    }

    // Process all discovered archives in parallel
    if !archive_files.is_empty() {
        use rayon::prelude::*;
        if !mft_options.quiet {
            println!("[*] Processing {} archive(s) in parallel...", archive_files.len());
        }

        let arch_results: Vec<(Vec<TimelineEntry>, ResidentStats)> = archive_files
            .par_iter()
            .filter_map(|arch_p| {
                process_archive_fast(arch_p, mft_options, temp_dir).ok().flatten()
            })
            .collect();

        for (entries, stats) in arch_results {
            combined_timeline.extend(entries);
            total_resident_stats.total_extracted += stats.total_extracted;
            total_resident_stats.total_bytes += stats.total_bytes;
        }
    }

    // If it's a Linux triage or generic directory with no MFTs or images found, walk filesystem
    if combined_timeline.is_empty() && (triage_type == TriageType::LinuxTriage || triage_type == TriageType::GenericFolder) {
        if !mft_options.quiet {
            println!("[*] Processing Linux / filesystem structure from: {}", dir_path.display());
        }
        if let Ok(entries) = walk_directory_timeline(dir_path) {
            combined_timeline.extend(entries);
        }
    }

    Ok((combined_timeline, total_resident_stats))
}

fn check_file_signature(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut header = [0u8; 8];
    let n = f.read(&mut header)?;
    if n >= 4 && (&header[0..4] == b"FILE" || &header[0..4] == b"BAAD") {
        return Ok("mft".to_string());
    }
    Ok("unknown".to_string())
}

fn uuid_or_random() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(777777)
}
