use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive as TarArchive;
use zip::read::ZipArchive;

use crate::error::{AllyError, ErrorCode, Result};
use crate::parsers::bodyfile::parse_bodyfile_stream;
use crate::parsers::mft::{parse_mft_file, MftParseOptions, ResidentStats};
use crate::timeline::TimelineEntry;

pub fn extract_archive(
    archive_path: &Path,
    target_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let mut extracted_files = Vec::new();
    let fname = archive_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fname_lower = fname.to_lowercase();

    if fname_lower.ends_with(".zip") {
        let file = File::open(archive_path).map_err(|e| AllyError::Io {
            code: ErrorCode::FileNotFound,
            source: e,
            context: format!("Opening zip archive {}", archive_path.display()),
        })?;
        let mut zip = ZipArchive::new(BufReader::new(file)).map_err(|e| AllyError::Archive {
            code: ErrorCode::ArchiveCorrupt,
            path: archive_path.display().to_string(),
            message: format!("Corrupted zip archive: {}", e),
        })?;

        for i in 0..zip.len() {
            let mut file = zip.by_index(i).map_err(|e| AllyError::Archive {
                code: ErrorCode::ArchiveDecompressionFailed,
                path: archive_path.display().to_string(),
                message: format!("Failed reading entry #{} from zip: {}", i, e),
            })?;
            let is_dir = file.name().map(|n| n.ends_with('/')).unwrap_or(false);
            let enclosed_name = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => continue,
            };

            let out_path = target_dir.join(&enclosed_name);
            if is_dir {
                let _ = fs::create_dir_all(&out_path);
            } else {
                if let Some(p) = out_path.parent() {
                    let _ = fs::create_dir_all(p);
                }
                if let Ok(mut outfile) = File::create(&out_path) {
                    let _ = io::copy(&mut file, &mut outfile);
                    extracted_files.push(out_path);
                }
            }
        }
    } else if fname_lower.ends_with(".tar.gz") || fname_lower.ends_with(".tgz") {
        let file = File::open(archive_path).map_err(|e| AllyError::Io {
            code: ErrorCode::FileNotFound,
            source: e,
            context: format!("Opening tar.gz archive {}", archive_path.display()),
        })?;
        let gz = GzDecoder::new(BufReader::new(file));
        let mut tar = TarArchive::new(gz);

        let entries = tar.entries().map_err(|e| AllyError::Archive {
            code: ErrorCode::ArchiveCorrupt,
            path: archive_path.display().to_string(),
            message: format!("Corrupted tar.gz: {}", e),
        })?;

        for entry_res in entries {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = match entry.path() {
                Ok(p) => p.to_path_buf(),
                Err(_) => continue,
            };
            let out_path = target_dir.join(&path);

            if entry.header().entry_type().is_dir() {
                let _ = fs::create_dir_all(&out_path);
            } else {
                if let Some(p) = out_path.parent() {
                    let _ = fs::create_dir_all(p);
                }
                if entry.unpack(&out_path).is_ok() {
                    extracted_files.push(out_path);
                }
            }
        }
    } else if fname_lower.ends_with(".tar") {
        let file = File::open(archive_path).map_err(|e| AllyError::Io {
            code: ErrorCode::FileNotFound,
            source: e,
            context: format!("Opening tar archive {}", archive_path.display()),
        })?;
        let mut tar = TarArchive::new(BufReader::new(file));

        let entries = tar.entries().map_err(|e| AllyError::Archive {
            code: ErrorCode::ArchiveCorrupt,
            path: archive_path.display().to_string(),
            message: format!("Corrupted tar: {}", e),
        })?;

        for entry_res in entries {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = match entry.path() {
                Ok(p) => p.to_path_buf(),
                Err(_) => continue,
            };
            let out_path = target_dir.join(&path);

            if entry.header().entry_type().is_dir() {
                let _ = fs::create_dir_all(&out_path);
            } else {
                if let Some(p) = out_path.parent() {
                    let _ = fs::create_dir_all(p);
                }
                if entry.unpack(&out_path).is_ok() {
                    extracted_files.push(out_path);
                }
            }
        }
    }

    Ok(extracted_files)
}

/// Attempts fast streaming inspection for UAC triages or embedded MFTs in an archive
pub fn process_archive_fast(
    archive_path: &Path,
    mft_options: &MftParseOptions,
    staging_dir: &Path,
) -> Result<Option<(Vec<TimelineEntry>, ResidentStats)>> {
    let fname = archive_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fname_lower = fname.to_lowercase();
    let container_name = fname
        .strip_suffix(".tar.gz")
        .or_else(|| fname.strip_suffix(".tgz"))
        .or_else(|| fname.strip_suffix(".zip"))
        .or_else(|| fname.strip_suffix(".tar"))
        .unwrap_or(fname);

    if fname_lower.ends_with(".tar.gz") || fname_lower.ends_with(".tgz") {
        let file = File::open(archive_path).map_err(|e| AllyError::Io {
            code: ErrorCode::FileNotFound,
            source: e,
            context: format!("Opening tar.gz {}", archive_path.display()),
        })?;
        let gz = GzDecoder::new(BufReader::new(file));
        let mut tar = TarArchive::new(gz);

        let entries = match tar.entries() {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };

        for entry_res in entries {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };

            let entry_path = match entry.path() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            let entry_lower = entry_path.to_lowercase();

            // Direct bodyfile in tar.gz
            if entry_lower.ends_with("bodyfile.txt") || entry_lower.ends_with("bodyfile") {
                let buf_reader = BufReader::new(&mut entry);
                let entries = parse_bodyfile_stream(buf_reader, Some(container_name));
                return Ok(Some((entries, ResidentStats::default())));
            }

            // Embedded inner tar.gz (e.g. UAC's outer packaging)
            if entry_lower.ends_with(".tar.gz") || entry_lower.ends_with(".tgz") {
                let inner_gz = GzDecoder::new(&mut entry);
                let mut inner_tar = TarArchive::new(inner_gz);

                if let Ok(inner_entries) = inner_tar.entries() {
                    for inner_entry_res in inner_entries {
                        let mut inner_entry = match inner_entry_res {
                            Ok(ie) => ie,
                            Err(_) => continue,
                        };

                        let inner_path = match inner_entry.path() {
                            Ok(ip) => ip.to_string_lossy().to_string(),
                            Err(_) => continue,
                        };
                        let inner_lower = inner_path.to_lowercase();

                        if inner_lower.ends_with("bodyfile.txt") || inner_lower.ends_with("bodyfile") {
                            let buf_reader = BufReader::new(&mut inner_entry);
                            let entries = parse_bodyfile_stream(buf_reader, Some(container_name));
                            return Ok(Some((entries, ResidentStats::default())));
                        }
                    }
                }
            }

            // Direct $MFT inside archive
            if entry_lower == "$mft" || entry_lower.ends_with("/$mft") || entry_lower.ends_with("\\$mft") {
                let out_mft = staging_dir.join(format!("mft_{}.bin", uuid_or_random()));
                let mut out_file = File::create(&out_mft).map_err(|e| AllyError::Io {
                    code: ErrorCode::IoError,
                    source: e,
                    context: format!("Creating temp mft {}", out_mft.display()),
                })?;
                io::copy(&mut entry, &mut out_file).map_err(|e| AllyError::Io {
                    code: ErrorCode::IoError,
                    source: e,
                    context: "Extracting $MFT from archive".to_string(),
                })?;
                let res = parse_mft_file(&out_mft, mft_options)?;
                let _ = fs::remove_file(out_mft);
                return Ok(Some(res));
            }
        }
    } else if fname_lower.ends_with(".zip") {
        let file = File::open(archive_path).map_err(|e| AllyError::Io {
            code: ErrorCode::FileNotFound,
            source: e,
            context: format!("Opening zip {}", archive_path.display()),
        })?;
        let mut zip = ZipArchive::new(BufReader::new(file)).map_err(|e| AllyError::Archive {
            code: ErrorCode::ArchiveCorrupt,
            path: archive_path.display().to_string(),
            message: format!("Corrupted zip: {}", e),
        })?;

        for i in 0..zip.len() {
            let mut file_entry = match zip.by_index(i) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let entry_name = file_entry.name().map(|n| n.to_lowercase()).unwrap_or_default();

            if entry_name.ends_with("bodyfile.txt") || entry_name.ends_with("bodyfile") {
                let buf_reader = BufReader::new(&mut file_entry);
                let entries = parse_bodyfile_stream(buf_reader, Some(container_name));
                return Ok(Some((entries, ResidentStats::default())));
            }

            if entry_name == "$mft" || entry_name.ends_with("/$mft") || entry_name.ends_with("\\$mft") {
                let out_mft = staging_dir.join(format!("mft_{}.bin", uuid_or_random()));
                let mut out_file = File::create(&out_mft).map_err(|e| AllyError::Io {
                    code: ErrorCode::IoError,
                    source: e,
                    context: format!("Creating temp mft {}", out_mft.display()),
                })?;
                io::copy(&mut file_entry, &mut out_file).map_err(|e| AllyError::Io {
                    code: ErrorCode::IoError,
                    source: e,
                    context: "Extracting $MFT from zip".to_string(),
                })?;
                let res = parse_mft_file(&out_mft, mft_options)?;
                let _ = fs::remove_file(out_mft);
                return Ok(Some(res));
            }
        }
    }

    Ok(None)
}

fn uuid_or_random() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(888888)
}
