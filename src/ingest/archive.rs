use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive as TarArchive;
use zip::read::ZipArchive;

use crate::parsers::bodyfile::parse_bodyfile_stream;
use crate::parsers::mft::{parse_mft_file, MftParseOptions, ResidentStats};
use crate::timeline::TimelineEntry;

pub fn extract_archive(
    archive_path: &Path,
    target_dir: &Path,
) -> io::Result<Vec<PathBuf>> {
    let mut extracted_files = Vec::new();
    let fname = archive_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fname_lower = fname.to_lowercase();

    if fname_lower.ends_with(".zip") {
        let file = File::open(archive_path)?;
        let mut zip = ZipArchive::new(BufReader::new(file))?;

        for i in 0..zip.len() {
            let mut file = zip.by_index(i)?;
            let is_dir = file.name().map(|n| n.ends_with('/')).unwrap_or(false);
            let enclosed_name = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => continue,
            };

            let out_path = target_dir.join(&enclosed_name);
            if is_dir {
                fs::create_dir_all(&out_path)?;
            } else {
                if let Some(p) = out_path.parent() {
                    fs::create_dir_all(p)?;
                }
                let mut outfile = File::create(&out_path)?;
                io::copy(&mut file, &mut outfile)?;
                extracted_files.push(out_path);
            }
        }
    } else if fname_lower.ends_with(".tar.gz") || fname_lower.ends_with(".tgz") {
        let file = File::open(archive_path)?;
        let gz = GzDecoder::new(BufReader::new(file));
        let mut tar = TarArchive::new(gz);

        for entry_res in tar.entries()? {
            let mut entry = entry_res?;
            let path = entry.path()?.to_path_buf();
            let out_path = target_dir.join(&path);

            if entry.header().entry_type().is_dir() {
                fs::create_dir_all(&out_path)?;
            } else {
                if let Some(p) = out_path.parent() {
                    fs::create_dir_all(p)?;
                }
                entry.unpack(&out_path)?;
                extracted_files.push(out_path);
            }
        }
    } else if fname_lower.ends_with(".tar") {
        let file = File::open(archive_path)?;
        let mut tar = TarArchive::new(BufReader::new(file));

        for entry_res in tar.entries()? {
            let mut entry = entry_res?;
            let path = entry.path()?.to_path_buf();
            let out_path = target_dir.join(&path);

            if entry.header().entry_type().is_dir() {
                fs::create_dir_all(&out_path)?;
            } else {
                if let Some(p) = out_path.parent() {
                    fs::create_dir_all(p)?;
                }
                entry.unpack(&out_path)?;
                extracted_files.push(out_path);
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
) -> Result<Option<(Vec<TimelineEntry>, ResidentStats)>, Box<dyn std::error::Error + Send + Sync>> {
    let fname = archive_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fname_lower = fname.to_lowercase();
    let container_name = fname
        .strip_suffix(".tar.gz")
        .or_else(|| fname.strip_suffix(".tgz"))
        .or_else(|| fname.strip_suffix(".zip"))
        .or_else(|| fname.strip_suffix(".tar"))
        .unwrap_or(fname);

    if fname_lower.ends_with(".tar.gz") || fname_lower.ends_with(".tgz") {
        let file = File::open(archive_path)?;
        let gz = GzDecoder::new(BufReader::new(file));
        let mut tar = TarArchive::new(gz);

        for entry_res in tar.entries()? {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };

            let entry_path = entry.path()?.to_string_lossy().to_string();
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

                        let inner_path = inner_entry.path()?.to_string_lossy().to_string();
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
                let mut out_file = File::create(&out_mft)?;
                io::copy(&mut entry, &mut out_file)?;
                let res = parse_mft_file(&out_mft, mft_options)?;
                let _ = fs::remove_file(out_mft);
                return Ok(Some(res));
            }
        }
    } else if fname_lower.ends_with(".zip") {
        let file = File::open(archive_path)?;
        let mut zip = ZipArchive::new(BufReader::new(file))?;

        for i in 0..zip.len() {
            let mut file_entry = zip.by_index(i)?;
            let entry_name = file_entry.name().map(|n| n.to_lowercase()).unwrap_or_default();

            if entry_name.ends_with("bodyfile.txt") || entry_name.ends_with("bodyfile") {
                let buf_reader = BufReader::new(&mut file_entry);
                let entries = parse_bodyfile_stream(buf_reader, Some(container_name));
                return Ok(Some((entries, ResidentStats::default())));
            }

            if entry_name == "$mft" || entry_name.ends_with("/$mft") || entry_name.ends_with("\\$mft") {
                let out_mft = staging_dir.join(format!("mft_{}.bin", uuid_or_random()));
                let mut out_file = File::create(&out_mft)?;
                io::copy(&mut file_entry, &mut out_file)?;
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
