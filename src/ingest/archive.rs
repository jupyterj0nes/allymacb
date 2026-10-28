use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use flate2::read::GzDecoder;
use tar::Archive as TarArchive;
use zip::read::ZipArchive;

use crate::error::{AllyError, ErrorCode, Result};
use crate::parsers::bodyfile::parse_bodyfile_stream;
use crate::parsers::mft::{parse_mft_file, MftParseOptions, ResidentStats};
use crate::parsers::usn::{parse_usn_file, UsnParseOptions};
use crate::timeline::TimelineEntry;

use super::{is_bodyfile_name, is_mft_name, is_usn_name, looks_like_bodyfile};

/// Process-wide counter so parallel workers never share a staging file name.
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique staging path inside `dir` for an extracted artifact.
pub fn staging_path(dir: &Path, prefix: &str, ext: &str) -> PathBuf {
    let n = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{}_{}_{}.{}", prefix, std::process::id(), n, ext))
}

/// Outcome of extracting an archive to disk.
#[derive(Debug, Default)]
pub struct ExtractReport {
    pub files: Vec<PathBuf>,
    /// Entries refused because their path would have escaped `target_dir`.
    pub unsafe_entries: usize,
    /// Entries that failed to extract for I/O or decompression reasons.
    pub failed_entries: usize,
}

fn zip_mtime_to_system_time(dt: zip::DateTime) -> Option<std::time::SystemTime> {
    // ZIP stores DOS local time with no zone; we have to treat it as UTC.
    let date = chrono::NaiveDate::from_ymd_opt(dt.year() as i32, dt.month() as u32, dt.day() as u32)?;
    let naive = date.and_hms_opt(dt.hour() as u32, dt.minute() as u32, dt.second() as u32)?;
    let secs = naive.and_utc().timestamp();
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

fn extract_tar<R: Read>(
    tar: &mut TarArchive<R>,
    archive_path: &Path,
    target_dir: &Path,
    report: &mut ExtractReport,
) -> Result<()> {
    let entries = tar.entries().map_err(|e| AllyError::Archive {
        code: ErrorCode::ArchiveCorrupt,
        path: archive_path.display().to_string(),
        message: format!("Corrupted tar stream: {}", e),
    })?;

    for entry_res in entries {
        let mut entry = match entry_res {
            Ok(e) => e,
            Err(_) => {
                report.failed_entries += 1;
                continue;
            }
        };
        let rel = match entry.path() {
            Ok(p) => p.to_path_buf(),
            Err(_) => {
                report.failed_entries += 1;
                continue;
            }
        };
        entry.set_preserve_mtime(true);
        entry.set_unpack_xattrs(false);
        entry.set_preserve_permissions(false);
        // unpack_in refuses any path that would land outside target_dir
        // (`..` components, absolute paths, symlink escapes).
        match entry.unpack_in(target_dir) {
            Ok(true) => {
                if !entry.header().entry_type().is_dir() {
                    report.files.push(target_dir.join(rel));
                }
            }
            Ok(false) => report.unsafe_entries += 1,
            Err(_) => report.failed_entries += 1,
        }
    }
    Ok(())
}

pub fn extract_archive(archive_path: &Path, target_dir: &Path) -> Result<Vec<PathBuf>> {
    let report = extract_archive_with_report(archive_path, target_dir)?;
    if report.unsafe_entries > 0 {
        eprintln!(
            "[!] {}: {} entries refused because their path escaped the extraction directory",
            archive_path.display(),
            report.unsafe_entries
        );
    }
    Ok(report.files)
}

pub fn extract_archive_with_report(archive_path: &Path, target_dir: &Path) -> Result<ExtractReport> {
    let mut report = ExtractReport::default();
    let fname = archive_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let fname_lower = fname.to_lowercase();

    if fname_lower.ends_with(".zip") {
        let file = File::open(archive_path).map_err(|e| AllyError::io_with_context(e, format!("Opening zip archive {}", archive_path.display())))?;
        let mut zip = ZipArchive::new(BufReader::new(file)).map_err(|e| AllyError::Archive {
            code: ErrorCode::ArchiveCorrupt,
            path: archive_path.display().to_string(),
            message: format!("Corrupted zip archive: {}", e),
        })?;

        for i in 0..zip.len() {
            let mut file = match zip.by_index(i) {
                Ok(f) => f,
                Err(_) => {
                    report.failed_entries += 1;
                    continue;
                }
            };
            let is_dir = file.is_dir();
            // enclosed_name() is None for any path that would escape target_dir.
            let enclosed_name = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => {
                    report.unsafe_entries += 1;
                    continue;
                }
            };
            let mtime = file.last_modified().and_then(zip_mtime_to_system_time);

            let out_path = target_dir.join(&enclosed_name);
            if is_dir {
                let _ = fs::create_dir_all(&out_path);
            } else {
                if let Some(p) = out_path.parent() {
                    let _ = fs::create_dir_all(p);
                }
                match File::create(&out_path) {
                    Ok(mut outfile) => {
                        if io::copy(&mut file, &mut outfile).is_err() {
                            report.failed_entries += 1;
                            continue;
                        }
                        if let Some(t) = mtime {
                            let _ = outfile.set_modified(t);
                        }
                        report.files.push(out_path);
                    }
                    Err(_) => report.failed_entries += 1,
                }
            }
        }
    } else if fname_lower.ends_with(".tar.gz") || fname_lower.ends_with(".tgz") {
        let file = File::open(archive_path).map_err(|e| AllyError::io_with_context(e, format!("Opening tar.gz archive {}", archive_path.display())))?;
        let gz = GzDecoder::new(BufReader::new(file));
        let mut tar = TarArchive::new(gz);
        extract_tar(&mut tar, archive_path, target_dir, &mut report)?;
    } else if fname_lower.ends_with(".tar") {
        let file = File::open(archive_path).map_err(|e| AllyError::io_with_context(e, format!("Opening tar archive {}", archive_path.display())))?;
        let mut tar = TarArchive::new(BufReader::new(file));
        extract_tar(&mut tar, archive_path, target_dir, &mut report)?;
    } else if fname_lower.ends_with(".gz") {
        // Single gzip member (not a tarball): decompress to one file.
        let file = File::open(archive_path).map_err(|e| AllyError::io_with_context(e, format!("Opening gzip file {}", archive_path.display())))?;
        let mut gz = GzDecoder::new(BufReader::new(file));
        let inner_name = fname.strip_suffix(".gz").unwrap_or("member");
        let out_path = target_dir.join(inner_name);
        if let Some(p) = out_path.parent() {
            let _ = fs::create_dir_all(p);
        }
        let mut out = File::create(&out_path).map_err(|e| AllyError::io_with_context(e, format!("Creating {}", out_path.display())))?;
        io::copy(&mut gz, &mut out).map_err(|e| AllyError::Archive {
            code: ErrorCode::ArchiveDecompressionFailed,
            path: archive_path.display().to_string(),
            message: format!("gzip decompression failed: {}", e),
        })?;
        report.files.push(out_path);
    } else {
        return Err(AllyError::Archive {
            code: ErrorCode::ArchiveUnsupportedFormat,
            path: archive_path.display().to_string(),
            message: "Unsupported archive extension (expected .zip, .tar, .tar.gz, .tgz or .gz)".to_string(),
        });
    }

    Ok(report)
}

/// Accumulator for artifacts found while streaming through an archive.
struct FastResult {
    timeline: Vec<TimelineEntry>,
    stats: ResidentStats,
    artifacts: usize,
}

impl FastResult {
    fn new() -> Self {
        Self { timeline: Vec::new(), stats: ResidentStats::default(), artifacts: 0 }
    }
    fn merge(&mut self, entries: Vec<TimelineEntry>, stats: ResidentStats) {
        self.timeline.extend(entries);
        self.stats.total_extracted += stats.total_extracted;
        self.stats.total_bytes += stats.total_bytes;
        self.stats.total_failed += stats.total_failed;
        self.stats.total_unsafe_paths += stats.total_unsafe_paths;
        self.artifacts += 1;
    }
}

fn log(quiet: bool, msg: String) {
    if !quiet {
        eprintln!("{}", msg);
    }
}

/// Stages a stream to disk and parses it as an $MFT or USN journal.
fn parse_staged<R: Read>(
    kind: &str,
    source: &mut R,
    entry_label: &str,
    mft_options: &MftParseOptions,
    staging_dir: &Path,
    acc: &mut FastResult,
) -> Result<()> {
    let out = staging_path(staging_dir, kind, "bin");
    {
        let mut out_file = File::create(&out).map_err(|e| AllyError::io_with_context(e, format!("Creating staging file {}", out.display())))?;
        io::copy(source, &mut out_file).map_err(|e| AllyError::io_with_context(e, format!("Extracting {} from archive", entry_label)))?;
    }
    let result = match kind {
        "mft" => parse_mft_file(&out, mft_options).map(|(t, s)| (t, s)),
        _ => {
            let usn_opts = UsnParseOptions {
                drive_letter: mft_options.drive_letter,
                quiet: mft_options.quiet,
                mft_path_cache: None,
            };
            parse_usn_file(&out, &usn_opts).map(|t| (t, ResidentStats::default()))
        }
    };
    let _ = fs::remove_file(&out);
    let (entries, stats) = result?;
    log(mft_options.quiet, format!("    [+] {}: {} timeline entries from {}", kind.to_uppercase(), entries.len(), entry_label));
    acc.merge(entries, stats);
    Ok(())
}

/// Routes one archive member by name to the right parser. Returns Ok(true)
/// when the member was consumed as an artifact.
fn route_member<R: Read>(
    name: &str,
    reader: &mut R,
    container_name: &str,
    mft_options: &MftParseOptions,
    staging_dir: &Path,
    acc: &mut FastResult,
) -> Result<bool> {
    let lower = name.to_lowercase().replace('\\', "/");
    let base = lower.rsplit('/').next().unwrap_or(&lower);

    if is_bodyfile_name(base) {
        let entries = parse_bodyfile_stream(BufReader::new(reader), Some(container_name));
        log(mft_options.quiet, format!("    [+] Bodyfile: {} timeline entries from {}", entries.len(), name));
        acc.merge(entries, ResidentStats::default());
        return Ok(true);
    }
    if is_mft_name(base) {
        parse_staged("mft", reader, name, mft_options, staging_dir, acc)?;
        return Ok(true);
    }
    if is_usn_name(&lower) {
        parse_staged("usn", reader, name, mft_options, staging_dir, acc)?;
        return Ok(true);
    }
    Ok(false)
}

fn scan_tar<R: Read>(
    tar: &mut TarArchive<R>,
    container_name: &str,
    mft_options: &MftParseOptions,
    staging_dir: &Path,
    acc: &mut FastResult,
    depth: usize,
) -> Result<()> {
    let entries = match tar.entries() {
        Ok(e) => e,
        Err(e) => {
            return Err(AllyError::Archive {
                code: ErrorCode::ArchiveCorrupt,
                path: container_name.to_string(),
                message: format!("Corrupted tar stream: {}", e),
            })
        }
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
        let lower = entry_path.to_lowercase();

        if route_member(&entry_path, &mut entry, container_name, mft_options, staging_dir, acc)? {
            continue;
        }

        // Embedded tar.gz (e.g. UAC's outer packaging); one level only.
        if depth == 0 && (lower.ends_with(".tar.gz") || lower.ends_with(".tgz")) {
            // Box the nested stream so the recursion monomorphises to one type.
            let inner_gz: Box<dyn Read + '_> = Box::new(GzDecoder::new(&mut entry));
            let mut inner_tar = TarArchive::new(inner_gz);
            if let Err(e) = scan_tar(&mut inner_tar, container_name, mft_options, staging_dir, acc, depth + 1) {
                eprintln!("[!] Nested archive {} inside {}: {}", entry_path, container_name, e);
            }
        } else if depth == 0 && lower.ends_with(".zip") {
            // Nested zip needs random access: stage it first.
            let staged = staging_path(staging_dir, "nested", "zip");
            if let Ok(mut f) = File::create(&staged) {
                if io::copy(&mut entry, &mut f).is_ok() {
                    drop(f);
                    if let Err(e) = scan_zip_file(&staged, container_name, mft_options, staging_dir, acc) {
                        eprintln!("[!] Nested archive {} inside {}: {}", entry_path, container_name, e);
                    }
                }
            }
            let _ = fs::remove_file(&staged);
        }
    }
    Ok(())
}

fn scan_zip_file(
    zip_path: &Path,
    container_name: &str,
    mft_options: &MftParseOptions,
    staging_dir: &Path,
    acc: &mut FastResult,
) -> Result<()> {
    let file = File::open(zip_path).map_err(|e| AllyError::io_with_context(e, format!("Opening zip {}", zip_path.display())))?;
    let mut zip = ZipArchive::new(BufReader::new(file)).map_err(|e| AllyError::Archive {
        code: ErrorCode::ArchiveCorrupt,
        path: zip_path.display().to_string(),
        message: format!("Corrupted zip: {}", e),
    })?;

    for i in 0..zip.len() {
        let mut file_entry = match zip.by_index(i) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if file_entry.is_dir() {
            continue;
        }
        let entry_name = match file_entry.name() {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };
        route_member(&entry_name, &mut file_entry, container_name, mft_options, staging_dir, acc)?;
    }
    Ok(())
}

/// Streams through an archive and parses every forensic artifact it contains
/// ($MFT, $UsnJrnl:$J, bodyfiles), including inside one level of nested
/// tar.gz/zip. Returns `Ok(None)` when the archive holds none of them, so the
/// caller can fall back to extracting it.
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
        .or_else(|| fname.strip_suffix(".gz"))
        .unwrap_or(fname);

    let mut acc = FastResult::new();

    if fname_lower.ends_with(".tar.gz") || fname_lower.ends_with(".tgz") {
        let file = File::open(archive_path).map_err(|e| AllyError::io_with_context(e, format!("Opening tar.gz {}", archive_path.display())))?;
        let gz = GzDecoder::new(BufReader::new(file));
        let mut tar = TarArchive::new(gz);
        scan_tar(&mut tar, container_name, mft_options, staging_dir, &mut acc, 0)?;
    } else if fname_lower.ends_with(".tar") {
        let file = File::open(archive_path).map_err(|e| AllyError::io_with_context(e, format!("Opening tar {}", archive_path.display())))?;
        let mut tar = TarArchive::new(BufReader::new(file));
        scan_tar(&mut tar, container_name, mft_options, staging_dir, &mut acc, 0)?;
    } else if fname_lower.ends_with(".zip") {
        scan_zip_file(archive_path, container_name, mft_options, staging_dir, &mut acc)?;
    } else if fname_lower.ends_with(".gz") {
        // Plain gzip member: a compressed bodyfile is the common case.
        let file = File::open(archive_path).map_err(|e| AllyError::io_with_context(e, format!("Opening gzip {}", archive_path.display())))?;
        let mut gz = BufReader::new(GzDecoder::new(BufReader::new(file)));
        let inner = fname.strip_suffix(".gz").unwrap_or("").to_lowercase();
        let first_line = {
            let buf = gz.fill_buf().map_err(|e| AllyError::Archive {
                code: ErrorCode::ArchiveDecompressionFailed,
                path: archive_path.display().to_string(),
                message: format!("gzip decompression failed: {}", e),
            })?;
            String::from_utf8_lossy(buf).lines().next().unwrap_or("").to_string()
        };
        if is_bodyfile_name(&inner) || looks_like_bodyfile(&first_line) {
            let entries = parse_bodyfile_stream(gz, Some(container_name));
            log(mft_options.quiet, format!("    [+] Bodyfile: {} timeline entries from {}", entries.len(), fname));
            acc.merge(entries, ResidentStats::default());
        } else if is_mft_name(&inner) {
            parse_staged("mft", &mut gz, fname, mft_options, staging_dir, &mut acc)?;
        } else if is_usn_name(&inner) {
            parse_staged("usn", &mut gz, fname, mft_options, staging_dir, &mut acc)?;
        }
    }

    if acc.artifacts == 0 {
        Ok(None)
    } else {
        Ok(Some((acc.timeline, acc.stats)))
    }
}

/// Convenience for tests and tools: writes `data` into a fresh file inside `dir`.
#[allow(dead_code)]
pub fn write_staging_file(dir: &Path, prefix: &str, ext: &str, data: &[u8]) -> io::Result<PathBuf> {
    let p = staging_path(dir, prefix, ext);
    let mut f = File::create(&p)?;
    f.write_all(data)?;
    f.seek(io::SeekFrom::Start(0))?;
    Ok(p)
}
