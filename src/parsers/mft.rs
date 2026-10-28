use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use indicatif::{ProgressBar, ProgressStyle};
use mft::attribute::header::ResidentialHeader;
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use mft::attribute::{MftAttributeContent, MftAttributeType};
use mft::entry::MftEntry;
use mft::MftParser;

use crate::error::{AllyError, ErrorCode, Result};
use crate::timefmt::{format_unix_timestamp, SECS_BETWEEN_1601_AND_1970};
use crate::timeline::{join_macb_flags, TimelineEntry};

/// MFT record number of the volume root directory.
const ROOT_RECORD: u64 = 5;
/// Maximum parent chain length followed when reconstructing a path.
const MAX_PATH_DEPTH: usize = 512;
/// Valid NTFS file record sizes.
const VALID_ENTRY_SIZES: [u32; 2] = [1024, 4096];
/// How far into a damaged $MFT we look for the first intact record.
const RECOVERY_SCAN_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Default, Clone)]
pub struct MftParseOptions {
    pub include_file_name_timestamps: bool,
    pub resident_dir: Option<PathBuf>,
    pub resident_report: Option<PathBuf>,
    pub drive_letter: Option<char>,
    pub quiet: bool,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ResidentStats {
    pub total_extracted: usize,
    pub total_bytes: u64,
    /// Resident streams that could not be written (I/O error).
    pub total_failed: usize,
    /// Resident streams whose reconstructed path tried to escape the output
    /// directory (`..` components) and were therefore not written.
    pub total_unsafe_paths: usize,
}

/// Helper struct to hold unique timestamp entries for an attribute
struct TimestampCollector {
    // map: (secs, nanos) -> macb string
    entries: HashMap<(i64, u32), String>,
}

impl TimestampCollector {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn add(&mut self, ts: &mft::Timestamp, flag: char) {
        let secs = ts.as_second();
        // FILETIME 0 (1601-01-01) means "not set" on NTFS. Everything else,
        // including pre-1970 values, is kept: those are timestomping evidence.
        if secs == -SECS_BETWEEN_1601_AND_1970 {
            return;
        }
        let nanos = ts.subsec_nanosecond().max(0) as u32;
        let key = (secs, nanos);
        let current = self.entries.entry(key).or_insert_with(|| "....".to_string());
        *current = join_macb_flags(current, flag);
    }
}

/// Reader adapter that hides the first `skip` bytes of the underlying stream,
/// used to hand the `mft` crate a stream whose first record is intact.
struct SkipReader<R> {
    inner: R,
    skip: u64,
}

impl<R: Read + Seek> Read for SkipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for SkipReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let actual = match pos {
            SeekFrom::Start(p) => self.inner.seek(SeekFrom::Start(self.skip + p))?,
            other => self.inner.seek(other)?,
        };
        Ok(actual.saturating_sub(self.skip))
    }
}

/// Inspects the start of an $MFT stream and returns `(entry_size, skipped_records)`.
///
/// The `mft` crate derives the record size from the first record and divides
/// by it, so a zeroed or garbage first record would panic with a division by
/// zero. We validate it here and, when it is damaged, locate the first intact
/// record so the rest of the table can still be timelined.
fn detect_entry_layout<R: Read + Seek>(reader: &mut R, stream_len: u64) -> Result<(u32, u64)> {
    fn header_entry_size(buf: &[u8]) -> Option<u32> {
        if buf.len() < 32 || (&buf[0..4] != b"FILE" && &buf[0..4] != b"BAAD") {
            return None;
        }
        let size = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        VALID_ENTRY_SIZES.contains(&size).then_some(size)
    }

    let mut head = [0u8; 32];
    reader.seek(SeekFrom::Start(0))?;
    let n = reader.read(&mut head)?;
    if let Some(size) = header_entry_size(&head[..n]) {
        reader.seek(SeekFrom::Start(0))?;
        return Ok((size, 0));
    }

    // First record is damaged: scan forward on 1 KiB boundaries.
    let limit = stream_len.min(RECOVERY_SCAN_LIMIT);
    let mut off: u64 = 1024;
    while off + 32 <= limit {
        reader.seek(SeekFrom::Start(off))?;
        let n = reader.read(&mut head)?;
        if let Some(size) = header_entry_size(&head[..n]) {
            if off % u64::from(size) == 0 {
                reader.seek(SeekFrom::Start(0))?;
                return Ok((size, off / u64::from(size)));
            }
        }
        off += 1024;
    }

    Err(AllyError::Mft {
        code: ErrorCode::MftInitFailed,
        entry: None,
        message: format!(
            "No valid FILE record found in the first {} bytes; not an $MFT or too damaged to parse",
            limit
        ),
    })
}

/// Reconstructs full paths with cycle protection, orphan detection and a
/// bounded depth. The `mft` crate's own resolver recurses parent-by-parent
/// without a visited set and overflows the stack on a parent cycle.
struct CachedDir {
    /// Directory path relative to the volume root ("" = root).
    path: String,
    /// Sequence number in the directory's record header.
    seq: u16,
    allocated: bool,
}

struct PathResolver {
    /// record number -> resolved directory
    cache: HashMap<u64, CachedDir>,
    /// Records skipped at the start of a damaged stream (see detect_entry_layout).
    skipped: u64,
}

enum Resolved {
    Dir(String),
    Orphan,
    Cycle,
}

/// A parent reference is valid when its sequence matches the record header.
/// A freed record has its sequence bumped by one, so children of a deleted
/// directory still resolve through it. Sequence 0 means "unknown": accept.
fn sequence_matches(expected: u16, header_seq: u16, allocated: bool) -> bool {
    expected == 0
        || header_seq == expected
        || (!allocated && header_seq == expected.wrapping_add(1))
}

impl PathResolver {
    fn new(skipped: u64) -> Self {
        let mut cache = HashMap::new();
        cache.insert(ROOT_RECORD, CachedDir { path: String::new(), seq: 0, allocated: true });
        Self { cache, skipped }
    }

    fn get_entry<R: Read + Seek>(&self, parser: &mut MftParser<R>, record: u64) -> Option<MftEntry> {
        let idx = record.checked_sub(self.skipped)?;
        parser.get_entry(idx).ok()
    }

    fn cached(&self, record: u64, expected_seq: u16) -> Option<Resolved> {
        let c = self.cache.get(&record)?;
        if record == ROOT_RECORD || sequence_matches(expected_seq, c.seq, c.allocated) {
            Some(Resolved::Dir(c.path.clone()))
        } else {
            Some(Resolved::Orphan)
        }
    }

    /// Returns the directory path for `dir_record` (expected sequence `seq`).
    fn resolve_dir<R: Read + Seek>(
        &mut self,
        parser: &mut MftParser<R>,
        dir_record: u64,
        seq: u16,
    ) -> Resolved {
        if let Some(r) = self.cached(dir_record, seq) {
            return r;
        }

        // Walk upwards collecting (record, name, header seq, allocated) until a
        // cached ancestor, the root, an orphan or a cycle.
        let mut chain: Vec<(u64, String, u16, bool)> = Vec::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut cur = dir_record;
        let mut cur_seq = seq;
        let base: Resolved = loop {
            if let Some(r) = self.cached(cur, cur_seq) {
                break r;
            }
            if !visited.insert(cur) || chain.len() >= MAX_PATH_DEPTH {
                break Resolved::Cycle;
            }
            let entry = match self.get_entry(parser, cur) {
                Some(e) => e,
                None => break Resolved::Orphan,
            };
            let hdr_seq = entry.header.sequence;
            let allocated = entry.is_allocated();
            if !sequence_matches(cur_seq, hdr_seq, allocated) || !entry.is_dir() {
                break Resolved::Orphan;
            }
            let fname = match self.best_name_for_entry(parser, &entry, cur) {
                Some(f) => f,
                None => break Resolved::Orphan,
            };
            let parent = fname.parent.entry;
            let parent_seq = fname.parent.sequence;
            chain.push((cur, fname.name, hdr_seq, allocated));
            if parent == cur {
                // Self-referencing non-root directory: treat as orphan root.
                break Resolved::Orphan;
            }
            cur = parent;
            cur_seq = parent_seq;
        };

        // Build the paths top-down and cache every directory on the chain.
        let mut acc = match &base {
            Resolved::Dir(p) => p.clone(),
            Resolved::Orphan => "[ORPHAN]".to_string(),
            Resolved::Cycle => "[CYCLE]".to_string(),
        };
        for (rec, name, hdr_seq, allocated) in chain.iter().rev() {
            if acc.is_empty() {
                acc = name.clone();
            } else {
                acc = format!("{}\\{}", acc, name);
            }
            self.cache.insert(*rec, CachedDir { path: acc.clone(), seq: *hdr_seq, allocated: *allocated });
        }
        if chain.is_empty() {
            base
        } else {
            Resolved::Dir(acc)
        }
    }

    /// Best $FILE_NAME of a record, following its $ATTRIBUTE_LIST when the
    /// long name lives in an extension record.
    fn best_name_for_entry<R: Read + Seek>(&self, parser: &mut MftParser<R>, entry: &MftEntry, record: u64) -> Option<FileNameAttr> {
        let mut acc = RecordAttrs::default();
        scan_record(entry, true, false, &mut acc);
        for ext_rec in extension_records(entry, record) {
            if let Some(ext) = self.get_entry(parser, ext_rec) {
                if ext.header.base_reference.entry == record {
                    scan_record(&ext, true, false, &mut acc);
                }
            }
        }
        best_name(&acc.fn_attrs)
    }

    /// Full path of `entry` (whose chosen $FILE_NAME is `fname`) relative to
    /// the volume root.
    fn resolve<R: Read + Seek>(&mut self, parser: &mut MftParser<R>, entry: &MftEntry, record: u64, fname: &FileNameAttr) -> String {
        if record == ROOT_RECORD {
            return String::new();
        }
        let dir = match self.resolve_dir(parser, fname.parent.entry, fname.parent.sequence) {
            Resolved::Dir(d) => d,
            Resolved::Orphan => "[ORPHAN]".to_string(),
            Resolved::Cycle => "[CYCLE]".to_string(),
        };
        let full = if dir.is_empty() { fname.name.clone() } else { format!("{}\\{}", dir, fname.name) };
        if entry.is_dir() {
            self.cache.insert(
                record,
                CachedDir { path: full.clone(), seq: entry.header.sequence, allocated: entry.is_allocated() },
            );
        }
        full
    }
}

/// Attributes gathered from a base record plus its extension records.
#[derive(Default)]
struct RecordAttrs {
    std_info: Option<StandardInfoAttr>,
    fn_attrs: Vec<FileNameAttr>,
    data_size: Option<u64>,
    ads_streams: Vec<(String, u64)>,
    /// (stream name or "" for the unnamed stream, bytes) of resident $DATA.
    resident_payloads: Vec<(String, Vec<u8>)>,
}

/// Collects the attributes of one record. Called for the base record first
/// and then for every extension record, so the first value seen wins.
fn scan_record(rec: &MftEntry, is_dir: bool, want_resident: bool, acc: &mut RecordAttrs) {
    for attr in rec.iter_attributes().flatten() {
        match &attr.data {
            MftAttributeContent::AttrX10(info) => {
                if acc.std_info.is_none() {
                    acc.std_info = Some(info.clone());
                }
            }
            MftAttributeContent::AttrX30(fn_attr) => acc.fn_attrs.push(fn_attr.clone()),
            MftAttributeContent::AttrX80(data_attr) => {
                // Resident $DATA: the bytes live inside the record.
                let attr_name = attr.header.name.clone();
                let data_bytes = data_attr.data();
                let stream_size = data_bytes.len() as u64;
                if attr_name.is_empty() {
                    if acc.data_size.is_none() {
                        acc.data_size = Some(stream_size);
                    }
                } else if !acc.ads_streams.iter().any(|(n, _)| n == &attr_name) {
                    acc.ads_streams.push((attr_name.clone(), stream_size));
                }
                if want_resident && !data_bytes.is_empty() && (!attr_name.is_empty() || !is_dir) {
                    acc.resident_payloads.push((attr_name, data_bytes.to_vec()));
                }
            }
            // The crate yields DataRun for *every* non-resident attribute
            // ($INDEX_ALLOCATION "$I30", $BITMAP, ...); only $DATA matters here.
            MftAttributeContent::DataRun(_) if attr.header.type_code == MftAttributeType::DATA => {
                // Non-resident $DATA (anything beyond ~700 bytes): the real
                // size is in the non-resident header, not in $FILE_NAME.
                if let ResidentialHeader::NonResident(nr) = &attr.header.residential_header {
                    // Only the first extent record (vcn_first == 0) carries a valid size.
                    if nr.vnc_first == 0 {
                        let attr_name = attr.header.name.clone();
                        if attr_name.is_empty() {
                            if acc.data_size.is_none() {
                                acc.data_size = Some(nr.file_size);
                            }
                        } else if !acc.ads_streams.iter().any(|(n, _)| n == &attr_name) {
                            acc.ads_streams.push((attr_name, nr.file_size));
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Records other than `base_id` referenced by a resident $ATTRIBUTE_LIST.
/// Large or heavily fragmented files keep part of their attributes there,
/// and the base record may then hold only the DOS 8.3 name and no $DATA.
/// A non-resident $ATTRIBUTE_LIST cannot be read from the $MFT alone.
fn extension_records(rec: &MftEntry, base_id: u64) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    for attr in rec.iter_attributes().flatten() {
        if let MftAttributeContent::AttrX20(list) = &attr.data {
            for e in &list.entries {
                let r = e.segment_reference.entry;
                if r != base_id && !out.contains(&r) {
                    out.push(r);
                }
            }
        }
    }
    out
}

/// Picks the most human-readable $FILE_NAME: Win32 / Win32AndDos first,
/// then POSIX, then whatever is left (DOS 8.3).
fn best_name(fns: &[FileNameAttr]) -> Option<FileNameAttr> {
    fns.iter()
        .find(|a| matches!(a.namespace, FileNamespace::Win32 | FileNamespace::Win32AndDos))
        .or_else(|| fns.iter().find(|a| a.namespace == FileNamespace::POSIX))
        .or_else(|| fns.first())
        .cloned()
}

pub fn parse_mft_reader<R: Read + Seek>(
    mut reader: R,
    options: &MftParseOptions,
) -> Result<(Vec<TimelineEntry>, ResidentStats)> {
    let stream_len = reader.seek(SeekFrom::End(0)).map_err(|e| AllyError::Io {
        code: ErrorCode::IoError,
        source: e,
        context: "Measuring $MFT stream".to_string(),
    })?;
    let (entry_size, skipped) = detect_entry_layout(&mut reader, stream_len)?;
    if skipped > 0 {
        eprintln!(
            "[!] $MFT: first {} record(s) are damaged and were skipped; paths through them will show as [ORPHAN]",
            skipped
        );
    }
    let skip_bytes = skipped * u64::from(entry_size);
    let remaining = stream_len.saturating_sub(skip_bytes);
    let mut skipping = SkipReader { inner: reader, skip: skip_bytes };
    // The crate reads the first record from the current position.
    skipping.seek(SeekFrom::Start(0)).map_err(|e| AllyError::Io {
        code: ErrorCode::IoError,
        source: e,
        context: "Positioning $MFT stream".to_string(),
    })?;

    let mut parser = MftParser::from_read_seek(skipping, Some(remaining)).map_err(|e| AllyError::Mft {
        code: ErrorCode::MftInitFailed,
        entry: None,
        message: format!("Failed to initialize MFT parser: {}", e),
    })?;

    let entry_count = parser.get_entry_count();

    let pb = if !options.quiet {
        let pb = ProgressBar::new(entry_count);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} entries ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    let mut timeline = Vec::new();
    let mut resident_stats = ResidentStats::default();
    let drive_prefix = options.drive_letter.unwrap_or('C');
    let mut resolver = PathResolver::new(skipped);

    for entry_idx in 0..entry_count {
        if let Some(ref pb) = pb {
            pb.inc(1);
        }

        let entry = match parser.get_entry(entry_idx) {
            Ok(e) => e,
            Err(_) => continue,
        };

        // True record number in the original table (the crate numbers from the
        // start of the stream it was given).
        let entry_id = entry.header.record_number + skipped;
        let is_dir = entry.is_dir();
        let is_allocated = entry.is_allocated();

        let base_mode = if is_dir {
            "d/drwxrwxrwx".to_string()
        } else {
            "-/-rwxrwxrwx".to_string()
        };

        let status_flag = if is_allocated {
            String::new()
        } else {
            " (deleted)".to_string()
        };

        // Collect attributes: $STANDARD_INFORMATION (0x10), $FILE_NAME (0x30),
        // $DATA (0x80), following $ATTRIBUTE_LIST (0x20) into extension records.
        let want_resident = options.resident_dir.is_some();
        let mut acc = RecordAttrs::default();
        scan_record(&entry, is_dir, want_resident, &mut acc);
        for ext_rec in extension_records(&entry, entry_id) {
            if let Some(ext) = resolver.get_entry(&mut parser, ext_rec) {
                if ext.header.base_reference.entry == entry_id {
                    scan_record(&ext, is_dir, want_resident, &mut acc);
                }
            }
        }
        let RecordAttrs { std_info, fn_attrs, data_size, ads_streams, resident_payloads } = acc;

        let resolved_path = match best_name(&fn_attrs) {
            Some(best) => format!("{}:\\{}", drive_prefix, resolver.resolve(&mut parser, &entry, entry_id, &best)),
            None => format!("{}:\\[UNKNOWN]\\entry_{}", drive_prefix, entry_id),
        };

        let fn_size = fn_attrs.iter().map(|f| f.logical_size).find(|&s| s > 0).unwrap_or(0);
        let file_size = data_size.unwrap_or(fn_size);

        if let Some(ref res_dir) = options.resident_dir {
            for (stream_name, bytes) in &resident_payloads {
                let target = if stream_name.is_empty() {
                    resolved_path.clone()
                } else {
                    format!("{}:{}", resolved_path, stream_name)
                };
                extract_resident_file(res_dir, &target, entry_id, is_allocated, bytes, &mut resident_stats);
            }
        }

        // 1. Process $STANDARD_INFORMATION (0x10) timestamps
        if let Some(info) = std_info {
            let mut collector = TimestampCollector::new();
            collector.add(&info.modified, 'm');
            collector.add(&info.accessed, 'a');
            collector.add(&info.mft_modified, 'c');
            collector.add(&info.created, 'b');

            for ((secs, nanos), macb) in collector.entries {
                if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
                    let full_name = format!("{}{}", resolved_path, status_flag);
                    timeline.push(TimelineEntry::new(
                        ts_iso.clone(),
                        secs,
                        nanos,
                        file_size,
                        macb.clone(),
                        base_mode.clone(),
                        0,
                        0,
                        entry_id.to_string(),
                        full_name,
                    ));

                    // ADS share the record's $STANDARD_INFORMATION timestamps,
                    // so they carry the same MACB flags.
                    for (stream_name, stream_size) in &ads_streams {
                        let ads_full_name = format!("{}:{}{}", resolved_path, stream_name, status_flag);
                        timeline.push(TimelineEntry::new(
                            ts_iso.clone(),
                            secs,
                            nanos,
                            *stream_size,
                            macb.clone(),
                            base_mode.clone(),
                            0,
                            0,
                            entry_id.to_string(),
                            ads_full_name,
                        ));
                    }
                }
            }
        }

        // 2. Process $FILE_NAME (0x30) timestamps if requested
        if options.include_file_name_timestamps {
            for fn_attr in fn_attrs {
                let mut collector = TimestampCollector::new();
                collector.add(&fn_attr.modified, 'm');
                collector.add(&fn_attr.accessed, 'a');
                collector.add(&fn_attr.mft_modified, 'c');
                collector.add(&fn_attr.created, 'b');

                for ((secs, nanos), macb) in collector.entries {
                    if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
                        let fn_full_name = format!("{}{} ($FILE_NAME: {})", resolved_path, status_flag, fn_attr.name);
                        let fn_row_size = if fn_attr.logical_size > 0 {
                            fn_attr.logical_size
                        } else {
                            file_size
                        };

                        timeline.push(TimelineEntry::new(
                            ts_iso,
                            secs,
                            nanos,
                            fn_row_size,
                            macb,
                            base_mode.clone(),
                            0,
                            0,
                            entry_id.to_string(),
                            fn_full_name,
                        ));
                    }
                }
            }
        }
    }

    if let Some(pb) = pb {
        pb.finish_with_message("MFT parsing completed");
    }

    if resident_stats.total_failed > 0 || resident_stats.total_unsafe_paths > 0 {
        eprintln!(
            "[!] Resident extraction: {} written, {} failed, {} refused (path escaped output directory)",
            resident_stats.total_extracted, resident_stats.total_failed, resident_stats.total_unsafe_paths
        );
    }

    // Write resident extraction report if requested
    if let Some(ref report_path) = options.resident_report {
        let mut rep = File::create(report_path).map_err(|e| AllyError::Io {
            code: ErrorCode::IoError,
            source: e,
            context: format!("Creating resident report {}", report_path.display()),
        })?;
        writeln!(rep, "=== Resident Files Extraction Summary ===")?;
        writeln!(rep, "Total resident files extracted: {}", resident_stats.total_extracted)?;
        writeln!(rep, "Total bytes extracted: {} bytes ({:.2} MB)", resident_stats.total_bytes, resident_stats.total_bytes as f64 / 1_048_576.0)?;
        writeln!(rep, "Failed writes: {}", resident_stats.total_failed)?;
        writeln!(rep, "Refused unsafe paths: {}", resident_stats.total_unsafe_paths)?;
    }

    Ok((timeline, resident_stats))
}

pub fn parse_mft_file(
    mft_path: &Path,
    options: &MftParseOptions,
) -> Result<(Vec<TimelineEntry>, ResidentStats)> {
    let file = File::open(mft_path).map_err(|e| AllyError::Io {
        code: ErrorCode::FileNotFound,
        source: e,
        context: format!("Opening MFT file {}", mft_path.display()),
    })?;
    let reader = BufReader::new(file);
    parse_mft_reader(reader, options)
}

/// Turns an NTFS path as rendered in the timeline (`C:\dir\file.txt:ads`) into
/// a relative path that is guaranteed to stay inside the extraction directory.
///
/// Returns `None` when the path contains `..` components, which only a crafted
/// $FILE_NAME can produce: NTFS itself never stores such names.
pub fn sanitize_relative_path(file_path: &str) -> Option<PathBuf> {
    // Normalise separators first, then drop the "X:\" drive prefix and turn
    // the ADS separator into '_'.
    let unified = file_path.replace('/', "\\");
    let without_drive = match unified.split_once(":\\") {
        Some((drive, rest)) if drive.len() == 1 => rest,
        _ => unified.as_str(),
    };
    let normalised = without_drive.replace(':', "_");

    let mut out = PathBuf::new();
    for raw in normalised.split('\\') {
        let comp = raw.trim();
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            return None;
        }
        // Neutralise characters that are invalid on Windows and trailing dots/spaces.
        let cleaned: String = comp
            .chars()
            .map(|c| if matches!(c, '<' | '>' | '"' | '|' | '?' | '*') || (c as u32) < 0x20 { '_' } else { c })
            .collect();
        let cleaned = cleaned.trim_end_matches(['.', ' ']).to_string();
        if cleaned.is_empty() {
            return None;
        }
        // Defensive: the std path parser must agree that this is a plain component.
        let p = Path::new(&cleaned);
        if p.components().any(|c| !matches!(c, Component::Normal(_))) {
            return None;
        }
        out.push(cleaned);
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_resident_file(
    out_dir: &Path,
    file_path: &str,
    record: u64,
    is_allocated: bool,
    data: &[u8],
    stats: &mut ResidentStats,
) {
    let rel = match sanitize_relative_path(file_path) {
        Some(r) => r,
        None => {
            stats.total_unsafe_paths += 1;
            return;
        }
    };

    let mut target_path = out_dir.join(&rel);
    // Deleted records and live records can share a path: never overwrite one
    // with the other, and never let two records with the same path collide.
    if !is_allocated {
        let name = target_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        target_path.set_file_name(format!("{}.deleted_rec{}", name, record));
    }
    if target_path.exists() {
        let name = target_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        target_path.set_file_name(format!("{}.rec{}", name, record));
    }

    if let Some(parent) = target_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            stats.total_failed += 1;
            if stats.total_failed <= 5 {
                eprintln!("[!] Resident dump: cannot create {}: {}", parent.display(), e);
            }
            return;
        }
    }

    let written = File::create(&target_path).and_then(|mut f| f.write_all(data));
    match written {
        Ok(()) => {
            stats.total_extracted += 1;
            stats.total_bytes += data.len() as u64;
        }
        Err(e) => {
            stats.total_failed += 1;
            if stats.total_failed <= 5 {
                eprintln!("[!] Resident dump: cannot write {}: {}", target_path.display(), e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_rejects_traversal() {
        assert_eq!(sanitize_relative_path("C:\\..\\..\\pwn.txt"), None);
        assert_eq!(sanitize_relative_path("C:\\a\\..\\b.txt"), None);
        assert_eq!(sanitize_relative_path("C:\\[UNKNOWN]\\../x"), None);
        assert_eq!(sanitize_relative_path("C:\\"), None);
    }

    #[test]
    fn test_sanitize_keeps_normal_paths() {
        assert_eq!(
            sanitize_relative_path("C:\\Windows\\System32\\cmd.exe"),
            Some(PathBuf::from("Windows").join("System32").join("cmd.exe"))
        );
        assert_eq!(
            sanitize_relative_path("C:\\host.txt:evil"),
            Some(PathBuf::from("host.txt_evil"))
        );
        assert_eq!(
            sanitize_relative_path("C:\\dir\\bad<name>?.txt"),
            Some(PathBuf::from("dir").join("bad_name__.txt"))
        );
    }

    #[test]
    fn test_detect_entry_layout_rejects_zero_stream() {
        let mut cur = io::Cursor::new(vec![0u8; 4096]);
        let err = detect_entry_layout(&mut cur, 4096).unwrap_err();
        assert_eq!(err.code(), ErrorCode::MftInitFailed);
        let err = parse_mft_reader(io::Cursor::new(vec![0u8; 4096]), &MftParseOptions { quiet: true, ..Default::default() }).unwrap_err();
        assert_eq!(err.code(), ErrorCode::MftInitFailed);
    }

    #[test]
    fn test_detect_entry_layout_skips_damaged_prefix() {
        let mut data = vec![0u8; 3072];
        data[2048..2052].copy_from_slice(b"FILE");
        data[2048 + 28..2048 + 32].copy_from_slice(&1024u32.to_le_bytes());
        let mut cur = io::Cursor::new(data);
        assert_eq!(detect_entry_layout(&mut cur, 3072).unwrap(), (1024, 2));
    }
}
