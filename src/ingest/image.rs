use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ntfs::Ntfs;

use crate::error::{AllyError, ErrorCode, Result};
use crate::parsers::ext4::parse_ext4_partition;
use crate::parsers::mft::{MftParseOptions, ResidentStats};
use crate::timeline::TimelineEntry;

use super::archive::staging_path;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const EXT_MAGIC_OFFSET: u64 = 1080;
const EXT_MAGIC: [u8; 2] = [0x53, 0xEF];
const GPT_SIGNATURE: &[u8] = b"EFI PART";
const MBR_PROTECTIVE_GPT: u8 = 0xEE;
const MAX_GPT_ENTRIES: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    Ntfs,
    Ext4,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub offset: u64,
    pub ptype: PartitionType,
}

/// Virtual-disk container formats that are not raw and that this tool does
/// not decode. Detected by signature so the analyst gets a clear error instead
/// of an empty timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerFormat {
    Vhdx,
    VmdkSparse,
    VmdkDescriptor,
    VhdDynamic,
    Qcow,
    Vdi,
}

impl ContainerFormat {
    pub fn describe(self) -> &'static str {
        match self {
            ContainerFormat::Vhdx => "VHDX (Hyper-V v2) container",
            ContainerFormat::VmdkSparse => "VMDK sparse extent",
            ContainerFormat::VmdkDescriptor => "VMDK descriptor file",
            ContainerFormat::VhdDynamic => "dynamic/differencing VHD",
            ContainerFormat::Qcow => "QCOW/QCOW2 image",
            ContainerFormat::Vdi => "VirtualBox VDI",
        }
    }
}

/// Reads the first bytes of an image and reports a known non-raw container.
pub fn detect_container_format<R: Read + Seek>(reader: &mut R) -> Option<ContainerFormat> {
    let mut head = [0u8; 64];
    reader.seek(SeekFrom::Start(0)).ok()?;
    let n = reader.read(&mut head).ok()?;
    let head = &head[..n];
    if head.starts_with(b"vhdxfile") {
        Some(ContainerFormat::Vhdx)
    } else if head.starts_with(b"KDMV") || head.starts_with(b"COWD") {
        Some(ContainerFormat::VmdkSparse)
    } else if head.starts_with(b"# Disk DescriptorFile") {
        Some(ContainerFormat::VmdkDescriptor)
    } else if head.starts_with(b"conectix") {
        // A fixed VHD has "conectix" only in its trailing footer; at offset 0
        // it is a dynamic or differencing disk.
        Some(ContainerFormat::VhdDynamic)
    } else if head.starts_with(b"QFI\xfb") {
        Some(ContainerFormat::Qcow)
    } else if head.starts_with(b"<<< ") && head.windows(4).any(|w| w == b"VDI ") {
        Some(ContainerFormat::Vdi)
    } else {
        None
    }
}

pub struct OffsetReader<'a, R: Read + Seek> {
    inner: &'a mut R,
    offset: u64,
}

impl<'a, R: Read + Seek> OffsetReader<'a, R> {
    pub fn new(inner: &'a mut R, offset: u64) -> Self {
        Self { inner, offset }
    }
}

impl<'a, R: Read + Seek> Read for OffsetReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<'a, R: Read + Seek> Seek for OffsetReader<'a, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => {
                let actual = self.inner.seek(SeekFrom::Start(self.offset + p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::Current(p) => {
                let actual = self.inner.seek(SeekFrom::Current(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
            SeekFrom::End(p) => {
                let actual = self.inner.seek(SeekFrom::End(p))?;
                Ok(actual.saturating_sub(self.offset))
            }
        }
    }
}

/// Presents a split raw image (`.001`, `.002`, ...) as one contiguous stream.
pub struct SegmentedReader {
    segments: Vec<(File, u64)>,
    starts: Vec<u64>,
    total: u64,
    pos: u64,
}

impl SegmentedReader {
    /// Opens `first` and every numerically following segment that exists.
    pub fn open(first: &Path) -> io::Result<Self> {
        let mut segments = Vec::new();
        let mut starts = Vec::new();
        let mut total = 0u64;

        let stem = first.file_stem().map(|s| s.to_os_string());
        let ext = first.extension().and_then(|e| e.to_str()).unwrap_or("");
        let width = ext.len();
        let mut idx: u32 = ext.parse().unwrap_or(1);

        loop {
            let candidate: PathBuf = if idx == ext.parse().unwrap_or(1) {
                first.to_path_buf()
            } else {
                match &stem {
                    Some(s) => first.with_file_name(format!("{}.{:0width$}", s.to_string_lossy(), idx, width = width)),
                    None => break,
                }
            };
            if !candidate.exists() {
                break;
            }
            let f = File::open(&candidate)?;
            let len = f.metadata()?.len();
            starts.push(total);
            total += len;
            segments.push((f, len));
            idx += 1;
            if idx > 9999 {
                break;
            }
        }
        if segments.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no image segments found"));
        }
        Ok(Self { segments, starts, total, pos: 0 })
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    pub fn total_size(&self) -> u64 {
        self.total
    }
}

impl Read for SegmentedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total || buf.is_empty() {
            return Ok(0);
        }
        // Find the segment containing pos.
        let idx = match self.starts.binary_search(&self.pos) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let seg_start = self.starts[idx];
        let (ref mut file, len) = self.segments[idx];
        let within = self.pos - seg_start;
        let avail = (len - within) as usize;
        let want = buf.len().min(avail);
        file.seek(SeekFrom::Start(within))?;
        let n = file.read(&mut buf[..want])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SegmentedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(p) => self.total as i128 + p as i128,
            SeekFrom::Current(p) => self.pos as i128 + p as i128,
        };
        if new_pos < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

pub fn detect_partition_type<R: Read + Seek>(reader: &mut R, offset: u64) -> PartitionType {
    // Check NTFS: "NTFS    " at offset + 3
    if reader.seek(SeekFrom::Start(offset + 3)).is_ok() {
        let mut sig = [0u8; 8];
        if reader.read_exact(&mut sig).is_ok() && &sig == NTFS_SIGNATURE {
            return PartitionType::Ntfs;
        }
    }

    // Check Ext4: 0x53, 0xEF at offset + 1080
    if reader.seek(SeekFrom::Start(offset + EXT_MAGIC_OFFSET)).is_ok() {
        let mut magic = [0u8; 2];
        if reader.read_exact(&mut magic).is_ok() && magic == EXT_MAGIC {
            return PartitionType::Ext4;
        }
    }

    PartitionType::Unknown
}

fn push_if_fs<R: Read + Seek>(reader: &mut R, offset: u64, image_size: u64, out: &mut Vec<PartitionInfo>) {
    if offset >= image_size || out.iter().any(|p| p.offset == offset) {
        return;
    }
    let ptype = detect_partition_type(reader, offset);
    if ptype != PartitionType::Unknown {
        out.push(PartitionInfo { offset, ptype });
    }
}

/// Parses a GPT header at `sector_size` and returns the partition byte offsets.
fn gpt_partition_offsets<R: Read + Seek>(reader: &mut R, sector_size: u64) -> Option<Vec<u64>> {
    let mut hdr = [0u8; 92];
    reader.seek(SeekFrom::Start(sector_size)).ok()?;
    reader.read_exact(&mut hdr).ok()?;
    if &hdr[0..8] != GPT_SIGNATURE {
        return None;
    }
    let entries_lba = u64::from_le_bytes(hdr[72..80].try_into().ok()?);
    let num_entries = u32::from_le_bytes(hdr[80..84].try_into().ok()?).min(MAX_GPT_ENTRIES);
    let entry_size = u32::from_le_bytes(hdr[84..88].try_into().ok()?) as u64;
    if !(128..=4096).contains(&entry_size) || entries_lba == 0 {
        return None;
    }

    let mut offsets = Vec::new();
    let mut entry = vec![0u8; entry_size as usize];
    for i in 0..num_entries as u64 {
        let pos = entries_lba.checked_mul(sector_size)?.checked_add(i * entry_size)?;
        if reader.seek(SeekFrom::Start(pos)).is_err() || reader.read_exact(&mut entry).is_err() {
            break;
        }
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first_lba = u64::from_le_bytes(entry[32..40].try_into().ok()?);
        if let Some(off) = first_lba.checked_mul(sector_size) {
            offsets.push(off);
        }
    }
    Some(offsets)
}

/// Parses the MBR (including EBR-chained logical partitions) at `sector_size`.
/// Returns the byte offsets of every used partition and whether a protective
/// GPT entry was seen.
fn mbr_partition_offsets<R: Read + Seek>(reader: &mut R, sector_size: u32) -> Option<(Vec<u64>, bool)> {
    reader.seek(SeekFrom::Start(0)).ok()?;
    let mbr = mbrman::MBR::read_from(reader, sector_size).ok()?;
    let mut offsets = Vec::new();
    let mut gpt = false;
    for (_, part) in mbr.iter() {
        if !part.is_used() {
            continue;
        }
        if part.sys == MBR_PROTECTIVE_GPT {
            gpt = true;
            continue;
        }
        if part.is_extended() {
            continue;
        }
        offsets.push(u64::from(part.starting_lba) * u64::from(sector_size));
    }
    Some((offsets, gpt))
}

pub fn find_partitions<R: Read + Seek>(reader: &mut R, image_size: u64) -> Vec<PartitionInfo> {
    let mut partitions = Vec::new();

    // 1. The image may be a bare filesystem (no partition table).
    let direct_type = detect_partition_type(reader, 0);
    if direct_type != PartitionType::Unknown {
        partitions.push(PartitionInfo { offset: 0, ptype: direct_type });
        return partitions;
    }

    // 2. GPT at LBA 1, trying both common sector sizes.
    for sector_size in [512u64, 4096] {
        if let Some(offsets) = gpt_partition_offsets(reader, sector_size) {
            for off in offsets {
                push_if_fs(reader, off, image_size, &mut partitions);
            }
            if !partitions.is_empty() {
                return partitions;
            }
        }
    }

    // 3. MBR (primary + logical via EBR chain), 512 first then 4Kn.
    for sector_size in [512u32, 4096] {
        if let Some((offsets, _gpt)) = mbr_partition_offsets(reader, sector_size) {
            for off in offsets {
                push_if_fs(reader, off, image_size, &mut partitions);
            }
            if !partitions.is_empty() {
                return partitions;
            }
        }
    }

    // 4. Fallback scan of common offsets if no partitions were detected
    let common_offsets = [
        1_048_576,    // 1 MiB (modern Windows / Linux standard offset, sector 2048)
        2_097_152,    // 2 MiB
        32_256,       // Sector 63 (legacy MBR)
        65_536,       // 64 KiB
        524_288,      // 512 KiB
        104_857_600,  // 100 MiB (Windows System Reserved offset)
        536_870_912,  // 512 MiB
    ];
    for &off in &common_offsets {
        push_if_fs(reader, off, image_size, &mut partitions);
    }

    partitions
}

/// Walks every detected partition of an opened image reader.
fn parse_partitions<R: Read + Seek + Send + 'static>(
    mut reader: R,
    total_size: u64,
    label: &str,
    mft_options: &MftParseOptions,
    temp_dir: &Path,
) -> Result<(Vec<TimelineEntry>, ResidentStats)> {
    let mut combined_timeline = Vec::new();
    let mut total_stats = ResidentStats::default();

    let partitions = find_partitions(&mut reader, total_size);
    if partitions.is_empty() {
        return Err(AllyError::Image {
            code: ErrorCode::ImagePartitionTableCorrupt,
            path: label.to_string(),
            message: "No NTFS or ext4 filesystem found (checked bare filesystem, GPT, MBR/EBR and common offsets)".to_string(),
        });
    }
    if !mft_options.quiet {
        eprintln!("    [i] {} partition(s) with a supported filesystem", partitions.len());
    }

    let mut failures = 0usize;
    for part in partitions {
        match part.ptype {
            PartitionType::Ntfs => {
                let mut offset_reader = OffsetReader::new(&mut reader, part.offset);
                match extract_and_parse_ntfs(&mut offset_reader, mft_options, temp_dir) {
                    Ok((timeline, stats)) => {
                        combined_timeline.extend(timeline);
                        total_stats.total_extracted += stats.total_extracted;
                        total_stats.total_bytes += stats.total_bytes;
                        total_stats.total_failed += stats.total_failed;
                        total_stats.total_unsafe_paths += stats.total_unsafe_paths;
                    }
                    Err(e) => {
                        failures += 1;
                        eprintln!("[!] NTFS partition @0x{:X} in {}: {}", part.offset, label, e);
                    }
                }
            }
            PartitionType::Ext4 => {
                let reader_arc = Arc::new(Mutex::new(reader));
                match parse_ext4_partition(reader_arc.clone(), part.offset) {
                    Ok(timeline) => combined_timeline.extend(timeline),
                    Err(e) => {
                        failures += 1;
                        eprintln!("[!] ext4 partition @0x{:X} in {}: {}", part.offset, label, e);
                    }
                }
                reader = Arc::try_unwrap(reader_arc)
                    .map_err(|_| AllyError::Image {
                        code: ErrorCode::ImageReadFailed,
                        path: label.to_string(),
                        message: "Failed unfreezing Arc reader".to_string(),
                    })?
                    .into_inner()
                    .map_err(|_| AllyError::Image {
                        code: ErrorCode::ImageReadFailed,
                        path: label.to_string(),
                        message: "Mutex poisoned on image reader".to_string(),
                    })?;
            }
            PartitionType::Unknown => {}
        }
    }

    if combined_timeline.is_empty() && failures > 0 {
        return Err(AllyError::Image {
            code: ErrorCode::ImageReadFailed,
            path: label.to_string(),
            message: format!("All {} partition(s) failed to parse", failures),
        });
    }

    Ok((combined_timeline, total_stats))
}

pub fn parse_forensic_image(
    image_path: &Path,
    mft_options: &MftParseOptions,
    temp_dir: &Path,
) -> Result<(Vec<TimelineEntry>, ResidentStats)> {
    let ext = image_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let label = image_path.display().to_string();

    if ext == "e01" || ext == "ex01" {
        let ewf_reader = ewf::EwfReader::open(&label).map_err(|e| AllyError::Image {
            code: ErrorCode::ImageReadFailed,
            path: label.clone(),
            message: format!("Failed opening E01 image: {}", e),
        })?;
        let total_size = ewf_reader.total_size();
        let buf_reader = BufReader::new(ewf_reader);
        return parse_partitions(buf_reader, total_size, &label, mft_options, temp_dir);
    }

    // Split raw sets (.001, .002, ...): chain every segment.
    if ext.chars().all(|c| c.is_ascii_digit()) && !ext.is_empty() {
        let seg = SegmentedReader::open(image_path).map_err(|e| AllyError::io_with_context(e, format!("Opening split raw image {}", label)))?;
        if !mft_options.quiet && seg.segment_count() > 1 {
            eprintln!("    [i] Split raw image: {} segments, {} bytes", seg.segment_count(), seg.total_size());
        }
        let total = seg.total_size();
        let mut reader = BufReader::new(seg);
        if let Some(fmt) = detect_container_format(&mut reader) {
            return Err(unsupported_container(&label, fmt));
        }
        return parse_partitions(reader, total, &label, mft_options, temp_dir);
    }

    let file = File::open(image_path).map_err(|e| AllyError::io_with_context(e, format!("Opening raw disk image {}", label)))?;
    let total_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::new(file);
    if let Some(fmt) = detect_container_format(&mut reader) {
        return Err(unsupported_container(&label, fmt));
    }
    parse_partitions(reader, total_size, &label, mft_options, temp_dir)
}

fn unsupported_container(label: &str, fmt: ContainerFormat) -> AllyError {
    AllyError::Image {
        code: ErrorCode::ImageUnsupportedFormat,
        path: label.to_string(),
        message: format!(
            "{} is not a raw image and cannot be parsed directly; convert it first, e.g. `qemu-img convert -O raw`",
            fmt.describe()
        ),
    }
}

fn extract_and_parse_ntfs<R: Read + Seek>(
    reader: &mut R,
    mft_options: &MftParseOptions,
    temp_dir: &Path,
) -> Result<(Vec<TimelineEntry>, ResidentStats)> {
    let ntfs = Ntfs::new(reader).map_err(|e| AllyError::Mft {
        code: ErrorCode::MftInitFailed,
        entry: None,
        message: format!("Failed reading NTFS volume: {}", e),
    })?;

    // In NTFS, record 0 is $MFT
    let mft_file = ntfs.file(reader, 0).map_err(|e| AllyError::Mft {
        code: ErrorCode::MftInitFailed,
        entry: Some(0),
        message: format!("Cannot open $MFT record: {}", e),
    })?;
    let mft_data_item = match mft_file.data(reader, "") {
        Some(Ok(item)) => item,
        Some(Err(e)) => {
            return Err(AllyError::Mft {
                code: ErrorCode::MftInitFailed,
                entry: Some(0),
                message: format!("Cannot read $MFT $DATA: {}", e),
            })
        }
        None => {
            return Err(AllyError::Mft {
                code: ErrorCode::MftInitFailed,
                entry: Some(0),
                message: "$MFT has no unnamed $DATA attribute".to_string(),
            })
        }
    };
    let mft_attr = mft_data_item.to_attribute().map_err(|e| AllyError::Mft {
        code: ErrorCode::MftAttributeInvalid,
        entry: Some(0),
        message: format!("$MFT $DATA attribute invalid: {}", e),
    })?;
    let attr_val = mft_attr.value(reader).map_err(|e| AllyError::Mft {
        code: ErrorCode::MftAttributeInvalid,
        entry: Some(0),
        message: format!("$MFT $DATA value unreadable: {}", e),
    })?;
    let mut mft_attached = attr_val.attach(reader);

    let mft_temp_path = staging_path(temp_dir, "mft_dump", "bin");
    {
        let mut out_file = File::create(&mft_temp_path).map_err(|e| AllyError::io_with_context(e, format!("Creating temp file {}", mft_temp_path.display())))?;
        io::copy(&mut mft_attached, &mut out_file).map_err(|e| AllyError::io_with_context(e, "Dumping $MFT stream from NTFS partition"))?;
    }

    let result = crate::parsers::mft::parse_mft_file(&mft_temp_path, mft_options);
    let _ = std::fs::remove_file(&mft_temp_path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_detect_container_formats() {
        let mut c = Cursor::new(b"vhdxfile\0\0\0\0".to_vec());
        assert_eq!(detect_container_format(&mut c), Some(ContainerFormat::Vhdx));
        let mut c = Cursor::new(b"KDMV\x01\x00".to_vec());
        assert_eq!(detect_container_format(&mut c), Some(ContainerFormat::VmdkSparse));
        let mut c = Cursor::new(b"conectix".to_vec());
        assert_eq!(detect_container_format(&mut c), Some(ContainerFormat::VhdDynamic));
        let mut c = Cursor::new(vec![0u8; 64]);
        assert_eq!(detect_container_format(&mut c), None);
    }

    fn ntfs_boot_sector() -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[3..11].copy_from_slice(b"NTFS    ");
        s
    }

    #[test]
    fn test_find_partitions_gpt() {
        // 512-byte sectors: protective MBR at 0, GPT header at LBA1, entries at LBA2, NTFS at LBA 2048.
        let ntfs_lba = 2048u64;
        let mut img = vec![0u8; (ntfs_lba as usize + 4) * 512];
        img[510] = 0x55;
        img[511] = 0xAA;
        // protective MBR entry
        img[446 + 4] = 0xEE;
        img[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // GPT header
        let h = 512;
        img[h..h + 8].copy_from_slice(b"EFI PART");
        img[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
        img[h + 80..h + 84].copy_from_slice(&1u32.to_le_bytes());
        img[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes());
        // entry 0
        let e = 1024;
        img[e..e + 16].copy_from_slice(&[0xAB; 16]);
        img[e + 32..e + 40].copy_from_slice(&ntfs_lba.to_le_bytes());
        img[e + 40..e + 48].copy_from_slice(&(ntfs_lba + 1).to_le_bytes());
        let off = ntfs_lba as usize * 512;
        img[off..off + 512].copy_from_slice(&ntfs_boot_sector());

        let size = img.len() as u64;
        let mut c = Cursor::new(img);
        let parts = find_partitions(&mut c, size);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].offset, ntfs_lba * 512);
        assert_eq!(parts[0].ptype, PartitionType::Ntfs);
    }

    #[test]
    fn test_find_partitions_mbr_with_logical() {
        // Primary NTFS at LBA 64, extended at LBA 128 containing a logical NTFS at LBA 192.
        let mut img = vec![0u8; 300 * 512];
        img[510] = 0x55;
        img[511] = 0xAA;
        // entry 0: NTFS primary
        img[446 + 4] = 0x07;
        img[446 + 8..446 + 12].copy_from_slice(&64u32.to_le_bytes());
        img[446 + 12..446 + 16].copy_from_slice(&32u32.to_le_bytes());
        // entry 1: extended
        img[462 + 4] = 0x05;
        img[462 + 8..462 + 12].copy_from_slice(&128u32.to_le_bytes());
        img[462 + 12..462 + 16].copy_from_slice(&128u32.to_le_bytes());
        // EBR at LBA 128: logical starts 64 sectors after the EBR (LBA 192)
        let ebr = 128 * 512;
        img[ebr + 510] = 0x55;
        img[ebr + 511] = 0xAA;
        img[ebr + 446 + 4] = 0x07;
        img[ebr + 446 + 8..ebr + 446 + 12].copy_from_slice(&64u32.to_le_bytes());
        img[ebr + 446 + 12..ebr + 446 + 16].copy_from_slice(&32u32.to_le_bytes());
        for lba in [64usize, 192] {
            let off = lba * 512;
            img[off..off + 512].copy_from_slice(&ntfs_boot_sector());
        }
        let size = img.len() as u64;
        let mut c = Cursor::new(img);
        let parts = find_partitions(&mut c, size);
        let mut offs: Vec<u64> = parts.iter().map(|p| p.offset).collect();
        offs.sort();
        assert_eq!(offs, vec![64 * 512, 192 * 512]);
    }

    #[test]
    fn test_segmented_reader_round_trip() {
        let dir = std::env::temp_dir().join(format!("allymacb_seg_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("img.001"), b"hello ").unwrap();
        std::fs::write(dir.join("img.002"), b"split ").unwrap();
        std::fs::write(dir.join("img.003"), b"world").unwrap();
        let mut r = SegmentedReader::open(&dir.join("img.001")).unwrap();
        assert_eq!(r.segment_count(), 3);
        let mut all = String::new();
        r.read_to_string(&mut all).unwrap();
        assert_eq!(all, "hello split world");
        r.seek(SeekFrom::Start(6)).unwrap();
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"split wo");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
