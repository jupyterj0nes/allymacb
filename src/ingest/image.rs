use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use ntfs::Ntfs;

use crate::parsers::ext4::parse_ext4_partition;
use crate::parsers::mft::{MftParseOptions, ResidentStats};
use crate::timeline::TimelineEntry;

const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const EXT_MAGIC_OFFSET: u64 = 1080;
const EXT_MAGIC: [u8; 2] = [0x53, 0xEF];

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

pub fn detect_partition_type<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
) -> PartitionType {
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

pub fn find_partitions<R: Read + Seek>(
    reader: &mut R,
    image_size: u64,
) -> Vec<PartitionInfo> {
    let mut partitions = Vec::new();

    // 1. Check if the entire image directly contains a filesystem at offset 0
    let direct_type = detect_partition_type(reader, 0);
    if direct_type != PartitionType::Unknown {
        partitions.push(PartitionInfo {
            offset: 0,
            ptype: direct_type,
        });
        return partitions;
    }

    // 2. Scan MBR partition table (Sector 0)
    let mut mbr_buf = [0u8; 512];
    if reader.seek(SeekFrom::Start(0)).is_ok() && reader.read_exact(&mut mbr_buf).is_ok() {
        let mut cursor = io::Cursor::new(&mbr_buf[..]);
        if let Ok(mbr) = mbrman::MBR::read_from(&mut cursor, 512) {
            for (_, part) in mbr.iter() {
                if !part.is_used() {
                    continue;
                }
                let part_offset = part.starting_lba as u64 * 512;
                if part_offset < image_size {
                    let ptype = detect_partition_type(reader, part_offset);
                    if ptype != PartitionType::Unknown {
                        partitions.push(PartitionInfo {
                            offset: part_offset,
                            ptype,
                        });
                    }
                }
            }
        }
    }

    // 3. Fallback scan of common offsets if no partitions were detected
    if partitions.is_empty() {
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
            if off < image_size {
                let ptype = detect_partition_type(reader, off);
                if ptype != PartitionType::Unknown {
                    partitions.push(PartitionInfo { offset: off, ptype });
                }
            }
        }
    }

    partitions
}

pub fn parse_forensic_image(
    image_path: &Path,
    mft_options: &MftParseOptions,
    temp_dir: &Path,
) -> Result<(Vec<TimelineEntry>, ResidentStats), Box<dyn std::error::Error + Send + Sync>> {
    let mut combined_timeline = Vec::new();
    let mut total_stats = ResidentStats::default();

    let ext = image_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext == "e01" || ext == "ex01" {
        // Open E01 image with ewf
        let path_str = image_path.to_string_lossy().to_string();
        let ewf_reader = ewf::EwfReader::open(&path_str)?;
        let total_size = ewf_reader.total_size();
        let mut buf_reader = BufReader::new(ewf_reader);

        let partitions = find_partitions(&mut buf_reader, total_size);
        for part in partitions {
            match part.ptype {
                PartitionType::Ntfs => {
                    let mut offset_reader = OffsetReader::new(&mut buf_reader, part.offset);
                    if let Ok((timeline, stats)) = extract_and_parse_ntfs(&mut offset_reader, mft_options, temp_dir) {
                        combined_timeline.extend(timeline);
                        total_stats.total_extracted += stats.total_extracted;
                        total_stats.total_bytes += stats.total_bytes;
                    }
                }
                PartitionType::Ext4 => {
                    // ext4 on E01 reader
                    let reader_arc = Arc::new(Mutex::new(buf_reader));
                    if let Ok(timeline) = parse_ext4_partition(reader_arc.clone(), part.offset) {
                        combined_timeline.extend(timeline);
                    }
                    buf_reader = Arc::try_unwrap(reader_arc)
                        .map_err(|_| "Arc unwrap failed")?
                        .into_inner()
                        .map_err(|_| "Mutex into_inner failed")?;
                }
                PartitionType::Unknown => {}
            }
        }
    } else {
        // Raw image (.dd, .raw, .img, .001, etc.)
        let file = File::open(image_path)?;
        let total_size = file.metadata()?.len();
        let mut reader = BufReader::new(file);

        let partitions = find_partitions(&mut reader, total_size);
        for part in partitions {
            match part.ptype {
                PartitionType::Ntfs => {
                    let mut offset_reader = OffsetReader::new(&mut reader, part.offset);
                    if let Ok((timeline, stats)) = extract_and_parse_ntfs(&mut offset_reader, mft_options, temp_dir) {
                        combined_timeline.extend(timeline);
                        total_stats.total_extracted += stats.total_extracted;
                        total_stats.total_bytes += stats.total_bytes;
                    }
                }
                PartitionType::Ext4 => {
                    let reader_arc = Arc::new(Mutex::new(reader));
                    if let Ok(timeline) = parse_ext4_partition(reader_arc.clone(), part.offset) {
                        combined_timeline.extend(timeline);
                    }
                    reader = Arc::try_unwrap(reader_arc)
                        .map_err(|_| "Arc unwrap failed")?
                        .into_inner()
                        .map_err(|_| "Mutex into_inner failed")?;
                }
                PartitionType::Unknown => {}
            }
        }
    }

    Ok((combined_timeline, total_stats))
}

fn extract_and_parse_ntfs<R: Read + Seek>(
    reader: &mut R,
    mft_options: &MftParseOptions,
    temp_dir: &Path,
) -> Result<(Vec<TimelineEntry>, ResidentStats), Box<dyn std::error::Error + Send + Sync>> {
    let ntfs = Ntfs::new(reader)?;
    let mut combined_timeline = Vec::new();
    let mut resident_stats = ResidentStats::default();

    // In NTFS, record 0 is $MFT
    if let Ok(mft_file) = ntfs.file(reader, 0) {
        if let Some(Ok(mft_data_item)) = mft_file.data(reader, "") {
            if let Ok(mft_attr) = mft_data_item.to_attribute() {
                if let Ok(attr_val) = mft_attr.value(reader) {
                    let mut mft_attached = attr_val.attach(reader);
                    let mft_temp_path = temp_dir.join(format!("mft_dump_{}.bin", uuid_or_random()));
                    {
                        let mut out_file = File::create(&mft_temp_path)?;
                        io::copy(&mut mft_attached, &mut out_file)?;
                    }

                    if let Ok((timeline, stats)) = crate::parsers::mft::parse_mft_file(&mft_temp_path, mft_options) {
                        combined_timeline.extend(timeline);
                        resident_stats.total_extracted += stats.total_extracted;
                        resident_stats.total_bytes += stats.total_bytes;
                    }
                    let _ = std::fs::remove_file(mft_temp_path);
                }
            }
        }
    }

    Ok((combined_timeline, resident_stats))
}

fn uuid_or_random() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(123456)
}
