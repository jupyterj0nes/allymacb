//! VMDK reader: a VMware virtual disk as `Read + Seek`, fed to the same partition walker as
//! a raw image.
//!
//! Supports monolithic sparse (`KDMV` header), streamOptimized (compressed grains, grain
//! directory in the footer: what VMware, OVF and cloud exports such as GCP's
//! `gcloud compute images export --export-format=vmdk` write), descriptor files with FLAT,
//! VMFS, SPARSE/VMFSSPARSE and ZERO extents (split sparse `-s001.vmdk`, split flat
//! `-flat.vmdk`), and a FLAT extent left as `<name>.filepart` by an interrupted upload.
//! A snapshot delta (a descriptor with a parent) is refused: it holds only the changes.
//! Ported from faramir (`src/ingest/vmdk.rs`), the parent check from evidencefs. Every file
//! is opened through [`crate::evidence::open`], so reading leaves no access time.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use super::vdisk::{open_evidence, seek_to, DiskError};
use crate::error::ErrorCode;

const SECTOR_SIZE: u64 = 512;
pub const SPARSE_MAGIC: u32 = 0x564D_444B; // "KDMV"
const GD_AT_END: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const FLAG_COMPRESSED: u32 = 0x1_0000;
/// Decompressed grains kept for reads that come back to them (64 MB with 64 KB grains).
const GRAIN_CACHE: usize = 1024;

#[derive(Debug, Clone)]
struct SparseHeader {
    capacity: u64,
    grain_size: u64,
    num_gte_per_gt: u32,
    gd_offset: u64,
    compressed: bool,
}

enum ExtentData {
    Zero,
    Flat {
        file: File,
        file_offset: u64,
    },
    Sparse {
        file: File,
        header: SparseHeader,
        grain_directory: Vec<u32>,
        grain_tables: HashMap<u32, Vec<u32>>,
        grains: HashMap<u64, Vec<u8>>,
    },
}

struct Extent {
    data: ExtentData,
    size_bytes: u64,
}

/// One extent line of a descriptor: `ACCESS SECTORS TYPE "FILENAME" [OFFSET]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentLine {
    pub sectors: u64,
    pub extent_type: String,
    pub filename: String,
    pub flat_offset: u64,
}

pub struct VmdkReader {
    extents: Vec<Extent>,
    total_size: u64,
    position: u64,
    files: Vec<PathBuf>,
    stream_optimized: bool,
}

impl VmdkReader {
    /// Opens a VMDK: a sparse extent, a descriptor, or (neither) a flat file read as raw.
    pub fn open(path: &Path) -> Result<Self, DiskError> {
        let base_dir = path.parent().unwrap_or(Path::new("."));
        let mut file = open_evidence(path).map_err(|e| DiskError::read(format!("cannot open VMDK: {e}")))?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).map_err(|e| DiskError::read(format!("cannot read the VMDK header: {e}")))?;
        if u32::from_le_bytes(magic) == SPARSE_MAGIC {
            drop(file);
            let (extent, stream) = open_sparse_extent(path)?;
            let size = extent.size_bytes;
            return Ok(VmdkReader { extents: vec![extent], total_size: size, position: 0, files: vec![path.to_path_buf()], stream_optimized: stream });
        }
        file.seek(SeekFrom::Start(0)).map_err(|e| DiskError::read(e.to_string()))?;
        let mut buf = vec![0u8; 65536];
        let n = file.read(&mut buf).map_err(|e| DiskError::read(format!("cannot read VMDK: {e}")))?;
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        if is_descriptor(&text) {
            drop(file);
            return open_from_descriptor(&text, base_dir);
        }
        // Neither a sparse header nor a descriptor: a flat disk named .vmdk.
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(VmdkReader {
            extents: vec![Extent { data: ExtentData::Flat { file, file_offset: 0 }, size_bytes: size }],
            total_size: size,
            position: 0,
            files: vec![path.to_path_buf()],
            stream_optimized: false,
        })
    }

    /// The virtual disk's size in bytes.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Every file the disk is read from (the descriptor's extents, or the file itself).
    pub fn extent_files(&self) -> &[PathBuf] {
        &self.files
    }

    /// True for a streamOptimized (compressed) extent.
    pub fn is_stream_optimized(&self) -> bool {
        self.stream_optimized
    }

    fn find_extent(&self, global: u64) -> Option<(usize, u64)> {
        let mut start = 0u64;
        for (i, e) in self.extents.iter().enumerate() {
            if global < start + e.size_bytes {
                return Some((i, global - start));
            }
            start += e.size_bytes;
        }
        None
    }
}

/// A descriptor file: text with the header comment or a `createType`.
pub fn is_descriptor(text: &str) -> bool {
    text.contains("# Disk DescriptorFile") || text.contains("createType")
}

/// A descriptor whose `parentCID` is set (not `ffffffff`): a snapshot delta.
pub fn descriptor_has_parent(text: &str) -> bool {
    text.lines().map(str::trim).any(|l| {
        l.strip_prefix("parentCID").map(|r| r.trim_start().trim_start_matches('=').trim().trim_matches('"')).is_some_and(|v| !v.is_empty() && !v.eq_ignore_ascii_case("ffffffff"))
    })
}

fn open_from_descriptor(text: &str, base_dir: &Path) -> Result<VmdkReader, DiskError> {
    if descriptor_has_parent(text) {
        let hint = text.lines().map(str::trim).find_map(|l| l.strip_prefix("parentFileNameHint")).map(|r| r.trim_start_matches([' ', '=']).trim_matches('"').to_string()).unwrap_or_default();
        return Err(DiskError::has_parent(format!("VMDK snapshot delta (parent {}): it holds only the changes over its parent; give the consolidated disk", if hint.is_empty() { "not named" } else { &hint })));
    }
    let mut extents = Vec::new();
    let mut files = Vec::new();
    let mut total = 0u64;
    let mut stream = false;
    for line in text.lines().map(str::trim) {
        if !line.starts_with("RW ") && !line.starts_with("RDONLY ") && !line.starts_with("NOACCESS ") {
            continue;
        }
        let parts = parse_extent_line(line)?;
        let extent_path = base_dir.join(&parts.filename);
        let extent = match parts.extent_type.to_ascii_uppercase().as_str() {
            "FLAT" | "VMFS" | "VMFSRAW" | "VMFSRDM" => {
                let file = match open_evidence(&extent_path) {
                    Ok(f) => {
                        files.push(extent_path.clone());
                        f
                    }
                    Err(_) => {
                        // An interrupted SFTP upload leaves the data file as <name>.filepart.
                        let part = PathBuf::from(format!("{}.filepart", extent_path.display()));
                        match open_evidence(&part) {
                            Ok(f) => {
                                crate::say!("    [!] VMDK extent '{}' read from its incomplete upload '{}'", parts.filename, part.display());
                                files.push(part);
                                f
                            }
                            Err(_) => return Err(DiskError::missing(format!("VMDK extent '{}' not found next to the descriptor (only the descriptor was collected?)", parts.filename))),
                        }
                    }
                };
                Extent { data: ExtentData::Flat { file, file_offset: parts.flat_offset * SECTOR_SIZE }, size_bytes: parts.sectors * SECTOR_SIZE }
            }
            "SPARSE" | "VMFSSPARSE" => {
                if !extent_path.is_file() {
                    return Err(DiskError::missing(format!("VMDK extent '{}' not found next to the descriptor (only the descriptor was collected?)", parts.filename)));
                }
                let (e, s) = open_sparse_extent(&extent_path)?;
                stream |= s;
                files.push(extent_path.clone());
                e
            }
            "ZERO" => Extent { data: ExtentData::Zero, size_bytes: parts.sectors * SECTOR_SIZE },
            other => return Err(DiskError::new(ErrorCode::ImageUnsupportedFormat, format!("VMDK extent type {other} cannot be read"))),
        };
        total = total.saturating_add(extent.size_bytes);
        extents.push(extent);
    }
    if extents.is_empty() {
        return Err(DiskError::damaged("VMDK descriptor without any extent line"));
    }
    Ok(VmdkReader { extents, total_size: total, position: 0, files, stream_optimized: stream })
}

/// Parses `ACCESS SECTORS TYPE "FILENAME" [OFFSET]` (a ZERO extent has no file name).
pub fn parse_extent_line(line: &str) -> Result<ExtentLine, DiskError> {
    let mut chars = line.chars().peekable();
    let mut tokens: Vec<String> = Vec::new();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut tok = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                tok.push(c);
            }
        } else {
            while let Some(c) = chars.peek().copied() {
                if c.is_whitespace() {
                    break;
                }
                tok.push(c);
                chars.next();
            }
        }
        tokens.push(tok);
    }
    let is_zero = tokens.get(2).is_some_and(|t| t.eq_ignore_ascii_case("ZERO"));
    if tokens.len() < 4 && !(is_zero && tokens.len() == 3) {
        return Err(DiskError::damaged(format!("malformed VMDK extent line: {line}")));
    }
    let sectors: u64 = tokens[1].parse().map_err(|_| DiskError::damaged(format!("invalid sector count in VMDK extent line: {line}")))?;
    if sectors.checked_mul(SECTOR_SIZE).is_none() {
        return Err(DiskError::damaged(format!("sector count out of range in VMDK extent line: {line}")));
    }
    Ok(ExtentLine {
        sectors,
        extent_type: tokens[2].clone(),
        filename: tokens.get(3).cloned().unwrap_or_default(),
        flat_offset: tokens.get(4).and_then(|t| t.parse().ok()).unwrap_or(0),
    })
}

fn read_sparse_header(file: &mut File) -> Result<SparseHeader, DiskError> {
    let mut buf = [0u8; 72];
    file.read_exact(&mut buf).map_err(|e| DiskError::damaged(format!("cannot read the sparse header: {e}")))?;
    if u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) != SPARSE_MAGIC {
        return Err(DiskError::damaged("not a sparse VMDK header (no KDMV magic)"));
    }
    let flags = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let capacity = u64::from_le_bytes(buf[12..20].try_into().unwrap_or_default());
    let grain_size = u64::from_le_bytes(buf[20..28].try_into().unwrap_or_default());
    let num_gte_per_gt = u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]);
    let gd_offset = u64::from_le_bytes(buf[56..64].try_into().unwrap_or_default());
    // VMware writes grainSize 128 and numGTEsPerGT 512; far-off values are damage.
    if grain_size == 0 || !grain_size.is_power_of_two() || grain_size > 2048 {
        return Err(DiskError::damaged(format!("damaged sparse VMDK header: grainSize {grain_size}")));
    }
    if num_gte_per_gt == 0 || num_gte_per_gt > 65536 {
        return Err(DiskError::damaged(format!("damaged sparse VMDK header: numGTEsPerGT {num_gte_per_gt}")));
    }
    if capacity.checked_mul(SECTOR_SIZE).is_none() {
        return Err(DiskError::damaged(format!("damaged sparse VMDK header: capacity {capacity} sectors")));
    }
    Ok(SparseHeader { capacity, grain_size, num_gte_per_gt, gd_offset, compressed: flags & FLAG_COMPRESSED != 0 })
}

fn gd_entry_count(h: &SparseHeader) -> usize {
    let sectors_per_gt = u64::from(h.num_gte_per_gt) * h.grain_size;
    if sectors_per_gt == 0 {
        return 0;
    }
    usize::try_from(h.capacity.div_ceil(sectors_per_gt)).unwrap_or(usize::MAX)
}

/// Opens one sparse extent; true when it is streamOptimized (directory in the footer).
fn open_sparse_extent(path: &Path) -> Result<(Extent, bool), DiskError> {
    let mut file = open_evidence(path).map_err(|e| DiskError::read(format!("cannot open sparse extent '{}': {e}", path.display())))?;
    let mut header = read_sparse_header(&mut file)?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut stream = false;
    if header.gd_offset == GD_AT_END || header.gd_offset == 0 {
        if !header.compressed && header.capacity > 0 {
            return Err(DiskError::damaged("sparse VMDK with its grain directory at the end but no compressed grains"));
        }
        stream = true;
        let declared = header.capacity.saturating_mul(SECTOR_SIZE);
        let mut found = None;
        // The footer header sits 1024 bytes before the end (footer marker, footer, end-of-stream
        // marker); some writers pad differently.
        for back in [1024u64, 1536, 2048, 512] {
            let at = file_len.saturating_sub(back);
            if file.seek(SeekFrom::Start(at)).is_err() {
                continue;
            }
            if let Ok(h) = read_sparse_header(&mut file)
                && h.gd_offset != GD_AT_END
                && h.gd_offset != 0
                && h.capacity > 0
            {
                found = Some(h);
                break;
            }
        }
        let footer = found.ok_or_else(|| {
            let gb = |b: u64| b as f64 / 1_073_741_824.0;
            if declared > 0 && file_len < declared / 1024 {
                DiskError::damaged(format!("streamOptimized VMDK without its footer: declared {:.1} GB, {:.2} GB on disk (an interrupted export or download?)", gb(declared), gb(file_len)))
            } else {
                DiskError::damaged(format!("streamOptimized VMDK without a valid footer (declared {:.1} GB, file {:.2} GB)", gb(declared), gb(file_len)))
            }
        })?;
        header.gd_offset = footer.gd_offset;
    }
    let entries = gd_entry_count(&header);
    let gd_at = header.gd_offset.saturating_mul(SECTOR_SIZE);
    if (entries as u64).saturating_mul(4) > file_len || gd_at >= file_len {
        return Err(DiskError::damaged(format!("damaged sparse VMDK: a grain directory of {entries} entries at byte {gd_at} does not fit in a {file_len}-byte file")));
    }
    file.seek(SeekFrom::Start(gd_at)).map_err(|e| DiskError::read(e.to_string()))?;
    let mut raw = vec![0u8; entries * 4];
    file.read_exact(&mut raw).map_err(|e| DiskError::damaged(format!("cannot read the grain directory: {e}")))?;
    let grain_directory = raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    let size_bytes = header.capacity * SECTOR_SIZE;
    Ok((Extent { data: ExtentData::Sparse { file, header, grain_directory, grain_tables: HashMap::new(), grains: HashMap::new() }, size_bytes }, stream))
}

fn grain_table<'a>(file: &mut File, cache: &'a mut HashMap<u32, Vec<u32>>, gd_entry: u32, entries: usize) -> io::Result<&'a Vec<u32>> {
    if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(gd_entry) {
        file.seek(SeekFrom::Start(u64::from(gd_entry) * SECTOR_SIZE))?;
        let mut raw = vec![0u8; entries * 4];
        file.read_exact(&mut raw)?;
        slot.insert(raw.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect());
    }
    Ok(&cache[&gd_entry])
}

#[allow(clippy::too_many_arguments)]
fn read_sparse(
    file: &mut File,
    header: &SparseHeader,
    grain_directory: &[u32],
    grain_tables: &mut HashMap<u32, Vec<u32>>,
    grains: &mut HashMap<u64, Vec<u8>>,
    local: u64,
    buf: &mut [u8],
) -> io::Result<usize> {
    let grain_bytes = header.grain_size * SECTOR_SIZE;
    let extent_size = header.capacity * SECTOR_SIZE;
    if buf.is_empty() || local >= extent_size {
        return Ok(0);
    }
    let per_gt = u64::from(header.num_gte_per_gt);
    let grain = (local / SECTOR_SIZE) / header.grain_size;
    let gd_index = (grain / per_gt) as usize;
    let gt_index = (grain % per_gt) as usize;
    let in_grain = local % grain_bytes;
    let n = buf.len().min((grain_bytes - in_grain) as usize).min((extent_size - local) as usize);
    let zero = |buf: &mut [u8]| {
        buf[..n].fill(0);
        Ok(n)
    };
    let Some(&gd_entry) = grain_directory.get(gd_index) else { return zero(buf) };
    if gd_entry <= 1 {
        return zero(buf);
    }
    let gt_entry = match grain_table(file, grain_tables, gd_entry, per_gt as usize)?.get(gt_index) {
        Some(&e) if e > 1 => e,
        _ => return zero(buf),
    };
    if !header.compressed {
        file.seek(SeekFrom::Start(u64::from(gt_entry) * SECTOR_SIZE + in_grain))?;
        return file.read(&mut buf[..n]);
    }
    if !grains.contains_key(&grain) {
        // Grain marker: lba (u64), compressed size (u32), zlib data.
        file.seek(SeekFrom::Start(u64::from(gt_entry) * SECTOR_SIZE))?;
        let mut marker = [0u8; 12];
        file.read_exact(&mut marker)?;
        let size = u32::from_le_bytes([marker[8], marker[9], marker[10], marker[11]]);
        let mut plain = vec![0u8; grain_bytes as usize];
        if size > 0 && u64::from(size) <= grain_bytes * 2 + 4096 {
            let mut packed = vec![0u8; size as usize];
            file.read_exact(&mut packed)?;
            let mut dec = ZlibDecoder::new(&packed[..]);
            let mut filled = 0usize;
            while filled < plain.len() {
                match dec.read(&mut plain[filled..]) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => filled += k,
                }
            }
        }
        if grains.len() >= GRAIN_CACHE {
            grains.clear();
        }
        grains.insert(grain, plain);
    }
    let plain = &grains[&grain];
    let start = in_grain as usize;
    buf[..n].copy_from_slice(&plain[start..start + n]);
    Ok(n)
}

impl Read for VmdkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_size {
            return Ok(0);
        }
        let Some((i, local)) = self.find_extent(self.position) else { return Ok(0) };
        let extent = &mut self.extents[i];
        let len = buf.len().min((extent.size_bytes - local) as usize);
        let n = match &mut extent.data {
            ExtentData::Zero => {
                buf[..len].fill(0);
                len
            }
            ExtentData::Flat { file, file_offset } => {
                file.seek(SeekFrom::Start(*file_offset + local))?;
                let got = file.read(&mut buf[..len])?;
                if got == 0 {
                    // A flat extent shorter than the descriptor says: the rest reads as zeros.
                    buf[..len].fill(0);
                    len
                } else {
                    got
                }
            }
            ExtentData::Sparse { file, header, grain_directory, grain_tables, grains } => read_sparse(file, header, grain_directory, grain_tables, grains, local, &mut buf[..len])?,
        };
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for VmdkReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        seek_to(&mut self.position, self.total_size, pos)
    }
}

/// Test builders: sparse and streamOptimized extents holding given grains.
#[cfg(test)]
pub mod build {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// A sparse extent of `capacity` sectors, grains of `grain` sectors, `gtes` entries per
    /// grain table, holding `data` (grain index, bytes of one grain). Compressed:
    /// streamOptimized, directory in the footer.
    pub fn sparse(capacity: u64, grain: u64, gtes: u32, data: &[(u64, Vec<u8>)], compressed: bool) -> Vec<u8> {
        let grain_bytes = (grain * SECTOR_SIZE) as usize;
        let n_gd = capacity.div_ceil(u64::from(gtes) * grain) as usize;
        let header = |gd_offset: u64| {
            let mut h = vec![0u8; 512];
            h[0..4].copy_from_slice(&SPARSE_MAGIC.to_le_bytes());
            h[4..8].copy_from_slice(&(if compressed { 3u32 } else { 1u32 }).to_le_bytes());
            h[8..12].copy_from_slice(&(if compressed { FLAG_COMPRESSED | 0x2_0000 } else { 0 }).to_le_bytes());
            h[12..20].copy_from_slice(&capacity.to_le_bytes());
            h[20..28].copy_from_slice(&grain.to_le_bytes());
            h[44..48].copy_from_slice(&gtes.to_le_bytes());
            h[56..64].copy_from_slice(&gd_offset.to_le_bytes());
            h
        };
        let pad = |v: &mut Vec<u8>| {
            while !v.len().is_multiple_of(512) {
                v.push(0);
            }
        };
        let mut gts: Vec<Vec<u32>> = vec![vec![0u32; gtes as usize]; n_gd];
        if !compressed {
            // header, GD, GTs, grains
            let gd_sector = 1u64;
            let gd_sectors = ((n_gd * 4) as u64).div_ceil(512);
            let gt_sectors = (u64::from(gtes) * 4).div_ceil(512);
            let first_gt = gd_sector + gd_sectors;
            let mut next = first_gt + gt_sectors * n_gd as u64;
            let mut grains_bytes = Vec::new();
            for (gi, bytes) in data {
                let gd_i = (*gi / u64::from(gtes)) as usize;
                let gt_i = (*gi % u64::from(gtes)) as usize;
                gts[gd_i][gt_i] = next as u32;
                let mut g = bytes.clone();
                g.resize(grain_bytes, 0);
                grains_bytes.extend_from_slice(&g);
                next += grain;
            }
            let mut img = header(gd_sector);
            let mut gd = Vec::new();
            for i in 0..n_gd {
                gd.extend_from_slice(&((first_gt + gt_sectors * i as u64) as u32).to_le_bytes());
            }
            img.extend_from_slice(&gd);
            pad(&mut img);
            for gt in &gts {
                for e in gt {
                    img.extend_from_slice(&e.to_le_bytes());
                }
                pad(&mut img);
            }
            img.extend_from_slice(&grains_bytes);
            img
        } else {
            // header (GD at end), grain markers, GTs, GD, footer header, end-of-stream
            let mut img = header(GD_AT_END);
            // The header area (embedded descriptor, overhead) before the first grain: a grain
            // table entry of 1 means a zeroed grain, so no grain may start at sector 1.
            img.resize(64 * 1024, 0);
            for (gi, bytes) in data {
                let mut g = bytes.clone();
                g.resize(grain_bytes, 0);
                let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
                enc.write_all(&g).unwrap();
                let packed = enc.finish().unwrap();
                let sector = (img.len() / 512) as u32;
                let gd_i = (*gi / u64::from(gtes)) as usize;
                let gt_i = (*gi % u64::from(gtes)) as usize;
                gts[gd_i][gt_i] = sector;
                img.extend_from_slice(&(gi * grain).to_le_bytes());
                img.extend_from_slice(&(packed.len() as u32).to_le_bytes());
                img.extend_from_slice(&packed);
                pad(&mut img);
            }
            let mut gt_sectors = Vec::new();
            for gt in &gts {
                gt_sectors.push((img.len() / 512) as u32);
                for e in gt {
                    img.extend_from_slice(&e.to_le_bytes());
                }
                pad(&mut img);
            }
            let gd_sector = (img.len() / 512) as u64;
            for s in &gt_sectors {
                img.extend_from_slice(&s.to_le_bytes());
            }
            pad(&mut img);
            img.extend_from_slice(&header(gd_sector));
            img.extend_from_slice(&[0u8; 512]);
            img
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("allymacb-vmdk-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add((i % 251) as u8)).collect()
    }

    fn read_all(r: &mut VmdkReader) -> Vec<u8> {
        let mut v = Vec::new();
        r.read_to_end(&mut v).unwrap();
        v
    }

    #[test]
    fn monolithic_sparse_reads_grains_and_zero_holes() {
        let d = tmpdir("sparse");
        // 64 sectors, grains of 8 sectors (4 KB), 4 entries per table: 2 tables.
        let g1 = pattern(1, 4096);
        let g6 = pattern(77, 4096);
        let p = d.join("disk.vmdk");
        std::fs::write(&p, build::sparse(64, 8, 4, &[(1, g1.clone()), (6, g6.clone())], false)).unwrap();
        let mut r = VmdkReader::open(&p).unwrap();
        assert_eq!(r.total_size(), 64 * 512);
        assert!(!r.is_stream_optimized());
        assert_eq!(r.extent_files(), std::slice::from_ref(&p));
        let all = read_all(&mut r);
        assert_eq!(all.len(), 64 * 512);
        assert!(all[..4096].iter().all(|b| *b == 0), "grain 0 unallocated");
        assert_eq!(&all[4096..8192], &g1[..]);
        assert_eq!(&all[6 * 4096..7 * 4096], &g6[..]);
        // A read across a grain boundary returns at most to the boundary, and seeking works.
        r.seek(SeekFrom::Start(4096 + 4000)).unwrap();
        let mut b = [0u8; 200];
        let n = r.read(&mut b).unwrap();
        assert_eq!(n, 96);
        assert_eq!(&b[..96], &g1[4000..]);
        r.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(r.read(&mut b).unwrap(), 0);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn stream_optimized_reads_compressed_grains_from_the_footer_directory() {
        let d = tmpdir("stream");
        let g0 = pattern(9, 4096);
        let g5 = vec![0xABu8; 4096];
        let p = d.join("export.vmdk");
        std::fs::write(&p, build::sparse(64, 8, 4, &[(0, g0.clone()), (5, g5.clone())], true)).unwrap();
        let mut r = VmdkReader::open(&p).unwrap();
        assert!(r.is_stream_optimized());
        let all = read_all(&mut r);
        assert_eq!(&all[..4096], &g0[..]);
        assert!(all[4096..5 * 4096].iter().all(|b| *b == 0));
        assert_eq!(&all[5 * 4096..6 * 4096], &g5[..]);
        // Reading the same grain twice comes from the cache, with the same bytes.
        r.seek(SeekFrom::Start(100)).unwrap();
        let mut b = [0u8; 16];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b, &g0[100..116]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn truncated_stream_optimized_export_is_refused_as_damaged() {
        let d = tmpdir("trunc");
        let full = build::sparse(64, 8, 4, &[(0, pattern(3, 4096))], true);
        let p = d.join("cut.vmdk");
        std::fs::write(&p, &full[..full.len() - 1500]).unwrap();
        let e = VmdkReader::open(&p).err().expect("refused");
        assert_eq!(e.code, ErrorCode::ImageContainerDamaged, "{e}");
        assert!(e.message.contains("footer"), "{e}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn damaged_sparse_headers_are_refused_not_trusted() {
        let d = tmpdir("damaged");
        let mut h = build::sparse(64, 8, 4, &[], false);
        h[44..48].copy_from_slice(&0u32.to_le_bytes());
        std::fs::write(d.join("gte0.vmdk"), &h).unwrap();
        assert_eq!(VmdkReader::open(&d.join("gte0.vmdk")).err().unwrap().code, ErrorCode::ImageContainerDamaged);
        let mut h = build::sparse(64, 8, 4, &[], false);
        h[20..28].copy_from_slice(&3u64.to_le_bytes());
        std::fs::write(d.join("grain3.vmdk"), &h).unwrap();
        assert_eq!(VmdkReader::open(&d.join("grain3.vmdk")).err().unwrap().code, ErrorCode::ImageContainerDamaged);
        let mut h = build::sparse(64, 8, 4, &[], false);
        h[12..20].copy_from_slice(&(1u64 << 40).to_le_bytes());
        std::fs::write(d.join("huge.vmdk"), &h).unwrap();
        assert_eq!(VmdkReader::open(&d.join("huge.vmdk")).err().unwrap().code, ErrorCode::ImageContainerDamaged, "a directory larger than the file");
        let mut h = build::sparse(64, 8, 4, &[], false);
        h[56..64].copy_from_slice(&GD_AT_END.to_le_bytes());
        std::fs::write(d.join("gdend.vmdk"), &h).unwrap();
        assert_eq!(VmdkReader::open(&d.join("gdend.vmdk")).err().unwrap().code, ErrorCode::ImageContainerDamaged, "directory at the end without compression");
        assert_eq!(VmdkReader::open(&d.join("missing.vmdk")).err().unwrap().code, ErrorCode::ImageReadFailed);
        std::fs::write(d.join("empty.vmdk"), b"").unwrap();
        assert_eq!(VmdkReader::open(&d.join("empty.vmdk")).err().unwrap().code, ErrorCode::ImageReadFailed);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn descriptor_with_flat_zero_and_split_sparse_extents() {
        let d = tmpdir("desc");
        let flat = pattern(5, 2048);
        std::fs::write(d.join("disk-flat.vmdk"), &flat).unwrap();
        let g = pattern(40, 4096);
        std::fs::write(d.join("disk-s002.vmdk"), build::sparse(16, 8, 4, &[(1, g.clone())], false)).unwrap();
        let desc = "# Disk DescriptorFile\nversion=1\nCID=abcdef01\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentSparse\"\n\n# Extent description\nRW 4 FLAT \"disk-flat.vmdk\" 0\nRW 4 ZERO\nRW 16 SPARSE \"disk-s002.vmdk\"\n\nddb.adapterType = \"lsilogic\"\n";
        std::fs::write(d.join("disk.vmdk"), desc).unwrap();
        let mut r = VmdkReader::open(&d.join("disk.vmdk")).unwrap();
        assert_eq!(r.total_size(), (4 + 4 + 16) * 512);
        assert_eq!(r.extent_files(), &[d.join("disk-flat.vmdk"), d.join("disk-s002.vmdk")]);
        let all = read_all(&mut r);
        assert_eq!(&all[..2048], &flat[..]);
        assert!(all[2048..4096].iter().all(|b| *b == 0), "ZERO extent");
        assert!(all[4096..8192].iter().all(|b| *b == 0), "grain 0 of the sparse extent");
        assert_eq!(&all[8192..12288], &g[..]);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn descriptor_refusals_and_filepart_fallback() {
        let d = tmpdir("refuse");
        let desc = "# Disk DescriptorFile\nCID=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 4 FLAT \"gone-flat.vmdk\" 0\n";
        std::fs::write(d.join("d.vmdk"), desc).unwrap();
        assert_eq!(VmdkReader::open(&d.join("d.vmdk")).err().unwrap().code, ErrorCode::ImageExtentMissing);
        std::fs::write(d.join("gone-flat.vmdk.filepart"), [4u8; 2048]).unwrap();
        let mut r = VmdkReader::open(&d.join("d.vmdk")).unwrap();
        assert!(read_all(&mut r).iter().all(|b| *b == 4));
        let sparse_missing = "# Disk DescriptorFile\ncreateType=\"twoGbMaxExtentSparse\"\nRW 16 SPARSE \"gone-s001.vmdk\"\n";
        std::fs::write(d.join("s.vmdk"), sparse_missing).unwrap();
        assert_eq!(VmdkReader::open(&d.join("s.vmdk")).err().unwrap().code, ErrorCode::ImageExtentMissing);
        let delta = desc.replace("parentCID=ffffffff", "parentCID=12345678\nparentFileNameHint=\"base.vmdk\"");
        std::fs::write(d.join("delta.vmdk"), &delta).unwrap();
        let e = VmdkReader::open(&d.join("delta.vmdk")).err().unwrap();
        assert_eq!(e.code, ErrorCode::ImageHasParent);
        assert!(e.message.contains("base.vmdk"), "{e}");
        assert!(descriptor_has_parent(&delta) && !descriptor_has_parent(desc));
        std::fs::write(d.join("odd.vmdk"), "# Disk DescriptorFile\nRW 4 WEIRD \"x\"\n").unwrap();
        assert_eq!(VmdkReader::open(&d.join("odd.vmdk")).err().unwrap().code, ErrorCode::ImageUnsupportedFormat);
        std::fs::write(d.join("none.vmdk"), "# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\n").unwrap();
        assert_eq!(VmdkReader::open(&d.join("none.vmdk")).err().unwrap().code, ErrorCode::ImageContainerDamaged);
        std::fs::write(d.join("bad.vmdk"), "# Disk DescriptorFile\nRW abc FLAT \"x\"\n").unwrap();
        assert_eq!(VmdkReader::open(&d.join("bad.vmdk")).err().unwrap().code, ErrorCode::ImageContainerDamaged);
        // Neither header nor descriptor: read as a flat disk.
        std::fs::write(d.join("raw.vmdk"), [1u8; 1024]).unwrap();
        let mut r = VmdkReader::open(&d.join("raw.vmdk")).unwrap();
        assert_eq!(r.total_size(), 1024);
        assert!(read_all(&mut r).iter().all(|b| *b == 1));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn extent_lines() {
        let z = parse_extent_line("RW 2048 ZERO").unwrap();
        assert_eq!(z.extent_type, "ZERO");
        assert!(z.filename.is_empty());
        let f = parse_extent_line(r#"RW 41943040 FLAT "my disk-flat.vmdk" 128"#).unwrap();
        assert_eq!(f, ExtentLine { sectors: 41943040, extent_type: "FLAT".into(), filename: "my disk-flat.vmdk".into(), flat_offset: 128 });
        assert!(parse_extent_line("RW abc FLAT \"x\"").is_err());
        assert!(parse_extent_line("RW 1").is_err());
        assert!(parse_extent_line("RW 99999999999999999999 FLAT \"x\"").is_err());
        assert!(parse_extent_line("RW 36028797018963968 FLAT \"x\"").is_err(), "sectors that overflow bytes");
    }
}
