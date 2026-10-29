//! Sector-level carving of NTFS metadata.
//!
//! Scans a disk image (or any blob: a pagefile, a VSS store, an old `$MFT`
//! copy, a raw dump of unallocated clusters) for two structures that carry
//! MACB timestamps and are recognisable on their own:
//!
//! * `FILE` records: 1 KiB or 4 KiB `$MFT` entries. Validated by signature,
//!   header geometry and the update sequence array (every sector's last two
//!   bytes must equal the update sequence number), so random data is almost
//!   never accepted.
//! * `INDX` blocks: `$I30` directory index records. Each entry holds a full
//!   `$FILE_NAME` attribute of a child, including the entries left in the
//!   slack after a file was deleted.
//!
//! Everything found is compared with the live `$MFT` of the volume it sits
//! in. A record whose number, sequence and timestamps are already in the
//! live table is dropped; an older incarnation of a record, a record from a
//! volume that no longer exists, or an index entry of a deleted child is
//! kept and reported with `source = carved` and its absolute offset.
//!
//! The scan runs only when the analyst asks for it (`--carve`).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use indicatif::{ProgressBar, ProgressStyle};
use mft::attribute::x30::FileNameAttr;
use mft::entry::MftEntry;
use mft::{MftParser, StandardInfoAttr};

use super::carve_text;
use crate::anomaly;
use crate::error::{AllyError, Result};
use crate::parsers::mft::{
    best_name, extension_records, open_mft_parser, record_rows, scan_record, sequence_matches, MftParseOptions,
    PathResolver, RecordAttrs, Resolved, RowSpec, SkipReader, TimestampCollector, MAX_PATH_DEPTH, ROOT_RECORD,
    VALID_ENTRY_SIZES,
};
use crate::timefmt::format_unix_timestamp;
use crate::timeline::{source, TimelineEntry};

/// Bytes read per iteration.
const BLOCK_SIZE: usize = 4 * 1024 * 1024;
/// Largest structure we recognise; kept from one block to the next so a
/// record straddling two reads is still seen whole.
const CARRY: usize = 64 * 1024;
/// Both structures start on a sector boundary.
const STEP: usize = 512;
/// Give up on a stream after this many consecutive read errors.
const MAX_READ_ERRORS: usize = 16;
/// FILETIME of 1970-01-01: INDX slack entries with timestamps before this
/// (or after 2^63) are treated as garbage. FILE records need no such filter,
/// their fixups already prove the structure.
const FILETIME_1970: u64 = 116_444_736_000_000_000;
/// `$FILE_NAME` flag for directories.
const FN_FLAG_DIRECTORY: u32 = 0x1000_0000;

/// An NTFS volume inside the scanned stream, with the live `$MFT` dumped to
/// a file when it could be read.
#[derive(Debug, Clone)]
pub struct VolumeContext {
    /// Absolute byte range of the volume inside the stream.
    pub start: u64,
    pub end: u64,
    pub live_mft: Option<PathBuf>,
    /// Unallocated space of the volume as absolute `(start, len)` ranges,
    /// sorted. Log lines and `utmp` records are carved only there; when
    /// `free_known` is false the whole volume is searched.
    pub free_ranges: Vec<(u64, u64)>,
    pub free_known: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CarveStats {
    pub bytes_scanned: u64,
    /// Structurally valid `FILE` records seen (including live ones).
    pub file_records: usize,
    /// `FILE` records not present in the live `$MFT` (rows were emitted).
    pub file_records_new: usize,
    pub indx_blocks: usize,
    /// `$I30` entries parsed (live and slack).
    pub indx_entries: usize,
    /// `$I30` entries whose file is not in the live `$MFT`.
    pub indx_entries_new: usize,
    /// Rows dropped because an identical row (same timestamp, flags, size,
    /// record and name) was already in the live timeline or emitted by an
    /// earlier carved state.
    pub rows_duplicate: usize,
    pub read_errors: usize,
    /// Timestamped log lines carved from free space (syslog, dpkg/apt, web
    /// server, bash history), after dedupe.
    pub text_lines: usize,
    /// `utmp` records (wtmp/btmp/lastlog) carved from free space, after dedupe.
    pub utmp_records: usize,
    /// Bytes of free space searched for those.
    pub free_bytes_scanned: u64,
    /// Records whose carved older state has a later creation or modification
    /// time than the live record: their timestamps were moved backwards. The
    /// live rows of these records get the `backdated` flag too.
    pub backdated_records: Vec<u64>,
}

/// Row identity used to keep every fact once: the `(carved @…)` tag is not
/// part of it, so a carved row that says exactly what a live row says is noise.
type RowKey = (i64, u32, String, u64, String, String);

fn row_key(e: &TimelineEntry) -> RowKey {
    let name = match e.file_name.rfind(" (carved @0x") {
        Some(i) => &e.file_name[..i],
        None => e.file_name.as_str(),
    };
    (e.timestamp_secs, e.timestamp_nanos, e.macb.clone(), e.size, e.meta.clone(), name.to_string())
}

type Ts = (i64, i32);

fn ts(t: &mft::Timestamp) -> Ts {
    (t.as_second(), t.subsec_nanosecond())
}

/// Identity of one *state* of an `$MFT` record. Two copies of the same
/// record with the same timestamps are the same evidence.
#[derive(Hash, PartialEq, Eq)]
struct RecordKey {
    record: u64,
    seq: u16,
    allocated: bool,
    si: Option<[Ts; 4]>,
    name: Option<String>,
    size: u64,
}

/// Identity of a file as the live `$MFT` knows it.
#[derive(Hash, PartialEq, Eq)]
struct NameKey {
    record: u64,
    seq: u16,
    name: String,
}

/// One state of a `$I30` entry.
#[derive(Hash, PartialEq, Eq)]
struct IndxKey {
    record: u64,
    seq: u16,
    name: String,
    times: [Ts; 4],
    size: u64,
}

struct Dedupe {
    records: HashSet<RecordKey>,
    names: HashSet<NameKey>,
    indx: HashSet<IndxKey>,
    /// (header record number, sequence) -> live `$SI` (created, modified,
    /// mft_modified) in seconds, to spot carved states that are later than
    /// the live one.
    live_si: HashMap<(u64, u16), (i64, i64, i64)>,
}

/// Key of a record *as its own bytes describe it*: the record number stored
/// in the header (0 on old-format or never-used records) and the attributes
/// of the base record alone. A carved record has nothing else, so the live
/// table must be keyed the same way for the comparison to be fair.
fn record_key(entry: &MftEntry, attrs: &RecordAttrs) -> RecordKey {
    let si = attrs
        .std_info
        .as_ref()
        .map(|i| [ts(&i.created), ts(&i.modified), ts(&i.mft_modified), ts(&i.accessed)]);
    RecordKey {
        record: header_record_number(&entry.data),
        seq: entry.header.sequence,
        allocated: entry.is_allocated(),
        si,
        name: best_name(&attrs.fn_attrs).map(|f| f.name),
        size: attrs.data_size.unwrap_or(0),
    }
}

fn fn_times(f: &FileNameAttr) -> [Ts; 4] {
    [ts(&f.created), ts(&f.modified), ts(&f.mft_modified), ts(&f.accessed)]
}

/// A volume being carved: its range plus, when available, the live `$MFT`
/// used to drop known records and to resolve parent directories.
struct LiveVolume {
    start: u64,
    end: u64,
    parser: Option<MftParser<SkipReader<BufReader<File>>>>,
    resolver: PathResolver,
}

impl LiveVolume {
    fn open(ctx: &VolumeContext, dedupe: &mut Dedupe) -> Result<Self> {
        let (parser, resolver) = match &ctx.live_mft {
            Some(path) => {
                let file = File::open(path)
                    .map_err(|e| AllyError::io_with_context(e, format!("Opening live $MFT dump {}", path.display())))?;
                let (mut parser, skipped) = open_mft_parser(BufReader::new(file))?;
                let resolver = PathResolver::new(skipped);
                seed_dedupe(&mut parser, &resolver, skipped, dedupe);
                (Some(parser), resolver)
            }
            None => (None, PathResolver::new(0)),
        };
        Ok(Self { start: ctx.start, end: ctx.end, parser, resolver })
    }
}

/// Registers every record state and every file name of the live `$MFT`.
fn seed_dedupe<R: Read + Seek>(parser: &mut MftParser<R>, resolver: &PathResolver, skipped: u64, dedupe: &mut Dedupe) {
    let count = parser.get_entry_count();
    for idx in 0..count {
        let entry = match parser.get_entry(idx) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.header.base_reference.entry != 0 {
            continue; // extension record: covered through its base
        }
        let record = entry.header.record_number + skipped;
        let mut base = RecordAttrs::default();
        scan_record(&entry, entry.is_dir(), false, &mut base);
        if let Some(si) = &base.std_info {
            dedupe.live_si.insert(
                (header_record_number(&entry.data), entry.header.sequence),
                (si.created.as_second(), si.modified.as_second(), si.mft_modified.as_second()),
            );
        }
        dedupe.records.insert(record_key(&entry, &base));

        // File names may live in extension records ($ATTRIBUTE_LIST); the
        // index entries of those names must still be recognised as live.
        let mut names: Vec<String> = base.fn_attrs.iter().map(|f| f.name.clone()).collect();
        for ext_rec in extension_records(&entry, record) {
            if let Some(ext) = resolver.get_entry(parser, ext_rec) {
                if ext.header.base_reference.entry == record {
                    let mut extra = RecordAttrs::default();
                    scan_record(&ext, entry.is_dir(), false, &mut extra);
                    names.extend(extra.fn_attrs.into_iter().map(|f| f.name));
                }
            }
        }
        for name in names {
            dedupe.names.insert(NameKey { record, seq: entry.header.sequence, name });
        }
    }
}

/// A carved `FILE` record waiting for path resolution.
struct PendingRecord {
    offset: u64,
    volume: usize,
    record: u64,
    is_dir: bool,
    allocated: bool,
    std_info: Option<StandardInfoAttr>,
    fn_attrs: Vec<FileNameAttr>,
    data_size: Option<u64>,
    ads: Vec<(String, u64)>,
    /// Indicators known only from the comparison with the live record.
    extra: Vec<&'static str>,
}

/// A carved `$I30` entry waiting for path resolution.
struct PendingIndx {
    offset: u64,
    volume: usize,
    record: u64,
    is_dir: bool,
    fname: FileNameAttr,
}

/// A directory seen among the carved records, used to resolve parents that
/// the live `$MFT` no longer knows.
struct CarvedDir {
    seq: u16,
    allocated: bool,
    name: String,
    parent: u64,
    parent_seq: u16,
}

/// Returns the size of a valid `FILE` record at the start of `buf`.
pub fn file_record_size(buf: &[u8]) -> Option<usize> {
    if buf.len() < 48 || &buf[0..4] != b"FILE" {
        return None;
    }
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    let first_attr = u16::from_le_bytes([buf[20], buf[21]]) as usize;
    let used = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]) as usize;
    let total = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
    if !VALID_ENTRY_SIZES.contains(&total) {
        return None;
    }
    let size = total as usize;
    if buf.len() < size || usa_count != size / 512 + 1 {
        return None;
    }
    if usa_offset < 0x2A || usa_offset + usa_count * 2 > first_attr || first_attr + 8 > size || used > size || used < first_attr {
        return None;
    }
    let usn = &buf[usa_offset..usa_offset + 2];
    for i in 1..usa_count {
        if &buf[i * 512 - 2..i * 512] != usn {
            return None;
        }
    }
    Some(size)
}

/// Record number stored in the header (NTFS 3.1+), 0 when the header is the
/// older short form.
fn header_record_number(buf: &[u8]) -> u64 {
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]);
    if usa_offset >= 0x30 {
        u64::from(u32::from_le_bytes([buf[44], buf[45], buf[46], buf[47]]))
    } else {
        0
    }
}

/// One parsed `$I30` entry: (offset inside the block, file reference, raw
/// `$FILE_NAME` flags, attribute).
pub struct IndxEntry {
    pub offset: usize,
    pub file_ref: u64,
    pub flags: u32,
    pub fname: FileNameAttr,
}

/// Validates an `INDX` block at the start of `buf`, applies its fixups and
/// returns its size with every entry found in the live chain and in the
/// slack.
pub fn parse_indx_block(buf: &[u8]) -> Option<(usize, Vec<IndxEntry>)> {
    if buf.len() < 0x58 || &buf[0..4] != b"INDX" {
        return None;
    }
    let usa_offset = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    let usa_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    if !(3..=129).contains(&usa_count) {
        return None;
    }
    let size = (usa_count - 1) * 512;
    if buf.len() < size || usa_offset < 0x28 || usa_offset + usa_count * 2 > size {
        return None;
    }
    let entries_offset = u32::from_le_bytes(buf[24..28].try_into().ok()?) as usize;
    let index_size = u32::from_le_bytes(buf[28..32].try_into().ok()?) as usize;
    let alloc_size = u32::from_le_bytes(buf[32..36].try_into().ok()?) as usize;
    if entries_offset < 0x10 || 24 + alloc_size > size || index_size > alloc_size || entries_offset > index_size {
        return None;
    }
    if usa_offset + usa_count * 2 > 24 + entries_offset {
        return None;
    }

    let mut block = buf[..size].to_vec();
    let usn = [block[usa_offset], block[usa_offset + 1]];
    for i in 1..usa_count {
        let end = i * 512;
        if block[end - 2..end] != usn {
            return None;
        }
        let fix = usa_offset + i * 2;
        block[end - 2] = block[fix];
        block[end - 1] = block[fix + 1];
    }

    let mut out = Vec::new();
    let live_end = 24 + index_size;
    let block_end = 24 + alloc_size;

    // Live chain: sequential entries until the LAST flag.
    let mut pos = 24 + entries_offset;
    while pos + 16 <= live_end {
        let (len, flags) = entry_header(&block, pos);
        if flags & 0x02 != 0 || len < 16 || len % 8 != 0 || pos + len > live_end {
            break;
        }
        if let Some(e) = try_entry(&block, pos, false) {
            out.push(e);
        }
        pos += len;
    }

    // Slack: anything 8-byte aligned that still looks like an entry.
    let mut pos = (live_end + 7) & !7;
    while pos + 0x58 <= block_end {
        match try_entry(&block, pos, true) {
            Some(e) => {
                let (len, _) = entry_header(&block, pos);
                out.push(e);
                pos += len.max(8);
            }
            None => pos += 8,
        }
    }

    Some((size, out))
}

fn entry_header(block: &[u8], pos: usize) -> (usize, u32) {
    let len = u16::from_le_bytes([block[pos + 8], block[pos + 9]]) as usize;
    let flags = u32::from_le_bytes(block[pos + 12..pos + 16].try_into().unwrap_or([0; 4]));
    (len, flags)
}

/// Parses the index entry at `pos`. `strict` adds the plausibility checks
/// needed when the entry comes from slack instead of the live chain.
fn try_entry(block: &[u8], pos: usize, strict: bool) -> Option<IndxEntry> {
    if pos + 0x58 > block.len() {
        return None;
    }
    let file_ref = u64::from_le_bytes(block[pos..pos + 8].try_into().ok()?);
    let (len, flags) = entry_header(block, pos);
    let fn_len = u16::from_le_bytes([block[pos + 10], block[pos + 11]]) as usize;
    let fn_start = pos + 16;
    if fn_len < 0x44 || fn_start + fn_len > block.len() || len < 16 + fn_len {
        return None;
    }
    let name_len = block[fn_start + 0x40] as usize;
    let namespace = block[fn_start + 0x41];
    if name_len == 0 || namespace > 3 || fn_len != 0x42 + 2 * name_len {
        return None;
    }
    if strict {
        let expected = (16 + fn_len + 7) & !7;
        let expected = if flags & 0x01 != 0 { expected + 8 } else { expected };
        if len != expected || flags & !0x03 != 0 {
            return None;
        }
        for i in 0..4 {
            let t = u64::from_le_bytes(block[fn_start + 8 + i * 8..fn_start + 16 + i * 8].try_into().ok()?);
            if t >= 1 << 63 || (t != 0 && t < FILETIME_1970) {
                return None;
            }
        }
    }
    let fn_flags = u32::from_le_bytes(block[fn_start + 0x38..fn_start + 0x3C].try_into().ok()?);
    let fname = FileNameAttr::from_stream(&mut Cursor::new(&block[fn_start..fn_start + fn_len])).ok()?;
    if fname.name.chars().any(|c| c.is_control() || c == '\\' || c == '/') {
        return None;
    }
    Some(IndxEntry { offset: pos, file_ref, flags: fn_flags, fname })
}

fn split_ref(file_ref: u64) -> (u64, u16) {
    (file_ref & 0x0000_FFFF_FFFF_FFFF, (file_ref >> 48) as u16)
}

/// State of one carving run over a stream.
struct Carver<'a> {
    options: &'a MftParseOptions,
    volumes: Vec<LiveVolume>,
    /// Index into `volumes` for offsets outside every NTFS volume.
    outside: usize,
    dedupe: Dedupe,
    carved_dirs: HashMap<u64, Vec<CarvedDir>>,
    records: Vec<PendingRecord>,
    indx: Vec<PendingIndx>,
    stats: CarveStats,
    /// Where log lines and utmp records are looked for.
    free: FreeSpace,
    text_rows: Vec<TimelineEntry>,
    text_seen: HashSet<(i64, u32, &'static str, String)>,
    now: i64,
}

/// Which bytes of the stream count as free space for artifact carving.
struct FreeSpace {
    /// `(start, end)` of every volume whose allocation is known.
    volumes: Vec<(u64, u64)>,
    /// Free `(start, end)` ranges inside those volumes, sorted by start.
    free: Vec<(u64, u64)>,
}

impl FreeSpace {
    fn from_contexts(contexts: &[VolumeContext]) -> Self {
        let mut volumes = Vec::new();
        let mut free = Vec::new();
        for c in contexts {
            if c.free_known {
                volumes.push((c.start, c.end));
                free.extend(c.free_ranges.iter().map(|&(s, l)| (s, s + l)));
            }
        }
        free.sort_unstable();
        Self { volumes, free }
    }

    /// Sub-ranges of `[a, b)` to search: everything outside the known
    /// volumes, plus the free ranges inside them.
    fn ranges_in(&self, a: u64, b: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        // Outside any volume with known allocation.
        let mut cur = a;
        let mut vols: Vec<(u64, u64)> = self.volumes.iter().copied().filter(|&(s, e)| e > a && s < b).collect();
        vols.sort_unstable();
        for (s, e) in vols {
            if s > cur {
                out.push((cur, s.min(b)));
            }
            cur = cur.max(e);
        }
        if cur < b {
            out.push((cur, b));
        }
        // Free ranges inside volumes.
        let start = self.free.partition_point(|&(_, e)| e <= a);
        for &(s, e) in &self.free[start..] {
            if s >= b {
                break;
            }
            out.push((s.max(a), e.min(b)));
        }
        out.sort_unstable();
        out
    }
}

impl<'a> Carver<'a> {
    fn new(contexts: &[VolumeContext], options: &'a MftParseOptions) -> Result<Self> {
        let mut dedupe = Dedupe { records: HashSet::new(), names: HashSet::new(), indx: HashSet::new(), live_si: HashMap::new() };
        let mut volumes = Vec::with_capacity(contexts.len() + 1);
        for ctx in contexts {
            volumes.push(LiveVolume::open(ctx, &mut dedupe)?);
        }
        volumes.push(LiveVolume { start: u64::MAX, end: u64::MAX, parser: None, resolver: PathResolver::new(0) });
        let outside = volumes.len() - 1;
        Ok(Self {
            options,
            volumes,
            outside,
            dedupe,
            carved_dirs: HashMap::new(),
            records: Vec::new(),
            indx: Vec::new(),
            stats: CarveStats::default(),
            free: FreeSpace::from_contexts(contexts),
            text_rows: Vec::new(),
            text_seen: HashSet::new(),
            now: anomaly::now_secs(),
        })
    }

    /// Looks for log lines and utmp records in the free parts of
    /// `buf[from..len]`, whose first byte sits at absolute offset `base`.
    /// A record may run past `len` into the carried-over tail (`buf[..filled]`),
    /// so the slices extend to `filled`, but only records that *start* before
    /// `len` are taken; the rest are seen on the next pass.
    fn scan_artifacts(&mut self, buf: &[u8], len: usize, filled: usize, base: u64, from: usize) {
        if len <= from {
            return;
        }
        for (s, e) in self.free.ranges_in(base + from as u64, base + len as u64) {
            let lo = (s - base) as usize;
            let hi = (e - base) as usize;
            if hi <= lo {
                continue;
            }
            // Extend to the end of the free range or of the buffer, whichever first.
            let ext = self.free.ranges_in(e, base + filled as u64).first().filter(|r| r.0 == e).map_or(hi, |r| ((r.1 - base) as usize).min(filled));
            let slice = &buf[lo..ext.max(hi)];
            self.stats.free_bytes_scanned += (hi - lo) as u64;
            let mut hits = carve_text::scan_text(slice, self.now);
            hits.extend(carve_text::scan_utmp(slice, self.now));
            for h in hits {
                if lo + h.offset >= hi {
                    continue; // starts in the tail: next pass
                }
                if !self.text_seen.insert((h.secs, h.nanos, h.kind, h.text.clone())) {
                    continue;
                }
                if let Some(row) = carve_text::row_for(&h, s + h.offset as u64) {
                    if h.kind == "utmp" {
                        self.stats.utmp_records += 1;
                    } else {
                        self.stats.text_lines += 1;
                    }
                    self.text_rows.push(row);
                }
            }
        }
    }

    fn volume_for(&self, offset: u64) -> usize {
        self.volumes
            .iter()
            .position(|v| offset >= v.start && offset < v.end)
            .unwrap_or(self.outside)
    }

    /// Handles a structurally valid `FILE` record found at `offset`.
    fn on_file_record(&mut self, raw: &[u8], offset: u64) {
        self.stats.file_records += 1;
        let record = header_record_number(raw);
        let parsed = catch_unwind(AssertUnwindSafe(|| {
            let entry = MftEntry::from_buffer(raw.to_vec(), record).ok()?;
            if entry.header.base_reference.entry != 0 {
                return None; // extension record: no timestamps of its own
            }
            let mut attrs = RecordAttrs::default();
            scan_record(&entry, entry.is_dir(), false, &mut attrs);
            Some((entry, attrs))
        }));
        let (entry, attrs) = match parsed {
            Ok(Some(x)) => x,
            _ => return,
        };
        if attrs.std_info.is_none() && attrs.fn_attrs.is_empty() {
            return;
        }
        if !self.dedupe.records.insert(record_key(&entry, &attrs)) {
            return;
        }
        self.stats.file_records_new += 1;
        let volume = self.volume_for(offset);

        // An older state (its record change time is not past the live one)
        // whose creation or modification time is later than what the live
        // record says now: the live timestamps were moved backwards.
        let mut extra = Vec::new();
        if let (Some(si), Some(&(lb, lm, lc))) = (&attrs.std_info, self.dedupe.live_si.get(&(record, entry.header.sequence))) {
            let (cb, cm, cc) = (si.created.as_second(), si.modified.as_second(), si.mft_modified.as_second());
            if cc <= lc && (cb > lb + 1 || cm > lm + 1) {
                extra.push(anomaly::BACKDATED);
                if !self.stats.backdated_records.contains(&record) {
                    self.stats.backdated_records.push(record);
                }
            }
        }
        if entry.is_dir() {
            if let Some(best) = best_name(&attrs.fn_attrs) {
                self.carved_dirs.entry(record).or_default().push(CarvedDir {
                    seq: entry.header.sequence,
                    allocated: entry.is_allocated(),
                    name: best.name,
                    parent: best.parent.entry,
                    parent_seq: best.parent.sequence,
                });
            }
        }
        self.records.push(PendingRecord {
            offset,
            volume,
            record,
            is_dir: entry.is_dir(),
            allocated: entry.is_allocated(),
            std_info: attrs.std_info,
            fn_attrs: attrs.fn_attrs,
            data_size: attrs.data_size,
            ads: attrs.ads_streams,
            extra,
        });
    }

    /// Handles a valid `INDX` block found at `offset`.
    fn on_indx_block(&mut self, entries: Vec<IndxEntry>, offset: u64) {
        self.stats.indx_blocks += 1;
        let volume = self.volume_for(offset);
        for e in entries {
            self.stats.indx_entries += 1;
            let (record, seq) = split_ref(e.file_ref);
            if self.dedupe.names.contains(&NameKey { record, seq, name: e.fname.name.clone() }) {
                continue; // the live $MFT still has this file: its rows cover it
            }
            let key = IndxKey { record, seq, name: e.fname.name.clone(), times: fn_times(&e.fname), size: e.fname.logical_size };
            if !self.dedupe.indx.insert(key) {
                continue;
            }
            self.stats.indx_entries_new += 1;
            self.indx.push(PendingIndx {
                offset: offset + e.offset as u64,
                volume,
                record,
                is_dir: e.flags & FN_FLAG_DIRECTORY != 0,
                fname: e.fname,
            });
        }
    }

    /// Directory path (relative to the volume root) of record `rec` whose
    /// expected sequence is `seq`: the live `$MFT` first, then directories
    /// seen among the carved records, otherwise `[ORPHAN]`.
    fn dir_path(&mut self, volume: usize, rec: u64, seq: u16, visiting: &mut Vec<u64>) -> String {
        if rec == ROOT_RECORD {
            return String::new();
        }
        if visiting.contains(&rec) || visiting.len() >= MAX_PATH_DEPTH {
            return "[CYCLE]".to_string();
        }
        let vol = &mut self.volumes[volume];
        if let Some(parser) = vol.parser.as_mut() {
            if let Resolved::Dir(d) = vol.resolver.resolve_dir(parser, rec, seq) {
                return d;
            }
        }
        let found = self.carved_dirs.get(&rec).and_then(|dirs| {
            dirs.iter()
                .find(|d| sequence_matches(seq, d.seq, d.allocated))
                .map(|d| (d.name.clone(), d.parent, d.parent_seq))
        });
        match found {
            Some((name, parent, parent_seq)) => {
                visiting.push(rec);
                let parent_path = self.dir_path(volume, parent, parent_seq, visiting);
                visiting.pop();
                if parent_path.is_empty() {
                    name
                } else {
                    format!("{}\\{}", parent_path, name)
                }
            }
            None => "[ORPHAN]".to_string(),
        }
    }

    fn full_path(&mut self, volume: usize, parent: u64, parent_seq: u16, name: &str) -> String {
        let drive = self.options.drive_letter.unwrap_or('C');
        let dir = self.dir_path(volume, parent, parent_seq, &mut Vec::new());
        if dir.is_empty() {
            format!("{}:\\{}", drive, name)
        } else {
            format!("{}:\\{}\\{}", drive, dir, name)
        }
    }

    /// Resolves every pending item and turns it into timeline rows. Rows that
    /// repeat a row of `live` (or of an earlier carved state) are dropped: an
    /// older state of a record usually shares some timestamps with the live
    /// one, and only what differs is worth a line.
    fn finish(mut self, live: &[TimelineEntry]) -> (Vec<TimelineEntry>, CarveStats) {
        let mut rows = Vec::new();
        let drive = self.options.drive_letter.unwrap_or('C');
        let include_fn = self.options.include_file_name_timestamps;
        let mut seen: HashSet<RowKey> = live.iter().map(row_key).collect();
        let mut out = Vec::new();

        let records = std::mem::take(&mut self.records);
        for r in records {
            let path = match best_name(&r.fn_attrs) {
                Some(_) if r.record == ROOT_RECORD => format!("{}:\\", drive),
                Some(best) => self.full_path(r.volume, best.parent.entry, best.parent.sequence, &best.name),
                None => format!("{}:\\[UNKNOWN]\\entry_{}", drive, r.record),
            };
            let suffix = format!(" (carved @0x{:X})", r.offset);
            let spec = RowSpec {
                entry_id: r.record,
                is_dir: r.is_dir,
                is_allocated: r.allocated,
                resolved_path: &path,
                suffix: &suffix,
                source: source::CARVED,
                include_file_name: include_fn,
                extra_flags: &r.extra,
            };
            record_rows(&spec, r.std_info.as_ref(), &r.fn_attrs, r.data_size, &r.ads, &mut rows);
        }

        let indx = std::mem::take(&mut self.indx);
        for i in indx {
            let path = self.full_path(i.volume, i.fname.parent.entry, i.fname.parent.sequence, &i.fname.name);
            let name = format!("{} ($I30) (carved @0x{:X})", path, i.offset);
            let mode = if i.is_dir { "d/drwxrwxrwx" } else { "-/-rwxrwxrwx" };
            let flags = anomaly::column(&anomaly::name_flags(&i.fname.name));
            let mut collector = TimestampCollector::new();
            collector.add(&i.fname.modified, 'm');
            collector.add(&i.fname.accessed, 'a');
            collector.add(&i.fname.mft_modified, 'c');
            collector.add(&i.fname.created, 'b');
            for ((secs, nanos), macb) in collector.entries {
                if let Some(ts_iso) = format_unix_timestamp(secs, nanos) {
                    rows.push(
                        TimelineEntry::new(
                            ts_iso,
                            secs,
                            nanos,
                            i.fname.logical_size,
                            macb,
                            mode.to_string(),
                            0,
                            0,
                            i.record.to_string(),
                            name.clone(),
                        )
                        .with_source(source::CARVED)
                        .with_flags(flags.clone()),
                    );
                }
            }
        }

        for row in rows {
            if seen.insert(row_key(&row)) {
                out.push(row);
            } else {
                self.stats.rows_duplicate += 1;
            }
        }
        out.append(&mut self.text_rows);
        (out, self.stats)
    }
}

/// Scans `reader` from start to end for `FILE` records and `INDX` blocks.
///
/// `size` is the stream length (0 when unknown). `volumes` describes the
/// NTFS volumes inside the stream; records outside them are still carved
/// but their parents can only be resolved through other carved records.
/// `live` is the timeline already built from the stream: carved rows that
/// repeat one of its rows are not emitted again.
pub fn carve_stream<R: Read + Seek>(
    reader: &mut R,
    size: u64,
    volumes: &[VolumeContext],
    options: &MftParseOptions,
    label: &str,
    live: &[TimelineEntry],
) -> Result<(Vec<TimelineEntry>, CarveStats)> {
    let mut carver = Carver::new(volumes, options)?;

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| AllyError::io_with_context(e, format!("Rewinding {} for carving", label)))?;

    let pb = if options.quiet || size == 0 {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.magenta/blue}] {bytes}/{total_bytes} carving ({eta}) {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-"),
        );
        pb
    };

    let mut buf = vec![0u8; BLOCK_SIZE + CARRY];
    let mut carry = 0usize;
    let mut block_start: u64 = 0; // absolute offset of buf[0]
    let mut resume = 0usize; // first position of buf still to scan
    let mut consecutive_errors = 0usize;

    loop {
        // Fill the block after the carried-over tail.
        let mut filled = carry;
        let mut eof = false;
        while filled < carry + BLOCK_SIZE {
            match reader.read(&mut buf[filled..carry + BLOCK_SIZE]) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => {
                    filled += n;
                    consecutive_errors = 0;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    carver.stats.read_errors += 1;
                    consecutive_errors += 1;
                    let at = block_start + filled as u64;
                    if carver.stats.read_errors <= 5 {
                        eprintln!("[!] {}: read error at 0x{:X} while carving: {}; skipping {} bytes", label, at, e, BLOCK_SIZE);
                    }
                    if consecutive_errors > MAX_READ_ERRORS {
                        eprintln!("[!] {}: too many consecutive read errors, carving stopped at 0x{:X}", label, at);
                        eof = true;
                        break;
                    }
                    // Skip the unreadable region and drop everything buffered.
                    let next = at + BLOCK_SIZE as u64;
                    if reader.seek(SeekFrom::Start(next)).is_err() {
                        eof = true;
                        break;
                    }
                    block_start = next;
                    carry = 0;
                    filled = 0;
                    resume = 0;
                }
            }
        }
        if filled == 0 {
            break;
        }

        let scan_end = if eof { filled } else { filled - CARRY };
        // Log lines and utmp records: free space only. A line that starts
        // before scan_end is whole in the buffer (lines are far shorter than
        // the carry-over); the rest is seen on the next pass.
        carver.scan_artifacts(&buf, scan_end, filled, block_start, resume);
        let mut pos = resume;
        while pos < scan_end {
            let avail = &buf[pos..filled];
            if avail.len() >= 4 {
                match &avail[0..4] {
                    b"FILE" => {
                        if let Some(sz) = file_record_size(avail) {
                            let abs = block_start + pos as u64;
                            carver.on_file_record(&avail[..sz], abs);
                            pos += sz;
                            continue;
                        }
                    }
                    b"INDX" => {
                        if let Some((sz, entries)) = parse_indx_block(avail) {
                            let abs = block_start + pos as u64;
                            carver.on_indx_block(entries, abs);
                            pos += sz;
                            continue;
                        }
                    }
                    _ => {}
                }
            }
            pos += STEP;
        }

        carver.stats.bytes_scanned = block_start + scan_end as u64;
        pb.set_position(carver.stats.bytes_scanned.min(size));
        pb.set_message(format!(
            "{} records, {} index entries",
            carver.stats.file_records_new, carver.stats.indx_entries_new
        ));

        if eof {
            break;
        }
        // Keep the tail so a structure that starts near the end is seen whole
        // on the next pass; resume after anything already consumed.
        buf.copy_within(scan_end..filled, 0);
        carry = filled - scan_end;
        resume = pos.saturating_sub(scan_end);
        block_start += scan_end as u64;
    }
    pb.finish_and_clear();

    Ok(carver.finish(live))
}

/// Carves a standalone file (a pagefile, a VSS store, an old `$MFT` copy, a
/// dump of unallocated clusters). Parents are resolved only through other
/// carved directory records.
pub fn carve_blob(path: &Path, options: &MftParseOptions) -> Result<(Vec<TimelineEntry>, CarveStats)> {
    let file = File::open(path).map_err(|e| AllyError::io_with_context(e, format!("Opening {} for carving", path.display())))?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::with_capacity(BLOCK_SIZE, file);
    carve_stream(&mut reader, size, &[], options, &path.display().to_string(), &[])
}

/// One-line summary for stderr.
pub fn describe_stats(s: &CarveStats) -> String {
    format!(
        "{} FILE record(s) seen, {} not in the live $MFT; {} INDX block(s), {} entries, {} not in the live $MFT{}",
        s.file_records,
        s.file_records_new,
        s.indx_blocks,
        s.indx_entries,
        s.indx_entries_new,
        [
            Some(format!(
                "; free space: {} MiB searched, {} log line(s), {} utmp record(s)",
                s.free_bytes_scanned >> 20,
                s.text_lines,
                s.utmp_records
            )),
            (s.rows_duplicate > 0).then(|| format!("; {} row(s) identical to live rows dropped", s.rows_duplicate)),
            (!s.backdated_records.is_empty()).then(|| format!("; {} record(s) BACKDATED (older state has later timestamps)", s.backdated_records.len())),
            (s.read_errors > 0).then(|| format!("; {} read error(s)", s.read_errors)),
        ]
        .into_iter()
        .flatten()
        .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_record_size_rejects_garbage_and_bad_fixups() {
        assert_eq!(file_record_size(b"FILE"), None);
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&48u16.to_le_bytes());
        r[6..8].copy_from_slice(&3u16.to_le_bytes());
        r[20..22].copy_from_slice(&56u16.to_le_bytes());
        r[24..28].copy_from_slice(&100u32.to_le_bytes());
        r[28..32].copy_from_slice(&1024u32.to_le_bytes());
        r[48..50].copy_from_slice(&7u16.to_le_bytes());
        // fixup bytes not yet in place
        assert_eq!(file_record_size(&r), None);
        r[510..512].copy_from_slice(&7u16.to_le_bytes());
        r[1022..1024].copy_from_slice(&7u16.to_le_bytes());
        assert_eq!(file_record_size(&r), Some(1024));
        // wrong usa count for a 1 KiB record
        r[6..8].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(file_record_size(&r), None);
    }

    #[test]
    fn split_ref_separates_entry_and_sequence() {
        assert_eq!(split_ref(0x0005_0000_0000_002A), (42, 5));
    }

    #[test]
    fn indx_rejects_non_block() {
        assert!(parse_indx_block(&[0u8; 4096]).is_none());
        let mut b = vec![0u8; 4096];
        b[0..4].copy_from_slice(b"INDX");
        assert!(parse_indx_block(&b).is_none());
    }
}
