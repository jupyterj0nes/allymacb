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
//! The scan runs only when the analyst asks for it (`--carve`). The block
//! scanner and the structure validators are the `blockcarve` crate shared
//! with masstin, faramir and caarea; what is kept, how it is compared with
//! the live `$MFT` and how it becomes a row is decided here.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

pub use blockcarve::ntfs::{file_record_size, parse_indx_block, split_ref, IndxEntry};
use blockcarve::ntfs::{file_record_number as header_record_number, FILE_MAGIC, FN_FLAG_DIRECTORY, INDX_MAGIC};
use blockcarve::scan::{scan_many, HitAction, ScanConfig, BLOCK_SIZE};
use blockcarve::source::DirectSource;
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
};
use crate::timefmt::format_unix_timestamp;
use crate::timeline::{source, TimelineEntry};

/// Largest structure we recognise; the scanner keeps this much from one block
/// to the next so a record straddling two reads is still seen whole.
const CARRY: usize = 64 * 1024;
/// Both structures start on a sector boundary.
const STEP: usize = 512;
/// Longest log line or `utmp` record that may straddle two blocks: the last
/// bytes of every block wait for the next one before text carving looks at them.
const TEXT_TAIL: usize = 8192;

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
    /// Last bytes of the previous block, scanned together with the next one.
    text_tail: Vec<u8>,
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
            text_tail: Vec::new(),
            now: anomaly::now_secs(),
        })
    }

    /// Looks for log lines and utmp records in the free parts of `block`,
    /// whose first byte sits at absolute offset `base`. The scanner offers
    /// every byte once, so the last [`TEXT_TAIL`] bytes are held back and
    /// scanned in front of the next block: a line or record cut by the block
    /// boundary is seen whole. `last` flushes what is held.
    fn scan_artifacts(&mut self, base: u64, block: &[u8], last: bool) {
        let joined;
        let (base, data): (u64, &[u8]) = if self.text_tail.is_empty() {
            (base, block)
        } else {
            let held = self.text_tail.len() as u64;
            let mut j = std::mem::take(&mut self.text_tail);
            j.extend_from_slice(block);
            joined = j;
            (base - held, &joined[..])
        };
        let accept_end = if last { data.len() } else { data.len().saturating_sub(TEXT_TAIL) };
        if !last {
            self.text_tail = data[accept_end..].to_vec();
        }
        if accept_end == 0 {
            return;
        }
        let filled = data.len();
        for (s, e) in self.free.ranges_in(base, base + accept_end as u64) {
            let lo = (s - base) as usize;
            let hi = (e - base) as usize;
            if hi <= lo {
                continue;
            }
            // A record that starts before `hi` may run on: extend to the end of the free
            // range or of the data, whichever comes first.
            let ext = self.free.ranges_in(e, base + filled as u64).first().filter(|r| r.0 == e).map_or(hi, |r| ((r.1 - base) as usize).min(filled));
            let slice = &data[lo..ext.max(hi)];
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
    let carver = RefCell::new(Carver::new(volumes, options)?);

    let size = if size == 0 {
        reader
            .seek(SeekFrom::End(0))
            .map_err(|e| AllyError::io_with_context(e, format!("Sizing {} for carving", label)))?
    } else {
        size
    };
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

    let mut src = DirectSource::new(reader, size, label.to_string());
    let cfg = ScanConfig { block_size: BLOCK_SIZE, window: CARRY, step: STEP };
    let signatures: [&[u8]; 2] = [FILE_MAGIC, INDX_MAGIC];

    // The scanner hands over every aligned `FILE` / `INDX` signature with at least
    // `CARRY` bytes behind it; what the validators accept is consumed in one go.
    let mut on_hit = |_src: &mut dyn blockcarve::BlockSource, abs: u64, window: &[u8], which: usize| -> HitAction {
        if which == 0 {
            match file_record_size(window) {
                Some(sz) => {
                    carver.borrow_mut().on_file_record(&window[..sz], abs);
                    HitAction::SkipTo(abs + sz as u64)
                }
                None => HitAction::Continue,
            }
        } else {
            match parse_indx_block(window) {
                Some((sz, entries)) => {
                    carver.borrow_mut().on_indx_block(entries, abs);
                    HitAction::SkipTo(abs + sz as u64)
                }
                None => HitAction::Continue,
            }
        }
    };
    // Log lines and utmp records: free space only, every byte offered once.
    let mut on_block = |base: u64, block: &[u8]| carver.borrow_mut().scan_artifacts(base, block, false);
    let mut on_progress = |offset: u64, _size: u64| {
        let mut c = carver.borrow_mut();
        c.stats.bytes_scanned = offset;
        pb.set_position(offset.min(size));
        pb.set_message(format!("{} records, {} index entries", c.stats.file_records_new, c.stats.indx_entries_new));
    };
    let stats = scan_many(&mut src, &cfg, &signatures, &mut on_hit, &mut on_progress, Some(&mut on_block));
    pb.finish_and_clear();

    let mut carver = carver.into_inner();
    carver.scan_artifacts(size, &[], true);
    carver.stats.read_errors = stats.read_errors + stats.stalls;
    if !options.quiet {
        for note in stats.notes.iter().take(5) {
            eprintln!("[!] {}", note);
        }
    }

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

    /// A blob with one valid `FILE` record and a syslog line in it: the record
    /// comes back carved and the line is found in the (unknown, so free) space,
    /// through the shared scanner.
    #[test]
    fn carves_a_record_and_a_log_line_from_a_blob() {
        let mut blob = vec![0u8; 3 * 4096];
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(b"FILE");
        r[4..6].copy_from_slice(&48u16.to_le_bytes());
        r[6..8].copy_from_slice(&3u16.to_le_bytes());
        r[20..22].copy_from_slice(&56u16.to_le_bytes());
        r[24..28].copy_from_slice(&100u32.to_le_bytes());
        r[28..32].copy_from_slice(&1024u32.to_le_bytes());
        r[48..50].copy_from_slice(&7u16.to_le_bytes());
        r[510..512].copy_from_slice(&7u16.to_le_bytes());
        r[1022..1024].copy_from_slice(&7u16.to_le_bytes());
        blob[4096..5120].copy_from_slice(&r);
        let line = b"\n2024-03-04T10:11:12.000000+00:00 host sshd[12]: Accepted publickey for root\n";
        blob[8192..8192 + line.len()].copy_from_slice(line);
        let mut reader = std::io::Cursor::new(blob);
        let options = MftParseOptions::default();
        let (rows, stats) = carve_stream(&mut reader, 0, &[], &options, "blob", &[]).unwrap();
        assert_eq!(stats.file_records, 1);
        assert_eq!(stats.text_lines, 1, "{rows:?}");
        assert!(rows.iter().any(|e| e.file_name.contains("Accepted publickey")));
    }
}
