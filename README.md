# allymacb

```text
    _    _     _ __   __   __  __    _    ____ ____  
   / \  | |   | |\ \ / /  |  \/  |  / \  / ___| __ ) 
  / _ \ | |   | | \ V /   | |\/| | / _ \| |   |  _ \ 
 / ___ \| |___| |__| |    | |  | |/ ___ \ |___| |_) |
/_/   \_\_____|_____|_|    |_|  |_/_/   \_\____|____/ 
```

A filesystem timeline generator in Rust. It reads NTFS `$MFT` and `$UsnJrnl:$J`, TSK bodyfiles, ext2/3/4 volumes, disk images and triage archives, and writes one CSV timeline in `mactime` MACB format with UTC ISO 8601 timestamps. Each row says which evidence it came from and flags the timestamps and names that look tampered with. On request it also carves what the live filesystem no longer shows: old `$MFT` records and `$I30` entries, the ext4 journal, and the log lines and `utmp` records left in free space.

It started as a rewrite of [mftmactime](https://github.com/kero99/mftmactime) by **kero**, which is still the reference for the idea: give it an `$MFT`, get a timeline, carve the resident files on the way. The name is a pun on MACB and a nineties TV lawyer; the resemblance ends there, although both have been known to argue with timestamps.

## What it reads

| Input | How it is detected | Notes |
|---|---|---|
| `$MFT` | file name (`$MFT`, `_MFT`, `*$MFT`) or `FILE`/`BAAD` signature | 1 KiB and 4 KiB records. Follows `$ATTRIBUTE_LIST` into extension records. Resident files can be dumped with `-r`. |
| `$UsnJrnl:$J` | `-u`, or file name (`$UsnJrnl%3A$J`, `$UsnJrnl_$J`, `$J` under `$Extend`) | USN_RECORD V2 and V3. V4 range-tracking records are skipped and counted. |
| Bodyfile (TSK 3.x) | file name (`bodyfile`, `bodyfile.txt`, `*.body`) or content | Used by UAC and other Linux collectors. |
| E01 / EWF | `.e01`, `.ex01` | Through the `ewf` crate. |
| Raw images | `.dd`, `.raw`, `.img`, split `.001`, or boot sector / GPT / MBR signature | GPT, MBR with extended partitions, 512 and 4096-byte sectors. NTFS and ext4 partitions are timelined; others are skipped. |
| ext2 / ext3 / ext4 | partition inside an image, or a bare filesystem image | Read from the on-disk structures: inode numbers, ctime, deleted inodes, and with `--carve` the jbd2 journal. `ext4-view` as fallback. See limitations. |
| Archives | `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.gz` | Streamed. Every `$MFT`, `$J` and bodyfile inside is parsed, one level of nested archives included. Archives with none of those are extracted and timelined from their modification times only. |
| Directories | `-d` | KAPE, Velociraptor or UAC output, or a plain tree. Artifacts found inside are parsed; a tree with none is timelined from host metadata, with a warning. |
| Raw sectors | `--carve`, never by default | NTFS `FILE` records and `$I30` index entries anywhere in an image or in an unrecognised file (pagefile, VSS store, old `$MFT` copy, `blkls` output); the ext4 journal; log lines and `utmp` records in free space. See [Carving](#carving). |

VHDX, sparse VMDK, dynamic VHD, QCOW and VDI are recognised by signature and refused with a clear error. Convert them to raw first.

## Build

```bash
git clone https://github.com/jupyterj0nes/allymacb.git
cd allymacb
cargo build --release
```

The binary is at `target/release/allymacb`. No C libraries are needed.

## Usage

```text
Usage: allymacb [OPTIONS]

  -f, --file <FILES>...        $MFT, $J, bodyfile, image or archive. Repeatable.
  -d, --dir <DIRECTORIES>...   Triage folder or evidence directory. Repeatable.
  -u, --usn <USN>              Standalone $UsnJrnl:$J.
  -o, --output <OUTPUT>        CSV path. Without it the CSV goes to stdout.
  -m, --drive <DRIVE>          Drive letter for NTFS paths [default: C].
  -n, --file-name              Also emit $FILE_NAME (0x30) timestamps.
  -r, --resident <DIR>         Dump resident $DATA streams under this directory.
      --resident-report <FILE> Summary of the resident dump.
  -q, --quiet                  No banner, progress bars or informational lines. Warnings stay.
      --carve                  Also scan images and unrecognised files sector by sector for
                               NTFS records outside the live $MFT. Off by default.
  -h, --help / -V, --version
```

Examples:

```bash
# An $MFT and its USN journal, with $FILE_NAME timestamps for timestomping checks
allymacb -f C/$MFT -u 'C/$Extend/$UsnJrnl%3A$J' -n -o host01.csv

# A folder of UAC collections, parsed in memory
allymacb -d /evidence/uac -o linux.csv

# A disk image, dumping resident files
allymacb -f disk.E01 -r resident/ --resident-report resident.txt -o disk.csv

# Piping works: only the CSV goes to stdout
allymacb -f $MFT | grep '(deleted)' > deleted.csv

# Same image, plus whatever old $MFT records and $I30 entries are left in its sectors
allymacb -f disk.E01 --carve -o disk_carved.csv

# A pagefile or a VSS store on its own: nothing to parse, so carve it
allymacb -f pagefile.sys --carve -o pagefile_carved.csv
```

### stdout, stderr and exit codes

The CSV is the only thing written to stdout. The banner, progress bars, `[*]` status lines, `[!]` warnings and the final summary go to stderr.

| Exit code | Meaning |
|---|---|
| 0 | Every source was parsed. |
| 1 | Usage error. |
| 2 | Nothing could be parsed. No CSV is written. |
| 3 | CSV written, but at least one source failed or was missing. The failures are listed on stderr. |

Anything skipped is reported: unreadable images, corrupt archives, rejected bodyfile lines, archive entries that tried to escape the extraction directory, ext4 inodes that could not be decoded. A short timeline is never silent.

## Output

```csv
time_created,size,type,mode,uid,gid,meta,file_name,source,flags
1991-10-03T02:25:06Z,72834,m...,-rw-r--r--,0,0,8989,[uac_results_server01] /usr/share/fonts/putb.pfa,bodyfile,WARN: m_before_b
2024-02-04T12:35:00Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe,mft,
2024-02-04T12:35:00Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe ($FILE_NAME: cmd.exe),mft,
2024-02-03T09:12:41Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe (carved @0x1A2B3C00),carved,
2026-09-23T23:05:14Z,1261,.a..,drwxr-xr-x,0,0,1572998,[uac-server02] /boot/grub2/datetime.mod,ext4,
2026-09-24T18:42:22Z,4096,....,-/-rwxrwxrwx,0,0,45120,C:\Windows\Temp\payload.exe (USN: FILE_CREATE+CLOSE),usn,
2001-01-01T00:00:00Z,4096,macb,-/-rwxrwxrwx,0,0,45120,C:\Windows\Temp\payload.exe,mft,ALERT: si_before_fn+si_subsec_zero
```

* `time_created`: UTC ISO 8601 timestamp of the event the row represents. Sub-second digits are printed when present.
* `size`: file size in bytes.
* `type`: MACB flags of that timestamp (`macb`, `m...`, `.a..`, `..c.`, `...b`, combinations, or `....` for USN rows).
* `mode`: `ls -l` style permissions. NTFS has none, so NTFS rows use the `mactime` convention `-/-rwxrwxrwx` and `d/drwxrwxrwx`.
* `uid`, `gid`: Unix ids, `0` for NTFS.
* `meta`: inode or MFT record number.
* `file_name`: full path, with a `[host]` or `[archive]` prefix when it comes from a collection, and tags: `(deleted)`, `($FILE_NAME: name)`, `(USN: REASON+REASON)`, `($I30)`, `(carved @0xOFFSET)`.
* `source`: what the row was built from: `mft`, `usn`, `bodyfile`, `ext4`, `fs` (host filesystem metadata of a directory walk or an extracted archive) or `carved`.
* `flags`: anti-forensics indicators for the file the row belongs to, `ALERT: a+b` or `WARN: a`, empty on most rows. See [Anti-forensics indicators](#anti-forensics-indicators).

Every column is RFC 4180 escaped. `meta` and `file_name` come from the evidence, so a value starting with `=`, `+`, `-`, `@`, tab or CR is written quoted with a leading apostrophe. A file named `=cmd|' /C calc'!A0` does not execute when the CSV is opened in a spreadsheet.

### Per source

| Source | m | a | c | b | Notes |
|---|---|---|---|---|---|
| `$MFT`, `$STANDARD_INFORMATION` | yes | yes | yes | yes | `-n` adds `$FILE_NAME` rows. Size comes from the non-resident `$DATA` header, so files above the resident limit report their real size. ADS get their own rows with the same flags as the host record. Pre-1970 timestamps are kept; only FILETIME 0 is dropped. |
| `$UsnJrnl:$J` | | | | | Rows are `....` with the reason flags in the name. |
| Bodyfile | yes | yes | yes | yes | Split from the right, so a `\|` inside a path does not shift the columns. `0` means unset. Lines with non-numeric uid, gid or size are rejected and counted. |
| ext4 | yes | yes | yes | yes | Read from the on-disk structures: inode number in `meta`, `ctime`, timestamps past 2038, and the inodes still marked deleted in the tables as `(deleted)` rows. SUID, SGID, sticky and device types are rendered. ext2 and ext3 block maps are followed too. |
| Directory walk | yes | yes | Unix only | yes | Timestamps come from the host filesystem, and the tool says so. Real mode, uid, gid and inode on Unix hosts. |
| Archive without artifacts | yes | | | | A zip or tar only preserves modification times. |
| Carved `FILE` record | yes | yes | yes | yes | Same rows as a live record (`-n` applies), tagged `(carved @0xOFFSET)` with the absolute offset in the image or file. `source` is `carved`. |
| Carved `$I30` entry | yes | yes | yes | yes | The `$FILE_NAME` copy kept in the directory index, tagged `($I30)`. Size and timestamps are the index's own. |

Orphans: an NTFS parent reference carries the sequence number of the directory record it pointed to. When that record has since been freed and reused, the file is reported as `[ORPHAN]\name` instead of being attached to whatever directory lives there now. This is what SleuthKit does with `$OrphanFiles`. A parent chain that loops, which only a crafted `$MFT` produces, is reported as `[CYCLE]\name`.

## Anti-forensics indicators

Every row carries a `flags` column. It is empty unless the file's timestamps or name show one of the patterns below. The value starts with `ALERT:` when at least one indicator has no ordinary explanation (or when `si_before_fn` and `si_subsec_zero` appear together, the classic timestomp signature) and with `WARN:` when only the patterns that installers and preserved-timestamp copies also produce are present:

```csv
1975-06-15T12:00:00Z,100,...b,-/-rwxrwxrwx,0,0,58,V:\docs\ts1975.txt,mft,ALERT: pre_1980+si_before_fn
2001-08-23T18:00:00Z,8192,m..b,-/-rwxrwxrwx,0,0,7720,C:\WINDOWS\system32\dllcache\bckgres.dll,mft,WARN: si_before_fn
```

At the end of every run, quiet or not, stderr lists each `ALERT` file on its own line (up to 40, then a count) and sums up the `WARN` ones:

```text
[ALERT] 3 file(s) with anti-forensics indicators (timestomping, name tricks). flags column says ALERT:
[ALERT]   pre_1980+si_before_fn              V:\docs\ts1975.txt  (meta 58)
[ALERT]   future                             V:\docs\ts2050.txt  (meta 59)
[ALERT]   rtlo_name                          V:\docs\report‮fdp.exe  (meta 63)
[!] 324 file(s) with WARN-level indicators (b_after_c 220, si_before_fn 324, si_subsec_zero 236): also produced by preserved-timestamp copies and installers; filter the flags column for WARN
```

None of this is proof: it says where to look first.

| Flag | Meaning | Also produced by |
|---|---|---|
| `si_before_fn` | `$STANDARD_INFORMATION` creation time earlier than the `$FILE_NAME` one. NTFS writes both at the same instant; only `$SI` can be set from user mode, so it was changed afterwards. | Copies that preserve timestamps: robocopy, 7-Zip, installers, `cp -p` over SMB. On an installed OS image, most of `C:\Windows` shows it. |
| `si_subsec_zero` | `$SI` created and modified have no sub-second part while the `$FILE_NAME` copies do: written with a whole-second API (`SetFileTime` from PowerShell or Python, timestomp). | Files extracted from zip or cab (2-second resolution) when the extractor also sets the creation time. |
| `b_after_c` | `$SI` creation later than the `$SI` record-change time. The change time moves with every creation, so this creation was set by hand or into the future. | Installers that set all four times with `NtSetInformationFile`; old Windows setups. |
| `future` | A timestamp more than a day after the run. | Clock skew on the evidence host. |
| `pre_1980` | A non-zero timestamp before 1980, older than any filesystem that could have written it. | Nothing legitimate on NTFS. |
| `m_before_b` | Unix: modified before created (`touch -d` to the past). | `cp -p`, `tar`, package installs: the original modification time is kept and the inode is new. Expect it on most of `/usr`. |
| `m_after_c` | Unix: modified after the inode change time. `ctime` cannot be set from user mode and moves with every change, so an `mtime` beyond it was set by hand. | Clock changes between the two writes. |
| `usn_basic_info` | A `$UsnJrnl` record whose only reasons are `BASIC_INFO_CHANGE` and `CLOSE`: timestamps or attributes changed without touching the data. | Attribute changes (`attrib`, hidden/read-only bits), some backup agents. |
| `backdated` | `--carve` found an older state of this record with a later creation or modification time than the live one: the timestamps were moved back. Both the live rows and the carved rows of the record carry it. | Nothing legitimate: an older copy cannot be newer. |
| `rtlo_name` | Right-to-left override or other bidi control in the name (`report\u202Efdp.exe` displays as `reportexe.pdf`). | Nothing legitimate in a file name. |
| `invisible_name` | Zero-width or other invisible characters in the name. | Rare; some web downloads. |
| `double_ext` | A document extension followed by an executable one: `invoice.pdf.exe`, `photo.jpg.scr`. `.lnk` is not counted (`Readme.txt.lnk` is a normal shortcut). | Nothing common. |

The NTFS indicators compare `$SI` with every `$FILE_NAME` of the record, so a file with a long and an 8.3 name is checked against both. ext4 rows get `m_before_b`, `future` and `pre_1980` only, since `ext4-view` does not expose `ctime`. For the stronger NTFS check, put the `$MFT` and the `$UsnJrnl` of the same volume in one run and look at `usn_basic_info` rows next to `si_before_fn` files, or run `--carve` on the image and look for `backdated`.

## Carving

`--carve` is off by default and changes nothing about the normal timeline. When it is on, every disk image is read a second time from the first sector to the last, and every file that is not recognised as an artifact (a pagefile, a VSS store, an old `$MFT` copy, a dump of unallocated clusters) is scanned the same way. Two structures are looked for on sector boundaries:

* `FILE` records, the 1 KiB or 4 KiB entries of an `$MFT`. A candidate is accepted only if its header geometry is sane and its update sequence array checks out: the last two bytes of every sector must equal the update sequence number. Random data does not pass that.
* `INDX` blocks, the `$I30` index of a directory. Each entry carries a complete `$FILE_NAME` of a child, and the entries of deleted children stay in the slack of the block after the live chain ends. Slack entries get extra plausibility checks (entry length, namespace, name characters, timestamps from 1970 on).

What comes back is compared with the live `$MFT` of the volume it was found in:

* A record with the same number, sequence number, flags, `$STANDARD_INFORMATION` timestamps, name and size as a live record is dropped. The live `$MFT` on disk, `$MFTMirr` and intact VSS copies produce nothing.
* An earlier state of a live record (same record, different timestamps or size), a record whose number has since been reused, or a record from a volume that no longer exists is kept.
* An index entry whose file reference and name are still in the live `$MFT` is dropped. One whose record was reused, or that only exists in slack, is kept.
* Identical copies of the same state, as VSS and pagefiles produce, appear once, at the first offset they were seen.
* Within a state that is kept, a row that repeats a live row exactly (same timestamp, flags, size, record and name) is dropped, and so is a row already emitted by an earlier carved state. An older state of a directory usually shares its creation time with the live one; only the timestamps that differ get a line. The count of dropped rows is reported on stderr.

Paths are rebuilt through the live `$MFT` when the parent reference still matches, then through directory records found by the carver itself, otherwise `[ORPHAN]\name`. A carved blob with no live `$MFT` (a pagefile on its own) still gets full paths as long as the directory records are in it too.

Carved rows say `carved` in `source` and carry `(carved @0xOFFSET)` in `file_name`, so they are easy to keep or drop with a filter. A record found by carving is not the same kind of evidence as a record read from the live table, and the timeline should not blur that.

A carved record is read on its own: a non-resident `$DATA` or a long name that lives in an extension record of an `$ATTRIBUTE_LIST` is not reachable from it, so such files report the size and name the base record has (usually the `$FILE_NAME` size and the 8.3 name). The record number comes from the record header, which is 0 on records written by very old NTFS versions and on records never used.

### ext4: the journal

ext4 has no carvable record format, but it has a journal (jbd2) that keeps a copy of every metadata block as it was before each transaction: inode tables and directory blocks included. Modern kernels zero a directory entry when the file is removed, so the journal is the only place the name of a deleted file survives, and it also holds the previous size, timestamps and name of files that were modified, renamed or whose inode was reused. With `--carve`, every ext4 volume of the image gets its journal read:

* Inodes marked deleted in the live tables are named through the journal's directory copies instead of `/[UNKNOWN]/inode_N`.
* Older states of inodes that differ from the live one become `carved` rows, with the path as of that transaction, `(deleted)` when the state is a deleted one, and `(carved @0xOFFSET)` pointing at the copy inside the journal.
* An older state of the same file (same creation time) with a later modification time than the live one marks both with `backdated`.
* Rows identical to live rows are dropped, as with NTFS.

The journal is small and circular (4 MiB on the lab volume, 128 MiB to 1 GiB on real systems), so it reaches back hours or days, not months.

### Timestamped artifacts in free space

Deleted or rotated logs leave their lines in unallocated blocks, and every line carries its own time. With `--carve`, the free space of each volume (from the ext4 block bitmaps or the NTFS `$Bitmap`; the gaps between partitions too) is searched for:

| Tag | Format | Example |
|---|---|---|
| `[syslog]` | RFC 3339 line (`2026-10-28T20:38:02.123456+00:00 host prog[pid]: …`) or BSD syslog (`Oct 28 20:38:02 host prog[pid]: …`). The BSD form has no year: the current one is assumed, or the previous one if that would be in the future. | `auth.log`, `syslog`, `kern.log`, journald exports |
| `[log]` | `YYYY-MM-DD HH:MM:SS …` at the start of the line, and apt's `Start-Date:` / `End-Date:` | `dpkg.log`, `apt/history.log`, most application logs |
| `[weblog]` | A `[DD/Mon/YYYY:HH:MM:SS +ZZZZ]` field anywhere in the line | Apache and nginx access logs |
| `[bash_history]` | `#<epoch>` followed by the command | `.bash_history` with `HISTTIMEFORMAT` |
| `[utmp]` | 384-byte glibc `utmp` records: type, user, tty, host, pid, time | `wtmp`, `btmp`, `utmp` |

Rows have `....` as type, the line as `file_name` (cut at 400 characters) and the absolute offset. Identical records are reported once. The search is restricted to free space on purpose: on allocated blocks it would be log parsing, which is another tool's job. A blob with no filesystem (a `blkls` output, a pagefile) is searched in full. Compressed rotated logs (`.gz`) and journald's binary files are not decoded; `lastlog` is not a `utmp` layout and is skipped.

## How it was checked

Unit tests cover the parsers. On top of that, the output was compared with independent tools on public evidence. The scripts and the sample list are in `scripts/`.

```bash
python scripts/fetch_samples.py samples/          # public $MFT, $J, E01 and their fls / fsutil / fiwalk references
bash scripts/build_test_images.sh samples/wsl     # optional, Linux or WSL: ext4, GPT, MBR+EBR, 4Kn, split raw, hostile archives
powershell -File scripts/carve_lab.ps1            # optional, as Administrator on a disposable Windows VM: carving ground truth, copy the outputs to samples/lab/basic/
powershell -File scripts/carve_lab_cases.ps1      # optional, same place: more carving cases, copy C:\rf-carve\cases\* to samples/lab/
sudo bash scripts/linux_lab.sh                    # optional, as root on a disposable Linux VM: ext4 image, bodyfile and UAC-shaped archive, copy /tmp/rf-carve-linux/* to samples/lab_linux/
sudo bash scripts/linux_lab_logs.sh               # optional, same place: the host's logs deleted on an ext4 image, copy /tmp/rf-carve-logs/* to samples/lab_linux_logs/
python scripts/cross_examine.py --bin target/release/allymacb --samples samples/
```

| Evidence | Compared with | Result |
|---|---|---|
| NIST Hacking Case `$MFT` (12,171 entries) | SleuthKit `fls -l` listing from the [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs) corpus | Timestamps, paths and sizes identical for all 12,171 entries. Every `$OrphanFiles` entry in `fls` is an `[ORPHAN]` here. |
| dfir_ntfs `$MFT` samples (orphan, unicode, 4 KiB records, slack, mapping pairs, compressed, deleted) | `fls` listings and `mft_dump` from the [mft](https://github.com/omerbenamram/mft) crate | Identical where a reference exists. On `different_la.mft`, 13 deleted files are reported as orphans where `mft_dump` attaches them to a directory whose record was freed and reused. |
| `$UsnJrnl:$J` from dfir_ntfs (271 records) | `fsutil usn readjournal` dump shipped with it | All 261 named records match on name, timestamp and reason set. The 7 V4 records are skipped. 3 records written after the `fsutil` capture are present. |
| Digital Corpora `nps-2009-ntfs1` E01 images | `fiwalk` DFXML and the extracted `$MFT` of the same image | DFXML paths and MACB match for all 19 allocated files. The E01 timeline is identical to the one from the loose `$MFT`. |
| Raw NTFS volumes, including one with a fragmented `$MFT` | Row counts | Parsed without a partition table. |
| Partition tables with no filesystem | Expected outcome | Exit code 2 with `E6002`, no empty CSV. |
| ext4 images built with `mkfs.ext4 -d` | The files put in them | SUID binary, `0640` shadow, symlink, 40-level nesting, Latin-1 names and a `=cmd` name all found; `/etc/passwd` mtime exact to the second; inodes timestomped to 1969 and 2040 reported as unreadable. |
| GPT with three partitions, MBR with a logical ext4 in an extended partition, GPT with 4096-byte sectors, split raw `.001`-`.003` | Marker files per partition | Every partition found. |
| tar with `../` and absolute entries | The analyst's filesystem | Nothing written outside the extraction directory. The entry is refused and counted. |
| UAC-style tar.gz with a bodyfile (pipe in a path, a 1969 timestamp, one garbage line) and a nested tar.gz | Its contents | 10 rows, the path intact, the 1969 row present, one line rejected and reported. |
| KAPE-style zip with two `$MFT` and a `$J` | Sum of the parts | Both MFTs and all 264 USN records. |
| Garbage `.E01`, fake VHDX, missing file, one good and one bad source | Exit codes | 2, 2 with `E6003`, 2, and 3 with a complete CSV for the good source. |
| `--carve` on the raw NTFS volumes and the gen2 E01 above | Their own live `$MFT` | No live record reported as carved, no carved row duplicating a live one. The clean volumes yield nothing. The volume whose `$MFT` was fragmented by creating and deleting files yields 40 `$I30` slack entries of files that are not in the `$MFT` any more. The volume with a file of 100 hard links reports those names as `$I30` entries, because they sit in a non-resident `$ATTRIBUTE_LIST` the live parse cannot see (see limitations). |
| Every record of the NIST `$MFT` (12,304 `FILE` records) scattered at random sector offsets in 36 MiB of random bytes, plus a bare `FILE` signature and a record with broken fixups | The live parse of the same `$MFT` | 12,304 records found, the decoys rejected. Of 61,063 live rows, 60,818 come back identical, paths included, with the directory tree rebuilt from the carved records alone. The rest differ only in what an extension record would supply: 205 sizes, 28 long directory names. |
| A real NTFS volume built by `scripts/carve_lab.ps1` on a Windows Server 2019 lab host: 87 files, a shadow copy, then 5 files appended, 5 renamed, 48 deleted (a whole tree among them) and 20 new files that reused 19 of the freed MFT records; acquired once after that and once more after a quick reformat with TRIM off | The file list the script recorded before and after the changes, with sizes and MFT record numbers | Without `--carve`, the renamed files' old names and the 19 overwritten records are gone, and the deleted tree shows as orphans. With `--carve`, all 48 deleted paths come back with their directory, the 5 pre-change sizes and 5 old names are recovered, and the previous owner of every reused record is named, 19 of 19. On the reformatted volume the live timeline has 69 rows; carving brings back all 87 original files with full paths. No live record is reported as carved in either image. |
| Four more volumes from `scripts/carve_lab_cases.ps1` on the same host, each with a shadow copy before the changes: Unicode, long and formula-looking names, a hard link, an ADS, files timestomped to 1960, 1975 and 2050, a 25-level directory chain deleted whole, a file moved between directories, a deleted directory whose record was reused; a directory of 600 files with the first and last 100 deleted; 3,000 files in 50 directories with 25 directories deleted and 500 new files reusing 492 records; two NTFS partitions in one VHD with deletions on both | The file lists recorded before and after each change | Every deleted path recovered with its directory in all four (37, 200, 1,525 and 40), every reused record's previous owner named (10/10, 150/150, 492/492), the old path of the moved file and the 25-level chain rebuilt from carved directory records, the ADS and the 1960 timestamp carried through. On the two-partition image every carved path is resolved against its own volume, none mixed, none orphaned. No carved row repeats a live row in any of them. |
| A real ext4 volume built by `scripts/linux_lab.sh` on an Ubuntu 22.04 lab host: 126 entries including Unicode names, a 25-level chain, a symlink, a SUID binary, a sticky directory, four files timestomped with `touch`, a `.pdf.exe` and a right-to-left-override name; then deletions and a move. Read three ways: the image itself, the `stat`-built bodyfile, and a UAC-shaped `tar.gz` with that bodyfile and a copy of `/etc` | `stat` output recorded before the changes | Bodyfile and archive: 126/126 files with mtime, ctime, crtime and size exact, modes `-rwsr-xr-x`, `drwxrwxrwt` and `lrwxrwxrwx` rendered. ext4 image read raw: 78/78 surviving files with mtime, ctime, crtime, size and inode number exact, the 2050 one included. With `--carve`, the 45 deleted files all come back with their full path, 26 from inodes still in the tables named through the journal and the rest from journal copies, and the pre-deletion size and mtime are recovered for 45/45. The six manipulated files carry exactly the expected indicators (`pre_1980+m_before_b`, `future+m_after_c`, `m_after_c`, `m_before_b`, `double_ext`, `rtlo_name`) and no clean file carries any. |
| A 64 MiB ext4 volume built by `scripts/linux_lab_logs.sh` on the same host, holding two copies of its real `syslog`, `auth.log`, `kern.log`, `dpkg.log`, `apt/history.log`, `wtmp`, a 300-line access log, a 120-command bash history with timestamps and a 50-record `btmp`; one copy deleted so its blocks are free, one kept | The original files | `--carve` recovers 8,128 of 8,128 timestamped records from free space (syslog, auth, kernel, dpkg and apt lines, web requests, bash commands, `wtmp` and `btmp` records), each exactly once, with no record that matches nothing in the originals. |
| An 8 MiB ext4 volume with a journal, built the same way and shipped gzipped in `tests/data` | What was done to it | Run by `cargo test`: inode numbers and ctime on live rows; a deleted file named through the journal; the pre-growth size of an appended file; the old name of a renamed file; a deleted directory tree with its paths; `backdated` on a file whose mtime was moved to 1975 after the journal saw it in 2026. |

## Limitations

* ext4: the raw reader does not handle `meta_bg` layouts or inline-data directories; on those it falls back to `ext4-view`, which exposes neither ctime nor inode numbers and refuses timestamps before 1970 or after 2038. Names of deleted files come only from the journal, so a deletion older than the journal's history is reported as `/[UNKNOWN]/inode_N (deleted)`. Data blocks are not recovered: that is a job for PhotoRec.
* A non-resident `$ATTRIBUTE_LIST`, where the list itself lives outside the record, cannot be followed from a loose `$MFT`. Names stored that way are unknown to the live parse, so `--carve` reports their `$I30` entries as if the files were not in the `$MFT`.
* USN rows carry the file name from the record and the MFT entry number, not a full path. Joining them with the `$MFT` is left to the analyst.
* VHDX, VMDK, dynamic VHD, QCOW and VDI are not decoded.
* Carving of `FILE` and `$I30` structures reads the whole image, allocated space included; log lines and `utmp` records are taken from free space only. Nothing is recovered from what used to be a `$UsnJrnl` or an `$LogFile`, from compressed rotated logs or from journald's binary files. Compressed or encrypted containers (hiberfil, BitLocker) hide their contents from it like from everything else.
* `fsutil` prints local time without a zone; this tool prints UTC. Keep that in mind when comparing by hand.

## Error codes

| Code | Identifier | Meaning |
|---|---|---|
| E1001 | `ERR_IO_1001` | Filesystem I/O error |
| E1002 | `ERR_FILE_NOT_FOUND_1002` | Evidence file or path does not exist |
| E1003 | `ERR_PERMISSION_DENIED_1003` | Cannot read the evidence |
| E2001 | `ERR_MFT_INIT_2001` | Not an `$MFT`, or too damaged to parse |
| E2002 | `ERR_MFT_ENTRY_CORRUPT_2002` | Record corrupted or bad fixup array |
| E2003 | `ERR_MFT_ATTR_INVALID_2003` | Attribute record corrupted |
| E2004 | `ERR_MFT_RESIDENT_DUMP_2004` | Resident file could not be written |
| E3001 | `ERR_USN_TRUNCATED_3001` | USN stream ends inside a record |
| E3002 | `ERR_USN_INVALID_LENGTH_3002` | USN record length invalid |
| E3003 | `ERR_USN_UNSUPPORTED_VERSION_3003` | USN major version is not 2, 3 or 4 |
| E4001 | `ERR_EXT4_SUPERBLOCK_4001` | ext4 superblock missing or corrupt |
| E4002 | `ERR_EXT4_TRAVERSAL_4002` | Directory could not be read |
| E4003 | `ERR_EXT4_METADATA_4003` | Inode metadata could not be read |
| E5001 | `ERR_ARCHIVE_DECOMPRESS_5001` | Decompression failed |
| E5002 | `ERR_ARCHIVE_CORRUPT_5002` | Archive structure corrupted |
| E5003 | `ERR_ARCHIVE_UNSUPPORTED_5003` | Archive type not supported |
| E6001 | `ERR_IMAGE_READ_6001` | Image read or seek failure |
| E6002 | `ERR_IMAGE_PARTITION_6002` | No NTFS or ext4 filesystem found |
| E6003 | `ERR_IMAGE_UNSUPPORTED_6003` | VHDX, VMDK, dynamic VHD, QCOW or VDI container |
| E7001 | `ERR_BODYFILE_FIELDS_7001` | Bodyfile line does not have 11 fields |
| E7002 | `ERR_BODYFILE_TIMESTAMP_7002` | Non-numeric timestamp in a bodyfile line |
| E7003 | `ERR_BODYFILE_NUMERIC_7003` | uid, gid or size is not an unsigned integer |
| E8001 | `ERR_TIMESTAMP_RANGE_8001` | Timestamp outside the supported range |
| E8002 | `ERR_FILETIME_INVALID_8002` | FILETIME is zero, negative or before 1601 |
| E9001 | `ERR_CSV_EXPORT_9001` | CSV could not be created or flushed |
| E10001 | `ERR_EVIDENCE_UNRECOGNIZED_10001` | Input is not a recognised evidence type |
| E10002 | `ERR_EVIDENCE_NOTHING_PARSED_10002` | No source could be parsed |

## Tests

```bash
cargo test
```

566 tests: parsers, anti-forensics indicators, the raw ext4 reader on a real journaled volume, log and utmp carving, MACB flag combinations, timestamp boundaries, permission matrices, synthetic `$MFT` records (parent cycles, stale sequence numbers, non-resident sizes, ADS, path traversal, deleted/live collisions, damaged first records), carving (records at odd sector offsets, across the read block boundary, duplicates and older states, dedup against a live `$MFT`, `$I30` slack, decoys, the flag being opt-in), and end-to-end runs of the binary that check stdout stays pure CSV and exit codes reflect partial or total failure.

## Credits and license

* Author: Toño Díaz ([@jupyterj0nes](https://github.com/jupyterj0nes)).
* [mftmactime](https://github.com/kero99/mftmactime) by kero ([@kero99](https://github.com/kero99)) is the origin of this tool: the CLI, the resident-file dump and the whole approach. Thanks, kero.
* The NTFS parsing engine is Omer BenAmram's [mft](https://github.com/omerbenamram/mft) crate, the same one mftmactime used. The samples used for checking come from Maxim Suhanov's [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs), the NIST Hacking Case and [Digital Corpora](https://digitalcorpora.org).
* License: AGPL-3.0-only.
