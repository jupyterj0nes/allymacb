# allymacb

```text
    _    _     _ __   __   __  __    _    ____ ____  
   / \  | |   | |\ \ / /  |  \/  |  / \  / ___| __ ) 
  / _ \ | |   | | \ V /   | |\/| | / _ \| |   |  _ \ 
 / ___ \| |___| |__| |    | |  | |/ ___ \ |___| |_) |
/_/   \_\_____|_____|_|    |_|  |_/_/   \_\____|____/ 
```

A filesystem timeline generator in Rust. It reads NTFS `$MFT` and `$UsnJrnl:$J`, TSK bodyfiles, ext4 partitions, disk images and triage archives, and writes one CSV timeline in `mactime` MACB format with UTC ISO 8601 timestamps.

It started as a rewrite of [mftmactime](https://github.com/kero99/mftmactime) by **kero**, which is still the reference for the idea: give it an `$MFT`, get a timeline, carve the resident files on the way. The name is a pun on MACB and a nineties TV lawyer; the resemblance ends there, although both have been known to argue with timestamps.

## What it reads

| Input | How it is detected | Notes |
|---|---|---|
| `$MFT` | file name (`$MFT`, `_MFT`, `*$MFT`) or `FILE`/`BAAD` signature | 1 KiB and 4 KiB records. Follows `$ATTRIBUTE_LIST` into extension records. Resident files can be dumped with `-r`. |
| `$UsnJrnl:$J` | `-u`, or file name (`$UsnJrnl%3A$J`, `$UsnJrnl_$J`, `$J` under `$Extend`) | USN_RECORD V2 and V3. V4 range-tracking records are skipped and counted. |
| Bodyfile (TSK 3.x) | file name (`bodyfile`, `bodyfile.txt`, `*.body`) or content | Used by UAC and other Linux collectors. |
| E01 / EWF | `.e01`, `.ex01` | Through the `ewf` crate. |
| Raw images | `.dd`, `.raw`, `.img`, split `.001`, or boot sector / GPT / MBR signature | GPT, MBR with extended partitions, 512 and 4096-byte sectors. NTFS and ext4 partitions are timelined; others are skipped. |
| ext4 | partition inside an image, or a bare filesystem image | Through `ext4-view`. See limitations. |
| Archives | `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.gz` | Streamed. Every `$MFT`, `$J` and bodyfile inside is parsed, one level of nested archives included. Archives with none of those are extracted and timelined from their modification times only. |
| Directories | `-d` | KAPE, Velociraptor or UAC output, or a plain tree. Artifacts found inside are parsed; a tree with none is timelined from host metadata, with a warning. |

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
time_created,size,type,mode,uid,gid,meta,file_name
1991-10-03T02:25:06Z,72834,m...,-rw-r--r--,0,0,8989,[uac_results_server01] /usr/share/fonts/putb.pfa
2024-02-04T12:35:00Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe
2024-02-04T12:35:00Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe ($FILE_NAME: cmd.exe)
2026-09-23T23:05:14Z,1261,.a..,drwxr-xr-x,0,0,1572998,[uac-server02] /boot/grub2/datetime.mod
2026-09-24T18:42:22Z,4096,....,-/-rwxrwxrwx,0,0,45120,C:\Windows\Temp\payload.exe (USN: FILE_CREATE+CLOSE)
```

* `time_created`: UTC ISO 8601 timestamp of the event the row represents. Sub-second digits are printed when present.
* `size`: file size in bytes.
* `type`: MACB flags of that timestamp (`macb`, `m...`, `.a..`, `..c.`, `...b`, combinations, or `....` for USN rows).
* `mode`: `ls -l` style permissions. NTFS has none, so NTFS rows use the `mactime` convention `-/-rwxrwxrwx` and `d/drwxrwxrwx`.
* `uid`, `gid`: Unix ids, `0` for NTFS.
* `meta`: inode or MFT record number.
* `file_name`: full path, with a `[host]` or `[archive]` prefix when it comes from a collection, and tags: `(deleted)`, `($FILE_NAME: name)`, `(USN: REASON+REASON)`.

Every column is RFC 4180 escaped. `meta` and `file_name` come from the evidence, so a value starting with `=`, `+`, `-`, `@`, tab or CR is written quoted with a leading apostrophe. A file named `=cmd|' /C calc'!A0` does not execute when the CSV is opened in a spreadsheet.

### Per source

| Source | m | a | c | b | Notes |
|---|---|---|---|---|---|
| `$MFT`, `$STANDARD_INFORMATION` | yes | yes | yes | yes | `-n` adds `$FILE_NAME` rows. Size comes from the non-resident `$DATA` header, so files above the resident limit report their real size. ADS get their own rows with the same flags as the host record. Pre-1970 timestamps are kept; only FILETIME 0 is dropped. |
| `$UsnJrnl:$J` | | | | | Rows are `....` with the reason flags in the name. |
| Bodyfile | yes | yes | yes | yes | Split from the right, so a `\|` inside a path does not shift the columns. `0` means unset. Lines with non-numeric uid, gid or size are rejected and counted. |
| ext4 | yes | yes | no | yes | `ext4-view` exposes neither ctime nor the inode number, so there are no `c` rows and `meta` is `0`. SUID, SGID, sticky and device types are rendered. |
| Directory walk | yes | yes | Unix only | yes | Timestamps come from the host filesystem, and the tool says so. Real mode, uid, gid and inode on Unix hosts. |
| Archive without artifacts | yes | | | | A zip or tar only preserves modification times. |

Orphans: an NTFS parent reference carries the sequence number of the directory record it pointed to. When that record has since been freed and reused, the file is reported as `[ORPHAN]\name` instead of being attached to whatever directory lives there now. This is what SleuthKit does with `$OrphanFiles`. A parent chain that loops, which only a crafted `$MFT` produces, is reported as `[CYCLE]\name`.

## How it was checked

Unit tests cover the parsers. On top of that, the output was compared with independent tools on public evidence. The scripts and the sample list are in `scripts/`.

```bash
python scripts/fetch_samples.py samples/          # public $MFT, $J, E01 and their fls / fsutil / fiwalk references
bash scripts/build_test_images.sh samples/wsl     # optional, Linux or WSL: ext4, GPT, MBR+EBR, 4Kn, split raw, hostile archives
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

## Limitations

* ext4: no ctime, no inode numbers, and inodes with timestamps before 1970 or after 2038 cannot be decoded by `ext4-view`. They are counted and reported; their subtree is still walked.
* A non-resident `$ATTRIBUTE_LIST`, where the list itself lives outside the record, cannot be followed from a loose `$MFT`.
* USN rows carry the file name from the record and the MFT entry number, not a full path. Joining them with the `$MFT` is left to the analyst.
* VHDX, VMDK, dynamic VHD, QCOW and VDI are not decoded.
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

532 tests: parsers, MACB flag combinations, timestamp boundaries, permission matrices, synthetic `$MFT` records (parent cycles, stale sequence numbers, non-resident sizes, ADS, path traversal, deleted/live collisions, damaged first records), and end-to-end runs of the binary that check stdout stays pure CSV and exit codes reflect partial or total failure.

## Credits and license

* Author: Toño Díaz ([@jupyterj0nes](https://github.com/jupyterj0nes)).
* [mftmactime](https://github.com/kero99/mftmactime) by kero ([@kero99](https://github.com/kero99)) is the origin of this tool: the CLI, the resident-file dump and the whole approach. Thanks, kero.
* The NTFS parsing engine is Omer BenAmram's [mft](https://github.com/omerbenamram/mft) crate, the same one mftmactime used. The samples used for checking come from Maxim Suhanov's [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs), the NIST Hacking Case and [Digital Corpora](https://digitalcorpora.org).
* License: AGPL-3.0-only.
