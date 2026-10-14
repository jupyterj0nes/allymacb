# ⚖️ Ally MACB

```text
    _    _     _ __   __   __  __    _    ____ ____  
   / \  | |   | |\ \ / /  |  \/  |  / \  / ___| __ ) 
  / _ \ | |   | | \ V /   | |\/| | / _ \| |   |  _ \ 
 / ___ \| |___| |__| |    | |  | |/ ___ \ |___| |_) |
/_/   \_\_____|_____|_|    |_|  |_/_/   \_\____|____/ 
       ⚖️  Ally MACB — The DFIR Courtroom Attorney ⚖️
    "Objection! The timeline proves file timestomping."
```

[![Rust 1.94+](https://img.shields.io/badge/rust-1.94%2B-blue.svg)](https://www.rust-lang.org)
[![Tests Passing](https://img.shields.io/badge/tests-496%20passed-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-orange.svg)]()
[![Format](https://img.shields.io/badge/output-UTC%20ISO%208601-success.svg)]()
[![Pure Rust](https://img.shields.io/badge/dependencies-100%25%20Pure%20Rust-red.svg)]()

> *"In the court of incident response, evidence is only as strong as its timeline.  
> Just like Boston's fiercest trial attorney Ally McBeal, **Ally MACB** fights in the forensic trenches of Windows NTFS and Linux ext4 to build an ironclad case."*

---

## 👩‍⚖️ Who is Ally MACB?

`allymacb` is an ultra-fast, industrial-grade **Filesystem MACB Timeline Generator** written 100% in pure Rust.

It is a complete architectural overhaul and expansion of [`mftmactime`](https://github.com/kero99/mftmactime), engineered to handle multi-gigabyte corporate triage collections, disk images, and live evidence without external C-bindings or runtime dependencies.

### 🌟 Why She Wins Every Case:
* ⚖️ **Cross-Jurisdiction Forensic Scope**: Not exclusive to Windows NTFS (`$MFT` & `$UsnJrnl`); she also cross-examines Linux file systems (`ext4`/`ext3`/`ext2` and UAC triage collections).
* 🏎️ **In-Memory Streaming (Zero Disk Bloat)**: Tested in production on **42.7 Million events across 48 enterprise servers in minutes** without extracting tens of thousands of tiny files to disk.
* 🕒 **UTC ISO 8601 Standardized**: Identical timestamp layout to [`masstin`](https://github.com/jupyterjones/masstin) and `caarea` (`YYYY-MM-DDTHH:MM:SSZ` with nanosecond precision).
* 🔍 **Timestomping Detection**: Cross-examines `$STANDARD_INFORMATION` (0x10) against `$FILE_NAME` (0x30) to catch attackers who altered timestamps.
* 📦 **Resident Artifact Carving**: Extracts resident file payloads directly out of MFT records and reconstructs their folder tree on disk.
* 🛡️ **Forensic Reliability**: Equipped with **structured error codes** (`ERR_IO_1001` through `ERR_CSV_EXPORT_9001`) and backed by **496 automated unit, property, and integration tests**.

---

## 🆚 Comparison Table

| Capability | SleuthKit `mactime` | Original `mftmactime` | ⚖️ **Ally MACB** |
|---|---|---|---|
| **Language & Engine** | Perl / C | Python (`pytsk3`, `yara`) | **Pure Rust (Zero C-deps)** |
| **Windows NTFS ($MFT)** | ❌ (Needs bodyfile input) | ✅ (Omer's Mft parser) | ✅ **High-speed Parallel MFT** |
| **USN Journal ($UsnJrnl:$J)** | ❌ | ✅ (Python script) | ✅ **Built-in USN V2/V3 Engine** |
| **Linux Partitions (ext4/3/2)** | ✅ (via `fls`) | ❌ (Windows only) | ✅ **Native `ext4-view` Traversal** |
| **Triage Packages (UAC / KAPE)** | ❌ | ❌ | ✅ **Direct Stream & Bodyfile Parser** |
| **Disk Images (E01, RAW, DD)** | Partial (slow) | ✅ (via pytsk3) | ✅ **Native `ewf` + MBR/GPT Autodetect** |
| **Compressed Archives (.tar.gz, .zip)** | ❌ | ❌ | ✅ **Nested Streaming (No disk clutter)** |
| **Timestamps** | Local time string | Local / `%a %b %d` | **UTC ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`)** |
| **Resident File Extraction** | ❌ | ✅ | ✅ **With hierarchy & audit report** |
| **Error Codes** | Exit codes only | Python Tracebacks | **Standardized DFIR Codes (`E1xxx`-`E9xxx`)** |
| **Automated Test Coverage** | Minimal | None | **496 Automated Tests** |

---

## 🚀 Forensic Playbooks

### Playbook 1: Massive Linux Triage Investigation (UAC / Unix Collections)
Analyze dozens of Linux server triages simultaneously in parallel using all CPU cores:

```bash
# Process a single UAC collection or a folder with 50+ UACs
allymacb -d /evidence/renfe_incident/UAC -o /cases/incident_timeline.csv
```
> *Result:* Automatically scans inner `.tar.gz` containers, parses `bodyfile.txt` in memory, and produces a unified timeline labeled by server hostname (e.g. `[uac-webserver01] /etc/shadow`).

### Playbook 2: Windows Ransomware & Timestomping Hunt
Inspect an `$MFT` and its `$UsnJrnl` while catching attackers who manipulated `$STANDARD_INFORMATION`:

```bash
allymacb -f evidence/$MFT -u evidence/$UsnJrnl -n -o timeline_full.csv
```
> *Result:* Generates a combined MFT and USN Journal timeline. With `-n`, emits `$FILE_NAME` entries annotated with `($FILE_NAME: <name>)` to instantly highlight timestomped files.

### Playbook 3: Full Disk Image Ingestion & Resident Payload Extraction
Mountless processing of forensic disk images (`.E01`, `.dd`, `.vmdk`, `.raw`):

```bash
allymacb -f disk_image.E01 -o image_timeline.csv -r dumped_payloads --resident-report report.txt
```
> *Result:* Automatically detects MBR/GPT partition tables, discovers NTFS and ext4 partitions, extracts the timeline, and dumps all resident files under `dumped_payloads/`.

---

## 📋 CLI Reference

```text
Usage: allymacb.exe [OPTIONS]

Options:
  -f, --file [<FILES>...]         Input file(s): $MFT, disk images (.e01, .dd), archives (.zip, .tar.gz)
  -d, --dir [<DIRECTORIES>...]   Evidence directory or triage folder (KAPE, Velociraptor, UAC)
  -u, --usn <USN>                 Path to standalone USN Journal ($UsnJrnl:$J) file
  -o, --output <OUTPUT>           Output CSV timeline file (defaults to stdout)
  -m, --drive <DRIVE>             Drive letter prefix for Windows paths [default: C]
  -n, --file-name                 Include $FILE_NAME (0x30) timestamp entries (Timestomping analysis)
  -r, --resident <RESIDENT>       Directory to extract and dump recovered resident files
      --resident-report <REPORT>  Path to output resident file extraction summary report
  -q, --quiet                     Suppress progress bars and courtroom banner
  -h, --help                      Print help
  -V, --version                   Print version
```

---

## 📊 Output Format (The MACB Standard)

The output adheres to the DFIR timeline standard with ISO 8601 UTC timestamps:

```csv
Date,Size,Type,Mode,UID,GID,Meta,File Name
1991-10-03T02:25:06Z,72834,m...,-rw-r--r--,0,0,8989,[uac_results_server01] /usr/share/fonts/putb.pfa
2024-02-04T12:35:00Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe
2024-02-04T12:35:00Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe ($FILE_NAME: cmd.exe)
2026-09-23T23:05:14Z,1261,.a..,drwxr-xr-x,0,0,1572998,[uac-server02] /boot/grub2/datetime.mod
2026-09-24T18:42:22Z,4096,....,-/-rwxrwxrwx,0,0,45120,C:\Windows\Temp\payload.exe (USN: FILE_CREATE+CLOSE)
```

* **Date**: UTC ISO 8601 string (`%Y-%m-%dT%H:%M:%SZ`).
* **Size**: File size in bytes.
* **Type**: MACB status flags (`macb`, `m...`, `.a..`, `..c.`, `...b`, `ma..`, `m.c.`, `....`).
* **Mode**: Unix permission string (`drwxr-xr-x`, `-rw-r--r--`, `-/-rwxrwxrwx`).
* **UID / GID**: Native Unix IDs or 0 for Windows NTFS.
* **Meta**: Inode or MFT record number.
* **File Name**: Full path with container/host prefix and forensic tags (`(deleted)`, `(USN: ...)`, `($FILE_NAME: ...)`).

---

## 🚨 Forensic Error Codes Reference

Every potential error is assigned an immutable DFIR error code to maintain chain-of-custody documentation:

| Error Code | Identifier | Description |
|---|---|---|
| **E1001** | `ERR_IO_1001` | Generic Filesystem I/O error |
| **E1002** | `ERR_FILE_NOT_FOUND_1002` | Specified evidence file or path does not exist |
| **E1003** | `ERR_PERMISSION_DENIED_1003` | Insufficient privileges to read evidence file |
| **E2001** | `ERR_MFT_INIT_2001` | MFT Parser initialization failed (unrecognized header) |
| **E2002** | `ERR_MFT_ENTRY_CORRUPT_2002` | MFT Entry record corrupted or bad fixup array |
| **E2003** | `ERR_MFT_ATTR_INVALID_2003` | Attribute record size or data run corrupted |
| **E2004** | `ERR_MFT_RESIDENT_DUMP_2004` | Failed writing resident file to target directory |
| **E3001** | `ERR_USN_TRUNCATED_3001` | USN Journal stream truncated prematurely |
| **E3002** | `ERR_USN_INVALID_LENGTH_3002` | USN record length header is invalid or corrupt |
| **E3003** | `ERR_USN_UNSUPPORTED_VERSION_3003` | USN Record version is neither V2 nor V3 |
| **E4001** | `ERR_EXT4_SUPERBLOCK_4001` | Ext4 magic 0xEF53 missing or superblock corrupted |
| **E4002** | `ERR_EXT4_TRAVERSAL_4002` | Ext4 directory block corrupted during tree walk |
| **E4003** | `ERR_EXT4_METADATA_4003` | Failed reading inode metadata |
| **E5001** | `ERR_ARCHIVE_DECOMPRESS_5001` | Failed decompressing archive entry (CRC/stream error) |
| **E5002** | `ERR_ARCHIVE_CORRUPT_5002` | Tar or Zip archive header corrupted |
| **E6001** | `ERR_IMAGE_READ_6001` | Forensic disk image read/seek failure |
| **E6002** | `ERR_IMAGE_PARTITION_6002` | Corrupted MBR/GPT partition table |
| **E7001** | `ERR_BODYFILE_FIELDS_7001` | Bodyfile line has fewer than 11 pipe-separated fields |
| **E7002** | `ERR_BODYFILE_TIMESTAMP_7002` | Non-numeric or overflow timestamp in bodyfile |
| **E8001** | `ERR_TIMESTAMP_RANGE_8001` | Timestamp out of supported calendar range |
| **E8002** | `ERR_FILETIME_INVALID_8002` | Windows FILETIME ticks represent date prior to 1601 |
| **E9001** | `ERR_CSV_EXPORT_9001` | Failed creating or flushing CSV output file |

---

## 🧪 Comprehensive Test Suite (496 Tests)

Every parser, bitwise operator, timestamp boundary, and filesystem quirk is covered:

```bash
cargo test
```

```text
running 496 tests
test parsers::bodyfile::tests::test_parse_bodyfile_stream ... ok
test test_mft_parsing_real_sample ... ok
test test_timeline_writer_sorting_strict_chronological ... ok
test test_bodyfile_multi_line_stream ... ok
test test_nanosecond_precision_variations ... ok
test test_oct_707 ... ok
test test_usn_reason_single_bits ... ok
...
test result: ok. 496 passed; 0 failed; 0 ignored; finished in 3.45s
```

---

## 📦 Building from Source

```bash
git clone https://github.com/jupyterj0nes/allymacb.git
cd allymacb
cargo build --release
```

Binary will be available at `./target/release/allymacb`.

---

## ⚖️ License & Attribution

* **Authors**: Toño Díaz ([@jupyterj0nes](https://github.com/jupyterj0nes))
* **Inspiration**: Based on the concept of `mftmactime` by Miguel Quero & Javier Marín, and Omer BenAmram's `mft` parsing library.
* **License**: AGPL-3.0-only
