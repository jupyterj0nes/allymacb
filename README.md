# allymacb ⚡

**Pure Rust MFT, USN, and Linux Filesystem MACB Timeline Generator**

`allymacb` is a high-performance, multi-format DFIR timeline generator written 100% in Rust. It rewrites and expands upon [`mftmactime`](https://github.com/kero99/mftmactime), introducing multi-source ingestion, native Linux filesystem parsing, and UTC ISO 8601 timestamps aligned with [`masstin`](https://github.com/jupyterjones/masstin) and `caarea`.

---

## 🚀 Key Features

1. **Pure Rust Architecture**:
   - Zero Python or external C dependencies (`pytsk3`, `yara-python` replaced by pure Rust crates).
   - Fast, memory-safe, and portable single binary.

2. **Multi-Source Evidence Ingestion (inspired by `masstin` & `caarea`)**:
   - **Forensic Disk Images**: `.dd`, `.raw`, `.img`, `.001`, `.e01`, `.ex01`, `.vmdk`, `.vhd`, `.vhdx`.
   - **Compressed Archives**: `.zip`, `.tar.gz`, `.tgz`, `.tar` (auto-extracted to an isolated, self-cleaning staging workspace).
   - **Triage Packages**: Automatic detection and traversal of KAPE, CyLR, Velociraptor, and UAC triages.
   - **Loose Files & Directories**: Point directly to individual `$MFT`, `$UsnJrnl:$J`, or folders.

3. **Multi-Filesystem Support**:
   - **Windows NTFS**:
     - Fast `$MFT` record traversal using Omer BenAmram's `mft` engine.
     - `$STANDARD_INFORMATION` (0x10) and `$FILE_NAME` (0x30) timestamp extraction.
     - Alternate Data Stream (ADS) identification.
     - Resident file extraction (`-r, --resident`) dumped into original hierarchy.
     - Integrated `$UsnJrnl:$J` parser matching USN records with MFT entry numbers.
   - **Linux Filesystems**:
     - Direct raw partition traversal for `ext4`/`ext3`/`ext2` filesystems via `ext4-view`.
     - MACB timestamps (`mtime`, `atime`, `ctime`, `crtime`/birth time).
     - Unix permissions (mode strings like `drwxr-xr-x`, `-rw-r--r--`), UID, GID, and inodes.
     - Logical Linux triage ingestion (UAC collections, `/etc`, `/var`, `/home`).

4. **Standardized UTC Timestamps**:
   - All timestamps are generated strictly in **UTC ISO 8601 / RFC 3339** (`YYYY-MM-DDTHH:MM:SSZ` or with nanosecond precision).
   - Identical formatting to `masstin` and `caarea` for seamless timeline merging and hunt analytics.

---

## 🛠️ Usage

```bash
# Basic usage: Parse an MFT file to CSV timeline
allymacb -f evidence/$MFT -o timeline.csv

# Process a forensic disk image (E01 or raw DD) with resident file dump
allymacb -f disk_image.E01 -o timeline.csv -r dumped_residents

# Process a ZIP or triage folder (KAPE / UAC)
allymacb -f kape_triage.zip -o timeline.csv
allymacb -d C:\Cases\Evidence\kape_output -o timeline.csv

# Combine MFT and USN Journal
allymacb -f $MFT -u $UsnJrnl -o combined_timeline.csv

# Include $FILE_NAME (0x30) timestamps for timestomping analysis
allymacb -f $MFT -n -o timeline_fn.csv
```

### CLI Arguments

| Option | Short | Description |
|---|---|---|
| `--file <PATH...>` | `-f` | Input file(s): `$MFT`, disk images (`.e01`, `.dd`, `.vmdk`), archives (`.zip`, `.tar.gz`). |
| `--dir <PATH...>` | `-d` | Input evidence directory or triage folder (KAPE, Velociraptor, UAC). |
| `--usn <PATH>` | `-u` | Path to standalone USN Journal (`$UsnJrnl:$J`) file. |
| `--output <PATH>` | `-o` | Output timeline CSV path (defaults to stdout if omitted). |
| `--drive <CHAR>` | `-m` | Drive letter prefix for Windows paths (default: `C`). |
| `--file-name` | `-n` | Include `$FILE_NAME` (0x30) timestamp entries in addition to 0x10. |
| `--resident <DIR>` | `-r` | Directory to extract and dump recovered resident files. |
| `--resident-report <PATH>` | | Path to export resident file extraction summary report. |
| `--quiet` | `-q` | Suppress banner and progress bars. |

---

## 📊 Timeline Output Format

The output follows the standard `mactime` CSV specification with UTC ISO 8601 timestamps:

```csv
Date,Size,Type,Mode,UID,GID,Meta,File Name
2024-02-04T12:35:00Z,1024,macb,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe
2024-02-04T12:35:00Z,4096,macb,drwxr-xr-x,0,0,2,/etc
2024-02-04T12:35:00Z,2048,m...,-rw-r--r--,1000,1000,14526,/home/analyst/script.sh
2024-02-04T12:35:00Z,1024,....,-/-rwxrwxrwx,0,0,34567,C:\Windows\System32\cmd.exe (USN: FILE_CREATE)
```

- **Date**: UTC ISO 8601 timestamp (`%Y-%m-%dT%H:%M:%SZ`).
- **Size**: File size in bytes.
- **Type**: MACB flags (`macb`, `m...`, `.a..`, `..c.`, `...b`, `m.c.`, `....`).
- **Mode**: Permission string (`d/drwxrwxrwx`, `-/-rwxrwxrwx`, `drwxr-xr-x`, `-rw-r--r--`).
- **UID / GID**: User and group identifiers (0 for Windows MFT entries, native IDs for Linux).
- **Meta**: Record/Inode number.
- **File Name**: Full file path, including container name for archives and status flags (`(deleted)`, `(USN: ...)`, `($FILE_NAME)`).
