<div align="center">
  <img src="resources/allymacb_logo.svg" alt="allymacb logo: a comic clock with M, A, C and B on its face and an exclamation mark for a hand, objecting; a STOMPED stamp slams on a fake timestamp" width="760"/>
  <br><br>
  <strong>The filesystem timeline, and the files whose timestamps lie.</strong>
  <br>
  <code>$MFT</code>, <code>$UsnJrnl</code>, ext4, XFS, LVM, bodyfiles, disk images and triage packages in one CSV. Timestomping flagged, deleted files carved back, a statistical hunt on top. One binary, no dependencies.
  <br><br>

  <a href="https://github.com/jupyterj0nes/allymacb/releases/latest"><img src="https://img.shields.io/github/v/release/jupyterj0nes/allymacb?label=release" alt="Release"></a>
  <a href="https://github.com/jupyterj0nes/allymacb/releases/latest"><img src="https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Platform"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/Rust-stable-orange?logo=rust" alt="Rust"></a>
  <a href="docs/validation.md"><img src="https://img.shields.io/badge/tests-619%20passing-brightgreen" alt="Tests"></a>
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPLv3-blue.svg" alt="License: AGPL v3"></a>

</div>

<div align="center">
  <img src="resources/demo-hunt.gif" alt="allymacb builds the timeline of the NIST Hacking Case $MFT with 20 timestomped files; the significant files, with hunt, hunt_score and hunt_why, are read straight from the timeline"/>
  <br>
  <em>One run on the NIST Hacking Case <code>$MFT</code> with 20 files timestomped after the cutoff. The verdict lands in the last columns of the timeline itself: <code>hunt</code>, <code>hunt_score</code> and <code>hunt_why</code>, which says whether a rule spoke (<code>rule …</code>) or the statistical test did (plain words). 14 found, no false positive.</em>
</div>

## What it does

An intrusion leaves its traces in the filesystem: the dropper's creation time, the deleted tool, the log wiped from `/var/log`, the timestamps moved back to blend in. allymacb reads the filesystem's own records and puts every timestamp in one timeline, in the MACB format of `mactime`, in UTC.

- **One timeline from any filesystem evidence.** NTFS `$MFT` and `$UsnJrnl:$J`, ext2/3/4 read from the disk structures, XFS (the default of RHEL, Rocky, Alma and Oracle Linux), plain or inside LVM, TSK bodyfiles (UAC and other Linux collectors), E01, raw, split raw and fixed VHD images with GPT or MBR, ZIP and TAR triage packages (KAPE, Velociraptor, UAC), and plain directories. Nothing to mount, nothing to extract by hand. [Inputs ↓](#what-it-reads)
- **Points at the timestamps that were tampered with.** Twelve rules catch timestomping and name tricks: `$SI` against `$FILE_NAME`, whole-second times, changes the journal saw, older carved copies that are newer than the live record, right-to-left overrides, double extensions. Each rule's weight is measured on clean Windows and Linux machines, not guessed. The volume's own history (its installation, its normal hours) explains away what a clean machine does too. On three clean hosts the result is zero alerts. [Anti-forensics →](docs/anti-forensics.md)
- **Hunts with statistics, not thresholds.** Give it the day the incident started. Every record touched since then is tested against everything the volume did before, and the ones that survive a false-discovery-rate test are kept. It is the method of [masstin](https://github.com/jupyterj0nes/masstin)'s graph-hunt, moved from logins to file records. [Statistical hunt →](docs/hunt.md)
- **Brings back what was deleted.** `--carve` reads every sector for old `$MFT` records and `$I30` index entries, replays the ext4 journal to name deleted files, and recovers log lines and `utmp` records from free space. On a quick-formatted volume it gets back all 87 original files with their paths. [Carving →](docs/carving.md)
- **Lines up with the rest of the toolkit.** The CSV has [masstin](https://github.com/jupyterj0nes/masstin)'s 19 columns, each in the position of the masstin column closest in meaning, and the same analysis tail as caarea and faramir (`hunt`, `hunt_score`, `hunt_why`, `verdict`, `notes`). Lateral movement, execution, persistence and filesystem activity of one case read side by side. [Output →](docs/output.md)
- **Treats evidence as hostile and never fails silently.** Archive entries cannot escape their folder, spreadsheet formulas in file names are defused, a damaged source is reported with a numbered error and an exit code, and stdout carries nothing but the CSV.

<div align="center">
  <img src="resources/demo-carve.gif" alt="allymacb on a quick-formatted NTFS volume: the live $MFT knows nothing of C:\docs, --carve recovers the files from the old FILE records and $I30 entries"/>
  <br>
  <em>A quick-formatted NTFS volume. The live <code>$MFT</code> no longer knows <code>C:\docs</code>; <code>--carve</code> brings the files back from the old <code>FILE</code> records and <code>$I30</code> entries still in its sectors.</em>
</div>

## Quick start

Download the binary for your system from the [latest release](https://github.com/jupyterj0nes/allymacb/releases/latest) (`allymacb-<version>-windows.exe`, `-linux`, `-macos-x86_64`, `-macos-arm64`), or build it:

```bash
git clone https://github.com/jupyterj0nes/allymacb.git
cd allymacb
cargo build --release          # binary in target/release/allymacb[.exe], no C libraries needed
```

| You have | Run |
| :--- | :--- |
| An `$MFT` and its USN journal | `allymacb -f '$MFT' -u '$J' -n -o host01.csv` |
| A disk image (E01, raw, dd, split `.001`, fixed VHD) | `allymacb -f disk.E01 -o disk.csv` |
| A KAPE or Velociraptor zip, a UAC tar.gz | `allymacb -f triage.zip -o host.csv` |
| A folder of collections from many hosts | `allymacb -d /evidence/uac -o fleet.csv` |
| A suspicion that files were deleted or the volume was reformatted | `allymacb -f disk.E01 --carve -o disk.csv` |
| A pagefile, a VSS store, an old `$MFT` copy, unallocated space | `allymacb -f pagefile.sys --carve -o pagefile.csv` |
| The date the intrusion started | `allymacb -f '$MFT' -u '$J' --investigation-from 2026-03-03 --hunt-out hunt.csv -o timeline.csv` |
| A pipeline | `allymacb -f '$MFT' \| grep ',unallocated,' > deleted.csv` (only the CSV goes to stdout) |

Then open the CSV in Timeline Explorer, Excel or any CSV tool, or load it next to masstin, caarea and faramir timelines in a case tool.

## Reading the timeline

```csv
time_created,host,action,type,source,uid,gid,volume,size,mode,deleted,meta,file_name,evidence,hunt,hunt_score,hunt_why,verdict,notes
2024-02-04T12:35:00Z,,,macb,mft,0,0,p2,1024,-/-rwxrwxrwx,,34567,C:\Windows\System32\cmd.exe,disk.E01:p2:$MFT,,,,,
2024-02-03T09:12:41Z,,,macb,carved,0,0,p2,1024,-/-rwxrwxrwx,unallocated,34567,C:\Windows\System32\cmd.exe (carved @0x1A2B3C00),disk.E01:p2,,,,,
2026-09-23T23:05:14Z,uac-server02,,.a..,ext4,0,0,p1,1261,drwxr-xr-x,dtime,1572998,/boot/grub2/datetime.mod,uac-server02.tar.gz:disk.img:p1,,,,,
2026-09-24T18:42:22Z,,created,....,usn,0,0,C:,4096,-/-rwxrwxrwx,,45120,C:\Windows\Temp\payload.exe (USN: FILE_CREATE+CLOSE),$J,significant,17,$SI creation before the $FILE_NAME creation; creation time in whole seconds,,
2001-01-01T00:00:00Z,,,macb,mft,0,0,C:,4096,-/-rwxrwxrwx,,45120,C:\Windows\Temp\payload.exe,$MFT,significant,40,"rule si_before_fn (high): $SI creation before the $FILE_NAME creation; rule si_subsec_zero (high): $SI times in whole seconds, the $FILE_NAME ones not; $SI creation before the $FILE_NAME creation; creation time in whole seconds",,
```

One row per timestamp. The columns you will filter on most:

| Column | What it tells you |
|---|---|
| `type` | Which timestamps the row stands for: `m` modified, `a` accessed, `c` metadata changed, `b` born (created), as in `mactime` |
| `source` | `mft`, `usn`, `ext4`, `xfs`, `bodyfile`, `fs` or `carved`: a carved row is a different kind of evidence, and the column says so |
| `deleted` | `unallocated`, `dtime` or `usn` when the file is known to be gone |
| `meta` | Inode or MFT record number: what ties the rows of one file together |
| `evidence` | Where the row came from, outermost first: `disk.E01:p2:$MFT`, `kape.zip:C/$MFT`, `rhel.E01:p2:rl/root` (a logical volume) |
| `hunt` | `significant` or `candidate` when a rule or the hunt speaks; `baseline` / `habitual` when the volume vouches for the file |
| `hunt_score` | How rare, 0 to 100, ten points per order of magnitude: `>= 30` keeps what is rarer than one in a thousand |
| `hunt_why` | Why, in words: `rule <id> (<level>): …` for the rules, plain sentences for the hunt |
| `verdict`, `notes` | Yours: `suspicious`, `confirmed`, `benign`, free text |

All 19 columns, what each source fills, exit codes and error codes: [Output →](docs/output.md)

## What it reads

| Input | Detected by | Notes |
|---|---|---|
| `$MFT` | name (`$MFT`, `_MFT`) or `FILE`/`BAAD` signature | 1 KiB and 4 KiB records, `$ATTRIBUTE_LIST` followed, resident files dumped with `-r` |
| `$UsnJrnl:$J` | `-u`, or name (`$UsnJrnl%3A$J`, `$J` under `$Extend`) | USN V2 and V3; V4 range records skipped and counted |
| Bodyfile (TSK 3.x) | name (`bodyfile`, `*.body`) or content | UAC and other Linux collectors |
| E01 / EWF | `.e01`, `.ex01` | |
| Raw images | `.dd`, `.raw`, `.img`, split `.001`, or boot sector / GPT / MBR | GPT, MBR with extended partitions, 512 and 4096-byte sectors; NTFS, ext4, XFS and LVM partitions timelined |
| Fixed VHD | footer | |
| ext2 / ext3 / ext4 | partition in an image, or a bare filesystem image | Read from the disk structures: inode numbers, ctime, deleted inodes, the jbd2 journal with `--carve` |
| XFS | `XFSB` superblock: partition, logical volume or bare image | Every inode of every allocation group: `crtime` and nanoseconds on v5, freed inodes with their creation and deletion times, names of removed entries from directory slack. Through the [rust-fs-xfs](https://github.com/antimatter-studios/rust-fs-xfs) driver faramir uses |
| LVM2 | `LABELONE` physical volume label | Every linear logical volume is opened and its ext4 (with its journal) or XFS read; `volume` names it `p2:vg/lv` |
| Archives | `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.gz` | Streamed; every `$MFT`, `$J` and bodyfile inside parsed, one level of nesting included |
| Directories | `-d` | KAPE, Velociraptor or UAC output, or a plain tree (timelined from its metadata, with a warning) |
| Raw sectors | `--carve` | NTFS records and `$I30` entries anywhere, the ext4 journal, log lines and `utmp` records in free space, through the [blockcarve](https://github.com/jupyterj0nes/blockcarve) crate shared with masstin, faramir and caarea |

VHDX, sparse VMDK, dynamic VHD, QCOW and VDI are recognised and refused with a clear error: convert them to raw first.

## Usage

```text
Usage: allymacb [OPTIONS]

  -f, --file <FILES>...        $MFT, $J, bodyfile, image or archive. Repeatable.
  -d, --dir <DIRECTORIES>...   Triage folder or evidence directory. Repeatable.
  -u, --usn <USN>              Standalone $UsnJrnl:$J.
  -o, --output <OUTPUT>        CSV path. Without it the CSV goes to stdout.
  -m, --drive <DRIVE>          Drive letter for NTFS paths [default: C].
  -n, --file-name              Also emit $FILE_NAME (0x30) timestamps.
  -r, --resident <DIR>         Dump resident $DATA streams into this folder, new or empty.
                               Off unless given; no file is ever overwritten.
      --resident-report <FILE> Summary of the resident dump of the whole run.
  -q, --quiet                  No banner, progress bars or informational lines. Warnings stay.
      --carve                  Also scan images and unrecognised files sector by sector for
                               NTFS records outside the live $MFT. Off by default.
      --investigation-from <TIME>
                               Statistical hunt: test the records active from this UTC time
                               against the earlier ones of their volume. Off by default.
      --alpha <RATE>           False discovery rate of the hunt [default: 0.05].
      --hunt-out <CSV>         Findings table of the hunt (19 columns, laid out like masstin's):
                               every irregular record of the window, with p, q and the reasons.
      --threads <N>            Threads to use [default: 0, every logical processor].
                               The output is byte for byte the same with any number.
  -h, --help / -V, --version
```

Exit codes: `0` everything parsed, `1` usage error, `2` nothing could be parsed (no CSV written), `3` CSV written but at least one source failed (listed on stderr). Anything skipped is reported; a short timeline is never silent.

## Does it hold up?

Every number in this README was measured. The details are in [How it was checked →](docs/validation.md).

- **Parsing.** It matches SleuthKit `fls` on all 12,171 entries of the NIST Hacking Case `$MFT` (paths, sizes and timestamps). It matches `fsutil` on the USN journal of the dfir_ntfs corpus and `fiwalk` DFXML on the Digital Corpora E01 images.
- **Carving.**
  - Lab NTFS volumes with a known truth: every deleted path is recovered, and every reused MFT record has its previous owner named (19/19, 150/150, 492/492). A quick-formatted volume gives back all 87 original files.
  - A lab ext4 volume: all 45 deleted files come back with their path, and 8,128 of 8,128 log records are recovered from free space.
- **Clean hosts.** On three clean machines (a Windows Server 2016, a domain controller from the same image and an Ubuntu 22.04 server), the rules raise 0 `significant` and 0 `candidate`.
- **No trace.** Reading the evidence writes nothing on it: after all 53 validation cases, every time of the 394 files and folders they read is unchanged. No row carries a time of the analysis itself.
- **Same output on every processor.** On 53 cases, 265 of 265 runs on 1 to 12 threads are byte for byte those of the single-threaded binary. Eight hosts in one folder take 21 s instead of 38 s; carving takes about half the time.
- **Planted timestomps.** On the NIST `$MFT`, 14 of 20 are found with no false positive. On the clean Server 2016, the rules alone find the 5 they can see with a precision of 1.00, and the hunt finds 15 of 20.

## Limitations

* ext4: `meta_bg` layouts and inline-data directories fall back to `ext4-view`, which has no ctime and no inode numbers. Names of deleted files come only from the journal. File contents are not recovered: that is PhotoRec's job.
* XFS: a freed inode keeps its times but not its type or size. Its name comes back only from the slack of a directory stored in blocks; a small directory kept inside its inode is compacted on removal and keeps nothing. The log holds operations, not block copies, so there are no older inode states as on ext4.
* LVM: linear logical volumes that lie on the physical volume being read. A volume that is striped, mirrored, thin or spread over a second disk is reported as unreadable and the exit code says the timeline is partial. `--carve` does not look for logs in the free space of a logical volume.
* A non-resident `$ATTRIBUTE_LIST` cannot be followed from a loose `$MFT`.
* USN rows carry the record's name and MFT entry, not a full path.
* VHDX, VMDK, dynamic VHD, QCOW and VDI are not decoded.
* Nothing is recovered from old `$UsnJrnl` or `$LogFile` data, compressed rotated logs or journald's binary files. Encrypted or compressed containers (BitLocker, hiberfil) stay closed.
* The hunt leaves out ext4 volumes read through the fallback and directories of loose files. It joins a `$J` to an `$MFT` only when the run holds exactly one live `$MFT`. A reused record whose times were all moved back before the cutoff can only be placed by the journal.

## Documentation

| Page | What is in it |
|---|---|
| [Output](docs/output.md) | The 19 columns against masstin's, what each source fills, orphans, CSV escaping, stdout and stderr, exit and error codes |
| [Anti-forensics indicators](docs/anti-forensics.md) | The twelve rules, what else produces each one, their measured rarity, the installation window and the clean hours |
| [Statistical hunt](docs/hunt.md) | How `--investigation-from` tests a record, the score scale, the findings table, where the numbers stop |
| [Carving](docs/carving.md) | `FILE` and `$I30` carving and deduplication against the live `$MFT`, the ext4 journal, XFS directory slack, logs and `utmp` in free space |
| [How it was checked](docs/validation.md) | Every comparison against independent tools and lab volumes with a known truth, and the test suite |
| [Roadmap](docs/roadmap.md) | What could come next and why it is not done yet: speed on a single machine, inputs read at once, reading without a trace |
| [CHANGELOG](CHANGELOG.md) | What changed, release by release |

## Credits and license

* Author: Toño Díaz ([@jupyterj0nes](https://github.com/jupyterj0nes)).
* allymacb started as a rewrite of [mftmactime](https://github.com/kero99/mftmactime) by kero ([@kero99](https://github.com/kero99)), the origin of the idea, the CLI and the resident-file dump. Thanks, kero. The name is a pun on MACB and a nineties TV lawyer; the resemblance ends there, although both have been known to argue with timestamps.
* The NTFS parsing engine is Omer BenAmram's [mft](https://github.com/omerbenamram/mft) crate. The samples used for checking come from Maxim Suhanov's [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs), the NIST Hacking Case and [Digital Corpora](https://digitalcorpora.org).
* License: AGPL-3.0-only.
