# allymacb

```text
    _    _     _ __   __   __  __    _    ____ ____  
   / \  | |   | |\ \ / /  |  \/  |  / \  / ___| __ ) 
  / _ \ | |   | | \ V /   | |\/| | / _ \| |   |  _ \ 
 / ___ \| |___| |__| |    | |  | |/ ___ \ |___| |_) |
/_/   \_\_____|_____|_|    |_|  |_/_/   \_\____|____/ 
```

A filesystem timeline generator in Rust. It reads NTFS `$MFT` and `$UsnJrnl:$J`, TSK bodyfiles, ext2/3/4 volumes, disk images and triage archives, and writes one CSV timeline in `mactime` MACB format with UTC ISO 8601 timestamps. Each row says which evidence it came from and marks the timestamps and names that look tampered with. The columns follow [masstin](https://github.com/jupyterj0nes/masstin)'s timeline one for one, so the two line up when read together. Given the start of the period under investigation, it tests every record touched since then against the volume's own history and keeps the ones that are rare at a chosen false discovery rate. On request it also carves what the live filesystem no longer shows: old `$MFT` records and `$I30` entries, the ext4 journal, and the log lines and `utmp` records left in free space.

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
| Raw sectors | `--carve`, never by default | NTFS `FILE` records and `$I30` index entries anywhere in an image or in an unrecognised file (pagefile, VSS store, old `$MFT` copy, `blkls` output); the ext4 journal; log lines and `utmp` records in free space. The block scanner and the record validators are the [blockcarve](https://github.com/jupyterj0nes/blockcarve) crate shared with masstin, faramir and caarea. See [Carving](#carving). |

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
      --investigation-from <TIME>
                               Statistical hunt: test the records active from this UTC time
                               against the earlier ones of their volume. Off by default.
      --alpha <RATE>           False discovery rate of the hunt [default: 0.05].
      --hunt-out <CSV>         Findings table of the hunt (19 columns, laid out like masstin's):
                               every irregular record of the window, with p, q and the reasons.
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
allymacb -f $MFT | grep ',unallocated,' > deleted.csv

# Same image, plus whatever old $MFT records and $I30 entries are left in its sectors
allymacb -f disk.E01 --carve -o disk_carved.csv

# A pagefile or a VSS store on its own: nothing to parse, so carve it
allymacb -f pagefile.sys --carve -o pagefile_carved.csv

# The intrusion started around 3 March: what was touched since then and looks unlike the volume's history?
allymacb -f '$MFT' -u '$J' --investigation-from "2026-03-03" --hunt-out hunt.csv -o timeline.csv
```

### stdout, stderr and exit codes

The CSV is the only thing written to stdout. The banner, progress bars, `[*]` status lines, `[!]` warnings and the final summary go to stderr.

| Exit code | Meaning |
|---|---|
| 0 | Every source was parsed. |
| 1 | Usage error. |
| 2 | Nothing could be parsed. No CSV is written. |
| 3 | CSV written, but at least one source failed or was missing, or the hunt CSV could not be written. The failures are listed on stderr. |

Anything skipped is reported: unreadable images, corrupt archives, rejected bodyfile lines, archive entries that tried to escape the extraction directory, ext4 inodes that could not be decoded. A short timeline is never silent.

## Output

```csv
time_created,host,action,type,source,uid,gid,volume,size,mode,deleted,meta,file_name,evidence,hunt,hunt_score,hunt_why,verdict,notes
1991-10-03T02:25:06Z,uac_results_server01,,m...,bodyfile,0,0,,72834,-rw-r--r--,,8989,/usr/share/fonts/putb.pfa,uac_results_server01.tar.gz:bodyfile.txt,candidate,0,"rule m_before_b (medium): modification before creation",,
2024-02-04T12:35:00Z,,,macb,mft,0,0,p2,1024,-/-rwxrwxrwx,,34567,C:\Windows\System32\cmd.exe,disk.E01:p2:$MFT,,,,,
2024-02-04T12:35:00Z,,,macb,mft,0,0,p2,1024,-/-rwxrwxrwx,,34567,C:\Windows\System32\cmd.exe ($FILE_NAME: cmd.exe),disk.E01:p2:$MFT,,,,,
2024-02-03T09:12:41Z,,,macb,carved,0,0,p2,1024,-/-rwxrwxrwx,unallocated,34567,C:\Windows\System32\cmd.exe (carved @0x1A2B3C00),disk.E01:p2,,,,,
2026-09-23T23:05:14Z,uac-server02,,.a..,ext4,0,0,p1,1261,drwxr-xr-x,dtime,1572998,/boot/grub2/datetime.mod,uac-server02.tar.gz:disk.img:p1,,,,,
2026-09-24T18:42:22Z,,created,....,usn,0,0,C:,4096,-/-rwxrwxrwx,,45120,C:\Windows\Temp\payload.exe (USN: FILE_CREATE+CLOSE),$J,significant,17,$SI creation before the $FILE_NAME creation; creation time in whole seconds,,
2001-01-01T00:00:00Z,,,macb,mft,0,0,C:,4096,-/-rwxrwxrwx,,45120,C:\Windows\Temp\payload.exe,$MFT,significant,34,"rule si_before_fn (high): $SI creation before the $FILE_NAME creation; rule si_subsec_zero (high): $SI times in whole seconds, the $FILE_NAME ones not; $SI creation before the $FILE_NAME creation; creation time in whole seconds",,
```

The last two rows come from a run with `--investigation-from`. The last one has both voices: its rules (17 points, measured) and the statistical hunt (17 points) add up to 34. Without `--investigation-from`, a row with rules carries the state they give and their points; a row without any is left with an empty tail.

The 19 columns are those of [masstin's timeline](https://github.com/jupyterj0nes/masstin/blob/main/docs/csv-format.md), each in the position of the masstin column closest in meaning, so a timeline of each read side by side keeps the same kind of value in the same column:

| # | masstin | allymacb | |
|---|---|---|---|
| 1 | `time_created` | `time_created` | UTC ISO 8601 timestamp of the event the row represents. Sub-second digits are printed when present. |
| 2 | `dst_computer` | `host` | The collection the row came from: the name of a UAC or KAPE archive, or the stem of a bodyfile (`server01.body`). Empty for a loose `$MFT` or an image. |
| 3 | `event_type` | `action` | What happened to the file, when the evidence says it: `created`, `deleted`, `renamed`, `modified` or `metadata`. Only USN rows carry it for now. |
| 4 | `event_id` | `type` | MACB flags of that timestamp (`macb`, `m...`, `.a..`, `..c.`, `...b`, combinations, or `....` for USN rows). |
| 5 | `logon_type` | `source` | What the row was built from: `mft`, `usn`, `bodyfile`, `ext4`, `fs` (host filesystem metadata of a directory walk or an extracted archive) or `carved`. |
| 6 | `target_user_name` | `uid` | Unix owner, `0` for NTFS. |
| 7 | `target_domain_name` | `gid` | Unix group, `0` for NTFS. |
| 8 | `src_computer` | `volume` | `C:` for a loose `$MFT` or `$J` (the drive letter of `-m`), `p1`, `p2`... for the partitions of an image in the order they were found. |
| 9 | `src_ip` | `size` | File size in bytes. |
| 10 | `subject_user_name` | `mode` | `ls -l` style permissions. NTFS has none, so NTFS rows use the `mactime` convention `-/-rwxrwxrwx` and `d/drwxrwxrwx`. |
| 11 | `subject_domain_name` | `deleted` | How the file is known to be deleted: `unallocated` (NTFS record not in use, ext4 inode without links), `dtime` (ext4 inode with a deletion time), `usn` (USN record with `FILE_DELETE`). Empty for a live file. |
| 12 | `logon_id` | `meta` | Inode or MFT record number: what ties the rows of one file together. |
| 13 | `detail` | `file_name` | Full path, with tags: `($FILE_NAME: name)`, `(USN: REASON+REASON)`, `($I30)`, `(carved @0xOFFSET)`. |
| 14 | `log_filename` | `evidence` | The input the row was read from, outermost first: `disk.E01:p2:$MFT`, `kape.zip:C/$MFT`, `triage:C/$Extend/$UsnJrnl%3A$J`. |
| 15 | `hunt` | `hunt` | The verdict on the row's file (see below). |
| 16 | `hunt_score` | `hunt_score` | How rare the file is, 0 to 100, on masstin's scale: the [statistical hunt](#statistical-hunt)'s `-10 · log10(q)` plus the measured rarity of its [rules](#anti-forensics-indicators), capped at 100. |
| 17 | `hunt_why` | `hunt_why` | One clause per rule, `rule <id> (<level>): ...`, strongest first, then what the hunt found unusual, in words. Clauses are separated by `; `. |
| 18 | `verdict` | `verdict` | The analyst's; written empty. |
| 19 | `notes` | `notes` | The analyst's; written empty. |

On masstin's columns 6 to 11 sit who logged in and from where; a filesystem keeps no author of a change, so those positions hold the file's attributes. The last five columns are masstin's analysis tail, with its names and its vocabulary, which masstin, caarea, faramir and allymacb share ([masstin's csv-format](https://github.com/jupyterj0nes/masstin/blob/main/docs/csv-format.md#the-same-tail-in-caarea-faramir-and-allymacb)). `hunt` holds one of six words: `significant`, `candidate`, `habitual`, `not_evaluated`, `baseline`, or nothing. The statistical hunt gives one, a rule another (a high rule `significant`, a medium one `candidate`), and the stronger wins. `suspicious` is not among them: that is the analyst's word, in `verdict`. To keep only what the rules said, filter `hunt_why` on `rule `; to keep only the statistics, on its absence.

Every column is RFC 4180 escaped. `meta` and `file_name` come from the evidence, so a value starting with `=`, `+`, `-`, `@`, tab or CR is written quoted with a leading apostrophe. A file named `=cmd|' /C calc'!A0` does not execute when the CSV is opened in a spreadsheet.

### Per source

| Source | m | a | c | b | Notes |
|---|---|---|---|---|---|
| `$MFT`, `$STANDARD_INFORMATION` | yes | yes | yes | yes | `-n` adds `$FILE_NAME` rows. Size comes from the non-resident `$DATA` header, so files above the resident limit report their real size. ADS get their own rows with the same flags as the host record. Pre-1970 timestamps are kept; only FILETIME 0 is dropped. |
| `$UsnJrnl:$J` | | | | | Rows are `....` with the reason flags in the name; `action` and `deleted` come from them. |
| Bodyfile | yes | yes | yes | yes | Split from the right, so a `\|` inside a path does not shift the columns. `0` means unset. Lines with non-numeric uid, gid or size are rejected and counted. |
| ext4 | yes | yes | yes | yes | Read from the on-disk structures: inode number in `meta`, `ctime`, timestamps past 2038, and the inodes still marked deleted in the tables, with `deleted` set. SUID, SGID, sticky and device types are rendered. ext2 and ext3 block maps are followed too. |
| Directory walk | yes | yes | Unix only | yes | Timestamps come from the host filesystem, and the tool says so. Real mode, uid, gid and inode on Unix hosts. |
| Archive without artifacts | yes | | | | A zip or tar only preserves modification times. |
| Carved `FILE` record | yes | yes | yes | yes | Same rows as a live record (`-n` applies), tagged `(carved @0xOFFSET)` with the absolute offset in the image or file. `source` is `carved`. |
| Carved `$I30` entry | yes | yes | yes | yes | The `$FILE_NAME` copy kept in the directory index, tagged `($I30)`. Size and timestamps are the index's own. |

Orphans: an NTFS parent reference carries the sequence number of the directory record it pointed to. When that record has since been freed and reused, the file is reported as `[ORPHAN]\name` instead of being attached to whatever directory lives there now. This is what SleuthKit does with `$OrphanFiles`. A parent chain that loops, which only a crafted `$MFT` produces, is reported as `[CYCLE]\name`.

## Anti-forensics indicators

These are allymacb's static rules: a known pattern, with no probability behind it. When a file's timestamps or name show one, every row of the file says so in the analysis tail, in the convention the four tools share:

* **Level.** An indicator is `high` when it has no ordinary explanation, and so is the pair `si_before_fn` with `si_subsec_zero` (the classic timestomp signature); the patterns that installers and preserved-timestamp copies also produce are `medium`. A high rule puts `significant` in `hunt`, a medium one `candidate`; a stronger statistical state keeps its place.
* **`hunt_why`** has one clause per indicator, `rule <id> (<level>): <what it means>`, strongest first, before the hunt's own words.
* **`hunt_score`** gets the rule's rarity on masstin's scale, measured, not chosen: `10 · log10(records / records that fire)` on a reference volume of the record's kind: for NTFS the `$MFT` of the NIST Hacking Case (12,183 file records of a Windows XP install, nearly all stock files and two setup programs); for Unix records a stock Ubuntu ext4 volume of a lab host (861 inodes, read from the on-disk structures). A pattern that never fired on the reference is not "never": it gets the bound the volume gives, one in `records + 1` (41 on the NTFS reference, 29 on the ext4 one). A rule not measured yet adds 0 and its clause ends with `rarity not measured`. Test and rules add, capped at 100.

| Rule | Level | Fired on | Points |
|---|---|---|---|
| `si_before_fn` | medium (high with `si_subsec_zero`) | 324 of 12,183 | 16 |
| `si_subsec_zero` | medium (high with `si_before_fn`) | 236 of 12,183 | 17 |
| `si_before_fn` with `si_subsec_zero` | high | 232 of 12,183 | 17 for the pair, not the sum |
| `b_after_c` | medium | 220 of 12,183 | 17 |
| `future`, `pre_1980`, `rtlo_name`, `invisible_name`, `double_ext` | high | none of 12,183 | 41: one in 12,184 or rarer |
| `m_before_b` on a Unix record | medium | 835 of 861 (package files keep their build mtime, older than the install's crtime) | 0 |
| `future`, `pre_1980` on a Unix record | high | none of 861 | 29: one in 862 or rarer |
| `m_after_c` (high) | | Unix only | not measured, 0 |
| `usn_basic_info` (high), `backdated` (high) | | no journal or carving on the reference | not measured, 0 |

NTFS records use the NTFS rarities; ext4, bodyfile and directory-walk records the ext4 ones. The measurement is what makes `m_before_b` worth nothing on Unix: on a stock Ubuntu volume nearly every file has a modification time older than its creation, because packages ship files with the mtime of their build. The rule still fires and still says so in `hunt_why`; it adds no points. A larger clean Linux volume, measured the same way, would tighten the bound of `future` and `pre_1980`.

```csv
1975-06-15T12:00:00Z,,,ma..,ext4,0,0,p1,100,-rw-r--r--,,133,/docs/ts1975.txt,ext4.img:p1,significant,29,"rule pre_1980 (high): a timestamp before 1980; rule m_before_b (medium): modification before creation",,
1999-02-07T07:08:08Z,,,m..b,mft,0,0,C:,78706,-/-rwxrwxrwx,,9854,C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\40\BIN\FPEXT.MSG,nist-hacking-case.mft,significant,17,"rule si_before_fn (high): $SI creation before the $FILE_NAME creation; rule si_subsec_zero (high): $SI times in whole seconds, the $FILE_NAME ones not",,
2000-11-18T12:28:36Z,,,m..b,mft,0,0,C:,450669,-/-rwxrwxrwx,,9852,C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\40\BIN\FP4AWEC.DLL,nist-hacking-case.mft,candidate,17,"rule si_subsec_zero (medium): $SI times in whole seconds, the $FILE_NAME ones not",,
```

At the end of every run, quiet or not, stderr lists each file with a high rule on its own line (up to 40, then a count) and sums up the medium ones:

```text
[ALERT] 3 file(s) with high-level rule indicators (timestomping, name tricks): `significant` in the hunt column, `rule <id> (high)` in hunt_why:
[ALERT]   pre_1980+si_before_fn              V:\docs\ts1975.txt  (meta 58)
[ALERT]   future                             V:\docs\ts2050.txt  (meta 59)
[ALERT]   rtlo_name                          V:\docs\report‮fdp.exe  (meta 63)
[!] 316 file(s) with medium-level rule indicators (b_after_c 220, si_before_fn 92, si_subsec_zero 4): also produced by preserved-timestamp copies and installers; `candidate` in the hunt column, `rule <id> (medium)` in hunt_why
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

## Statistical hunt

The indicators above say what a record looks like. On a real system many of them fire on thousands of files: installers, archive extractors and copies that keep timestamps produce the same patterns as a timestomping tool. `--investigation-from` asks a different question: of the records touched since that time, which ones look unlike anything this volume did before?

It is the method of masstin's [graph-hunt](https://github.com/jupyterj0nes/masstin/blob/main/docs/graph-hunt-statistics.md), moved from logins to file records:

1. **Unit.** One state of one record: an NTFS `FILE` record (live or carved), an ext4 inode (live, deleted, or an older copy from the journal), a bodyfile line.
2. **When it was touched.** Its latest creation, modification or change time, `$FILE_NAME` copies and USN records included. Access times do not count. An NTFS record used for the first time cannot be older than the first-use record numbered just before it, because NTFS hands out the lowest free record; that neighbour's creation counts too, so a file whose every timestamp was moved back still lands in the window.
3. **Baseline and window.** Records touched before the cutoff are the baseline, the rest the window. Each volume is compared with itself.
4. **What is measured.** For every record, how far each timestamp relation is from what the filesystem writes on its own:

   | Coordinate | Measured as |
   |---|---|
   | `b_before_fn` | Seconds the `$SI` creation lies before the `$FILE_NAME` creation |
   | `b_after_c`, `m_after_c` | Seconds the creation or modification lies after the change time (`m_after_c` on Unix only: NTFS leaves it on every file written through a mapped section, such as the registry hives) |
   | `m_before_b` | Seconds the modification lies before the creation |
   | `whole_sec_b`, `_m`, `_c`, `_a`, `_fn` | Timestamp with no sub-second part. Switched off on a volume that never stores one (bodyfiles, 128-byte ext4 inodes) |
   | `before_volume` | Seconds the creation lies before the volume was formatted (`$MFT`'s own creation, or the root directory's) |
   | `alloc_order` | Seconds the `$FILE_NAME` creation lies before that of the first-use record numbered just before it |
   | `fn_before_usn`, `basic_info` | Seconds the `$FILE_NAME` creation lies before the journal's create record; journal records that changed only timestamps or attributes. Only when the `$J` given with `-u` reaches into the baseline |
   | `future`, `backdated`, `name` | The rule indicators of the same names, and the name tricks |

   A record with any coordinate above zero is irregular. Most records are not, and are not tested.
5. **Test.** Each irregular window record is compared with the irregular baseline records of its volume. Its score is the sum, over its coordinates above zero, of `-ln(share of baseline records at least as high)`, and its p-value is the share of baseline records whose own score (computed leaving themselves out) is at least as high, with the add-one correction. This is a conformal p-value: it holds whatever the dependence between coordinates.
6. **Decision.** Benjamini-Hochberg across every tested record of the run. The only number chosen by hand is the false discovery rate, `--alpha`, 0.05 by default.

The output follows masstin. Every row of the timeline gets the verdict on its record in the analysis tail; the rows of one record (`$SI`, `$FILE_NAME`, ADS, and the USN records joined to it) share it, as the rows of one connection do in masstin:

| `hunt` | Meaning |
|---|---|
| `significant` | Irregular, tested, q ≤ `--alpha` |
| `candidate` | Irregular, tested, q > `--alpha`: nothing that passes the bar, but worth a look |
| `habitual` | Active in the window with no coordinate above zero, like most records of the volume; q = 1, not a test |
| `not_evaluated` | Active in the window on a volume with nothing to compare it with (no irregular baseline record, or no baseline at all) |
| `baseline` | Active before the cutoff: reference, not judged |
| *(empty)* | The row did not enter the hunt: no `--investigation-from`, a directory of loose files, an ext4 volume read through `ext4-view`, a USN record not joined to an `$MFT` record |

A rule speaks in the same columns (see [Anti-forensics indicators](#anti-forensics-indicators)): the stronger state wins, the points add, and the rule's clause comes before the hunt's words.

`hunt_score` is the q-value turned into a number people can read and filter, as masstin writes it: `-10 · log10(q)`, rounded, capped at 100. Ten points are one order of magnitude.

| `hunt_score` | q | Read as |
|---|---|---|
| 0 | 1 | no rarer than chance (every `habitual` record) |
| 13 | 0.05 | one in twenty (the default `--alpha`: `significant` starts here) |
| 20 | 0.01 | one in a hundred |
| 30 | 0.001 | one in a thousand |

The score a volume can reach is bounded by its history: the smallest p is 1 / (irregular baseline records + 1), and stderr prints the resulting ceiling per volume. On the NIST `$MFT` below it is 39; a volume with 15 irregular baseline records cannot pass 12, so nothing on it can be significant. A file judged by its rules alone carries their points; the exact p and q stay in `--hunt-out`.

stderr shows each volume's numbers and the significant records (here, the NIST `$MFT` with timestomps written into it by `scripts/hunt_inject.py`, see [How it was checked](#how-it-was-checked)):

```text
[*] Hunt: records active from 2004-08-26 00:00:00 UTC tested against the earlier records of their volume, FDR 0.05
    volume 1 (ntfs, C:): 12183 records; baseline 11578, of which 8661 irregular on 6 day(s) form the null; window 605, 272 irregular tested; highest reachable score 39
    records: 14 significant, 258 candidate, 0 not evaluated, 333 habitual, 11578 baseline; 0 row(s) outside the hunt
[ALERT] Hunt: 14 of 272 tested record(s) significant at FDR 0.05; `significant` in the hunt column
[ALERT]   score 22 (one in 160) contradiction C:\WINDOWS\system32\nsndis5.sys  (meta 12012): creation after the metadata change time by 26.3 years: shared by 0 of 8661 irregular baseline records, on 0 of 6 days
[ALERT]   score 17 (one in 50) stomp         C:\Program Files\Ethereal\plugins\0.10.6\mgcp.dll  (meta 12172): metadata change time in whole seconds: shared by 124 of 8661 irregular baseline records, on 4 of 6 days
```

`--hunt-out` writes the findings table, one row per irregular record of the window, significant first. It has the 19 columns of masstin's graph-hunt table, each in the position of the one closest in meaning:

| # | masstin | allymacb | Here |
|---|---|---|---|
| 1-4 | `rank`, `significant`, `p_value`, `q_value` | same | `significant` is `yes` / `no` at `--alpha`, `not evaluated` when the volume has no irregular baseline record (p and q empty) |
| 5-7 | `day`, `first_seen_utc`, `last_seen_utc` | same | Day of the record's activity; its earliest timestamp; its activity (latest creation, modification or change) |
| 8 | `origin` | `volume` | Host and volume as the timeline names them (`srv01 p2`), or the root of the path (`C:`) |
| 9 | `destination` | `file_name` | The file |
| 10 | `account` | `owner` | The owner's uid on Unix; empty on NTFS |
| 11 | `result` | `rules` | The rule ids with their level, strongest first: `future (high)+b_after_c (medium)` |
| 12-13 | `events`, `logs` | `rows`, `sources` | Timeline rows of the record, joined USN records included; the sources they came from (`mft+usn`, `ext4`, `carved`...) |
| 14 | `signature` | same | Kind of finding, made to filter on: `contradiction` (an ordering the filesystem never writes, or two kernel records that disagree), `stomp`, `name`, `copy` |
| 15 | `why_unusual` | same | What is unusual, in short phrases without numbers |
| 16 | `evidence` | same | The same phrases with the value and the baseline count behind each: `$SI creation before the $FILE_NAME creation by 3.0 years: shared by 4 of 8661 irregular baseline records, on 2 of 6 days`. That count is what an analyst can defend without the model |
| 17-18 | `chain`, `campaign` | `related`, `group` | Empty for now |
| 19 | `cypher_snippet` | `lookup` | The pivot to the record's rows in the timeline: `meta=12172` |

What the numbers mean and where they stop:

* The p-value is valid when window and baseline records are alike when nothing happened. Files written every day (registry hives, logs, databases) are always in the window; that is why `m_after_c` is not used on NTFS.
* The smallest p a record can get is 1 / (baseline size + 1); stderr prints the highest score it allows per volume. A volume with a short history, or a cutoff right after the installation, cannot make anything significant, and the run says so instead of guessing.
* Where installers and copies left the same pattern a thousand times in the baseline, a stomp with that pattern is not rare on that volume and is not reported. The rule indicators still mark it.
* A file whose timestamps were all moved back before the cutoff, with no USN record and no first-use record number to place it, is part of the baseline and is never tested.

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
* Older states of inodes that differ from the live one become `carved` rows, with the path as of that transaction, `deleted` set when the state is a deleted one, and `(carved @0xOFFSET)` pointing at the copy inside the journal.
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
python scripts/hunt_inject.py samples/dfir_ntfs/nist-hacking-case.mft stomped.mft 1093478400 truth.json
allymacb -f stomped.mft --investigation-from 2004-08-26 --hunt-out hunt.csv -o t.csv
python scripts/check_hunt.py truth.json hunt.csv
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
| The NIST Hacking Case `$MFT`, hunt from 2004-08-26 (the system was installed on the 19th; the suspect's tools went in on the 27th) | Nothing in it was timestomped | 263 records of the window are irregular and tested; none is significant at 5 %. The rules mark 232 files high on the same volume, nearly all of them files the XP installer and the tools' setup programs wrote with old, whole-second timestamps. |
| The same `$MFT` with 20 window files timestomped by `scripts/hunt_inject.py` in four ways: `SetFileTime`-style whole-second B/M/A with C moved to the time of the change, all four times copied from `kernel32.dll`, the move trick (`$SI` and `$FILE_NAME` both in 2003, whole seconds), and B/M pushed to 2031 | The list of records written | Significant: 5/5 copied from `kernel32.dll`, 5/5 in the future, 4/5 move tricks (the fifth is a reused record, which only a journal can place in time). Not significant: 0/5 `SetFileTime`, because 82 baseline files on that volume already carry a `$SI` creation more than a year before the `$FILE_NAME` one, with the same whole seconds; the rules still mark them. No other record is significant. |
| An 8 MiB ext4 volume with a journal, built the same way and shipped gzipped in `tests/data` | What was done to it | Run by `cargo test`: inode numbers and ctime on live rows; a deleted file named through the journal; the pre-growth size of an appended file; the old name of a renamed file; a deleted directory tree with its paths; `backdated` on a file whose mtime was moved to 1975 after the journal saw it in 2026. |

## Limitations

* ext4: the raw reader does not handle `meta_bg` layouts or inline-data directories; on those it falls back to `ext4-view`, which exposes neither ctime nor inode numbers and refuses timestamps before 1970 or after 2038. Names of deleted files come only from the journal, so a deletion older than the journal's history is reported as `/[UNKNOWN]/inode_N`, with `deleted` set. Data blocks are not recovered: that is a job for PhotoRec.
* A non-resident `$ATTRIBUTE_LIST`, where the list itself lives outside the record, cannot be followed from a loose `$MFT`. Names stored that way are unknown to the live parse, so `--carve` reports their `$I30` entries as if the files were not in the `$MFT`.
* USN rows carry the file name from the record and the MFT entry number, not a full path. Joining them with the `$MFT` is left to the analyst.
* VHDX, VMDK, dynamic VHD, QCOW and VDI are not decoded.
* Carving of `FILE` and `$I30` structures reads the whole image, allocated space included; log lines and `utmp` records are taken from free space only. Nothing is recovered from what used to be a `$UsnJrnl` or an `$LogFile`, from compressed rotated logs or from journald's binary files. Compressed or encrypted containers (hiberfil, BitLocker) hide their contents from it like from everything else.
* `fsutil` prints local time without a zone; this tool prints UTC. Keep that in mind when comparing by hand.
* ext4 volumes read through the `ext4-view` fallback have no change time and are left out of the hunt; so are directories of loose files, whose timestamps belong to the analyst's machine. The hunt joins a `$J` to an `$MFT` only when the run holds exactly one live `$MFT`. The allocation-order check covers records used for the first time; a reused record whose timestamps were all moved back is placed in time only by the journal.

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

586 tests: parsers, anti-forensics indicators and their place in the shared tail, the statistical hunt (stomped records against a baseline of ordinary copies, a calibration window with none, the journal and allocation-order checks, the score scale, the CLI), the 19-column layout and how `evidence` is built from nested inputs, the raw ext4 reader on a real journaled volume, log and utmp carving, MACB flag combinations, timestamp boundaries, permission matrices, synthetic `$MFT` records (parent cycles, stale sequence numbers, non-resident sizes, ADS, path traversal, deleted/live collisions, damaged first records), carving (records at odd sector offsets, across the read block boundary, duplicates and older states, dedup against a live `$MFT`, `$I30` slack, decoys, the flag being opt-in), and end-to-end runs of the binary that check stdout stays pure CSV and exit codes reflect partial or total failure.

## Credits and license

* Author: Toño Díaz ([@jupyterj0nes](https://github.com/jupyterj0nes)).
* [mftmactime](https://github.com/kero99/mftmactime) by kero ([@kero99](https://github.com/kero99)) is the origin of this tool: the CLI, the resident-file dump and the whole approach. Thanks, kero.
* The NTFS parsing engine is Omer BenAmram's [mft](https://github.com/omerbenamram/mft) crate, the same one mftmactime used. The samples used for checking come from Maxim Suhanov's [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs), the NIST Hacking Case and [Digital Corpora](https://digitalcorpora.org).
* License: AGPL-3.0-only.
