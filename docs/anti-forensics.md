# Anti-forensics indicators

[← README](../README.md)

allymacb's static rules look for known patterns, with no probability behind them. This page covers what each one means, what else produces it, how rare it was measured on clean machines, and how the volume's own history (its installation, its hours) speaks before them.

- [The rules](#the-rules)
- [What lands in the tail](#what-lands-in-the-tail)
- [How much a rule is worth](#how-much-a-rule-is-worth)
- [The volume speaks first](#the-volume-speaks-first)
- [What it looks like](#what-it-looks-like)

## The rules

| Rule | Meaning | Also produced by |
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
| `double_ext` | A document extension followed by an executable one: `invoice.pdf.exe`, `photo.jpg.scr`. `.lnk` is not counted (`Readme.txt.lnk` is a normal shortcut), nor is PowerShell's own `__PSScriptPolicyTest_<random>.<random>.ps1`. | Nothing common. |

The NTFS rules compare `$SI` with every `$FILE_NAME` of the record, so a file with a long and an 8.3 name is checked against both. ext4 rows read through the `ext4-view` fallback get only `m_before_b`, `future` and `pre_1980`, because that fallback exposes no `ctime`. The raw ext4 reader also gives `m_after_c`. For the strongest NTFS check, give the `$MFT` and the `$UsnJrnl` of the same volume in one run and look at `usn_basic_info` next to `si_before_fn`, or run `--carve` on the image and look for `backdated`.

None of this is proof. It says where to look first.

## What lands in the tail

When a file's timestamps or name show a pattern, every row of the file says so in the analysis tail, in the convention masstin, caarea, faramir and allymacb share:

* **`hunt`.** A `high` rule (no ordinary explanation, and the pair `si_before_fn` + `si_subsec_zero`, the classic timestomp signature) gives `significant`. A `medium` rule (a pattern installers and copies also produce) gives `candidate`. When the statistical hunt also speaks, the stronger state wins.
* **`hunt_why`.** One clause per rule, `rule <id> (<level>): <what it means>`, strongest first, then what the volume said, then the hunt's own words. Filter on `rule ` to keep only what the rules said.
* **`hunt_score`.** The rule's measured rarity on masstin's scale (next section). Test and rules add, capped at 100.

The level is the author's opinion; the measurement decides. A rule measured below 10 points on the record's kind (it fires on more than one clean record in ten) is noise there. It gets no state and no points, only its clause.

## How much a rule is worth

Points are measured, not chosen: `10 · log10(records / records that fire)` on a clean reference volume of the record's kind.

* **NTFS:** the `$MFT` of a clean Windows Server 2016 lab host read from the live volume (431,153 file records, SQL Server Express and IIS installed, nothing planted), and its `$UsnJrnl:$J` (273,208 records) for the USN rule.
* **Unix:** the whole ext4 root of a clean Ubuntu 22.04 lab host (77,881 inodes, a bodyfile with birth times).

A pattern that never fired is not "never". It gets the bound the volume gives, one in `records + 1`: 56 points on the NTFS reference, 54 on the journal, 49 on the Unix root. A rule not measured yet adds 0 and its clause ends with `rarity not measured`.

| Rule | Level | Fired on | Points |
|---|---|---|---|
| `si_before_fn` | medium (high with `si_subsec_zero`) | 103,104 of 431,153 | 6: noise, no state, no points |
| `si_subsec_zero` | medium (high with `si_before_fn`) | 2,073 of 431,153 | 23 |
| `si_before_fn` with `si_subsec_zero` | high | 2,061 of 431,153 | 23 for the pair, not the sum |
| `b_after_c` | medium | 16,964 of 431,153 | 14 |
| `usn_basic_info` | high | 6,520 of 273,208 USN records | 16 |
| `future`, `pre_1980`, `rtlo_name`, `invisible_name`, `double_ext` | high | none of 431,153 | 56: one in 431,154 or rarer |
| `m_before_b` on a Unix record | medium | 71,982 of 77,881 | 0: noise |
| `future`, `pre_1980`, `m_after_c` on a Unix record | high | none of 77,881 | 49: one in 77,882 or rarer |
| `backdated` (high) | | no carving on the reference | not measured, 0 |
| `m_before_b` on an NTFS record | | | not measured, 0 |

NTFS records use the NTFS rarities; ext4, XFS, bodyfile and directory-walk records use the Unix ones.

**Why two rules are worth nothing.**
* On a stock Ubuntu root nearly every file has a modification time older than its creation, because packages ship files with the mtime of their build. That makes `m_before_b` noise on Unix.
* A quarter of the files of a clean Server 2016 have `$SI` times older than their `$FILE_NAME` ones, because the install lays them down with the times of the image. That makes `si_before_fn` alone noise on a modern Windows.

Both rules still fire and still say so in `hunt_why`.

The pair with `si_subsec_zero` is another matter: 2,061 records in 431,153, the timestomp signature, worth 23 points. On the reference, 918 of those 2,061 were written by the installation and 1,139 by the first boot of the machine, in one hour. The next section is what keeps them quiet.

On the Windows XP `$MFT` of the NIST Hacking Case, the previous reference, `si_before_fn` fired on 324 of 12,183 records and was worth 16. What a rule is worth depends on the generation of Windows it meets, and the table follows the modern one.

## The volume speaks first

A rule judges one record. The volume knows its own history, and two things in it make the rules fire by the thousand on a clean system. Read alone, the rules gave 8,169 records `significant` and 17,078 `candidate` (85,327 rows) on the clean Server 2016 of the reference.

### The installation window

A volume is born at a moment, the creation time of its first record (`$MFT` on NTFS, the root inode on Unix). It is then populated in one burst. On the reference, 98 % of the records changed in the four hours after the birth. Image extraction and servicing set times by hand: times preserved from the image, records reused by the servicing stack. As a result, 16,615 of the reference's 16,964 `b_after_c` fall in one of those hours.

The window runs from the birth hour through every following hour that still changed one record in a thousand of the volume. A record changed inside it, with no time later than its end, was installed with the volume and is `baseline`. Its time rules keep their clause and add nothing. A name rule and `backdated` still count. A `$UsnJrnl` given with the `$MFT` of the same volume takes the same window.

### The hour against clean hours

Outside the installation, every record with rules that count is judged together with the other records of its hour: the hour of its `$SI` change time, or of its creation when it was created after that change time (`b_after_c`: a copy keeps its source's change time, and a record cannot change before it exists). The yardstick is the hours of clean machines: 14 hours of `$MFT` records, 12 of journal records and 11 of a Unix root, measured by `scripts/measure_hours.py` and stored in `src/hours.rs`. The question is what share of the records that changed in that hour carry the same pattern, and how many clean hours reach that share. The p is empirical with the add-one correction, as in masstin's graph-hunt: `(1 + clean hours at or above the share) / (1 + clean hours)`.

* **Above `--alpha`: a clean machine does this.** The record is `habitual`, with no points, and the clause gives the numbers. For example, `1139 of the 3319 records changed in 2026-11-03T10 carry si_before_fn+si_subsec_zero and 1 of 14 clean hours reach that share (what a clean machine does)` is the first boot of a virtual machine, which the reference has too.
* **At or below `--alpha`: something happened that clean machines do not do.** Hundreds of records with the same pattern in one hour are one operation, not hundreds of anomalies. The first record keeps the state and the points and says `burst: … (the other N habitual)`. The others are `habitual`, with `same burst as record <meta>`.
* **A pattern no clean hour has at all** (`future`, `pre_1980`, the names, `backdated`) is never explained by its hour and never folded. Every record keeps its state: `… carry future and no clean hour has that pattern`.

What this can say is bounded by the clean hours measured. With fourteen hours, no share is rarer than one in fifteen. On an NTFS volume, only the patterns clean machines never produce reach a state. A lone preserved-time copy in a quiet hour will only reach one once the reference holds weeks of hours from clean machines.

With the volume's word, the clean server gives nothing at all. A second clean host the reference was not measured on (PTR-DC01, same image, a domain controller) gives nothing either. What the rules still find on their own is measured in [How it was checked](validation.md): the patterns clean machines never produce, with no false positive. The rest is the statistical hunt's job.

## What it looks like

```csv
1975-06-15T12:00:00Z,,,ma..,ext4,0,0,p1,100,-rw-r--r--,,133,/docs/ts1975.txt,ext4.img:p1,significant,49,"rule pre_1980 (high): a timestamp before 1980; rule m_before_b (medium): modification before creation",,
2022-05-16T21:40:04Z,,,m..b,mft,0,0,C:,16767,-/-rwxrwxrwx,,161232,C:\Program Files\OpenSSH\FixHostFilePermissions.ps1,$MFT,habitual,0,"rule si_before_fn (high): $SI creation before the $FILE_NAME creation; rule si_subsec_zero (high): $SI times in whole seconds, the $FILE_NAME ones not; 1139 of the 3319 records changed in 2026-11-03T10 carry si_before_fn+si_subsec_zero and 1 of 14 clean hours reach that share (what a clean machine does)",,
2026-11-03T10:45:03.984688500Z,,metadata,....,usn,0,0,C:,0,-/-rwxrwxrwx,,161142,C:\[UNKNOWN]\UsrClass.dat (USN: BASIC_INFO_CHANGE),$J,habitual,0,rule usn_basic_info (high): USN record of a timestamp or attribute change alone; 1561 of the 48719 records changed in 2026-11-03T10 carry usn_basic_info and 9 of 12 clean hours reach that share (what a clean machine does),,
2026-10-12T13:56:10Z,,,m...,mft,0,0,C:,14609165,-/-rwxrwxrwx,unallocated,369368,C:\[ORPHAN]\0050e6cabc4aa3b42d843675021947d643b9976e-1,$MFT,baseline,,rule b_after_c (medium): $SI creation after the record change time; installed with the volume from 2026-10-26T03:36:07Z to 2026-10-26T06:59:59Z (408887 of 417972 records),,
2026-11-03T12:06:01.983762Z,,,.a..,mft,0,0,C:,1015,-/-rwxrwxrwx,,214785,C:\Users\raj.helpdesk\AppData\Local\Microsoft\Windows\WinX\Group3\03 - Computer Management.lnk,stomped.mft,significant,93,"rule future (high): a timestamp more than a day after the timeline was built; rule b_after_c (medium): $SI creation after the record change time; rule si_subsec_zero (medium): $SI times in whole seconds, the $FILE_NAME ones not; 2 of the 504 records changed in 2026-11-03T12 carry future and no clean hour has that pattern",,
```

The first row is the ext4 lab volume. The other four are the clean Server 2016 of the reference; the last one comes from a copy of its `$MFT` with timestomps written into it by `scripts/hunt_inject.py`.
* The first boot laid down 1,139 files with the timestomp signature in one hour, and the volume says a clean machine does that.
* The hourly touch of `UsrClass.dat` is in 9 of the 12 clean journal hours.
* The orphan is one of the 16,615 `b_after_c` of the installation.
* The shortcut pushed to 2031 carries a pattern no clean hour has. It stays `significant` with the points of its three rules.

At the end of every run, quiet or not, stderr shows three things. It lists each file the rules make `significant` on its own line, up to 40 and then a count. It sums up the `candidate` ones. It says what the volume vouched for or folded:

```text
[ALERT] 3 file(s) `significant` by their rules (timestomping, name tricks), `rule <id> (high)` in hunt_why:
[ALERT]   pre_1980+si_before_fn              V:\docs\ts1975.txt  (meta 58)
[ALERT]   future                             V:\docs\ts2050.txt  (meta 59)
[ALERT]   rtlo_name                          V:\docs\report‮fdp.exe  (meta 63)
[*] C: $MFT: installed from 2026-10-26T03:36:07Z to 2026-10-26T06:59:59Z, 408887 of 417972 records
[*] C: $J: installed from 2026-10-26T03:36:07Z to 2026-10-26T06:59:59Z, 145493 of 273208 records
[*] 117492 file(s) installed with their volume: the rules that fired on them add nothing, `baseline` in the hunt column
[*] 3115 file(s) whose rules clean hours also show at that share of the records changed in their hour: `habitual`
```
