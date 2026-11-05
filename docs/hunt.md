# Statistical hunt

[← README](../README.md)

`--investigation-from`: which records touched since a date look unlike everything the volume did before, at a chosen false discovery rate.

The [anti-forensics indicators](anti-forensics.md) say what a record looks like. On a real system many of them fire on thousands of files: installers, archive extractors and copies that keep timestamps produce the same patterns as a timestomping tool. `--investigation-from` asks a different question: of the records touched since that time, which ones look unlike anything this volume did before?

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

A rule speaks in the same columns (see [Anti-forensics indicators](anti-forensics.md)): the stronger state wins, the points add, and the rule's clause comes before the hunt's words.

`hunt_score` is the q-value turned into a number people can read and filter, as masstin writes it: `-10 · log10(q)`, rounded, capped at 100. Ten points are one order of magnitude.

| `hunt_score` | q | Read as |
|---|---|---|
| 0 | 1 | no rarer than chance (every `habitual` record) |
| 13 | 0.05 | one in twenty (the default `--alpha`: `significant` starts here) |
| 20 | 0.01 | one in a hundred |
| 30 | 0.001 | one in a thousand |

The score a volume can reach is bounded by its history: the smallest p is 1 / (irregular baseline records + 1), and stderr prints the resulting ceiling per volume. On the NIST `$MFT` below it is 39; a volume with 15 irregular baseline records cannot pass 12, so nothing on it can be significant. A file judged by its rules alone carries their points; the exact p and q stay in `--hunt-out`.

stderr shows each volume's numbers and the significant records (here, the NIST `$MFT` with timestomps written into it by `scripts/hunt_inject.py`, see [How it was checked](validation.md)):

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
