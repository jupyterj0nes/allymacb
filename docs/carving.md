# Carving

[← README](../README.md)

`--carve`: old `$MFT` records and `$I30` entries from raw sectors, the ext4 journal, and timestamped log lines and `utmp` records in free space.

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

## ext4: the journal

ext4 has no carvable record format, but it has a journal (jbd2) that keeps a copy of every metadata block as it was before each transaction: inode tables and directory blocks included. Modern kernels zero a directory entry when the file is removed, so the journal is the only place the name of a deleted file survives, and it also holds the previous size, timestamps and name of files that were modified, renamed or whose inode was reused. With `--carve`, every ext4 volume of the image gets its journal read:

* Inodes marked deleted in the live tables are named through the journal's directory copies instead of `/[UNKNOWN]/inode_N`.
* Older states of inodes that differ from the live one become `carved` rows, with the path as of that transaction, `deleted` set when the state is a deleted one, and `(carved @0xOFFSET)` pointing at the copy inside the journal.
* An older state of the same file (same creation time) with a later modification time than the live one marks both with `backdated`.
* Rows identical to live rows are dropped, as with NTFS.

The journal is small and circular (4 MiB on the lab volume, 128 MiB to 1 GiB on real systems), so it reaches back hours or days, not months.

## Timestamped artifacts in free space

Deleted or rotated logs leave their lines in unallocated blocks, and every line carries its own time. With `--carve`, the free space of each volume (from the ext4 block bitmaps or the NTFS `$Bitmap`; the gaps between partitions too) is searched for:

| Tag | Format | Example |
|---|---|---|
| `[syslog]` | RFC 3339 line (`2026-10-28T20:38:02.123456+00:00 host prog[pid]: …`) or BSD syslog (`Oct 28 20:38:02 host prog[pid]: …`). The BSD form has no year: the current one is assumed, or the previous one if that would be in the future. | `auth.log`, `syslog`, `kern.log`, journald exports |
| `[log]` | `YYYY-MM-DD HH:MM:SS …` at the start of the line, and apt's `Start-Date:` / `End-Date:` | `dpkg.log`, `apt/history.log`, most application logs |
| `[weblog]` | A `[DD/Mon/YYYY:HH:MM:SS +ZZZZ]` field anywhere in the line | Apache and nginx access logs |
| `[bash_history]` | `#<epoch>` followed by the command | `.bash_history` with `HISTTIMEFORMAT` |
| `[utmp]` | 384-byte glibc `utmp` records: type, user, tty, host, pid, time | `wtmp`, `btmp`, `utmp` |

Rows have `....` as type, the line as `file_name` (cut at 400 characters) and the absolute offset. Identical records are reported once. The search is restricted to free space on purpose: on allocated blocks it would be log parsing, which is another tool's job. A blob with no filesystem (a `blkls` output, a pagefile) is searched in full. Compressed rotated logs (`.gz`) and journald's binary files are not decoded; `lastlog` is not a `utmp` layout and is skipped.
