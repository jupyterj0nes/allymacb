# Output

[← README](../README.md)

The timeline CSV column by column, what each source fills, what goes to stdout and stderr, exit codes and error codes.

```csv
time_created,host,action,type,source,uid,gid,volume,size,mode,deleted,meta,file_name,evidence,hunt,hunt_score,hunt_why,verdict,notes
1991-10-03T02:25:06Z,uac_results_server01,,m...,bodyfile,0,0,,72834,-rw-r--r--,,8989,/usr/share/fonts/putb.pfa,uac_results_server01.tar.gz:bodyfile.txt,,,rule m_before_b (medium): modification before creation,,
2024-02-04T12:35:00Z,,,macb,mft,0,0,p2,1024,-/-rwxrwxrwx,,34567,C:\Windows\System32\cmd.exe,disk.E01:p2:$MFT,,,,,
2024-02-04T12:35:00Z,,,macb,mft,0,0,p2,1024,-/-rwxrwxrwx,,34567,C:\Windows\System32\cmd.exe ($FILE_NAME: cmd.exe),disk.E01:p2:$MFT,,,,,
2024-02-03T09:12:41Z,,,macb,carved,0,0,p2,1024,-/-rwxrwxrwx,unallocated,34567,C:\Windows\System32\cmd.exe (carved @0x1A2B3C00),disk.E01:p2,,,,,
2026-09-23T23:05:14Z,uac-server02,,.a..,ext4,0,0,p1,1261,drwxr-xr-x,dtime,1572998,/boot/grub2/datetime.mod,uac-server02.tar.gz:disk.img:p1,,,,,
2026-09-24T18:42:22Z,,created,....,usn,0,0,C:,4096,-/-rwxrwxrwx,,45120,C:\Windows\Temp\payload.exe (USN: FILE_CREATE+CLOSE),$J,significant,17,$SI creation before the $FILE_NAME creation; creation time in whole seconds,,
2001-01-01T00:00:00Z,,,macb,mft,0,0,C:,4096,-/-rwxrwxrwx,,45120,C:\Windows\Temp\payload.exe,$MFT,significant,40,"rule si_before_fn (high): $SI creation before the $FILE_NAME creation; rule si_subsec_zero (high): $SI times in whole seconds, the $FILE_NAME ones not; $SI creation before the $FILE_NAME creation; creation time in whole seconds",,
```

The last two rows come from a run with `--investigation-from`. The last one has both voices: its rules (23 points, measured) and the statistical hunt (17 points) add up to 40. Without `--investigation-from`, a row with rules carries the state they give and their points; a row without any is left with an empty tail. The first row shows a rule measured common on its kind of record (`m_before_b` on Unix, see [Anti-forensics indicators](anti-forensics.md#how-much-a-rule-is-worth)): it gives no state and no points, only its clause.

The 19 columns are those of [masstin's timeline](https://github.com/jupyterj0nes/masstin/blob/main/docs/csv-format.md), each in the position of the masstin column closest in meaning, so a timeline of each read side by side keeps the same kind of value in the same column:

| # | masstin | allymacb | |
|---|---|---|---|
| 1 | `time_created` | `time_created` | UTC ISO 8601 timestamp of the event the row represents. Sub-second digits are printed when present. |
| 2 | `dst_computer` | `host` | The collection the row came from: the name of a UAC or KAPE archive, or the stem of a bodyfile (`server01.body`). Empty for a loose `$MFT` or an image. |
| 3 | `event_type` | `action` | What happened to the file, when the evidence says it: `created`, `deleted`, `renamed`, `modified` or `metadata`. Only USN rows carry it for now. |
| 4 | `event_id` | `type` | MACB flags of that timestamp (`macb`, `m...`, `.a..`, `..c.`, `...b`, combinations, or `....` for USN rows). |
| 5 | `logon_type` | `source` | What the row was built from: `mft`, `usn`, `bodyfile`, `ext4`, `xfs`, `fs` (host filesystem metadata of a directory walk or an extracted archive) or `carved`. |
| 6 | `target_user_name` | `uid` | Unix owner, `0` for NTFS. |
| 7 | `target_domain_name` | `gid` | Unix group, `0` for NTFS. |
| 8 | `src_computer` | `volume` | `C:` for a loose `$MFT` or `$J` (the drive letter of `-m`), `p1`, `p2`... for the partitions of an image in the order they were found, `p2:vg/lv` for a logical volume in an LVM partition. |
| 9 | `src_ip` | `size` | File size in bytes. |
| 10 | `subject_user_name` | `mode` | `ls -l` style permissions. NTFS has none, so NTFS rows use the `mactime` convention `-/-rwxrwxrwx` and `d/drwxrwxrwx`. |
| 11 | `subject_domain_name` | `deleted` | How the file is known to be deleted: `unallocated` (NTFS record not in use, ext4 inode without links, freed XFS inode), `dtime` (ext4 inode with a deletion time), `usn` (USN record with `FILE_DELETE`). Empty for a live file. |
| 12 | `logon_id` | `meta` | Inode or MFT record number: what ties the rows of one file together. |
| 13 | `detail` | `file_name` | Full path, with tags: `($FILE_NAME: name)`, `(USN: REASON+REASON)`, `($I30)`, `(carved @0xOFFSET)`. |
| 14 | `log_filename` | `evidence` | The input the row was read from, outermost first: `disk.E01:p2:$MFT`, `kape.zip:C/$MFT`, `triage:C/$Extend/$UsnJrnl%3A$J`. |
| 15 | `hunt` | `hunt` | The verdict on the row's file (see below). |
| 16 | `hunt_score` | `hunt_score` | How rare the file is, 0 to 100, on masstin's scale: the [statistical hunt](hunt.md)'s `-10 · log10(q)` plus the measured rarity of its [rules](anti-forensics.md), capped at 100. |
| 17 | `hunt_why` | `hunt_why` | One clause per rule, `rule <id> (<level>): ...`, strongest first, then what the hunt found unusual, in words. Clauses are separated by `; `. |
| 18 | `verdict` | `verdict` | The analyst's; written empty. |
| 19 | `notes` | `notes` | The analyst's; written empty. |

On masstin's columns 6 to 11 sit who logged in and from where; a filesystem keeps no author of a change, so those positions hold the file's attributes. The last five columns are masstin's analysis tail, with its names and its vocabulary, which masstin, caarea, faramir and allymacb share ([masstin's csv-format](https://github.com/jupyterj0nes/masstin/blob/main/docs/csv-format.md#the-same-tail-in-caarea-faramir-and-allymacb)). `hunt` holds one of six words: `significant`, `candidate`, `habitual`, `not_evaluated`, `baseline`, or nothing. The statistical hunt gives one, a rule another (a high rule `significant`, a medium one `candidate`), and the stronger wins; the volume has the first word on its own records (installed with it: `baseline`; one of a burst: `habitual`, see [Anti-forensics indicators](anti-forensics.md#the-volume-speaks-first)). `suspicious` is not among them: that is the analyst's word, in `verdict`. To keep only what the rules said, filter `hunt_why` on `rule `; to keep only the statistics, on its absence.

Every column is RFC 4180 escaped. `meta` and `file_name` come from the evidence, so a value starting with `=`, `+`, `-`, `@`, tab or CR is written quoted with a leading apostrophe. A file named `=cmd|' /C calc'!A0` does not execute when the CSV is opened in a spreadsheet.

## Per source

| Source | m | a | c | b | Notes |
|---|---|---|---|---|---|
| `$MFT`, `$STANDARD_INFORMATION` | yes | yes | yes | yes | `-n` adds `$FILE_NAME` rows. Size comes from the non-resident `$DATA` header, so files above the resident limit report their real size. ADS get their own rows with the same flags as the host record. Pre-1970 timestamps are kept; only FILETIME 0 is dropped. |
| `$UsnJrnl:$J` | | | | | Rows are `....` with the reason flags in the name; `action` and `deleted` come from them. |
| Bodyfile | yes | yes | yes | yes | Split from the right, so a `\|` inside a path does not shift the columns. `0` means unset. Lines with non-numeric uid, gid or size are rejected and counted. |
| ext4 | yes | yes | yes | yes | Read from the on-disk structures: inode number in `meta`, `ctime`, timestamps past 2038, and the inodes still marked deleted in the tables, with `deleted` set. SUID, SGID, sticky and device types are rendered. ext2 and ext3 block maps are followed too. |
| XFS | yes | yes | yes | yes (v5) | Every inode of every allocation group, read with the [rust-fs-xfs](https://github.com/antimatter-studios/rust-fs-xfs) driver: inode number in `meta`, nanoseconds, `crtime` on v5 filesystems (the default since RHEL 7.3). Freed inodes keep their creation time and the time of their last change (usually the deletion): `deleted` is `unallocated`, the name comes from directory slack when it survives (`(dir slack)`), otherwise `/[UNKNOWN]/inode_N`. |
| LVM2 | | | | | Not a filesystem: each linear logical volume of a physical volume is read as the ext4 or XFS it holds, with `volume` set to `p2:vg/lv`. |
| Directory walk | yes | yes | Unix only | yes | Timestamps come from the host filesystem, and the tool says so. Real mode, uid, gid and inode on Unix hosts. |
| Archive without artifacts | yes | | | | A zip or tar only preserves modification times. |
| Carved `FILE` record | yes | yes | yes | yes | Same rows as a live record (`-n` applies), tagged `(carved @0xOFFSET)` with the absolute offset in the image or file. `source` is `carved`. |
| Carved `$I30` entry | yes | yes | yes | yes | The `$FILE_NAME` copy kept in the directory index, tagged `($I30)`. Size and timestamps are the index's own. |

Orphans: an NTFS parent reference carries the sequence number of the directory record it pointed to. When that record has since been freed and reused, the file is reported as `[ORPHAN]\name` instead of being attached to whatever directory lives there now. This is what SleuthKit does with `$OrphanFiles`. A parent chain that loops, which only a crafted `$MFT` produces, is reported as `[CYCLE]\name`.

## stdout, stderr and exit codes

The CSV is the only thing written to stdout. The banner, progress bars, `[*]` status lines, `[!]` warnings and the final summary go to stderr.

| Exit code | Meaning |
|---|---|
| 0 | Every source was parsed. |
| 1 | Usage error. |
| 2 | Nothing could be parsed. No CSV is written. |
| 3 | CSV written, but at least one source failed or was missing, or the hunt CSV could not be written. The failures are listed on stderr. |

Anything skipped is reported: unreadable images, corrupt archives, rejected bodyfile lines, archive entries that tried to escape the extraction directory, ext4 inodes that could not be decoded. A short timeline is never silent.

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
| E4101 | `ERR_XFS_SUPERBLOCK_4101` | XFS superblock missing, corrupt or of a version the driver refuses |
| E4102 | `ERR_XFS_METADATA_4102` | XFS inode or directory could not be read |
| E4201 | `ERR_LVM_METADATA_4201` | LVM physical volume label or metadata could not be read |
| E5001 | `ERR_ARCHIVE_DECOMPRESS_5001` | Decompression failed |
| E5002 | `ERR_ARCHIVE_CORRUPT_5002` | Archive structure corrupted |
| E5003 | `ERR_ARCHIVE_UNSUPPORTED_5003` | Archive type not supported |
| E6001 | `ERR_IMAGE_READ_6001` | Image read or seek failure |
| E6002 | `ERR_IMAGE_PARTITION_6002` | No NTFS, ext4, XFS or LVM volume found |
| E6003 | `ERR_IMAGE_UNSUPPORTED_6003` | VHDX, VMDK, dynamic VHD, QCOW or VDI container |
| E7001 | `ERR_BODYFILE_FIELDS_7001` | Bodyfile line does not have 11 fields |
| E7002 | `ERR_BODYFILE_TIMESTAMP_7002` | Non-numeric timestamp in a bodyfile line |
| E7003 | `ERR_BODYFILE_NUMERIC_7003` | uid, gid or size is not an unsigned integer |
| E8001 | `ERR_TIMESTAMP_RANGE_8001` | Timestamp outside the supported range |
| E8002 | `ERR_FILETIME_INVALID_8002` | FILETIME is zero, negative or before 1601 |
| E9001 | `ERR_CSV_EXPORT_9001` | CSV could not be created or flushed |
| E10001 | `ERR_EVIDENCE_UNRECOGNIZED_10001` | Input is not a recognised evidence type |
| E10002 | `ERR_EVIDENCE_NOTHING_PARSED_10002` | No source could be parsed |
