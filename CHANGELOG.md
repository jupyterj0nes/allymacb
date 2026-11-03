# Changelog

## Unreleased

### The timeline lines up with masstin's, column for column

The CSV has masstin's 19 columns: 14 that describe the event, each in the position of the masstin column closest in meaning, then the five-column analysis tail the four tools share (masstin, caarea, faramir and allymacb), so their timelines read side by side and a case tool maps the tail once.

- **19 columns.** `time_created,host,action,type,source,uid,gid,volume,size,mode,deleted,meta,file_name,evidence` and `hunt,hunt_score,hunt_why,verdict,notes`. `host` takes the place of the `[host]` prefix `file_name` used to carry; `action` says what a USN record did (`created`, `deleted`, `renamed`, `modified`, `metadata`); `volume` is `C:` for a loose `$MFT` or `$J` and `p1`, `p2`... for the partitions of an image; `deleted` says how a file is known to be gone (`unallocated`, `dtime`, `usn`) instead of a ` (deleted)` tag in its name; `evidence` names the input from the outside in, as masstin's `log_filename` does (`disk.E01:p2:$MFT`, `kape.zip:C/$MFT`). The `flags` column is gone: the rules speak in the tail.
- **Statistical hunt for manipulated timestamps** (`--investigation-from`, `--alpha`, `--hunt-out`). Records active from the cutoff on are tested against the earlier records of the same volume (conformal p-values, Benjamini-Hochberg); every row gets the verdict on its record. `hunt_score` is masstin's `-10 · log10(q)`, 0 to 100, and stderr prints the highest score each volume can reach. `--hunt-out` writes the findings table in the 19 columns of masstin's, with allymacb's names. On the NIST Hacking Case `$MFT` with 20 timestomps written into it: 14 significant, no false positive.

### The tail speaks the shared convention

The tail follows masstin's `docs/csv-format.md`, section "The same tail in caarea, faramir and allymacb".

- **`hunt` has masstin's six words only:** `significant`, `candidate`, `habitual`, `not_evaluated`, `baseline` or nothing. A high rule (what the timeline called `ALERT`) gives `significant`, a medium one (`WARN`) `candidate`, and when a test and a rule both speak the stronger state wins. `suspicious` and `review` are no longer written: `suspicious` is the analyst's word, in `verdict`.
- **`hunt_why` names the source.** Each rule's clause begins with its id and level, `rule si_before_fn (high): $SI creation before the $FILE_NAME creation`, strongest first, separated by `; `, before the test's words. It replaces the `ALERT: a+b` / `WARN: a` head. Filtering `hunt_why` on `rule ` keeps what the rules said.
- **`hunt_score` is rarity for rules too.** A row with rules alone used to have an empty score. A rule now adds its rarity measured on a clean volume, `10 · log10(records / records that fire)` on the 12,183 file records of the NIST Hacking Case `$MFT`: `si_before_fn` 16, `si_subsec_zero` 17, the two together 17 (measured as a pair, not summed), `b_after_c` 17, and 41 for `future`, `pre_1980` and the name rules, which fired on none. The Unix rules, `usn_basic_info`, `backdated` and every rule on a non-NTFS row are not measured yet: they add 0 and their clause ends with `rarity not measured`. Test and rules add, capped at 100.
- The `rules` column of `--hunt-out` gives the ids with their level, `future (high)+b_after_c (medium)`. stderr says `high-level` / `medium-level` and where each lands in the tail.
- **The 14 event columns are unchanged, byte for byte**, against the build before this change: the NIST `$MFT` with and without the hunt (33,809 rows), a VHD with two partitions carved, a raw ext4 image, a UAC collection and a `$J`. Only the tail differs.

## v0.1.0 — 2026-10-29

First release: MACB timeline from `$MFT`, `$UsnJrnl:$J`, bodyfiles, ext4 read from the disk, images (E01, raw, split raw, fixed VHD), archives and triage directories; anti-forensics indicators; carving of NTFS records and `$I30` entries; release binaries for Windows, Linux and macOS.
