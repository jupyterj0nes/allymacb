# Demo recordings

The GIFs in `resources/demo-*.gif` are recorded from these tapes with [VHS](https://github.com/charmbracelet/vhs) (`vhs demo-carve.tape`). Replace `<allymacb dir>` with the folder of the binary and `<evidence dir>` with a folder that holds:

- `demo-carve.tape`: `reformat.vhd`, the quick-formatted NTFS volume `scripts/carve_lab.ps1` builds on a disposable Windows VM.
- `demo-hunt.tape`: `nist_stomped.mft`, the NIST Hacking Case `$MFT` (public, from [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs)) with 20 files timestomped by `python scripts/hunt_inject.py nist-hacking-case.mft nist_stomped.mft 1093478400 truth.json`.

Under VHS the progress bars run slower than in a terminal; the tapes hide the wait and show the end of each run.
