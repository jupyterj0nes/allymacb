#!/usr/bin/env bash
# Ground truth for the Linux side of allymacb, built on a real ext4 volume.
#
# Run as root on a disposable Linux host (Ubuntu 22.04 was used). It creates
# a 64 MiB ext4 image, mounts it, fills it with files, timestomps some of them
# with touch, deletes files and a directory tree, and keeps:
#
#   ext4.img            the unmounted image (allymacb reads ext4 directly)
#   bodyfile.txt        TSK 3.x bodyfile of the volume, from stat (crtime included)
#   uac-<host>.tar.gz   a UAC-shaped collection: bodyfile/bodyfile.txt plus a
#                       copy of /etc under [root]/
#   truth.json          every file as stat saw it before the deletions, and the
#                       lists of deleted / timestomped paths with the expected flags
#   sha256.txt
#
# Copy the outputs to <samples>/lab_linux/ and run scripts/cross_examine.py.
set -euo pipefail
W=${1:-/tmp/rf-carve-linux}
MNT=$W/mnt
rm -rf "$W"; mkdir -p "$MNT"
HOST=$(hostname)

dd if=/dev/zero of="$W/ext4.img" bs=1M count=64 status=none
mkfs.ext4 -q -F "$W/ext4.img"
mount -o loop "$W/ext4.img" "$MNT"
cd "$MNT"

mk() { head -c "$2" /dev/urandom > "$1"; }
mkdir -p docs secret/inner keep moveme
for i in $(seq 1 30); do mk "docs/report_$i.txt" $((200 + i * 37)); done
for i in $(seq 1 25); do mk "secret/payroll_$i.xlsx" $((1500 + i * 101)); done
for i in $(seq 1 10); do mk "secret/inner/exfil_$i.zip" $((3000 + i * 211)); done
for i in $(seq 1 15); do mk "keep/config_$i.ini" $((100 + i * 13)); done
mk docs/big_video.mp4 $((5 * 1024 * 1024))
mk moveme/moved.txt 456
# names
mk "docs/informe ñandú ágil.txt" 777
mk "docs/報告書 2026.txt" 777
mk "docs/invoice.pdf.exe" 777
printf 'x' > "docs/$(printf 'report\xe2\x80\xaefdp.exe')"
mk "docs/=SUM(A1).txt" 100
# 25-level chain
d=.; for i in $(seq -w 1 25); do d="$d/d$i"; done; mkdir -p "$d"; mk "$d/deep_file.txt" 321
# symlink, suid, device-like perms, sticky dir
ln -s ../docs/report_1.txt keep/link_to_report
mk keep/suidtool 2048; chmod 4755 keep/suidtool
mkdir -p keep/sticky; chmod 1777 keep/sticky
sync; sleep 2

# --- timestomping ---------------------------------------------------------
mk docs/ts1975.txt 100; touch -d '1975-06-15 12:00:00 UTC' docs/ts1975.txt            # mtime+atime 1975: pre_1980, m_before_b
mk docs/ts2050.txt 100; touch -m -d '2050-01-01 00:00:00 UTC' docs/ts2050.txt         # future, m_after_c
mk docs/mplus.txt 100;  touch -m -d "$(date -u -d '+1 hour' '+%Y-%m-%d %H:%M:%S') UTC" docs/mplus.txt   # m_after_c only
mk docs/backdated.txt 100; touch -d '2020-03-04 05:06:07 UTC' docs/backdated.txt     # m_before_b (mtime < crtime), atime too
sync; sleep 1

# --- truth before deletions (stat: %W crtime, %Y mtime, %Z ctime, %X atime) ---
truth_lines() {
  find . -mindepth 1 -printf '%p\n' | sort | while read -r p; do
    stat --printf '%n|%s|%W|%Y|%Z|%X|%i|%A|%u|%g\n' "$p"
  done
}
truth_lines > "$W/stat_before.txt"
# bodyfile, TSK 3.x layout: MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
bodyfile() {
  find . -mindepth 1 -printf '%p\n' | sort | while read -r p; do
    stat --printf "0|${p#.}|%i|%A|%u|%g|%s|%X|%Y|%Z|%W\n" "$p"
  done
}
bodyfile > "$W/bodyfile.txt"

# --- changes ----------------------------------------------------------------
sleep 2
rm -f docs/report_1?.txt
rm -rf secret
mv moveme/moved.txt keep/moved.txt
mkdir -p new; for i in $(seq 1 20); do mk "new/replacement_$i.log" $((400 + i * 23)); done
sync; sleep 1
truth_lines > "$W/stat_after.txt"
cd /
umount "$MNT"

# --- UAC-shaped collection --------------------------------------------------
C="$W/uac-$HOST-linux"
mkdir -p "$C/bodyfile" "$C/[root]"
cp "$W/bodyfile.txt" "$C/bodyfile/bodyfile.txt"
cp -a /etc "$C/[root]/etc" 2>/dev/null || true
tar -C "$W" -czf "$W/uac-$HOST.tar.gz" "uac-$HOST-linux"
rm -rf "$C"

# --- truth.json ---------------------------------------------------------------
python3 - "$W" "$HOST" <<'EOF'
import json, sys
w, host = sys.argv[1], sys.argv[2]
def load(p):
    out = []
    for line in open(p, encoding='utf-8', errors='surrogateescape'):
        line = line.rstrip('\n')
        if not line: continue
        # name may contain '|'? not here; split from the right: 9 fields after name
        parts = line.rsplit('|', 9)
        name = parts[0][1:]  # strip leading '.'
        size, crtime, mtime, ctime, atime, inode, mode, uid, gid = parts[1:]
        out.append(dict(path=name, size=int(size), crtime=int(crtime), mtime=int(mtime), ctime=int(ctime),
                        atime=int(atime), inode=int(inode), mode=mode, uid=int(uid), gid=int(gid), dir=mode.startswith('d')))
    return out
before = load(f'{w}/stat_before.txt'); after = load(f'{w}/stat_after.txt')
deleted = [f'/docs/report_{i}.txt' for i in range(10, 20)] + [f['path'] for f in before if f['path'].startswith('/secret')]
expected_flags = {
    '/docs/ts1975.txt': ['pre_1980', 'm_before_b'],
    '/docs/ts2050.txt': ['future', 'm_after_c'],
    '/docs/mplus.txt': ['m_after_c'],
    '/docs/backdated.txt': ['m_before_b'],
    '/docs/invoice.pdf.exe': ['double_ext'],
    '/docs/report‮fdp.exe': ['rtlo_name'],
}
json.dump(dict(host=host, populated=before, after_changes=after, deleted=deleted, renamed=['/moveme/moved.txt'],
               expected_flags=expected_flags), open(f'{w}/truth.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('truth:', len(before), 'entries before,', len(after), 'after')
EOF
rm -f "$W/stat_before.txt" "$W/stat_after.txt"
rmdir "$MNT"
( cd "$W" && sha256sum ext4.img bodyfile.txt "uac-$HOST.tar.gz" truth.json > sha256.txt && cat sha256.txt )
