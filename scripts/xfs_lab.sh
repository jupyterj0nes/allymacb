#!/usr/bin/env bash
# XFS ground truth for allymacb, built by a real kernel.
#
#   sudo bash scripts/xfs_lab.sh [outdir]
#
# Needs xfsprogs (mkfs.xfs) and loop devices: a disposable Linux VM, or WSL 2
# with `sudo apt install xfsprogs`. Nothing outside the image is changed.
#
# Produces, in <outdir> (default /tmp/allymacb-xfslab):
#   xfs.img      64 MiB, no partition table, XFS v5 (crtime, ftype)
#   truth.json   `stat` of every file before and after the changes, and the
#                lists of what was deleted, where, and what was timestomped
#
# What is done on the volume:
#   /big          400 files: a directory stored in blocks (leaf form), from
#                 which 25 files are removed, so their names stay in the
#                 directory's free space
#   /small        3 files, one removed: a short-form directory, compacted on
#                 removal, whose deleted name is lost
#   /stomp        files with `touch -d` to 1975 and to 2050, and one whose
#                 mtime is set before its creation
set -eu
OUT="${1:-/tmp/allymacb-xfslab}"
MNT=/tmp/allymacb-xfslab-mnt
mkdir -p "$OUT" "$MNT"
cd "$OUT"
rm -f xfs.img truth.json

truncate -s 64M xfs.img
mkfs.xfs -q -f -L allymacb xfs.img
mount -o loop xfs.img "$MNT"

snapshot() {  # snapshot <file>: one JSON object per path, from stat
    find "$MNT" -mindepth 1 -printf '%P\n' | sort | while read -r p; do
        stat -c '{"path":"/%n","inode":%i,"size":%s,"mode":"%A","atime":"%.9X","mtime":"%.9Y","ctime":"%.9Z","crtime":"%.9W"}' "$MNT/$p" \
            | sed "s#/$MNT/#/#"
    done > "$1"
}

mkdir "$MNT/big" "$MNT/small" "$MNT/stomp"
for i in $(seq -w 1 400); do echo "file $i" > "$MNT/big/report_$i.txt"; done
for n in a b c; do echo "$n" > "$MNT/small/$n.txt"; done
echo old > "$MNT/stomp/ts1975.txt"
echo future > "$MNT/stomp/ts2050.txt"
echo back > "$MNT/stomp/backdated.txt"
sync
sleep 1
snapshot before.jsonl

touch -d '1975-06-15 12:00:00' "$MNT/stomp/ts1975.txt"
touch -d '2050-01-01 00:00:00' "$MNT/stomp/ts2050.txt"
touch -m -d '2020-01-01 00:00:00' "$MNT/stomp/backdated.txt"
DELETED=""
for i in 010 020 030 040 050 060 070 080 090 100 110 120 130 140 150 160 170 180 190 200 210 220 230 240 250; do
    rm "$MNT/big/report_$i.txt"
    DELETED="$DELETED\"/big/report_$i.txt\","
done
rm "$MNT/small/b.txt"
DELETED="$DELETED\"/small/b.txt\""
sync
snapshot after.jsonl
umount "$MNT"

{
    echo '{'
    echo '"before": ['; paste -sd, before.jsonl; echo '],'
    echo '"after": ['; paste -sd, after.jsonl; echo '],'
    echo "\"deleted\": [$DELETED],"
    echo '"slack_expected": "/big", "slack_lost": "/small",'
    echo '"stomped": {"/stomp/ts1975.txt": ["pre_1980"], "/stomp/ts2050.txt": ["future"], "/stomp/backdated.txt": ["m_before_b"]}'
    echo '}'
} > truth.json
rm -f before.jsonl after.jsonl
sha256sum xfs.img truth.json > sha256.txt
echo "done: $OUT/xfs.img, $OUT/truth.json"
