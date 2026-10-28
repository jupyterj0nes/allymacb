#!/bin/bash
# Builds ext4 / GPT / MBR / 4Kn / split-raw test images and hostile archives.
# Needs e2fsprogs (mkfs.ext4, debugfs), util-linux (sfdisk), gdisk (sgdisk),
# python3 and tar. Runs unprivileged on Linux or WSL.
#   bash scripts/build_test_images.sh <output dir>
set -e
OUT=${1:?usage: build_test_images.sh <output dir>}
mkdir -p "$OUT"
W=$(mktemp -d /tmp/allymacb_build.XXXX)
cd "$W"

# ---------- ext4 content tree ----------
mkdir -p tree/etc tree/home/user/docs tree/var/log tree/deep
printf 'root:x:0:0:root:/root:/bin/bash\n' > tree/etc/passwd
printf 'secret\n' > tree/etc/shadow
chmod 0640 tree/etc/shadow
printf 'hello\n' > tree/home/user/docs/notes.txt
printf 'bin\n' > tree/home/user/suidtool
chmod 4755 tree/home/user/suidtool
printf 'log line\n' > tree/var/log/syslog
ln -s /etc/passwd tree/home/user/link_to_passwd
# non-UTF-8 directory and file names (Latin-1 0xE9)
mkdir -p "tree/data/caf$(printf '\xe9')"
printf 'x\n' > "tree/data/caf$(printf '\xe9')/inside.txt"
printf 'y\n' > "tree/data/na$(printf '\xef')ve.txt"
# formula-injection and comma names
printf 'z\n' > 'tree/home/user/=cmd|calc.txt'
printf 'w\n' > 'tree/home/user/a,b "q".txt'
# deep nesting
d=tree/deep; for i in $(seq 1 40); do d="$d/l$i"; mkdir -p "$d"; done; printf 'bottom\n' > "$d/bottom.txt"
# fixed known timestamps
touch -d '2001-09-09 01:46:40 UTC' tree/etc/passwd
touch -d '2024-02-04 12:35:00 UTC' tree/home/user/docs/notes.txt
touch -d '1999-12-31 23:59:59 UTC' tree/var/log/syslog
printf 'future\n' > tree/home/user/future.txt
printf 'past\n' > tree/home/user/past.txt

# ---------- plain ext4 image ----------
truncate -s 32M ext4_plain.img
mkfs.ext4 -q -F -d tree ext4_plain.img
# timestomp: post-2038 and pre-1970 through debugfs (raw high bit -> ext4-view cannot decode)
debugfs -w -R "set_inode_field /home/user/future.txt mtime 20400101000000" ext4_plain.img >/dev/null 2>&1 || true
debugfs -w -R "set_inode_field /home/user/past.txt mtime 19691231000000" ext4_plain.img >/dev/null 2>&1 || true
e2fsck -fn ext4_plain.img >/dev/null 2>&1 || true
cp ext4_plain.img "$OUT/ext4_plain.img"

# ---------- GPT disk, 512-byte sectors: EFI(empty), ext4, ext4 ----------
truncate -s 96M gpt_512.img
sgdisk -o -n 1:2048:4095 -t 1:ef00 -n 2:4096:67583 -t 2:8300 -n 3:67584:0 -t 3:8300 gpt_512.img >/dev/null
truncate -s 31M p2.img; mkfs.ext4 -q -F -d tree p2.img
mkdir -p tree3/only_on_p3; printf 'p3\n' > tree3/only_on_p3/marker.txt
truncate -s 28M p3.img; mkfs.ext4 -q -F -d tree3 p3.img
dd if=p2.img of=gpt_512.img bs=512 seek=4096 conv=notrunc status=none
dd if=p3.img of=gpt_512.img bs=512 seek=67584 conv=notrunc status=none
cp gpt_512.img "$OUT/gpt_512.img"

# ---------- MBR disk with extended partition and logical ext4 ----------
truncate -s 96M mbr_ext.img
sfdisk -q mbr_ext.img <<'SF'
label: dos
unit: sectors
1 : start=2048, size=32768, type=83
2 : start=34816, size=131072, type=5
5 : start=36864, size=65536, type=83
SF
truncate -s 16M p1.img; mkfs.ext4 -q -F -d tree3 p1.img
truncate -s 32M p5.img; mkfs.ext4 -q -F -d tree p5.img
dd if=p1.img of=mbr_ext.img bs=512 seek=2048 conv=notrunc status=none
dd if=p5.img of=mbr_ext.img bs=512 seek=36864 conv=notrunc status=none
cp mbr_ext.img "$OUT/mbr_ext.img"

# ---------- GPT disk with 4096-byte sectors ----------
truncate -s 96M gpt_4kn.img
sgdisk -o gpt_4kn.img >/dev/null 2>&1 || true
# sgdisk cannot pick a sector size on a file; craft the 4Kn table with python
python3 - <<'PY'
import struct, zlib, uuid
SS=4096
img=open('gpt_4kn.img','r+b')
# protective MBR
mbr=bytearray(SS)
mbr[446+4]=0xEE
mbr[446+8:446+12]=struct.pack('<I',1)
mbr[446+12:446+16]=struct.pack('<I',0xFFFFFFFF)
mbr[510]=0x55; mbr[511]=0xAA
img.seek(0); img.write(mbr)
# entries: one ext4 at LBA 256 (1 MiB), size 32 MiB
entries=bytearray(128*128)
t=uuid.UUID('0FC63DAF-8483-4772-8E79-3D69D8477DE4').bytes_le
u=uuid.uuid4().bytes_le
first=256; last=first+ (32*1024*1024)//SS -1
entries[0:16]=t; entries[16:32]=u
entries[32:40]=struct.pack('<Q',first); entries[40:48]=struct.pack('<Q',last)
entries[56:56+2*len('ext4')]= 'ext4'.encode('utf-16-le')
img.seek(2*SS); img.write(entries)
hdr=bytearray(92)
hdr[0:8]=b'EFI PART'; hdr[8:12]=struct.pack('<I',0x00010000); hdr[12:16]=struct.pack('<I',92)
hdr[24:32]=struct.pack('<Q',1); hdr[32:40]=struct.pack('<Q',(96*1024*1024)//SS-1)
hdr[40:48]=struct.pack('<Q',34); hdr[48:56]=struct.pack('<Q',(96*1024*1024)//SS-34)
hdr[56:72]=uuid.uuid4().bytes_le
hdr[72:80]=struct.pack('<Q',2); hdr[80:84]=struct.pack('<I',128); hdr[84:88]=struct.pack('<I',128)
hdr[88:92]=struct.pack('<I',zlib.crc32(bytes(entries)) & 0xffffffff)
hdr[16:20]=struct.pack('<I',zlib.crc32(bytes(hdr)) & 0xffffffff)
img.seek(SS); img.write(hdr)
img.close()
PY
dd if=p2.img of=gpt_4kn.img bs=4096 seek=256 conv=notrunc status=none
cp gpt_4kn.img "$OUT/gpt_4kn.img"

# ---------- split raw of the MBR image (.001 .002 .003) ----------
split -b 40M -d -a 3 --additional-suffix= mbr_ext.img mbr_split.
i=1; for f in mbr_split.*; do cp "$f" "$OUT/mbr_split.$(printf '%03d' $i)"; i=$((i+1)); done

# ---------- hostile tar: path traversal + absolute path ----------
python3 - <<'PY'
import tarfile, io
def add(t, name, data):
    ti=tarfile.TarInfo(name); ti.size=len(data); ti.mtime=1000000000
    t.addfile(ti, io.BytesIO(data))
with tarfile.open('evil.tar','w') as t:
    add(t,'../../ALLYMACB_ESCAPE.txt',b'owned')
    add(t,'/tmp/ALLYMACB_ABS.txt',b'owned')
    add(t,'safe/inside.txt',b'fine')
PY
cp evil.tar "$OUT/evil.tar"

# ---------- UAC-like collection: outer tar.gz containing bodyfile + inner tar.gz ----------
mkdir -p uac/bodyfile uac/inner
cat > uac/bodyfile/bodyfile.txt <<'BF'
0|/etc/passwd|4230|-rw-r--r--|0|0|2323|1710234798|1710234798|1710247956|0
0|/tmp/a|b.txt|100|-rw-r--r--|1000|1000|5|1700000000|1700000001|1700000002|1700000003
0|/tmp/old|101|-rw-r--r--|0|0|5|-86400|1700000001|1700000002|1700000003
garbage line that must be rejected
BF
printf 'x\n' > uac/inner/file.txt
tar -C uac -czf inner.tar.gz inner
cp inner.tar.gz uac/inner.tar.gz
tar -C . -czf "$OUT/uac-server01.tar.gz" uac
# plain gzip bodyfile
gzip -c uac/bodyfile/bodyfile.txt > "$OUT/bodyfile.txt.gz"

# ---------- Linux triage directory as tar (for -d after extraction) ----------
tar -C . -cf "$OUT/linux_tree.tar" tree

ls -la "$OUT"
rm -rf "$W"
