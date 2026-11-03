"""Writes timestomps into a copy of an $MFT the way the usual techniques leave
them, to check what the statistical hunt (--investigation-from) catches.

    python scripts/hunt_inject.py <src $MFT> <dst $MFT> <cutoff epoch> <truth.json>

Twenty files created after the cutoff are picked at even steps and get, in turn:

  setfiletime    B, M and A set to a whole-second 2003 date; C moved to the
                 time of the change (what SetFileTime and PowerShell leave)
  copy_kernel32  all four $SI times copied from kernel32.dll, sub-seconds
                 included (timestomp -f, SetMACE copying a reference file)
  move_trick     $SI set, the file moved so $FILE_NAME copies it, $SI set again:
                 every timestamp of the record is in 2003, in whole seconds
  future         B and M pushed to 2031

Only bytes inside the $SI and $FILE_NAME attributes change; the records keep
their fixups. The truth file maps record numbers to the technique.
"""
import json
import struct
import sys

EPOCH_DIFF = 11644473600
REC = 1024
OLD = 1046520000      # 2003-03-01 12:00:00 UTC
FUTURE = 1924992000   # 2031-01-01 00:00:00 UTC


def ft(epoch):
    return (epoch + EPOCH_DIFF) * 10_000_000


def unft(v):
    return v / 10_000_000 - EPOCH_DIFF


def resident_attrs(data, off):
    a = struct.unpack_from('<H', data, off + 0x14)[0]
    while a + 8 <= REC:
        t, ln = struct.unpack_from('<II', data, off + a)
        if t == 0xFFFFFFFF or ln == 0:
            break
        if not data[off + a + 8]:
            yield t, off + a + struct.unpack_from('<H', data, off + a + 0x14)[0]
        a += ln


def main():
    src, dst, cutoff, truth_path = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    data = bytearray(open(src, 'rb').read())
    recs = []
    for i in range(len(data) // REC):
        off = i * REC
        if data[off:off + 4] != b'FILE':
            continue
        flags = struct.unpack_from('<H', data, off + 0x16)[0]
        si = fn = None
        name = ''
        for t, p in resident_attrs(data, off):
            if t == 0x10 and si is None:
                si = p
            elif t == 0x30 and (fn is None or data[p + 0x41] in (1, 3)):
                fn = p
                name = data[p + 0x42:p + 0x42 + 2 * data[p + 0x40]].decode('utf-16le', 'replace')
        if si is not None and fn is not None:
            recs.append((i, off, flags, si, fn, name))

    k32 = next(r for r in recs if r[5].lower() == 'kernel32.dll')
    k32_si = struct.unpack_from('<QQQQ', data, k32[3])
    window = [r for r in recs
              if r[2] & 1 and not r[2] & 2 and '.' in r[5]
              and unft(struct.unpack_from('<Q', data, r[4] + 8)[0]) >= cutoff
              and not r[5].upper().endswith(('.DAT', '.LOG'))]
    window.sort(key=lambda r: r[0])
    pick = window[::max(1, len(window) // 20)][:20]

    truth = {}
    for n, (i, off, _, si, _, name) in enumerate(pick):
        b, m, c, a = struct.unpack_from('<QQQQ', data, si)
        kind = ('setfiletime', 'copy_kernel32', 'move_trick', 'future')[n % 4]
        if kind == 'setfiletime':
            struct.pack_into('<QQQQ', data, si, ft(OLD), ft(OLD), c + 1234567, ft(OLD))
        elif kind == 'copy_kernel32':
            struct.pack_into('<QQQQ', data, si, *k32_si)
        elif kind == 'move_trick':
            struct.pack_into('<QQQQ', data, si, *[ft(OLD)] * 4)
            for t, p in resident_attrs(data, off):
                if t == 0x30:
                    struct.pack_into('<QQQQ', data, p + 8, *[ft(OLD)] * 4)
        else:
            struct.pack_into('<QQQQ', data, si, ft(FUTURE), ft(FUTURE), c, a)
        truth[str(i)] = {'name': name, 'kind': kind}

    open(dst, 'wb').write(data)
    with open(truth_path, 'w') as f:
        json.dump(truth, f, indent=1)
    print(f'{len(window)} candidate files after the cutoff; {len(truth)} stomped')


if __name__ == '__main__':
    main()
