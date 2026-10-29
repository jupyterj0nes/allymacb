"""Checks the artifacts `allymacb --carve` recovered from the free space of
the lab image built by scripts/linux_lab_logs.sh against the original files.

    python scripts/check_linux_logs.py <lab dir> <timeline.csv>

Every original was copied into the image twice and one copy deleted, so each
timestamped line / utmp record of the originals should come back exactly
once (the deleted copy's blocks are free, the kept copy's are not, and
identical lines are deduplicated anyway). Lines carved that match no original
are false positives.
"""
import csv
import os
import re
import struct
import sys
from collections import Counter, defaultdict

MONTHS = {m: i + 1 for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}
ISO = re.compile(r'^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)')
BSD = re.compile(r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([ \d]\d) (\d\d):(\d\d):(\d\d) ')
CLF = re.compile(r'\[(\d\d)/(\w{3})/(\d{4}):(\d\d):(\d\d):(\d\d) [+-]\d{4}\]')
APT = re.compile(r'^(Start|End)-Date: (\d{4})-(\d\d)-(\d\d)  (\d\d):(\d\d):(\d\d)')
SUFFIX = re.compile(r' \(carved @0x[0-9A-F]+\)$')


def shown(line):
    """What the carver prints: control characters become spaces, 400 chars max."""
    line = ''.join(' ' if c < ' ' or c == '\x7f' else c for c in line).rstrip()
    return line[:400] + '…' if len(line) > 400 else line


def expected_lines(path):
    """Timestamped lines of one original, as the carver would show them."""
    out = []
    data = open(path, 'rb').read()
    lines = data.split(b'\n')
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = shown(raw.decode('utf-8', 'replace'))
        if line.startswith('#') and line[1:].isdigit() and i + 1 < len(lines):
            out.append(('bash_history', shown(lines[i + 1].decode('utf-8', 'replace'))))
            i += 2
            continue
        if ISO.match(line) or BSD.match(line) or CLF.search(line) or APT.match(line):
            out.append(('*', line))
        i += 1
    return out


def expected_utmp(path):
    out = []
    d = open(path, 'rb').read()
    names = ["EMPTY", "RUN_LVL", "BOOT_TIME", "NEW_TIME", "OLD_TIME", "INIT_PROCESS", "LOGIN_PROCESS", "USER_PROCESS", "DEAD_PROCESS", "ACCOUNTING"]
    for i in range(0, len(d) - 383, 384):
        r = d[i:i + 384]
        t = struct.unpack_from('<h', r, 0)[0]
        if not 1 <= t <= 9:
            continue
        pid = struct.unpack_from('<i', r, 4)[0]
        cs = lambda b: b.split(b'\0')[0].decode('utf-8', 'replace') or '-'
        out.append(('utmp', f'{names[t]} user={cs(r[44:76])} line={cs(r[8:40])} host={cs(r[76:332])} pid={pid}'))
    return out


def check(lab, csv_path):
    rows = list(csv.DictReader(open(csv_path, newline='', encoding='utf-8')))
    carved = defaultdict(set)   # kind -> texts
    for r in rows:
        if r['source'] != 'carved' or not r['file_name'].startswith('['):
            continue
        kind, text = r['file_name'][1:].split('] ', 1)
        carved[kind].add(SUFFIX.sub('', text))
    all_carved = set().union(*carved.values()) if carved else set()
    out = [f'    carved rows: ' + ', '.join(f'{k} {len(v)}' for k, v in sorted(carved.items()))]
    total_exp = total_hit = 0
    for name in sorted(os.listdir(os.path.join(lab, 'originals'))):
        p = os.path.join(lab, 'originals', name)
        if os.path.getsize(p) == 0:
            continue
        exp = expected_utmp(p) if name in ('wtmp', 'btmp', 'btmp_synth') else expected_lines(p)
        if not exp:
            out.append(f'    {name:<16} no timestamped records (not a format the carver knows)')
            continue
        hit = sum(1 for _, t in exp if t in all_carved)
        total_exp += len(exp)
        total_hit += hit
        out.append(f'    {name:<16} {hit:>5}/{len(exp):<5} recovered')
    out.append(f'    total {total_hit}/{total_exp} timestamped records recovered from free space')
    known = set()
    for name in os.listdir(os.path.join(lab, 'originals')):
        p = os.path.join(lab, 'originals', name)
        known.update(t for _, t in (expected_utmp(p) if name in ('wtmp', 'btmp', 'btmp_synth') else expected_lines(p)))
    fp = [t for t in all_carved if t not in known]
    out.append(f'    carved records matching no original (false positives / partial lines): {len(fp)}')
    for t in fp[:5]:
        out.append('        ' + t[:120])
    return out


if __name__ == '__main__':
    print('\n'.join(check(sys.argv[1], sys.argv[2])))
