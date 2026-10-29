"""Checks allymacb timelines of the Linux lab (scripts/linux_lab.sh) against
its truth.json.

    python scripts/check_linux_lab.py <truth.json> <timeline.csv> ext4|bodyfile|archive

For every file stat saw before the changes: is it in the timeline, do its
mtime and crtime rows match (ctime too for bodyfile input), and do the
timestomped / oddly named files carry the expected flags?
"""
import csv
import datetime
import json
import re
import sys
from collections import defaultdict


def flag_list(column):
    """Indicators of a flags column value ('ALERT: a+b' / 'WARN: a' / '')."""
    body = column.split(': ', 1)[1] if ': ' in column else column
    return [x for x in body.split('+') if x]


def iso_secs(s):
    """Unix seconds of an ISO 8601 UTC timestamp with up to 9 fractional digits."""
    s = re.sub(r'(\.\d{6})\d+', r'\1', s).replace('Z', '+00:00')
    return int(datetime.datetime.fromisoformat(s).timestamp())


def check(truth_path, csv_path, kind):
    truth = json.load(open(truth_path, encoding='utf-8'))
    rows = list(csv.DictReader(open(csv_path, newline='', encoding='utf-8')))
    deleted = set(truth['deleted'])
    out = [f'    rows {len(rows)}, sources {sorted({r["source"] for r in rows})}']

    tag = re.compile(r' \((deleted|carved @0x[0-9A-F]+)\)')

    def norm(name):
        # "[uac-host-linux] /docs/x", "/docs/x (deleted)", "/docs/x (carved @0x...)"
        if name.startswith('['):
            name = name.split('] ', 1)[1]
        return tag.sub('', name)

    by_path = defaultdict(list)
    for r in rows:
        by_path[norm(r['file_name'])].append(r)

    def in_deleted(p):
        return p in deleted or any(p.startswith(d + '/') for d in deleted)

    # The ext4 image is the volume after the changes; the bodyfile (loose or
    # inside the collection) was taken before them. Directories changed by the
    # deletions are compared with their post-change stat on the image.
    after = {f['path']: f for f in truth.get('after_changes', [])}
    expect = [f for f in truth['populated'] if kind != 'ext4' or (not in_deleted(f['path']) and f['path'] != '/moveme/moved.txt')]
    found = m_ok = b_ok = c_ok = size_ok = 0
    missing = []
    for f in expect:
        if kind == 'ext4' and f['dir'] and f['path'] in after:
            f = after[f['path']]
        rs = [r for r in by_path.get(f['path'], []) if r['source'] != 'carved']
        if not rs:
            missing.append(f['path'])
            continue
        found += 1
        secs = {r['type']: iso_secs(r['time_created']) for r in rs}
        def has(flag, want):
            return any(flag in t and s == want for t, s in secs.items())
        m_ok += has('m', f['mtime'])
        b_ok += has('b', f['crtime']) if f['crtime'] else 1
        c_ok += has('c', f['ctime'])
        size_ok += any(int(r['size']) == f['size'] for r in rs) or f['dir']
    out.append(f'    {len(expect)} files expected, {found} in timeline, mtime matches {m_ok}, crtime {b_ok}, ctime {c_ok}, size {size_ok}')
    for p in missing[:8]:
        out.append('        missing ' + p)

    # Deleted files on the image: the inode may still be in the table (rows
    # tagged "(deleted)", named through the journal) or only in the journal
    # (carved rows with the pre-deletion state).
    if kind == 'ext4':
        gone = [f for f in truth['populated'] if in_deleted(f['path']) and not f['dir']]
        named = pre_state = 0
        via = {}
        for f in gone:
            rs = by_path.get(f['path'], [])
            if rs:
                named += 1
                for s in {r['source'] for r in rs}:
                    via[s] = via.get(s, 0) + 1
            carved = [r for r in rs if r['source'] == 'carved']
            if any(int(r['size']) == f['size'] for r in carved) and any('m' in r['type'] and iso_secs(r['time_created']) == f['mtime'] for r in carved):
                pre_state += 1
        out.append(f'    deleted files: {len(gone)}; present with their path {named} (via {via}); pre-deletion size and mtime recovered from the journal for {pre_state}')

    # flags
    ok = 0
    for p, want in truth['expected_flags'].items():
        rs = by_path.get(p, [])
        got = set()
        for r in rs:
            got.update(x for x in flag_list(r['flags']))
        want = set(want)
        if kind == 'ext4':
            want.discard('m_after_c')   # ext4-view exposes no ctime
        if want <= got:
            ok += 1
        else:
            out.append(f'        flags for {p!r}: want {sorted(want)}, got {sorted(got)}')
    out.append(f'    expected indicators present on {ok}/{len(truth["expected_flags"])} files')
    # false positives on files that should be clean
    clean = [f['path'] for f in expect if f['path'] not in truth['expected_flags']]
    noisy = defaultdict(int)
    for p in clean:
        for r in by_path.get(p, []):
            for x in flag_list(r['flags']):
                noisy[x] += 1
    out.append(f'    indicators on files that should be clean: {dict(noisy) or "none"}')
    # mode rendering
    modes = {f['path']: f['mode'] for f in truth['populated']}
    for p in ['/keep/suidtool', '/keep/sticky', '/keep/link_to_report']:
        rs = by_path.get(p, [])
        if rs:
            out.append(f'    mode {p}: timeline {rs[0]["mode"]}, stat {modes.get(p)}')
    return out


if __name__ == '__main__':
    print('\n'.join(check(sys.argv[1], sys.argv[2], sys.argv[3])))
