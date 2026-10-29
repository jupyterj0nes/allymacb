"""Checks an allymacb timeline of a lab VHD against the truth.json that
scripts/carve_lab.ps1 wrote next to it.

    python scripts/check_carve_lab.py <truth.json> <timeline.csv>

The truth file lists every file as it was right after population (sizes,
timestamps, MFT record numbers) and again after the changes, plus which paths
were deleted, modified and renamed. The check reports, per category, how many
items the timeline contains, through which `source`, and whether the state
that only existed before the changes (old size, old name, the file that used
to own a reused record) was recovered by carving.
"""
import csv
import json
import re
import sys
from collections import defaultdict

TAG = re.compile(r' \((deleted|\$FILE_NAME: [^)]*|\$I30|carved @0x[0-9A-F]+|USN: [^)]*)\)')
BS = chr(92)


def _norm(p):
    p = TAG.sub('', p).strip()
    if len(p) > 2 and p[1] == ':':
        p = p[2:]
    return p.rstrip(BS) or BS


def _base(p):
    return _norm(p).rsplit(BS, 1)[-1]


def check(truth_path, csv_path):
    """Returns the report as a list of lines."""
    truth = json.load(open(truth_path, encoding='utf-8-sig'))
    rows = list(csv.DictReader(open(csv_path, newline='', encoding='utf-8')))
    populated = {f['path']: f for f in truth['populated']}
    after = {f['path']: f for f in truth['after_changes']}
    deleted = set(truth['deleted'])
    modified = set(truth['modified'])
    renamed = set(truth['renamed'])

    def in_deleted_tree(p):
        return p in deleted or any(p.startswith(d + BS) for d in deleted)

    by_path = defaultdict(list)
    by_base = defaultdict(list)
    for r in rows:
        by_path[_norm(r['file_name'])].append(r)
        by_base[_base(r['file_name'])].append(r)

    def rows_for(path):
        rs = by_path.get(path, [])
        if not rs:
            rs = [r for r in by_base.get(path.rsplit(BS, 1)[-1], []) if '[ORPHAN]' in r['file_name']]
        return rs

    out = [f'    rows {len(rows)}, carved {sum(1 for r in rows if r["source"] == "carved")}']

    def summarize(label, paths, want_old_size=False):
        found = old_state = 0
        via = defaultdict(int)
        missing = []
        for p in sorted(paths):
            rs = rows_for(p)
            if not rs:
                missing.append(p)
                continue
            found += 1
            for s in sorted({r['source'] for r in rs}):
                via[s] += 1
            if want_old_size and any(r['size'] == str(populated[p]['size']) and r['source'] == 'carved' for r in rs):
                old_state += 1
        extra = f', pre-change size recovered by carving for {old_state}' if want_old_size else ''
        out.append(f'    {label:<10} {len(paths):>3} items, {found:>3} in timeline, via {dict(via)}{extra}')
        for p in missing[:8]:
            out.append('               missing ' + p)

    surviving = [p for p in populated if not in_deleted_tree(p) and p not in modified and p not in renamed]
    summarize('surviving', surviving)
    summarize('modified', sorted(modified), want_old_size=True)
    summarize('renamed', sorted(renamed))
    summarize('deleted', sorted(p for p in populated if in_deleted_tree(p)))

    old_ids = {f['record']: p for p, f in populated.items() if f.get('record') is not None}
    reused = {p: f['record'] for p, f in after.items() if p.startswith(BS + 'new' + BS) and f.get('record') in old_ids}
    hit = sum(1 for r in reused.values() if any(x['source'] == 'carved' for x in rows_for(old_ids[r])))
    out.append(f'    MFT records reused by the replacement files: {len(reused)}; previous owner recovered by carving: {hit}/{len(reused)}')
    return out


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    print('\n'.join(check(sys.argv[1], sys.argv[2])))
