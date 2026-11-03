"""Scores a hunt CSV (--hunt-out) against the truth file of hunt_inject.py.

    python scripts/check_hunt.py <truth.json> <hunt.csv>

Per technique: how many stomped records were significant, tested but not
significant, or not tested at all. Then every significant record that was not
stomped (a false positive).
"""
import csv
import json
import sys
from collections import Counter


def main():
    truth = json.load(open(sys.argv[1]))
    rows = {r['lookup'].removeprefix('meta='): r for r in csv.DictReader(open(sys.argv[2], encoding='utf-8'))}
    per = Counter()
    for meta, t in sorted(truth.items(), key=lambda kv: (kv[1]['kind'], int(kv[0]))):
        r = rows.get(meta)
        status = 'not tested' if r is None else ('significant' if r['significant'] == 'yes' else 'not significant')
        per[(t['kind'], status)] += 1
        detail = '' if r is None else f"q={r['q_value']} {r['evidence']}"
        print(f"{t['kind']:<14} {meta:>7} {t['name'][:32]:<32} {status:<16} {detail[:110]}")
    print()
    for kind in sorted({k for k, _ in per}):
        print(f"{kind:<14} " + ', '.join(f"{s}: {per[(kind, s)]}" for s in ('significant', 'not significant', 'not tested')))
    fp = [r for m, r in rows.items() if r['significant'] == 'yes' and m not in truth]
    print(f"false positives: {len(fp)}")
    for r in fp:
        print(f"  {r['lookup']:>12} {r['file_name'][-70:]}  {r['evidence'][:100]}")


if __name__ == '__main__':
    main()
