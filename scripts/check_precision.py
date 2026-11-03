"""Precision and recall of the tail against the truth file of hunt_inject.py.

    python scripts/check_precision.py <truth.json> <timeline.csv> [<hunt.csv>]

Counts records, not rows (one per `meta` of the `$MFT` rows, `$FILE_NAME`
rows folded in). A record is flagged when its `hunt` word is `significant`
or `candidate`. With the hunt CSV of `--hunt-out`, the statistical verdict
is scored on its own too. Records installed with the volume (`baseline`) and
records the hour explains (`habitual`) are not flagged, which is the point.
"""
import csv
import json
import re
import sys
from collections import Counter, defaultdict

RULE = re.compile(r'rule (\w+) \(')


def main():
    truth = json.load(open(sys.argv[1]))
    words = {}
    why = defaultdict(set)
    for r in csv.DictReader(open(sys.argv[2], encoding='utf-8', newline='')):
        if r['source'] != 'mft':
            continue
        m = r['meta']
        rank = {'significant': 2, 'candidate': 1}.get(r['hunt'], 0)
        if rank > words.get(m, (-1, ''))[0]:
            words[m] = (rank, r['hunt'])
        elif m not in words:
            words[m] = (rank, r['hunt'])
        why[m].update(RULE.findall(r['hunt_why']))
    flagged = {m for m, (rank, _) in words.items() if rank > 0}
    hit = {m for m in truth if m in flagged}
    print(f'records: {len(words)}; flagged (significant or candidate): {len(flagged)}; stomped: {len(truth)}')
    per = Counter()
    for m, t in sorted(truth.items(), key=lambda kv: (kv[1]['kind'], int(kv[0]))):
        word = words.get(m, (0, '(absent)'))[1] or '(no state)'
        per[(t['kind'], word)] += 1
        print(f"  {t['kind']:<14} {m:>7} {t['name'][:34]:<34} {word:<12} {'+'.join(sorted(why.get(m, ())))}")
    for kind in sorted({k for k, _ in per}):
        print(f"  {kind:<14} " + ', '.join(f'{w}: {per[(kind, w)]}' for (k, w) in sorted(per) if k == kind))
    fp = flagged - set(truth)
    recall = len(hit) / len(truth) if truth else 0
    precision = len(hit) / len(flagged) if flagged else 0
    print(f'tail: recall {len(hit)}/{len(truth)} = {recall:.2f}; precision {len(hit)}/{len(flagged)} = {precision:.2f}; false positives {len(fp)}')
    for m in sorted(fp, key=int)[:12]:
        print(f'    fp {m:>7} {words[m][1]:<12} {"+".join(sorted(why.get(m, ())))}')
    if len(sys.argv) > 3:
        rows = {r['lookup'].removeprefix('meta='): r for r in csv.DictReader(open(sys.argv[3], encoding='utf-8', newline=''))}
        sig = {m for m, r in rows.items() if r['significant'] == 'yes'}
        tested = {m for m, r in rows.items() if r['significant'] in ('yes', 'no')}
        hit_h = sig & set(truth)
        print(f'hunt: tested {len(tested)}, significant {len(sig)}; recall {len(hit_h)}/{len(truth)}; false positives {len(sig - set(truth))}; stomped not tested {len(set(truth) - tested)}')


if __name__ == '__main__':
    main()
