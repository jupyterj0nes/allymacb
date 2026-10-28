"""Cross-examination harness: runs allymacb over every public sample and
cross-checks the timeline against independent references (SleuthKit fls,
fsutil usn readjournal, fiwalk DFXML and the mft crate's mft_dump).

Usage:
    python scripts/fetch_samples.py samples/
    bash scripts/build_test_images.sh samples/wsl      # optional, needs Linux/WSL
    python scripts/cross_examine.py --bin target/release/allymacb --samples samples/
"""
import csv, datetime, io, json, os, re, subprocess, sys, time, zipfile
from collections import defaultdict

import argparse
ap = argparse.ArgumentParser(description='Cross-examine allymacb against SleuthKit fls, fsutil and fiwalk references on public samples.')
ap.add_argument('--bin', required=True, help='path to the allymacb binary')
ap.add_argument('--samples', required=True, help='directory populated by fetch_samples.py (and build_test_images.sh)')
ap.add_argument('--mft-dump', default='', help='optional path to the mft_dump binary of the mft crate for path cross-checks')
ap.add_argument('--out', default='cross_examination_out')
A = ap.parse_args()
SAMPLES = A.samples
BIN = A.bin
MFT_DUMP = A.mft_dump
OUT = A.out
os.makedirs(OUT, exist_ok=True)
REPORT = []

def say(msg):
    print(msg, flush=True)
    REPORT.append(msg)

def run(args, name, extra=()):
    out = os.path.join(OUT, name + '.csv')
    t0 = time.time()
    p = subprocess.run([BIN, '-q', *extra, *args, '-o', out], capture_output=True, text=True, encoding='utf-8', errors='replace')
    dt = time.time() - t0
    rows = []
    bad = 0
    if os.path.exists(out):
        with open(out, encoding='utf-8', newline='') as f:
            r = csv.reader(f)
            header = next(r, None)
            assert header == ['time_created', 'size', 'type', 'mode', 'uid', 'gid', 'meta', 'file_name'], header
            for row in r:
                if len(row) != 8:
                    bad += 1
                    continue
                try:
                    datetime.datetime.strptime(row[0][:19], '%Y-%m-%dT%H:%M:%S')
                    assert row[0].endswith('Z')
                    int(row[1]); int(row[4]); int(row[5])
                    assert len(row[2]) == 4 and all(c in 'macb.' for c in row[2])
                except Exception:
                    bad += 1
                rows.append(row)
    status = 'OK' if p.returncode == 0 else f'exit={p.returncode}'
    warn = [l for l in p.stderr.splitlines() if l.startswith('[!]')]
    say(f'  [{status}] {name}: {len(rows)} rows, {bad} malformed, {dt:.1f}s, {len(warn)} warnings')
    for w in warn[:4]:
        say(f'        {w[:160]}')
    if 'panicked' in p.stderr:
        say('        PANIC: ' + p.stderr[p.stderr.find('panicked'):][:300])
    return p.returncode, rows, p.stderr

# ---------- reference parsers ----------
def parse_fls(path):
    """fls -l long listing -> {entry: [(name, m, a, c, b, size)]}"""
    ref = defaultdict(list)
    def ts(s):
        m = re.match(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \((\w+)\)', s)
        if not m:
            return None
        dt = datetime.datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
        tz = m.group(2)
        off = {'UTC': 0, 'MSK': 3}.get(tz, 0)
        return int((dt - datetime.timedelta(hours=off) - datetime.datetime(1970, 1, 1)).total_seconds())
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 9:
                continue
            m = re.match(r'([rd\-]/[rd\-]) (\*\s*)?(\d+)-(\d+)-(\d+):', parts[0])
            if not m:
                continue
            deleted = bool(m.group(2))
            entry, atype = int(m.group(3)), int(m.group(4))
            if atype != 128 and atype != 144:
                continue
            name = parts[1]
            ref[entry].append(dict(name=name, deleted=deleted, m=ts(parts[2]), a=ts(parts[3]), c=ts(parts[4]), b=ts(parts[5]), size=int(parts[6]), atype=atype))
    return ref

def norm_path(p):
    p = re.sub(r'^[A-Z]:\\', '', p)
    p = re.sub(r' \((deleted)\)$', '', p)
    p = re.sub(r' \(\$FILE_NAME: .*\)$', '', p)
    return p.replace('\\', '/').lower()

def rows_by_entry(rows):
    d = defaultdict(list)
    for r in rows:
        if '($FILE_NAME' in r[7] or '(USN:' in r[7]:
            continue
        d[r[6]].append(r)
    return d

def iso_to_unix(s):
    return int((datetime.datetime.strptime(s[:19], '%Y-%m-%dT%H:%M:%S') - datetime.datetime(1970, 1, 1)).total_seconds())

def compare_fls(name, rows, fls_path, orphan_prefix='$OrphanFiles/'):
    ref = parse_fls(fls_path)
    mine = rows_by_entry(rows)
    checked = path_ok = ts_ok = missing = size_ok = size_checked = 0
    examples = []
    path_examples = []
    for entry, items in ref.items():
        base = [i for i in items if ':' not in i['name'] and i['name'] != '$MFT:$Bitmap']
        if not base:
            continue
        i = base[0]
        key = str(entry)
        if key not in mine:
            missing += 1
            if len(examples) < 5:
                examples.append(f'missing entry {entry} {i["name"]}')
            continue
        checked += 1
        my_paths = {norm_path(r[7]) for r in mine[key]}
        ref_path = i['name'].lower()
        if ref_path.startswith(orphan_prefix.lower()):
            ok = any(p.endswith(ref_path[len(orphan_prefix):]) or '[orphan]' in p for p in my_paths)
        else:
            ok = any(p == ref_path or p.endswith('/' + ref_path) or p == ref_path.split('/')[-1] for p in my_paths)
        if ok:
            path_ok += 1
        elif len(path_examples) < 8:
            path_examples.append(f'path entry {entry}: fls={i["name"]!r} mine={sorted(my_paths)[:2]}')
        # timestamps: every fls time must appear with the right flag
        my_ts = defaultdict(set)
        for r in mine[key]:
            for pos, flag in enumerate('macb'):
                if r[2][pos] == flag:
                    my_ts[flag].add(iso_to_unix(r[0]))
        t_ok = True
        for flag in 'macb':
            v = i[flag]
            if v is None or v == 0:
                continue
            if v not in my_ts[flag]:
                # mactime fls uses crtime 'b'; allow missing when FILETIME 0
                t_ok = False
        if t_ok:
            ts_ok += 1
        elif len(examples) < 8:
            examples.append(f'ts entry {entry} {i["name"]}: fls m={i["m"]} a={i["a"]} c={i["c"]} b={i["b"]} mine={dict(my_ts)}')
        if i['atype'] == 128 and i['size'] > 0:
            size_checked += 1
            if any(int(r[1]) == i['size'] for r in mine[key]):
                size_ok += 1
            elif len(examples) < 10:
                examples.append(f'size entry {entry} {i["name"]}: fls={i["size"]} mine={sorted({r[1] for r in mine[key]})}')
    say(f'    vs fls: {checked} entries compared, paths match {path_ok}/{checked}, timestamps match {ts_ok}/{checked}, sizes match {size_ok}/{size_checked}, missing {missing}')
    for e in path_examples + examples:
        say('        ' + e)

def parse_fsutil(path):
    recs = []
    cur = {}
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if not line.strip():
                if 'Usn' in cur:
                    recs.append(cur)
                cur = {}
                continue
            if ':' in line:
                k, v = line.split(':', 1)
                cur[k.strip()] = v.strip()
    if 'Usn' in cur:
        recs.append(cur)
    return [r for r in recs if 'File name' in r]

def compare_fsutil(rows, ref_path):
    ref = parse_fsutil(ref_path)
    # fsutil prints local time (Moscow, UTC+3 in Jan 2019 per dfir_ntfs); compare names + reasons in order, timestamps modulo zone
    ok_name = ok_reason = ok_time = 0
    usn_rows = [r for r in rows if '(USN:' in r[7]]
    # rows were sorted chronologically by allymacb; re-sort by (time, meta) for a stable order and match multiset
    mine_multiset = defaultdict(int)
    for r in usn_rows:
        m = re.search(r'\\([^\\]+) \(USN: (.*)\)$', r[7])
        name = m.group(1) if m else ''
        reasons = m.group(2) if m else ''
        mine_multiset[(name, iso_to_unix(r[0]))] += 1
    best = (0, None)
    for off in range(-12, 15):
        ref_multiset = defaultdict(int)
        for rr in ref:
            name = rr['File name']
            t = datetime.datetime.strptime(rr['Time stamp'], '%m/%d/%Y %H:%M:%S')
            ref_multiset[(name, int((t - datetime.timedelta(hours=off) - datetime.datetime(1970, 1, 1)).total_seconds()))] += 1
        inter = sum(min(c, mine_multiset.get(k, 0)) for k, c in ref_multiset.items())
        if inter > best[0]:
            best = (inter, off, ref_multiset)
    inter, off, ref_multiset = best
    say(f'    vs fsutil: reference records {len(ref)}, mine {len(usn_rows)}, (name,timestamp) matches {inter}/{len(ref)} with fsutil local time = UTC{off:+d}')
    extra = {k: c - ref_multiset.get(k, 0) for k, c in mine_multiset.items() if c > ref_multiset.get(k, 0)}
    if extra:
        say(f'        rows in mine not in fsutil: {list(extra.items())[:5]}')
    # reason bit check on a sample
    bits = {'Object ID change': 'OBJECT_ID_CHANGE', 'Named data extend': 'NAMED_DATA_EXTEND', 'Named data overwrite': 'NAMED_DATA_OVERWRITE', 'Named data truncation': 'NAMED_DATA_TRUNCATION', 'Indexable change': 'INDEXABLE_CHANGE', 'Hard link change': 'HARD_LINK_CHANGE', 'Compression change': 'COMPRESSION_CHANGE', 'Encryption change': 'ENCRYPTION_CHANGE', 'Reparse point change': 'REPARSE_POINT_CHANGE', 'Stream change': 'STREAM_CHANGE', 'EA change': 'EA_CHANGE', 'Integrity change': 'INTEGRITY_CHANGE', 'Transacted change': 'TRANSACTED_CHANGE', 'Desired storage class change': 'DESIRED_STORAGE_CLASS_CHANGE', 'File create': 'FILE_CREATE', 'Close': 'CLOSE', 'Data extend': 'DATA_EXTEND', 'File delete': 'FILE_DELETE', 'Rename: old name': 'RENAME_OLD_NAME', 'Rename: new name': 'RENAME_NEW_NAME', 'Basic info change': 'BASIC_INFO_CHANGE', 'Data overwrite': 'DATA_OVERWRITE', 'Data truncation': 'DATA_TRUNCATION', 'Security change': 'SECURITY_CHANGE'}
    reason_ref = defaultdict(int)
    for rr in ref:
        rs = rr['Reason'].split(':', 1)[1] if ':' in rr['Reason'] else rr['Reason']
        parts = tuple(sorted(bits.get(x.strip(), x.strip()) for x in rs.split('|')))
        reason_ref[(rr['File name'], parts)] += 1
    reason_mine = defaultdict(int)
    for r in usn_rows:
        m = re.search(r'\\([^\\]+) \(USN: (.*)\)$', r[7])
        if m:
            reason_mine[(m.group(1), tuple(sorted(m.group(2).split('+'))))] += 1
    inter2 = sum(min(c, reason_mine.get(k, 0)) for k, c in reason_ref.items())
    say(f'    vs fsutil: (name,reason-set) matches {inter2}/{len(ref)}')
    if inter2 < len(ref):
        miss = [k for k, c in reason_ref.items() if reason_mine.get(k, 0) < c][:4]
        for k in miss:
            say(f'        unmatched reason: {k}')

def compare_mft_dump(name, mft_path, rows):
    if not os.path.exists(MFT_DUMP):
        say('    mft_dump not available')
        return
    p = subprocess.run([MFT_DUMP, '-o', 'csv', mft_path], capture_output=True, text=True, encoding='utf-8', errors='replace')
    if p.returncode != 0:
        say(f'    mft_dump failed: {p.stderr[:200]}')
        return
    ref = {}
    for row in csv.DictReader(io.StringIO(p.stdout)):
        ref[row['EntryId']] = row
    mine = rows_by_entry(rows)
    same = diff = 0
    ex = []
    for entry, row in ref.items():
        if entry not in mine:
            continue
        rp = row['FullPath'].replace('\\', '/').lower()
        if rp.startswith('[unknown]') or entry in ('5', '12', '13', '14', '15'):
            continue
        mp = {norm_path(r[7]) for r in mine[entry]}
        if rp in mp:
            same += 1
        else:
            diff += 1
            if len(ex) < 5:
                ex.append(f'entry {entry}: mft_dump={rp!r} mine={sorted(mp)[:2]}')
    say(f'    vs mft_dump paths: {same} identical, {diff} different (of {len(ref)} entries dumped)')
    for e in ex:
        say('        ' + e)

def compare_dfxml(rows, xml_path):
    import xml.etree.ElementTree as ET
    objs = []
    data = open(xml_path, 'rb').read().replace(b'<dc:type>', b'<dctype>').replace(b'</dc:type>', b'</dctype>')
    for ev, el in ET.iterparse(io.BytesIO(data)):
        if el.tag == 'fileobject':
            d = {c.tag: c.text for c in el}
            objs.append(d)
            el.clear()
    mine = rows_by_entry(rows)
    checked = ok_path = ok_ts = 0
    ex = []
    for o in objs:
        if o.get('alloc') != '1' or not o.get('inode') or ':' in (o.get('filename') or ''):
            continue
        key = o['inode']
        if key not in mine:
            continue
        checked += 1
        fn = (o.get('filename') or '').lower()
        mp = {norm_path(r[7]) for r in mine[key]}
        if fn in mp:
            ok_path += 1
        elif len(ex) < 5:
            ex.append(f'inode {key}: dfxml={fn!r} mine={sorted(mp)[:2]}')
        my_ts = defaultdict(set)
        for r in mine[key]:
            for pos, flag in enumerate('macb'):
                if r[2][pos] == flag:
                    my_ts[flag].add(iso_to_unix(r[0]))
        want = {'m': o.get('mtime'), 'a': o.get('atime'), 'c': o.get('ctime'), 'b': o.get('crtime')}
        good = all((v is None) or (int(v) in my_ts[f]) for f, v in want.items())
        if good:
            ok_ts += 1
        elif len(ex) < 8:
            ex.append(f'ts inode {key} {fn}: dfxml={want} mine={dict(my_ts)}')
    say(f'    vs fiwalk DFXML: {checked} allocated files compared, paths {ok_path}/{checked}, MACB timestamps {ok_ts}/{checked}')
    for e in ex:
        say('        ' + e)

# ================= runs =================
D = os.path.join(SAMPLES, 'dfir_ntfs')
M = os.path.join(SAMPLES, 'mft_repo')
E = os.path.join(SAMPLES, 'e01')
R = os.path.join(SAMPLES, 'raw')
W = os.path.join(SAMPLES, 'wsl')

say('== $MFT samples (NTFS) ==')
rc, rows, _ = run([ '-f', os.path.join(D, 'nist-hacking-case.mft')], 'nist_mft')
compare_fls('nist', rows, os.path.join(D, 'nist-hacking-case.fls'))
compare_mft_dump('nist', os.path.join(D, 'nist-hacking-case.mft'), rows)
rc, rows_n, _ = run(['-n', '-f', os.path.join(D, 'nist-hacking-case.mft')], 'nist_mft_fn')
say(f'    with -n: {len(rows_n)} rows ({len(rows_n) - len(rows)} $FILE_NAME rows)')

for nm in ['orphan', 'unicode', '4k-large']:
    rc, rows, _ = run(['-f', os.path.join(D, nm + '.mft')], nm + '_mft')
    compare_fls(nm, rows, os.path.join(D, nm + '.fls'))
    compare_mft_dump(nm, os.path.join(D, nm + '.mft'), rows)

for nm in ['deleted', 'different_la', 'compressed_sparse', 'mapping_pairs_1', 'mapping_pairs_2', 'slack', 'slack-2', 'slack-3']:
    rc, rows, _ = run(['-f', os.path.join(D, nm + '.mft')], nm + '_mft')
    compare_mft_dump(nm, os.path.join(D, nm + '.mft'), rows)
rc, rows, _ = run(['-f', os.path.join(D, 'ntfs_frag_mft.bin')], 'frag_mft')
rc, rows, _ = run(['-f', os.path.join(M, 'ntfs1-gen2.MFT')], 'gen2_mft')
compare_mft_dump('gen2', os.path.join(M, 'ntfs1-gen2.MFT'), rows)
gen2_mft_rows = rows

say('== single MFT records (1 KiB each) ==')
for nm in sorted(os.listdir(M)):
    if nm.startswith('entry_'):
        run(['-f', os.path.join(M, nm)], nm)
for nm in ['frs.bin', 'frs_ea.bin', 'frs-81151.bin']:
    run(['-f', os.path.join(D, nm)], nm)

say('== USN journal ==')
rc, rows, _ = run(['-u', os.path.join(D, 'usnjrnlj.bin')], 'usnjrnl')
compare_fsutil(rows, os.path.join(D, 'usnjrnlj.fsutil.txt'))
for nm in ['usn_1170953448.bin', 'usn_1170955904.bin', 'usn_1170989584.bin', 'usn_1170990440.bin']:
    run(['-u', os.path.join(D, nm)], nm)

say('== E01 images (Digital Corpora nps-2009-ntfs1) ==')
for g in ['gen0', 'gen1', 'gen2']:
    rc, rows, err = run(['-f', os.path.join(E, f'ntfs1-{g}.E01')], f'e01_{g}')
    if g == 'gen2':
        compare_dfxml(rows, os.path.join(M, 'ntfs1-gen2.xml'))
        a = sorted((r[0], r[2], r[6], r[7]) for r in rows)
        b = sorted((r[0], r[2], r[6], r[7]) for r in gen2_mft_rows)
        say(f'    E01 vs loose $MFT of the same image: {"IDENTICAL" if a == b else "DIFFERENT"} ({len(a)} vs {len(b)} rows)')

say('== raw NTFS images and partition tables ==')
for nm in ['ntfs3.raw', 'ntfs3_attrlist.raw', 'ntfs_index.raw']:
    run(['-f', os.path.join(R, nm)], nm)
run(['-f', os.path.join(R, 'mbr-win-512', 'mbr-win-512.raw')], 'mbr-win-512')
run(['-f', os.path.join(R, 'ntfs_frag_mft.raw')], 'ntfs_frag_mft.raw')
for nm in ['gpt-512-0p.raw', 'gpt-512-3p.raw', 'mbr-4096-p1e0.bin', 'mbr-4096-p1e1.bin', 'mbr-512-p1e2.bin', 'mbr-512-p1e2_2.bin']:
    run(['-f', os.path.join(R, nm)], nm)

say('== WSL-built ext4 / GPT / MBR / 4Kn / split images ==')
if os.path.isdir(W):
    for nm in ['ext4_plain.img', 'gpt_512.img', 'mbr_ext.img', 'gpt_4kn.img', 'mbr_split.001']:
        rc, rows, err = run(['-f', os.path.join(W, nm)], nm)
        paths = {r[7] for r in rows}
        for want in ['/etc/shadow', '/home/user/suidtool', '/data/caf', '/deep/l1/l2', '/only_on_p3/marker.txt']:
            hit = any(want in p for p in paths)
            say(f'        contains {want!r}: {hit}')
        modes = {r[7]: r[3] for r in rows}
        for p, m in modes.items():
            if p.endswith('/etc/shadow') or p.endswith('suidtool') or p.endswith('link_to_passwd'):
                say(f'        mode {p} = {m}')
        for r in rows:
            if r[7].endswith('/etc/passwd') and r[2][0] == 'm':
                say(f'        /etc/passwd mtime = {r[0]} (expected 2001-09-09T01:46:40Z)')
        inj = [r for r in rows if '=cmd' in r[7]]
        say(f'        formula-like name rows: {len(inj)}')
    say('== archives ==')
    rc, rows, err = run(['-f', os.path.join(W, 'evil.tar')], 'evil_tar')
    esc = [p for p in [os.path.join(os.environ.get('TEMP', ''), 'ALLYMACB_ESCAPE.txt'), 'C:\\tmp\\ALLYMACB_ABS.txt', '/tmp/ALLYMACB_ABS.txt'] if os.path.exists(p)]
    say(f'        escaped files on disk: {esc}')
    say(f'        rows: {[r[7] for r in rows]}')
    rc, rows, err = run(['-f', os.path.join(W, 'uac-server01.tar.gz')], 'uac_targz')
    say(f'        bodyfile rows: {len(rows)}; pipe-name row: {[r[7] for r in rows if "a|b" in r[7]]}; pre-1970 row: {[r[0] for r in rows if r[0].startswith("1969")]}')
    rc, rows, err = run(['-f', os.path.join(W, 'bodyfile.txt.gz')], 'bodyfile_gz')
    say(f'        plain .gz bodyfile rows: {len(rows)}')
    # KAPE-like zip with $MFT and $J inside, built here
    kz = os.path.join(OUT, 'kape_like.zip')
    with zipfile.ZipFile(kz, 'w') as z:
        z.write(os.path.join(M, 'ntfs1-gen2.MFT'), 'C/$MFT')
        z.write(os.path.join(D, 'orphan.mft'), 'D/$MFT')
        z.write(os.path.join(D, 'usnjrnlj.bin'), 'C/$Extend/$UsnJrnl%3A$J')
    rc, rows, err = run(['-f', kz], 'kape_zip')
    say(f'        rows: {len(rows)} (gen2 MFT {len(gen2_mft_rows)} + orphan MFT + USN); USN rows: {sum(1 for r in rows if "(USN:" in r[7])}')
    # directory scan with mixed evidence
    dd = os.path.join(OUT, 'triage_dir')
    os.makedirs(os.path.join(dd, 'C', '$Extend'), exist_ok=True)
    import shutil
    shutil.copy(os.path.join(M, 'ntfs1-gen2.MFT'), os.path.join(dd, 'C', '$MFT'))
    shutil.copy(os.path.join(D, 'usnjrnlj.bin'), os.path.join(dd, 'C', '$Extend', '$UsnJrnl%3A$J'))
    shutil.copy(kz, os.path.join(dd, 'other_host.zip'))
    rc, rows, err = run(['-d', dd], 'triage_dir')
    say(f'        rows: {len(rows)}, USN rows: {sum(1 for r in rows if "(USN:" in r[7])}')
    # Linux triage directory walk
    lt = os.path.join(OUT, 'linux_tree')
    import tarfile
    with tarfile.open(os.path.join(W, 'linux_tree.tar')) as t:
        for m in t.getmembers():
            try:
                t.extract(m, lt)
            except OSError:
                pass
    rc, rows, err = run(['-d', lt], 'linux_tree_walk')

say('== failure modes ==')
rc, rows, err = run(['-f', os.path.join(OUT, 'nope.E01')], 'missing_file')
with open(os.path.join(OUT, 'garbage.E01'), 'wb') as f:
    f.write(b'garbage')
rc, rows, err = run(['-f', os.path.join(OUT, 'garbage.E01')], 'garbage_e01')
with open(os.path.join(OUT, 'fake.vhdx'), 'wb') as f:
    f.write(b'vhdxfile' + b'\0' * 4096)
rc, rows, err = run(['-f', os.path.join(OUT, 'fake.vhdx')], 'fake_vhdx')
rc, rows, err = run(['-f', os.path.join(OUT, 'garbage.E01'), '-f', os.path.join(D, 'orphan.mft')], 'partial')

with open(os.path.join(OUT, 'REPORT.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(REPORT))
