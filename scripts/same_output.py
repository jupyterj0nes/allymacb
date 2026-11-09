"""Same output, whatever the number of threads and whatever changed inside.

Records what one binary writes for every sample (CSV, stderr, exit code,
--hunt-out, the resident dump), then checks that another binary, on every
thread count asked for, writes the same bytes. Use it before merging any
change that is meant not to change the output: multithreading, a refactor,
a faster parser.

    python scripts/same_output.py record --bin old/allymacb --samples samples/ --out ref.json
    python scripts/same_output.py check  --bin target/release/allymacb --samples samples/ --ref ref.json --threads 1,2,3,8,12

`samples/` is the folder of fetch_samples.py and build_test_images.sh (the
same as cross_examine.py); missing samples are skipped, and the lab
folders (lab/, lab_linux/, lab_linux_logs/) are used when present. Pass
--extra DIR to add every $MFT, image and archive under DIR as a case of its
own, and all of them together as one more.

The elapsed time and thread count of the summary are left out of the
comparison, and nothing else. Binaries older than the strict reading of
evidence (CHANGELOG) wrote rows with the time of the run itself (the access
time a directory walk had just set, folders an archive was extracted into);
pass --old-binary to leave `fs` rows dated after the run started out when
the reference comes from one.
"""
import argparse, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time

ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
ap.add_argument('mode', choices=['record', 'check'])
ap.add_argument('--bin', required=True)
ap.add_argument('--samples', required=True)
ap.add_argument('--out', help='record: where the reference goes')
ap.add_argument('--ref', help='check: the reference recorded before')
ap.add_argument('--threads', default='1,2,8', help='check: thread counts, comma separated')
ap.add_argument('--repeat', type=int, default=1, help='check: runs per thread count')
ap.add_argument('--extra', action='append', default=[], help='more evidence: every artifact under this folder')
ap.add_argument('--old-binary', action='store_true', help='leave out fs rows dated during the run (references from binaries before the strict reading)')
A = ap.parse_args()
A.bin = os.path.abspath(A.bin)  # Windows does not resolve a relative path with slashes

S = A.samples
# A fixed folder: its paths are in stderr, so record and check must share them.
WORK = os.path.join(tempfile.gettempdir(), 'allymacb_same_output')
shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK)
OUT, HUNT, RES, REP = (os.path.join(WORK, n) for n in ('out.csv', 'hunt.csv', 'res', 'res_report.txt'))
p = os.path.join


def cases():
    c = {}
    def add(name, args, need):
        if all(os.path.exists(x) for x in need):
            c[name] = args
    nist = p(S, 'dfir_ntfs', 'nist-hacking-case.mft')
    add('nist_mft', ['-f', nist, '-n'], [nist])
    add('nist_hunt', ['-f', nist, '--investigation-from', '2004-08-26', '--hunt-out', HUNT], [nist])
    add('usn', ['-u', p(S, 'dfir_ntfs', 'usnjrnlj.bin')], [p(S, 'dfir_ntfs', 'usnjrnlj.bin')])
    for d in ('dfir_ntfs', 'mft_repo', 'lab_linux'):
        add(f'dir_{d}', ['-d', p(S, d)], [p(S, d)])
    for f in ('ntfs1-gen0.E01', 'ntfs1-gen1.E01', 'ntfs1-gen2.E01'):
        add(f'e01_{f}', ['-f', p(S, 'e01', f)], [p(S, 'e01', f)])
        add(f'e01_{f}_carve', ['-f', p(S, 'e01', f), '--carve'], [p(S, 'e01', f)])
    for d in ('raw', 'wsl'):
        if os.path.isdir(p(S, d)):
            for f in sorted(os.listdir(p(S, d))):
                if f.endswith(('.raw', '.img', '.bin', '.001')):
                    add(f'{d}_{f}_carve', ['-f', p(S, d, f), '--carve'], [p(S, d, f)])
    lab = p(S, 'lab')
    if os.path.isdir(lab):
        for case in sorted(os.listdir(lab)):
            for f in sorted(os.listdir(p(lab, case))):
                if f.endswith('.vhd'):
                    add(f'lab_{case}_{f}_carve', ['-f', p(lab, case, f), '--carve'], [p(lab, case, f)])
    for f in ('ext4.img', 'bodyfile.txt'):
        add(f'linux_{f}', ['-f', p(S, 'lab_linux', f), '--carve'], [p(S, 'lab_linux', f)])
    add('linux_logs_carve', ['-f', p(S, 'lab_linux_logs', 'logs.img'), '--carve'], [p(S, 'lab_linux_logs', 'logs.img')])
    # Several inputs at once, in two orders, hunted; the resident dump of several sources.
    many = [x for x in (nist, p(S, 'e01', 'ntfs1-gen2.E01'), p(S, 'raw', 'ntfs3.raw'), p(S, 'lab_linux', 'ext4.img'), p(S, 'lab_linux', 'bodyfile.txt')) if os.path.exists(x)]
    if len(many) > 1:
        add('many', ['-f', *many, '--carve', '--investigation-from', '2004-08-26', '--hunt-out', HUNT], many)
        add('many_reversed', ['-f', *reversed(many)], many)
        add('many_resident', ['-f', *many, '-r', RES, '--resident-report', REP], many)
        add('many_partial', ['-f', many[0], p(WORK, 'missing.mft'), *many[1:]], many)
    dirs = [p(S, d) for d in ('dfir_ntfs', 'mft_repo', 'lab_linux', 'e01') if os.path.isdir(p(S, d))]
    if len(dirs) > 1:
        add('dirs', ['-d', *dirs], dirs)
    for root in A.extra:
        found = []
        for d, _, files in os.walk(root):
            for f in sorted(files):
                low = f.lower()
                if low.endswith(('$mft', '.e01', '.vhd', '.img', '.raw', '.dd', '.zip', '.tar.gz', '.tgz')):
                    found.append(p(d, f))
        for f in found:
            add('extra_' + os.path.relpath(f, root).replace(os.sep, '_'), ['-f', f, '--carve'], [f])
        if found:
            add('extra_dir_' + os.path.basename(os.path.normpath(root)), ['-d', root, '--carve'], [root])
    return c


STARTED = time.strftime('%Y-%m-%d', time.gmtime(time.time() - 86400))
NORM = [
    (re.compile(rb'Elapsed time\s*:[^\n]*\n'), b''),
    (re.compile(rb'  Threads\s*:[^\n]*\n'), b''),
    (re.compile(rb'allymacb_\d+_\d+'), b'allymacb_PID_N'),
    # Temporary names: numbered by a shared counter before multithreading, by place since.
    (re.compile(rb'(mft|usn|nested|bin|zip)_[0-9.\-_]+\.'), rb'\1_TMP.'),
    (re.compile(rb'arch_[0-9.\-]+'), b'arch_TMP'),
    (re.compile(rb'\r\n'), b'\n'),
]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def csv_sha(path):
    if not os.path.exists(path):
        return None
    keep = []
    for line in open(path, 'rb').read().split(b'\n'):
        f = line.split(b',', 5)
        if A.old_binary and len(f) > 4 and f[4] == b'fs' and f[0][:10].decode(errors='replace') >= STARTED:
            continue
        keep.append(line)
    return sha(b'\n'.join(keep))


def file_sha(path):
    return sha(open(path, 'rb').read()) if os.path.exists(path) else None


def tree_sha(root):
    if not os.path.isdir(root):
        return None
    items = sorted((os.path.relpath(p(d, f), root).replace('\\', '/'), file_sha(p(d, f))) for d, _, fs in os.walk(root) for f in fs)
    return [len(items), sha(json.dumps(items).encode())]


def run(name, args, threads):
    for x in (OUT, HUNT, REP):
        if os.path.exists(x):
            os.remove(x)
    shutil.rmtree(RES, ignore_errors=True)
    cmd = [A.bin] + list(args) + ['-o', OUT] + (['--threads', str(threads)] if threads else [])
    t = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True)
    dt = time.perf_counter() - t
    err = r.stderr
    for rx, rep in NORM:
        err = rx.sub(rep, err)
    return {'exit': r.returncode, 'csv': csv_sha(OUT), 'stderr': sha(err), 'hunt': file_sha(HUNT), 'resident': tree_sha(RES), 'report': file_sha(REP)}, dt


def main():
    c = cases()
    if A.mode == 'record':
        ref = {}
        for name, args in c.items():
            ref[name], dt = run(name, args, None)
            print(f'{name:40s} exit {ref[name]["exit"]} {dt:7.2f}s', flush=True)
        json.dump(ref, open(A.out, 'w'), indent=1)
        print(f'{len(ref)} cases recorded in {A.out}')
        return 0
    ref = json.load(open(A.ref))
    total = bad = 0
    for name, args in c.items():
        if name not in ref:
            print(f'{name:40s} not in the reference, skipped')
            continue
        line = []
        for th in [int(x) for x in A.threads.split(',')]:
            for k in range(A.repeat):
                got, dt = run(name, args, th)
                total += 1
                diff = [key for key in got if got[key] != ref[name][key]]
                if diff:
                    bad += 1
                    print(f'DIFF {name} threads={th} run={k + 1}: {", ".join(diff)}', flush=True)
            line.append(f'{th}:{dt:.2f}s')
        print(f'{name:40s} ' + '  '.join(line), flush=True)
    print(f'\n{total - bad} of {total} runs identical to the reference')
    return 1 if bad else 0


try:
    sys.exit(main())
finally:
    shutil.rmtree(WORK, ignore_errors=True)
