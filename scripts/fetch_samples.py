"""Downloads the public evidence used by scripts/cross_examine.py.

    python scripts/fetch_samples.py <samples dir>

Sources (all public):
  * Maxim Suhanov's dfir_ntfs test corpus: $MFT corner cases with SleuthKit
    `fls -l` references, the NIST Hacking Case $MFT, a $UsnJrnl:$J with its
    `fsutil usn readjournal` dump, raw NTFS volumes and partition tables.
  * Omer BenAmram's mft crate samples, including the $MFT of Digital Corpora's
    ntfs1-gen2 image and its fiwalk DFXML.
  * Digital Corpora nps-2009-ntfs1 E01 images (gen0, gen1, gen2).
"""
import gzip
import os
import shutil
import sys
import tarfile
import urllib.request

DFIR_NTFS = 'https://raw.githubusercontent.com/msuhanov/dfir_ntfs/master/test_data/'
MFT_REPO = 'https://raw.githubusercontent.com/omerbenamram/mft/master/'
CORPORA = 'https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-ntfs1/'

DFIR_FILES = [
    'nist-hacking-case.mft', 'nist-hacking-case.fls',
    'orphan.mft', 'orphan.fls', 'unicode.mft', 'unicode.fls', '4k-large.mft', '4k-large.fls',
    'deleted.mft', 'different_la.mft', 'compressed_sparse.mft', 'mapping_pairs_1.mft',
    'mapping_pairs_2.mft', 'slack.mft', 'slack-2.mft', 'slack-3.mft', 'ntfs_frag_mft.bin',
    'usnjrnlj.bin', 'usnjrnlj.fsutil.txt', 'usn_1170953448.bin', 'usn_1170955904.bin',
    'usn_1170989584.bin', 'usn_1170990440.bin',
    'ntfs3.raw.gz', 'ntfs3_attrlist.raw.gz', 'ntfs_index.raw.gz', 'mbr-win-512.raw.tgz',
    'gpt-512-0p.raw.gz', 'gpt-512-3p.raw.gz', 'mbr-4096-p1e0.bin.gz', 'mbr-4096-p1e1.bin.gz',
    'mbr-512-p1e2.bin.gz', 'mbr-512-p1e2_2.bin.gz',
    'frs.bin', 'frs_ea.bin', 'frs-81151.bin',
]
MFT_FILES = [
    'samples/ntfs1-gen2.MFT', 'samples/entry_102130_fixup_issue', 'samples/entry_62525_dos_name_extension',
    'samples/entry_6645_dos_name_base', 'samples/entry_76746_deleted_base', 'samples/entry_77871_deleted_extension',
    'samples/entry_87354_extended_attributes', 'samples/entry_data_run_at_offset',
    'samples/entry_multiple_index_root_entries', 'samples/entry_single_file', 'testdata/ntfs/ntfs1-gen2.xml',
]
E01_FILES = ['ntfs1-gen0.E01', 'ntfs1-gen1.E01', 'ntfs1-gen2.E01']


def fetch(url, dest):
    if os.path.exists(dest):
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    print('  ', url)
    with urllib.request.urlopen(url) as r, open(dest, 'wb') as f:
        shutil.copyfileobj(r, f)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else 'samples'
    d, m, e, raw = (os.path.join(root, x) for x in ('dfir_ntfs', 'mft_repo', 'e01', 'raw'))
    print('dfir_ntfs')
    for f in DFIR_FILES:
        fetch(DFIR_NTFS + f, os.path.join(d, f))
    print('mft crate')
    for f in MFT_FILES:
        fetch(MFT_REPO + f, os.path.join(m, os.path.basename(f)))
    print('Digital Corpora')
    for f in E01_FILES:
        fetch(CORPORA + f, os.path.join(e, f))

    os.makedirs(raw, exist_ok=True)
    for f in DFIR_FILES:
        if f.endswith('.gz') and not f.endswith('.tgz'):
            out = os.path.join(raw, f[:-3])
            if not os.path.exists(out):
                with gzip.open(os.path.join(d, f)) as g, open(out, 'wb') as o:
                    shutil.copyfileobj(g, o)
    tgz = os.path.join(d, 'mbr-win-512.raw.tgz')
    outdir = os.path.join(raw, 'mbr-win-512')
    if not os.path.isdir(outdir):
        with tarfile.open(tgz) as t:
            t.extractall(outdir)
    frag = os.path.join(raw, 'ntfs_frag_mft.raw')
    if not os.path.exists(frag):
        shutil.copy(os.path.join(d, 'ntfs_frag_mft.bin'), frag)
    print('done:', root)


if __name__ == '__main__':
    main()
