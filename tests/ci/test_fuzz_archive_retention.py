"""Archive retention checks at the real publication boundary."""
# ruff: noqa: PT009 - unittest assertions remain active under Python -O

from __future__ import annotations

import json
import subprocess
import sys

from test_security_fuzz import SecurityFuzzFixture

CONTROL = r"""
import contextlib,gzip,io,json,os,pathlib,runpy,struct,sys,tarfile,zlib
h=runpy.run_path(sys.argv[1]);state=h['write_exclusive_archive'].__globals__
root=h['ROOT'];case=sys.argv[2];source=root/'fuzz/corpus/owned'
source.mkdir(parents=True);(source/'seed').write_bytes(b'raw input')
output=root/'fuzz/corpus_archive';output.mkdir()
prior={}
for i in range(3):
    p=output/f'1999010{i+1}T000000000000Z.tar.gz'
    with tarfile.open(p,'w:gz') as archive:archive.add(source/'seed',arcname='seed')
    prior[p.name]=p.read_bytes()
final=output/'20261004T123456123456Z.tar.gz'
sentinel=root.parent/'sentinel';sentinel.write_bytes(b'outside preserved')
unsupported={}
deflate_raw=io.BytesIO()
with tarfile.open(fileobj=deflate_raw,mode='w') as archive:
    member=tarfile.TarInfo('seed');member.size=len(b'raw input')
    archive.addfile(member,io.BytesIO(b'raw input'))
plain=deflate_raw.getvalue()
plain+=b'\0'*(65535-len(plain))
# A valid non-final stored block allows tar parsing before the invalid block.
deflate_bytes=(gzip.compress(b'',mtime=0)[:10]+b'\0'
    +struct.pack('<HH',len(plain),len(plain)^65535)+plain+b'\x07'+b'\0'*8)
if case=='unsupported':
    try:state['verify_archive_stream'](io.BytesIO(deflate_bytes),output/'deflate-probe')
    except zlib.error:pass
    else:raise RuntimeError('DEFLATE fixture did not reach the intended decoder error')
    link=output/'19980101T000000000000Z.tar.gz';link.symlink_to(sentinel)
    unsupported[link.name]='symlink'
    directory=output/'19980102T000000000000Z.tar.gz';directory.mkdir()
    unsupported[directory.name]='directory'
    fifo=output/'19980103T000000000000Z.tar.gz';os.mkfifo(fifo)
    unsupported[fifo.name]='fifo'
    alias=output/'19980104T000000000000Z.tar.gz';os.link(sentinel,alias)
    unsupported[alias.name]='hardlink'
    malformed=output/'19980105T000000000000Z.tar.gz';malformed.write_bytes(b'not an archive')
    unsupported[malformed.name]='malformed'
    corrupt=output/'19980106T000000000000Z.tar.gz'
    corrupt_bytes=bytearray(next(iter(prior.values())));corrupt_bytes[-8]^=1
    corrupt.write_bytes(corrupt_bytes);unsupported[corrupt.name]='corrupt-gzip'
    deflate=output/'19980107T000000000000Z.tar.gz'
    deflate.write_bytes(deflate_bytes);unsupported[deflate.name]='corrupt-deflate'
    unmanaged=output/'unmanaged.tar.gz';unmanaged.write_bytes(b'unmanaged evidence')
    unsupported[unmanaged.name]='unmanaged'
if case in ('historical-io-error','current-deflate-corruption'):
    original_verify=state['verify_archive_stream']
    def verify(stream,path):
        if case=='historical-io-error' and path!=final:
            raise OSError('owned historical archive read failure')
        if case=='current-deflate-corruption' and path==final:
            stream.seek(0);stream.write(deflate_bytes);stream.truncate();stream.flush()
        return original_verify(stream,path)
    state['verify_archive_stream']=verify
if case=='scan-current-change':
    original=state['os'].listdir
    def scan(fd):
        result=original(fd)
        with final.open('r+b') as stream:stream.write(b'changed bytes')
        return result
    state['os'].listdir=scan
if case in ('pinned-replacement','pinned-content-change'):
    original=state['archive_retention_plan']
    @contextlib.contextmanager
    def plan(*args):
        with original(*args) as rows:
            name=rows[-1][0];path=output/name
            if case=='pinned-replacement':path.unlink();path.symlink_to(sentinel)
            else:path.write_bytes(b'changed prior bytes')
            yield rows
    state['archive_retention_plan']=plan
if case in ('prune-error','partial-prune-error','prune-current-change',
            'restore-collision','restore-error'):
    original=state['os'].unlink;count=0
    def unlink(name,*args,**kwargs):
        global count
        if name in prior:
            count+=1
            if case in ('prune-current-change','restore-collision','restore-error') and count==1:
                with final.open('r+b') as stream:stream.write(b'changed during pruning')
            elif case in ('prune-error','partial-prune-error') and count==(
                    1 if case=='prune-error' else 2):
                raise OSError('owned prune failure')
        return original(name,*args,**kwargs)
    state['os'].unlink=unlink
original_link=os.link
if case in ('restore-collision','restore-error'):
    def link(source,destination,*args,**kwargs):
        if source.startswith('.retention-'):
            if case=='restore-error':raise OSError('owned restoration failure')
            (output/destination).symlink_to(sentinel)
        return original_link(source,destination,*args,**kwargs)
    state['os'].link=link
failed=False
try:h['write_exclusive_archive'](final,[(source,'corpus')],1)
except (OSError,ValueError,zlib.error):failed=True
finally:
    state['os'].link=original_link
    if case=='scan-current-change':state['os'].listdir=original
    if case in ('prune-error','partial-prune-error','prune-current-change',
            'restore-collision','restore-error'):
        state['os'].unlink=original
backup_rows={}
for path in output.iterdir():
    if path.name.startswith('.retention-'):
        name=path.name.split('-',2)[-1].removesuffix('.tmp')
        backup_rows[name]=path.read_bytes()==prior[name]
restoration_links=[name for name in prior if (output/name).is_symlink()]
remaining={name:((output/name).read_bytes()==data) for name,data in prior.items()
           if (output/name).is_file() and not (output/name).is_symlink()}
published=final.is_file();valid=False
if published:
    with tarfile.open(final) as archive:
        valid=archive.extractfile('corpus/seed').read()==b'raw input'
preserved={}
for name,kind in unsupported.items():
    p=output/name
    if kind=='symlink':ok=p.is_symlink() and os.readlink(p)==str(sentinel)
    elif kind=='directory':ok=p.is_dir()
    elif kind=='fifo':ok=__import__('stat').S_ISFIFO(p.lstat().st_mode)
    elif kind=='hardlink':ok=p.stat().st_ino==sentinel.stat().st_ino
    elif kind=='corrupt-gzip':ok=p.read_bytes()==corrupt_bytes
    elif kind=='corrupt-deflate':ok=p.read_bytes()==deflate_bytes
    else:ok=p.read_bytes()==(b'not an archive' if kind=='malformed' else b'unmanaged evidence')
    preserved[name]=ok
print(json.dumps({'case':case,'failed':failed,'published':published,'valid':valid,
    'remaining':remaining,'unsupported':preserved,'recovery_backups':backup_rows,
    'restoration_links':restoration_links,
    'replacement_preserved':case!='pinned-replacement' or
        ((output/sorted(prior)[-1]).is_symlink()
         and os.readlink(output/sorted(prior)[-1])==str(sentinel)),
    'changed_prior_preserved':case!='pinned-content-change' or
        (output/sorted(prior)[-1]).read_bytes()==b'changed prior bytes',
    'raw_preserved':(source/'seed').read_bytes()==b'raw input',
    'external_preserved':sentinel.read_bytes()==b'outside preserved',
    'temps':[p.name for p in output.iterdir() if p.name.startswith('.archive-')]}))
"""


class FuzzArchiveRetentionTests(SecurityFuzzFixture):
    def control(self, case):
        result = subprocess.run(  # noqa: S603 - bounded owned fixture and actual archive writer
            [
                sys.executable,
                "-I",
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                CONTROL,
                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                case,
            ],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(result.stdout)
        self.assertTrue(record["raw_preserved"] and record["external_preserved"], record)
        self.assertEqual(record["temps"], [], record)
        self.assertTrue(all(record["recovery_backups"].values()), record)
        return record

    def test_supported_retention_keeps_the_current_complete_archive(self):
        record = self.control("supported")
        self.assertFalse(record["failed"], record)
        self.assertTrue(record["valid"], record)
        self.assertEqual(record["remaining"], {}, record)

    def test_unsupported_entries_are_preserved_without_counting_as_managed(self):
        record = self.control("unsupported")
        self.assertFalse(record["failed"], record)
        self.assertTrue(record["valid"], record)
        self.assertTrue(all(record["unsupported"].values()), record)
        self.assertEqual(record["remaining"], {}, record)

    def test_historical_filesystem_errors_abort_without_pruning(self):
        record = self.control("historical-io-error")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 3, record)
        self.assertTrue(all(record["remaining"].values()), record)

    def test_current_deflate_corruption_aborts_without_pruning(self):
        record = self.control("current-deflate-corruption")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 3, record)
        self.assertTrue(all(record["remaining"].values()), record)

    def test_scan_content_change_rejects_before_any_prior_archive_is_deleted(self):
        record = self.control("scan-current-change")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 3, record)
        self.assertTrue(all(record["remaining"].values()), record)

    def test_pinned_replacement_rejects_the_entire_pruning_plan(self):
        record = self.control("pinned-replacement")
        self.assertTrue(record["failed"] and record["replacement_preserved"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 2, record)
        self.assertTrue(all(record["remaining"].values()), record)

    def test_pinned_content_change_rejects_before_any_prior_archive_is_deleted(self):
        record = self.control("pinned-content-change")
        self.assertTrue(record["failed"] and record["changed_prior_preserved"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 3, record)
        self.assertEqual(sum(record["remaining"].values()), 2, record)

    def test_pruning_failure_preserves_all_prior_archives(self):
        record = self.control("prune-error")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 3, record)
        self.assertTrue(all(record["remaining"].values()), record)

    def test_partial_pruning_failure_restores_all_prior_archives(self):
        record = self.control("partial-prune-error")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 3, record)
        self.assertTrue(all(record["remaining"].values()), record)

    def test_content_change_during_pruning_restores_all_prior_archives(self):
        record = self.control("prune-current-change")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["remaining"]), 3, record)
        self.assertTrue(all(record["remaining"].values()), record)

    def test_restore_collision_preserves_literal_replacements_and_independent_bytes(self):
        record = self.control("restore-collision")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["recovery_backups"]), 3, record)
        self.assertEqual(len(record["restoration_links"]), 3, record)
        self.assertEqual(record["remaining"], {}, record)

    def test_restore_failure_retains_every_independent_archive_copy(self):
        record = self.control("restore-error")
        self.assertTrue(record["failed"], record)
        self.assertFalse(record["published"], record)
        self.assertEqual(len(record["recovery_backups"]), 3, record)
        self.assertEqual(record["remaining"], {}, record)
