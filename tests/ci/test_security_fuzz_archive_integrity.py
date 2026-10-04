"""Bind real tar bytes and literal links to the frozen fuzz evidence inventory."""

# ruff: noqa: PT009 - unittest controls remain effective under -O

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from test_security_fuzz import TARGETS, SecurityFuzzFixture

CONTROL = r"""
import hashlib,json,os,pathlib,runpy,sys,tarfile
h=runpy.run_path(sys.argv[1]); state=h['add_evidence_entry'].__globals__
route,case=sys.argv[2:4]
root=h['ROOT']; target=h['REQUIRED_TARGETS'][0]
source=root/'fuzz'/('artifacts' if route=='crash' else 'corpus')/target
source.mkdir(parents=True)
(source/'stable').write_bytes(b'stable unrelated evidence')
entry=source/'entry'
original=b'original A evidence'
replacement=b'archived B evidence'
if case=='changed-size-file': replacement+=b' with a different size'
if case=='supported': original=b'A'*(2*1024*1024+17)
outside=root.parent/'outside'; outside.mkdir()
sentinel=outside/'private-input'; sentinel.write_bytes(b'inert external sentinel')
if case=='symlink-target':
    entry.symlink_to('../original-literal-target')
elif case=='directory-to-file':
    entry.mkdir()
else:
    entry.write_bytes(original)
if case=='supported':
    (source/'file-link').symlink_to(sentinel)
    (source/'directory-link').symlink_to(outside, target_is_directory=True)
before=h['raw_inventory'](source)
actual=state['add_evidence_entry']; attacks=[]
def interleave(tar,path,arcname,*args,**kwargs):
    if path!=entry or case=='supported': return actual(tar,path,arcname,*args,**kwargs)
    attacks.append(case)
    if case=='file-to-directory':
        path.unlink(); path.mkdir()
    elif case=='directory-to-file':
        path.rmdir(); path.write_bytes(replacement)
    elif case=='symlink-target':
        path.unlink(); path.symlink_to('../replacement-literal-target')
    else:
        path.write_bytes(replacement)
    try:
        return actual(tar,path,arcname,*args,**kwargs)
    finally:
        if case=='file-to-directory':
            path.rmdir(); path.write_bytes(original)
        elif case=='directory-to-file':
            path.unlink(); path.mkdir()
        elif case=='symlink-target':
            path.unlink(); path.symlink_to('../original-literal-target')
        else:
            path.write_bytes(original)
state['add_evidence_entry']=interleave
opened=[]; original_open=state['open_evidence_file']
def owned_open(path,*args,**kwargs):
    if pathlib.Path(path).is_relative_to(outside): raise RuntimeError('external content read')
    opened.append(str(path))
    return original_open(path,*args,**kwargs)
state['open_evidence_file']=owned_open
read_sizes=[]; read_bytes=0; actual_add=tarfile.TarFile.addfile
class Probe:
    def __init__(self,stream): self.stream=stream
    def read(self,size):
        global read_bytes
        if size<=0 or size>1024*1024: raise RuntimeError('unbounded archive content read')
        read_sizes.append(size); data=self.stream.read(size); read_bytes+=len(data)
        return data
def record_add(tar,info,content=None):
    return actual_add(tar,info,Probe(content) if content is not None else None)
tarfile.TarFile.addfile=record_add
rejected=False; reason=''; archive_path=None
output=root/'artifacts/archive-control'
try:
    if route=='upload':
        h['package_upload'](output); archive_path=output/'security-evidence.tar.gz'
    elif route=='corpus':
        archive_path=h['create_archive']()
    elif route=='crash':
        archive_path=h['archive_crashes'](h['gather_crash_stats'](),output)
    else:
        raise RuntimeError('unknown archive route')
except ValueError as error:
    rejected=True; reason=str(error)
if h['raw_inventory'](source)!=before: raise RuntimeError('input inventory was not restored')
if sentinel.read_bytes()!=b'inert external sentinel':
    raise RuntimeError('external sentinel changed')
record={'route':route,'case':case,'rejected':rejected,'reason':reason,
        'attacks':attacks,'inputs_restored':True,'external_reads':0,
        'max_tar_read':max(read_sizes,default=0),'tar_read_bytes':read_bytes,
        'optimize':sys.flags.optimize,'published_archive':False,'published_manifest':False}
if route=='upload':
    record['published_archive']=(output/'security-evidence.tar.gz').exists()
    record['published_manifest']=(output/'manifest.json').exists()
    if rejected and (record['published_archive'] or record['published_manifest']):
        raise RuntimeError('rejected upload was published')
if not rejected:
    if archive_path is None: raise RuntimeError('archive was not created')
    member=(f'fuzz/corpus/{target}/entry' if route=='upload'
            else f'corpus/{target}/entry' if route=='corpus' else f'{target}/entry')
    with tarfile.open(archive_path) as archive:
        info=archive.getmember(member)
        if info.isfile():
            stream=archive.extractfile(info)
            if stream is None: raise RuntimeError('regular archived content missing')
            with stream: archived=stream.read()
            archived_record={'type':'file','sha256':hashlib.sha256(archived).hexdigest()}
            record['archived_size']=info.size
            if len(archived)!=info.size: raise RuntimeError('archive size/content differ')
        elif info.issym(): archived_record={'type':'symlink','target':info.linkname}
        elif info.isdir(): archived_record={'type':'directory'}
        else: raise RuntimeError('unsupported archived fixture entry')
        record['expected_entry']=before['entry']; record['archived_entry']=archived_record
        record['archive_matches_inventory']=archived_record==before['entry']
        if case=='supported':
            for name,path in (('file-link',sentinel),('directory-link',outside)):
                link=archive.getmember(member.removesuffix('entry')+name)
                if not link.issym() or link.linkname!=str(path):
                    raise RuntimeError('nested inert literal link was not preserved')
            record['literal_links_preserved']=True
    if route=='upload':
        manifest=json.loads((output/'manifest.json').read_text())
        frozen=manifest['roots']['fuzz/corpus']['entries'][target+'/entry']
        if frozen!=before['entry']: raise RuntimeError('manifest differs from initial inventory')
        record['manifest_entry']=frozen
print(json.dumps(record,sort_keys=True))
"""

PUBLICATION_CONTROL = r"""
import hashlib,json,os,pathlib,runpy,sys,tarfile
from datetime import datetime,UTC
h=runpy.run_path(sys.argv[1]); state=h['write_exclusive_archive'].__globals__
route,case=sys.argv[2:4]
root=h['ROOT']; target=h['REQUIRED_TARGETS'][0]
class FixedTime(datetime):
    @classmethod
    def now(cls,tz=None): return cls(2026,10,4,12,34,56,123456,tzinfo=UTC)
h['create_archive'].__globals__['datetime']=FixedTime
os.environ['CORPUS_ARCHIVE_KEEP']='2'
source=root/'fuzz'/('artifacts' if route=='crash' else 'corpus')/target
source.mkdir(parents=True)
(source/'entry').write_bytes(b'preserve raw evidence')
before=h['raw_inventory'](source)
output=h['ARCHIVE_DIR'] if route=='corpus' else root/'artifacts/archive-control'
output.mkdir(parents=True)
timestamp=FixedTime.now().strftime('%Y%m%dT%H%M%S%fZ')
final=output/(('crashes_' if route=='crash' else '')+timestamp+'.tar.gz')
outside=root.parent/'outside'; outside.mkdir()
sentinel=outside/'external-input'; sentinel.write_bytes(b'preserve external bytes')
prior=output/'19990101T000000000000Z.tar.gz'; prior.write_bytes(b'prior archive bytes')
if case=='supported':
    for number in range(2):
        (output/f'1998010{number}T000000000000Z.tar.gz').write_bytes(b'old retained archive')
unrelated=output/'.archive-unrelated.tmp'; unrelated.symlink_to(sentinel)
prior_external={}
for number in range(5):
    path=outside/f'1900010{number}T000000000000Z.tar.gz'
    path.write_bytes(b'external prior archive '+str(number).encode())
    prior_external[path.name]=path.read_bytes()
original_final=b'prior final destination'
if case=='symlink': final.symlink_to(sentinel)
elif case=='hardlink': os.link(sentinel,final)
elif case=='regular': final.write_bytes(original_final)
elif case=='directory': final.mkdir(); (final/'sentinel').write_bytes(original_final)
attacks=[]; actual=state['archive_raw_tree']; swapped=None; held=None
def interleave(tar,path,arcname):
    global swapped,held
    if case=='input-failure': raise ValueError('controlled raw input failure')
    actual(tar,path,arcname)
    if case=='partial-write': raise OSError('controlled partial archive write')
    if case=='collision-race':
        final.write_bytes(original_final); attacks.append(case)
    if case in ('directory-swap','ancestor-swap'):
        swapped=output if case=='directory-swap' else output.parent
        held=swapped.with_name(swapped.name+'.held')
        swapped.rename(held); swapped.symlink_to(outside,target_is_directory=True)
        attacks.append(case)
    if case=='temp-swap':
        entries=[p for p in output.iterdir() if p.name.startswith('.archive-') and p!=unrelated]
        if len(entries)!=1: raise RuntimeError('exclusive owned temp was not created')
        temporary=entries[0]
        temporary.rename(temporary.with_name(temporary.name+'.held'))
        temporary.symlink_to(sentinel)
        attacks.append(case)
state['archive_raw_tree']=interleave
if case=='incomplete-footer':
    original_verify=state['verify_archive_stream']
    def truncate_footer(stream,path):
        stream.seek(0,2); stream.truncate(stream.tell()-5); stream.flush()
        return original_verify(stream,path)
    state['verify_archive_stream']=truncate_footer
if case in ('postlink-directory-swap','postlink-final-replacement'):
    original_link=os.link
    def after_link(*args,**kwargs):
        global swapped,held
        original_link(*args,**kwargs)
        if case=='postlink-directory-swap':
            swapped=output; held=output.with_name(output.name+'.held')
            swapped.rename(held); swapped.symlink_to(outside,target_is_directory=True)
        else:
            final.unlink(); final.symlink_to(sentinel)
        attacks.append(case)
    state['os'].link=after_link
rejected=False; reason=''; archive=None
try:
    archive=(h['create_archive']() if route=='corpus'
             else h['archive_crashes'](h['gather_crash_stats'](),output))
except (ValueError,OSError) as error:
    rejected=True; reason=str(error)
finally:
    if swapped is not None:
        swapped.unlink(); held.rename(swapped)
if h['raw_inventory'](source)!=before: raise RuntimeError('raw input was changed')
record={'route':route,'case':case,'rejected':rejected,'reason':reason,
        'attacks':attacks,'raw_preserved':True,'optimize':sys.flags.optimize,
        'external_preserved':sentinel.read_bytes()==b'preserve external bytes',
        'prior_preserved':prior.exists() and prior.read_bytes()==b'prior archive bytes',
        'unrelated_temp_preserved':unrelated.is_symlink() and os.readlink(unrelated)==str(sentinel),
        'external_prior_preserved':all((outside/name).exists() and (outside/name).read_bytes()==data
                                        for name,data in prior_external.items()),
        'published':final.exists() or final.is_symlink(),
        'temps':[p.name for p in output.iterdir()
                 if p.name.startswith('.archive-') and p!=unrelated],
        'native_calls':0}
if case=='temp-swap':
    foreign=[p for p in output.iterdir() if p.is_symlink() and p!=unrelated]
    record['replacement_temp_preserved']=len(foreign)==1 and os.readlink(foreign[0])==str(sentinel)
if case=='postlink-final-replacement':
    record['replacement_final_preserved']=final.is_symlink() and os.readlink(final)==str(sentinel)
if case in ('regular','collision-race'):
    record['original_final_preserved']=final.exists() and final.read_bytes()==original_final
elif case=='directory':
    record['original_final_preserved']=(final/'sentinel').read_bytes()==original_final
elif case=='symlink':
    record['original_final_preserved']=final.is_symlink() and os.readlink(final)==str(sentinel)
elif case=='hardlink':
    record['original_final_preserved']=final.stat().st_ino==sentinel.stat().st_ino
if not rejected and case=='supported':
    with tarfile.open(archive) as tar:
        member=tar.getmember(('corpus/' if route=='corpus' else '')+target+'/entry')
        stream=tar.extractfile(member)
        record['archive_raw_bytes_match']=stream.read()==b'preserve raw evidence'
    record['archive_name']=archive.name
    record['archive_regular']=archive.is_file() and not archive.is_symlink()
    record['archive_unaliased']=archive.stat().st_nlink==1
    record['retained_archives']=sorted(p.name for p in output.glob('*.tar.gz'))
    header=archive.read_bytes()
    record['gzip_original_name']=header[10:].split(b'\0',1)[0].decode() if header[3]&8 else None
print(json.dumps(record,sort_keys=True))
"""


class SecurityFuzzArchiveIntegrityTests(SecurityFuzzFixture):
    def publication_control(self, route, case):
        helper = self.root / "scripts/fuzz/manage_fuzz_corpus.py"
        result = subprocess.run(  # noqa: S603 - actual archive writer with owned negative controls
            [
                sys.executable,
                "-I",
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                PUBLICATION_CONTROL,
                str(helper),
                route,
                case,
            ],
            cwd=self.root,
            env={**self.env, "FUZZ_TARGETS": TARGETS[0]},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(Path(self.env["CARGO_TARGET_DIR"]).exists())
        record = json.loads(result.stdout)
        self.assertTrue(record["raw_preserved"], record)
        self.assertTrue(record["external_preserved"], record)
        self.assertTrue(record["unrelated_temp_preserved"], record)
        self.assertTrue(record["external_prior_preserved"], record)
        self.assertEqual(record["optimize"], sys.flags.optimize)
        return record

    def test_corpus_and_crash_archive_destinations_reject_aliases_and_collisions(self):
        for route in ("corpus", "crash"):
            for case in ("symlink", "hardlink", "regular", "directory", "collision-race"):
                with self.subTest(route=route, case=case):
                    fixture = SecurityFuzzArchiveIntegrityTests()
                    fixture.setUp()
                    try:
                        record = fixture.publication_control(route, case)
                        self.assertTrue(record["rejected"], record)
                        self.assertTrue(record["original_final_preserved"], record)
                        self.assertTrue(record["prior_preserved"], record)
                        self.assertEqual(record["temps"], [], record)
                    finally:
                        fixture.doCleanups()

    def test_failed_corpus_and_crash_archive_construction_publishes_no_partial_output(self):
        for route in ("corpus", "crash"):
            for case in ("input-failure", "partial-write"):
                with self.subTest(route=route, case=case):
                    fixture = SecurityFuzzArchiveIntegrityTests()
                    fixture.setUp()
                    try:
                        record = fixture.publication_control(route, case)
                        self.assertTrue(record["rejected"], record)
                        self.assertFalse(record["published"], record)
                        self.assertTrue(record["prior_preserved"], record)
                        self.assertEqual(record["temps"], [], record)
                    finally:
                        fixture.doCleanups()

    def test_archive_directory_swaps_preserve_prior_and_external_outputs(self):
        for route in ("corpus", "crash"):
            for case in ("directory-swap", "ancestor-swap"):
                with self.subTest(route=route, case=case):
                    fixture = SecurityFuzzArchiveIntegrityTests()
                    fixture.setUp()
                    try:
                        record = fixture.publication_control(route, case)
                        self.assertTrue(record["rejected"], record)
                        self.assertFalse(record["published"], record)
                        self.assertTrue(record["prior_preserved"], record)
                        self.assertEqual(record["temps"], [], record)
                    finally:
                        fixture.doCleanups()

    def test_archive_readback_rejects_incomplete_gzip_footer_before_publication(self):
        for route in ("corpus", "crash"):
            with self.subTest(route=route):
                fixture = SecurityFuzzArchiveIntegrityTests()
                fixture.setUp()
                try:
                    record = fixture.publication_control(route, "incomplete-footer")
                    self.assertTrue(record["rejected"], record)
                    self.assertFalse(record["published"], record)
                    self.assertTrue(record["prior_preserved"], record)
                    self.assertEqual(record["temps"], [], record)
                finally:
                    fixture.doCleanups()

    def test_archive_cleanup_preserves_replaced_temporary_names(self):
        for route in ("corpus", "crash"):
            with self.subTest(route=route):
                fixture = SecurityFuzzArchiveIntegrityTests()
                fixture.setUp()
                try:
                    record = fixture.publication_control(route, "temp-swap")
                    self.assertTrue(record["rejected"], record)
                    self.assertFalse(record["published"], record)
                    self.assertTrue(record["prior_preserved"], record)
                    self.assertTrue(record["replacement_temp_preserved"], record)
                    # The moved owned inode and foreign replacement remain held.
                    self.assertEqual(len(record["temps"]), 2, record)
                finally:
                    fixture.doCleanups()

    def test_postlink_mismatch_rejects_success_and_disposes_only_matching_owned_entries(self):
        for route in ("corpus", "crash"):
            for case in ("postlink-directory-swap", "postlink-final-replacement"):
                with self.subTest(route=route, case=case):
                    fixture = SecurityFuzzArchiveIntegrityTests()
                    fixture.setUp()
                    try:
                        record = fixture.publication_control(route, case)
                        self.assertTrue(record["rejected"], record)
                        self.assertTrue(record["prior_preserved"], record)
                        self.assertEqual(record["temps"], [], record)
                        if case == "postlink-final-replacement":
                            self.assertTrue(record["replacement_final_preserved"], record)
                        else:
                            self.assertFalse(record["published"], record)
                    finally:
                        fixture.doCleanups()

    def test_corpus_and_crash_archive_success_preserves_names_contents_and_retention(self):
        for route in ("corpus", "crash"):
            with self.subTest(route=route):
                fixture = SecurityFuzzArchiveIntegrityTests()
                fixture.setUp()
                try:
                    record = fixture.publication_control(route, "supported")
                    self.assertFalse(record["rejected"], record)
                    self.assertTrue(record["archive_raw_bytes_match"], record)
                    self.assertTrue(record["archive_regular"], record)
                    self.assertTrue(record["archive_unaliased"], record)
                    self.assertTrue(record["prior_preserved"], record)
                    expected = (
                        "crashes_" if route == "crash" else ""
                    ) + "20261004T123456123456Z.tar.gz"
                    self.assertEqual(record["archive_name"], expected)
                    self.assertEqual(record["gzip_original_name"], expected.removesuffix(".gz"))
                    self.assertEqual(
                        len(record["retained_archives"]), 2 if route == "corpus" else 4
                    )
                    self.assertEqual(record["temps"], [], record)
                finally:
                    fixture.doCleanups()

    def archive_control(self, route, case):
        helper = self.root / "scripts/fuzz/manage_fuzz_corpus.py"
        result = subprocess.run(  # noqa: S603 - actual helper, owned fixtures and real tar
            [
                sys.executable,
                "-I",
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                CONTROL,
                str(helper),
                route,
                case,
            ],
            cwd=self.root,
            env={**self.env, "FUZZ_TARGETS": TARGETS[0]},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertFalse(Path(self.env["CARGO_TARGET_DIR"]).exists())
        record = json.loads(result.stdout)
        self.assertTrue(record["inputs_restored"])
        self.assertEqual(record["external_reads"], 0)
        self.assertEqual(record["optimize"], sys.flags.optimize)
        return record

    def test_upload_corpus_and_crash_reject_content_swaps_between_inventories(self):
        for route in ("upload", "corpus", "crash"):
            for case in ("same-size-file", "changed-size-file"):
                with self.subTest(route=route, case=case):
                    fixture = SecurityFuzzArchiveIntegrityTests()
                    fixture.setUp()
                    try:
                        record = fixture.archive_control(route, case)
                        self.assertTrue(record["rejected"], record)
                        self.assertIn("content differs from expected inventory", record["reason"])
                        self.assertEqual(record["attacks"], [case])
                    finally:
                        fixture.doCleanups()

    def test_archive_entries_reject_type_and_literal_link_swaps_between_inventories(self):
        for route in ("upload", "corpus", "crash"):
            for case in ("file-to-directory", "directory-to-file", "symlink-target"):
                with self.subTest(route=route, case=case):
                    fixture = SecurityFuzzArchiveIntegrityTests()
                    fixture.setUp()
                    try:
                        record = fixture.archive_control(route, case)
                        self.assertTrue(record["rejected"], record)
                        self.assertIn(
                            "type or literal link differs from expected inventory", record["reason"]
                        )
                        self.assertEqual(record["attacks"], [case])
                    finally:
                        fixture.doCleanups()

    def test_supported_archives_bind_regular_bytes_and_preserve_inert_literal_links(self):
        for route in ("upload", "corpus", "crash"):
            with self.subTest(route=route):
                fixture = SecurityFuzzArchiveIntegrityTests()
                fixture.setUp()
                try:
                    record = fixture.archive_control(route, "supported")
                    self.assertFalse(record["rejected"], record)
                    self.assertTrue(record["archive_matches_inventory"])
                    self.assertTrue(record["literal_links_preserved"])
                    self.assertEqual(record["archived_size"], 2 * 1024 * 1024 + 17)
                    self.assertGreater(record["tar_read_bytes"], 2 * 1024 * 1024)
                    self.assertGreater(record["max_tar_read"], 0)
                    self.assertLessEqual(record["max_tar_read"], 1024 * 1024)
                    if route == "upload":
                        self.assertTrue(record["published_archive"])
                        self.assertTrue(record["published_manifest"])
                finally:
                    fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
