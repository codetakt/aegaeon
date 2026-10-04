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


class SecurityFuzzArchiveIntegrityTests(SecurityFuzzFixture):
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
