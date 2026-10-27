"""Bind fuzz cleanup to the output directories saved with recovery evidence."""

# ruff: noqa: PT009 - unittest checks remain active under Python -O

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from test_security_fuzz import TARGETS, SecurityFuzzFixture

DIRECT_CONTROL = r"""import json, os, pathlib, runpy, sys
h=runpy.run_path(sys.argv[1]);state=h['remove_cleanup'].__globals__
root=h['ROOT']; case=sys.argv[2]
cache=root.parent/'cleanup-cache';cache.mkdir()
(cache/'compiled').write_bytes(b'owned compiled output')
for name in h['RECOVERY_RAW_NAMES']:
    directory=root/'fuzz'/name;directory.mkdir(parents=True)
    (directory/'original').write_bytes(b'owned '+name.encode())
paths=h['cleanup_paths'](cache)
bindings={name:h['cleanup_root_binding'](path) for name,path in paths.items()}
manifest={'cleanup_roots':bindings,
 'raw':{name:{'present':True,'inventory':h['raw_inventory'](paths[name])}
        for name in h['RECOVERY_RAW_NAMES']}}
manifest['cleanup_entries']={name:state['cleanup_tree_snapshot'](path,bindings[name])
                             for name,path in paths.items()}
recovery=root.parent/'recovery';recovery.mkdir()
data={'selected_targets':[],'target_dir':str(cache)}
manifest['source']={};snapshots={'execution.json':json.dumps(data)}
state['collected_execution']=lambda _:data
state['execution_cache']=lambda _:cache
state['source_hashes']=lambda _:{}
state['load_cleanup_backup']=lambda *_:(recovery,manifest,snapshots)
foreign=root.parent/'foreign';foreign.mkdir();(foreign/'original').write_bytes(b'foreign preserved')
substituted=None;held=None;attacks=[]
if case=='absent-present':
    empty=paths['artifacts'];(empty/'original').unlink();empty.rmdir()
    manifest['raw']['artifacts']['present']=False
    manifest['raw']['artifacts']['inventory']={}
    manifest['cleanup_entries']['artifacts']={}
    bindings['artifacts']=h['cleanup_root_binding'](empty)
    empty.mkdir();(empty/'original').write_bytes(b'foreign preserved');substituted=empty
    attacks.append(case)
elif case.startswith('replace:') or case.startswith('symlink:'):
    name=case.split(':')[1];substituted=paths[name];held=substituted.with_name(substituted.name+'.held')
    substituted.rename(held)
    if case.startswith('symlink:'):substituted.symlink_to(foreign,target_is_directory=True)
    else:substituted.mkdir();(substituted/'original').write_bytes(b'foreign preserved')
    attacks.append(case)
elif case in ('ancestor-directory','ancestor-symlink'):
    ancestor=root/'fuzz';held=ancestor.with_name('fuzz.held');ancestor.rename(held)
    if case=='ancestor-directory':
        ancestor.mkdir()
        for name in h['RECOVERY_RAW_NAMES']:
            (ancestor/name).mkdir();(ancestor/name/'original').write_bytes(b'foreign preserved')
    else:ancestor.symlink_to(foreign,target_is_directory=True)
    substituted=ancestor;attacks.append(case)
elif case=='root-during-traversal':
    actual=state['remove_owned_cleanup_tree']
    def interleave(descriptor,device,check_root,*args):
        global held,substituted
        if not attacks:
            substituted=cache;held=cache.with_name('cleanup-cache.held');cache.rename(held)
            cache.mkdir();(cache/'original').write_bytes(b'foreign preserved');attacks.append(case)
        return actual(descriptor,device,check_root,*args)
    state['remove_owned_cleanup_tree']=interleave
elif case=='nested-symlink':
    (cache/'outside-link').symlink_to(foreign,target_is_directory=True)
    manifest['cleanup_entries']['cache']=state['cleanup_tree_snapshot'](cache,bindings['cache'])
elif case=='special-entry':
    os.mkfifo(cache/'unsupported')
rejected=False;reason=''
try:h['remove_cleanup'](root.parent/'evidence','run')
except (ValueError,OSError) as error:rejected=True;reason=str(error)
foreign_preserved=(foreign/'original').read_bytes()==b'foreign preserved'
preserved=True
if substituted is not None:
    if substituted.is_symlink():preserved=os.readlink(substituted)==str(foreign)
    elif case=='ancestor-directory':
        preserved=all((substituted/name/'original').read_bytes()==b'foreign preserved'
                      for name in h['RECOVERY_RAW_NAMES'])
    else:preserved=(substituted/'original').read_bytes()==b'foreign preserved'
record={'case':case,'rejected':rejected,'reason':reason,'attacks':attacks,
 'foreign_preserved':foreign_preserved,'replacement_preserved':preserved,
 'cache_present':cache.is_dir(),
 'raw_presence':{name:path.exists() or path.is_symlink()
                 for name,path in paths.items() if name!='cache'},'optimize':sys.flags.optimize}
if held is not None:record['original_held_preserved']=held.exists()
print(json.dumps(record))
"""


class FuzzCleanupIdentityTests(SecurityFuzzFixture):
    def cleanup_control(self, case):
        result = subprocess.run(  # noqa: S603 - instrument an owned source fixture
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                DIRECT_CONTROL,
                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                case,
            ],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def fresh_control(self, method, *args, **kwargs):
        fixture = FuzzCleanupIdentityTests()
        fixture.setUp()
        try:
            return getattr(fixture, method)(*args, **kwargs)
        finally:
            fixture.doCleanups()

    def test_replacements_links_and_changed_absence_fail_without_deletion(self):
        cases = [
            *(f"replace:{name}" for name in ("cache", "corpus", "artifacts", "corpus_archive")),
            "symlink:cache",
            "symlink:corpus",
            "absent-present",
            "ancestor-directory",
            "ancestor-symlink",
            "root-during-traversal",
        ]
        for case in cases:
            with self.subTest(case=case):
                # Each control owns a separate temporary fixture.
                record = self.fresh_control("cleanup_control", case)
                self.assertTrue(record["rejected"], record)
                self.assertTrue(record["foreign_preserved"], record)
                self.assertTrue(record["replacement_preserved"], record)
                self.assertEqual(record["attacks"], [case])
                if case != "symlink:cache":
                    self.assertTrue(record["cache_present"], record)

    def test_owned_cleanup_unlinks_nested_symlink_without_following_it(self):
        record = self.cleanup_control("nested-symlink")
        self.assertFalse(record["rejected"], record)
        self.assertTrue(record["foreign_preserved"], record)
        self.assertFalse(record["cache_present"], record)
        self.assertFalse(any(record["raw_presence"].values()), record)

    def test_special_cache_entry_is_blocking(self):
        record = self.cleanup_control("special-entry")
        self.assertTrue(record["rejected"], record)
        self.assertIn("special filesystem", record["reason"])
        self.assertTrue(record["foreign_preserved"], record)
        self.assertTrue(record["cache_present"], record)
        self.assertTrue(all(record["raw_presence"].values()), record)

    def wrapper_control(self, name, *, absent=False):
        if not absent:
            self.seed_stale_collection()
        hook = f"""
original_backup = backup_cleanup
def backup_then_replace(directory):
    run_id = original_backup(directory)
    name = {name!r}
    path = Path(os.environ['CARGO_TARGET_DIR']) / 'fuzz' if name == 'cache' else FUZZ_DIR / name
    if path.exists():
        path.rename(path.with_name(path.name + '.held'))
    path.mkdir()
    sentinel = path / {TARGETS[0]!r} / 'previous-input'
    sentinel.parent.mkdir(parents=True)
    sentinel.write_bytes(b'foreign sentinel matching original relative name')
    (path / 'replacement-marker').write_bytes(b'foreign marker')
    return run_id
backup_cleanup = backup_then_replace
"""
        self.install_helper_hooks({"--backup-cleanup": hook})
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        summary = self.summary()
        path = (
            Path(self.env["CARGO_TARGET_DIR"]) / "fuzz"
            if name == "cache"
            else self.root / "fuzz" / name
        )
        preserved = (
            (
                (path / TARGETS[0] / "previous-input").read_bytes()
                == b"foreign sentinel matching original relative name"
                and (path / "replacement-marker").read_bytes() == b"foreign marker"
            )
            if path.exists()
            else False
        )
        backup = self.artifacts / "fuzz/cleanup-recovery" / summary["execution"]["run_id"]
        reports = list(backup.glob("recovery-result-*.json"))
        return {
            "case": name,
            "absent": absent,
            "returncode": result.returncode,
            "status": summary["status"],
            "cleanup_exit_code": summary["execution"].get("cleanup_exit_code"),
            "replacement_preserved": preserved,
            "backup_present": (backup / "backup-ready.json").is_file(),
            "recovery": json.loads(reports[0].read_text()) if reports else None,
            "manifest": json.loads((backup / "backup-ready.json").read_text()),
        }

    def test_actual_wrapper_preserves_replacements_and_failed_recovery_receipts(self):
        for name, absent in (("corpus", False), ("cache", False), ("artifacts", True)):
            with self.subTest(name=name, absent=absent):
                record = self.fresh_control("wrapper_control", name, absent=absent)
                self.assertNotEqual(record["returncode"], 0, record)
                self.assertEqual(record["status"], "failed", record)
                self.assertEqual(record["cleanup_exit_code"], 2, record)
                self.assertTrue(record["replacement_preserved"], record)
                self.assertTrue(record["backup_present"], record)
                self.assertEqual(
                    record["recovery"]["status"], "restored" if name == "cache" else "failed"
                )
                self.assertEqual(record["recovery"]["reason"], "removal")
                self.assertEqual(
                    set(record["manifest"]["cleanup_roots"]),
                    {"cache", "corpus", "artifacts", "corpus_archive"},
                )


if __name__ == "__main__":
    unittest.main()
