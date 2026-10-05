"""Reject changed nested outputs and restore only missing original evidence."""

# ruff: noqa: PT009 - checks remain active under optimized Python

from __future__ import annotations

import json
import subprocess
import sys

from test_security_fuzz import SecurityFuzzFixture

CONTROL = r"""import json, os, pathlib, runpy, shutil, sys

h = runpy.run_path(sys.argv[1])
state = h["remove_cleanup"].__globals__
root = h["ROOT"]
case = sys.argv[2]
cache = root.parent / "owned-cache"
cache.mkdir()
(cache / "binary").write_bytes(b"owned binary")
for name in h["RECOVERY_RAW_NAMES"]:
    path = root / "fuzz" / name
    path.mkdir(parents=True)
    (path / "nested").mkdir()
    (path / "nested/input").write_bytes(b"original raw " + name.encode())
outside = root.parent / "outside"
outside.mkdir()
(outside / "sentinel").write_bytes(b"foreign preserved")
literal = str(outside) + "/./sentinel"
(root / "fuzz/corpus/literal").symlink_to(literal)
paths = h["cleanup_paths"](cache)
bindings = {name: h["cleanup_root_binding"](path) for name, path in paths.items()}
entries = {
    name: state["cleanup_tree_snapshot"](path, bindings[name]) for name, path in paths.items()
}
recovery = root.parent / "recovery"
recovery.mkdir()
raw = h["copy_raw_backups"](recovery)
data = {"selected_targets": [], "target_dir": str(cache)}
manifest = {"cleanup_roots": bindings, "cleanup_entries": entries, "raw": raw, "source": {}}
state["collected_execution"] = lambda _: data
state["execution_cache"] = lambda _: cache
state["source_hashes"] = lambda _: {}
state["load_cleanup_backup"] = lambda *_: (recovery, manifest, {"execution.json": json.dumps(data)})
attack = []
rejected = False
reason = ""
held = None
before = {name: h["raw_inventory"](path) for name, path in paths.items() if name != "cache"}
if case == "raw-added":
    (paths["corpus"] / "added").write_bytes(b"new raw evidence")
    attack.append(case)
elif case == "cache-child-replaced":
    p = cache / "binary"
    p.rename(cache / "held-binary")
    p.write_bytes(b"foreign cache file")
    attack.append(case)
elif case == "raw-content-changed":
    p = paths["corpus"] / "nested/input"
    old = p.stat()
    original = p.read_bytes()
    changed = bytes([original[0] ^ 1]) + original[1:]
    p.write_bytes(changed)
    os.utime(p, ns=(old.st_atime_ns, old.st_mtime_ns))
    attack.append(case)
elif case == "nested-during-delete":
    actual = state["remove_owned_cleanup_tree"]

    def replace(descriptor, device, check, expected, prefix=""):
        global held
        if prefix == "nested/" and not attack:
            p = paths["corpus"] / "nested"
            held = p.with_name("nested.held")
            p.rename(held)
            p.mkdir()
            (p / "input").write_bytes(b"foreign nested file")
            attack.append(case)
        return actual(descriptor, device, check, expected, prefix)

    state["remove_owned_cleanup_tree"] = replace
elif case.startswith("restore-"):
    (paths["corpus"] / "nested/input").unlink()
    if case == "restore-replacement":
        p = paths["artifacts"] / "nested"
        p.rename(p.with_name("nested.held"))
        p.mkdir()
        (p / "input").write_bytes(b"foreign nested file")
        attack.append(case)
    elif case == "restore-during-copy":
        actual = state["restore_missing_file"]

        def replace(source, destination, name, expected, check):
            global held
            if not attack:
                p = paths["corpus"] / "nested"
                held = p.with_name("nested.held")
                p.rename(held)
                p.mkdir()
                (p / "input").write_bytes(b"foreign nested file")
                attack.append(case)
            return actual(source, destination, name, expected, check)

        state["restore_missing_file"] = replace
try:
    if case.startswith("restore-"):
        h["restore_raw_copy"](recovery, manifest)
    else:
        h["remove_cleanup"](root.parent / "evidence", "run")
except (ValueError, OSError) as error:
    rejected = True
    reason = str(error)
record = {
    "case": case,
    "rejected": rejected,
    "reason": reason,
    "attack": attack,
    "outside_preserved": (outside / "sentinel").read_bytes() == b"foreign preserved",
    "recovery_preserved": all(
        h["raw_inventory"](recovery / "raw" / name) == record["inventory"]
        for name, record in raw.items()
    ),
    "optimize": sys.flags.optimize,
}
if case in ("restore-replacement", "restore-during-copy", "nested-during-delete"):
    path = paths["artifacts"] if case == "restore-replacement" else paths["corpus"]
    record["replacement_preserved"] = (path / "nested/input").read_bytes() == b"foreign nested file"
if case in ("restore-replacement", "restore-during-copy"):
    record["no_missing_file_created"] = (
        not (paths["corpus"] / "nested/input").exists()
        if case == "restore-replacement"
        else not (held / "input").exists()
    )
if case == "restore-partial":
    record["raw_exact"] = all(
        h["raw_inventory"](paths[name]) == expected for name, expected in before.items()
    )
    record["literal_preserved"] = os.readlink(paths["corpus"] / "literal") == literal
if case == "raw-added":
    record["addition_preserved"] = (paths["corpus"] / "added").read_bytes() == b"new raw evidence"
if case == "cache-child-replaced":
    record["replacement_preserved"] = (cache / "binary").read_bytes() == b"foreign cache file"
if case == "raw-content-changed":
    record["changed_bytes_preserved"] = (paths["corpus"] / "nested/input").read_bytes() == changed
print(json.dumps(record))
"""


class FuzzOutputLifecycleTests(SecurityFuzzFixture):
    def test_support_modules_bind_source_bytes_with_isolated_startup(self):
        code = """import hashlib, json, runpy, sys
h = runpy.run_path(sys.argv[1])
selected = list(h['REQUIRED_TARGETS'])
before = h['source_hashes'](selected)
support = h['ROOT'] / 'scripts/fuzz/fuzz_support'
files = list(support.glob('*.py'))
bound = all(before[p.relative_to(h['ROOT']).as_posix()]['sha256'] ==
            hashlib.sha256(p.read_bytes()).hexdigest() for p in files)
path = support / 'recovery.py'
original = path.read_bytes()
path.write_bytes(original + b'\\n# changed recovery input\\n')
changed = h['source_hashes'](selected) != before
path.write_bytes(original)
print(json.dumps({'bound': bound, 'changed': changed,
                  'root': str(h['ROOT']), 'bytecode': list(support.glob('__pycache__'))}))
"""
        result = subprocess.run(  # noqa: S603 - actual source inventory on the owned fixture
            [
                sys.executable,
                "-I",
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                code,
                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
            ],
            cwd=self.root.parent,
            env={**self.env, "PYTHONPATH": str(self.bin)},
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(result.stdout)
        self.assertTrue(record["bound"], record)
        self.assertTrue(record["changed"], record)
        self.assertEqual(record["root"], str(self.root), record)
        self.assertEqual(record["bytecode"], [], record)

    def control(self, case):
        result = subprocess.run(  # noqa: S603 - owned deterministic filesystem interleavings
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
        self.assertTrue(record["outside_preserved"], record)
        self.assertTrue(record["recovery_preserved"], record)
        return record

    def test_raw_additions_after_backup_remain_untouched(self):
        record = self.control("raw-added")
        self.assertTrue(record["rejected"], record)
        self.assertTrue(record["addition_preserved"], record)

    def test_nested_cache_replacement_remains_untouched(self):
        record = self.control("cache-child-replaced")
        self.assertTrue(record["rejected"], record)
        self.assertTrue(record["replacement_preserved"], record)

    def test_changed_raw_bytes_fail_even_with_restored_mtime(self):
        record = self.control("raw-content-changed")
        self.assertTrue(record["rejected"], record)
        self.assertTrue(record["changed_bytes_preserved"], record)

    def test_nested_ancestor_swap_during_deletion_is_blocking(self):
        record = self.control("nested-during-delete")
        self.assertTrue(record["rejected"], record)
        self.assertTrue(record["replacement_preserved"], record)
        self.assertEqual(record["attack"], ["nested-during-delete"])

    def test_partial_restore_keeps_existing_literal_links(self):
        record = self.control("restore-partial")
        self.assertFalse(record["rejected"], record)
        self.assertTrue(record["raw_exact"], record)
        self.assertTrue(record["literal_preserved"], record)

    def test_restore_preflights_all_nested_destinations_before_writing(self):
        record = self.control("restore-replacement")
        self.assertTrue(record["rejected"], record)
        self.assertTrue(record["replacement_preserved"], record)
        self.assertTrue(record["no_missing_file_created"], record)

    def test_restore_rechecks_nested_ancestor_before_exclusive_copy(self):
        record = self.control("restore-during-copy")
        self.assertTrue(record["rejected"], record)
        self.assertTrue(record["replacement_preserved"], record)
        self.assertTrue(record["no_missing_file_created"], record)
