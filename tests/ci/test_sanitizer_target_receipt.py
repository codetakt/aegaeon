# ruff: noqa: PT009 - these controls run under unittest discovery
"""Safe ownership admission and original child receipt preservation controls."""

from __future__ import annotations

import contextlib
import io
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_sanitizer_dispatch as dispatch_fixture

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/sanitizers/sanitizer_paths.sh"


class SanitizerTargetReceiptTests(unittest.TestCase):
    def modeled_binding(self, operation, *, final_owner, parent_owner):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_binding.py"))
        binding_main = namespace["main"]
        failure = binding_main.__globals__["require"].__globals__["Failure"]
        identities = [[1, 10], [1, 11], [1, 12]]
        value = (
            "/system-parent/producer-target"
            if operation == "prepare"
            else json.dumps({"target": "/system-parent/producer-target", "identities": identities})
        )
        metadata = {
            10: SimpleNamespace(st_dev=1, st_ino=10, st_uid=parent_owner),
            11: SimpleNamespace(st_dev=1, st_ino=11, st_uid=parent_owner),
            12: SimpleNamespace(st_dev=1, st_ino=12, st_uid=final_owner),
        }
        output = io.StringIO()
        # All filesystem operations are inert. No literal system directory opens
        # or recursive removal are delegated by these ownership models.
        with (
            patch.object(sys, "argv", ["binding", operation, value, "", ""]),
            patch(
                "os.open",
                side_effect=lambda name, *args, **kwargs: {
                    "/": 10,
                    "system-parent": 11,
                    "producer-target": 12,
                }[name],
            ),
            patch("os.fstat", side_effect=lambda descriptor: metadata[descriptor]),
            patch("os.mkdir") as mkdir,
            patch("os.close"),
            patch("os.scandir", return_value=[]) as scan,
            patch(
                "os.stat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=1, st_ino=12)
            ),
            patch("os.rmdir") as remove,
            contextlib.redirect_stdout(output),
        ):
            try:
                binding_main()
            except failure as error:
                return error, output.getvalue(), scan.called, remove.called, mkdir.call_count
        return None, output.getvalue(), scan.called, remove.called, mkdir.call_count

    def test_foreign_final_owner_rejects_prepare_validate_cleanup_before_record_or_removal(self):
        for operation in ("prepare", "validate", "cleanup"):
            with self.subTest(operation=operation):
                error, output, scanned, removed, _ = self.modeled_binding(
                    operation, final_owner=os.getuid() + 1, parent_owner=os.getuid()
                )
                self.assertIsNotNone(error)
                self.assertIn("must belong to the producer", str(error))
                self.assertEqual(output, "")
                self.assertFalse(scanned)
                self.assertFalse(removed)

    def test_foreign_shared_parents_remain_allowed_for_owned_final_target(self):
        for operation in ("prepare", "validate", "cleanup"):
            with self.subTest(operation=operation):
                error, output, scanned, removed, _ = self.modeled_binding(
                    operation, final_owner=os.getuid(), parent_owner=os.getuid() + 1
                )
                self.assertIsNone(error)
                if operation == "prepare":
                    self.assertEqual(json.loads(output)["target"], "/system-parent/producer-target")
                self.assertEqual(scanned, operation == "cleanup")
                self.assertEqual(removed, operation == "cleanup")

    def test_owned_target_prepare_validate_cleanup_preserves_fixture_sibling(self):
        with tempfile.TemporaryDirectory() as directory:
            producer = Path(directory)
            target = producer / "owned-target"
            sibling = producer / "sibling-sentinel"
            sibling.write_bytes(b"preserve producer sibling\n")

            def invoke(operation, value):
                return subprocess.run(  # noqa: S603 - fixed helper and owned fixture only
                    [
                        shutil.which("bash"),
                        "-c",
                        'source "$1"; sanitizer_target_binding "$2" "$3"',
                        "fixture",
                        str(HELPER),
                        operation,
                        value,
                    ],
                    cwd=producer,
                    env={"PATH": os.environ["PATH"]},
                    capture_output=True,
                    text=True,
                    check=False,
                )

            prepared = invoke("prepare", str(target))
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            binding = prepared.stdout.strip()
            self.assertEqual(target.stat().st_uid, os.getuid())
            (target / "owned-output").write_bytes(b"controlled transient bytes\n")
            self.assertEqual(invoke("validate", binding).returncode, 0)
            cleaned = invoke("cleanup", binding)
            self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
            self.assertFalse(target.exists())
            self.assertEqual(sibling.read_bytes(), b"preserve producer sibling\n")

    def child_fixture(self):
        owner = dispatch_fixture.SanitizerDispatchTests()
        self.addCleanup(owner.doCleanups)
        fixture = owner.fixture()
        receipt = {
            "status": "failed",
            "stage": "execution",
            "exit_code": 71,
            "commands": [{"phase": "run", "exit_code": 71}],
            "units": [{"status": "failed", "targets": [{"name": "ffi", "status": "failed"}]}],
        }
        raw = json.dumps(receipt, indent=2) + "\n"
        child = dispatch_fixture.NIX.replace(
            "raise SystemExit(code)",
            "if sanitizer:\n"
            f"    raw = {raw!r}\n"
            "    (directory / 'run-summary.json').write_text(raw)\n"
            "    (root / 'original-child-summary.json').write_text(raw)\n"
            "raise SystemExit(code)",
            1,
        )
        fixture.install("nix", child)
        return owner, fixture

    def test_child_failure_with_successful_cleanup_preserves_exact_original_receipt(self):
        owner, fixture = self.child_fixture()
        result = owner.run_suite(fixture, SANITIZER_CHILD_EXIT="71")
        self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
        self.assertEqual(
            (fixture.artifacts / "sanitizers/run-summary.json").read_bytes(),
            (fixture.root / "original-child-summary.json").read_bytes(),
        )
        self.assertEqual(owner.calls(fixture, "cleanup")[0]["exit_code"], 0)
        self.assertFalse((fixture.root / "target/sanitizers").exists())
        log = (fixture.artifacts / "summary/security.log").read_text()
        self.assertIn("sanitizer smoke: failed (exit=71)", log)
        self.assertNotIn("sanitizer cleanup: failed", log)
        self.assertNotIn("sanitizer smoke: ok", log)

    def test_actual_cleanup_failure_records_cleanup_and_keeps_child_numeric_priority(self):
        owner, fixture = self.child_fixture()
        result = owner.run_suite(fixture, SANITIZER_CHILD_EXIT="71", SANITIZER_CLEANUP_EXIT="79")
        self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
        summary = json.loads((fixture.artifacts / "sanitizers/run-summary.json").read_text())
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["preflight_phase"], "cleanup")
        self.assertEqual(summary["exit_code"], 71)
        self.assertEqual(owner.calls(fixture, "cleanup")[0]["exit_code"], 79)
        self.assertTrue((fixture.root / "target/sanitizers/child-output").exists())
        self.assertIn(
            "sanitizer cleanup: failed (exit=79)",
            (fixture.artifacts / "summary/security.log").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
