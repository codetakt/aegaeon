# ruff: noqa: PT009 - these controls run under unittest discovery
"""Exercise Python startup isolation through the actual fuzz shell entrypoint."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

from test_security_fuzz import CARGO, TARGETS, SecurityFuzzFixture


class SecurityFuzzPythonIsolationTests(SecurityFuzzFixture):
    def setUp(self):
        super().setUp()
        # Controlled Cargo/timeout/compiler fixtures are Python programs too.
        # Isolate their own startup so the probe measures production invocations.
        for executable in self.bin.iterdir():
            if executable.is_symlink():
                continue
            text = executable.read_text()
            prefix = f"#!{sys.executable}\n"
            if text.startswith(prefix):
                executable.write_text(text.replace(prefix, f"#!{sys.executable} -I\n", 1))
        self.startup = Path(self.temporary) / "python-startup"
        self.startup.mkdir()
        self.startup_marker = Path(self.temporary) / "startup-hook-called"
        self.python_calls = Path(self.temporary) / "python-calls.jsonl"

    def startup_hook(self, *, drop_compiler=False):
        code = (
            "import os, pathlib, sys\n"
            f"pathlib.Path({str(self.startup_marker)!r}).write_text('called')\n"
        )
        if drop_compiler:
            code += (
                "if sys.argv[0].endswith('/manage_fuzz_corpus.py'):\n"
                " os.environ.pop('RUSTC', None)\n"
            )
        (self.startup / "sitecustomize.py").write_text(code)

    def record_python_calls(self, *, fail_cleanup_receipt=False, fail_cleanup_removal=False):
        self.install(
            "python3",
            "import json, os, pathlib, sys\n"
            f"with pathlib.Path({str(self.python_calls)!r}).open('a') as output:\n"
            " output.write(json.dumps(sys.argv[1:]) + chr(10))\n"
            + (
                "if '--cleanup-result' in sys.argv:\n raise SystemExit(29)\n"
                if fail_cleanup_receipt
                else ""
            )
            + (
                "if '--remove-cleanup' in sys.argv:\n raise SystemExit(31)\n"
                if fail_cleanup_removal
                else ""
            )
            + f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n",
        )
        wrapper = self.bin / "python3"
        wrapper.write_text(
            wrapper.read_text().replace(f"#!{sys.executable}\n", f"#!{sys.executable} -I\n", 1)
        )

    def assert_isolated_calls(self):
        calls = [json.loads(line) for line in self.python_calls.read_text().splitlines()]
        self.assertTrue(calls)
        for arguments in calls:
            self.assertEqual(arguments[0], "-I", arguments)
        self.assertFalse(self.startup_marker.exists())
        return calls

    def test_inherited_startup_cannot_hide_unsupported_compiler_before_preflight(self):
        self.startup_hook(drop_compiler=True)
        parent_compiler = Path(self.temporary) / "cargo-retained-parent-compiler"
        self.install(
            "cargo",
            "import os, pathlib\n"
            f"pathlib.Path({str(parent_compiler)!r}).write_text(str('RUSTC' in os.environ))\n"
            + CARGO,
        )
        cargo = self.bin / "cargo"
        cargo.write_text(
            cargo.read_text().replace(f"#!{sys.executable}\n", f"#!{sys.executable} -I\n", 1)
        )
        self.seed_stale_results()
        receipts = self.saved_receipts()
        raw = {
            path: path.read_bytes()
            for path in (self.root / "fuzz").glob("*/" + TARGETS[0] + "/previous-input")
        }
        result = self.run_suite(PYTHONPATH=str(self.startup), RUSTC="unsupported-compiler-fixture")
        observed = {
            "startup_hook_executed": self.startup_marker.exists(),
            "cargo_parent_retained_RUSTC": (
                parent_compiler.exists() and parent_compiler.read_text() == "True"
            ),
            "fuzz_build_or_run": any(
                call[:2] in (["fuzz", "build"], ["fuzz", "run"]) for call in self.calls()
            ),
        }
        self.assertNotEqual(result.returncode, 0, json.dumps(observed, sort_keys=True))
        self.assertIn("inherited RUSTC override", result.stderr)
        self.assertFalse(self.startup_marker.exists())
        self.assertFalse(parent_compiler.exists())
        self.assertEqual(self.calls(), [])
        self.assert_receipts_unchanged(receipts)
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse(Path(self.env["CARGO_HOME"]).exists())
        self.assertFalse((self.artifacts / "summary").exists())

    def test_valid_execution_inline_selection_and_success_receipts_ignore_startup_hooks(self):
        self.startup_hook()
        self.record_python_calls()
        selected = TARGETS[:2]
        result = self.run_suite(
            PYTHONPATH=str(self.startup), FUZZ_TARGETS="\t" + " \n ".join(selected) + "\n"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["execution"]["status"], "passed")
        self.assertEqual(
            [call[-1] for call in self.calls() if call[:2] == ["fuzz", "build"]],
            list(selected),
        )
        self.assertEqual(
            [call[-3] for call in self.calls() if call[:2] == ["fuzz", "run"]],
            list(selected),
        )
        calls = self.assert_isolated_calls()
        self.assertTrue(
            any(arguments[1:2] == ["-c"] and "FUZZ_TARGETS" in arguments[2] for arguments in calls)
        )
        for action in (
            "--validate-git-environment",
            "--validate-preflight",
            "--validate-cache",
            "--prepare-run",
            "--record-environment",
            "--execution-cache",
            "--record-target",
            "--finish-run",
            "--backup-cleanup",
            "--remove-cleanup",
            "--cleanup-result",
        ):
            self.assertTrue(any(action in arguments for arguments in calls), action)
        self.assert_backup()
        self.assertFalse((self.root / "fuzz/corpus").exists())

    def check_recovery_isolated(self, *, receipt_failure):
        self.startup_hook()
        self.record_python_calls(
            fail_cleanup_receipt=receipt_failure, fail_cleanup_removal=not receipt_failure
        )
        _, raw = self.seed_stale_collection()
        result = self.run_suite(PYTHONPATH=str(self.startup), FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_restored(
            raw, "receipt" if receipt_failure else "removal", 0 if receipt_failure else 31
        )
        calls = self.assert_isolated_calls()
        self.assertTrue(any("--restore-cleanup" in arguments for arguments in calls))

    def test_cleanup_receipt_failure_restores_evidence_without_startup_hook(self):
        self.check_recovery_isolated(receipt_failure=True)

    def test_cleanup_removal_failure_restores_evidence_without_startup_hook(self):
        self.check_recovery_isolated(receipt_failure=False)

    def test_shared_helper_hooks_preserve_receipt_and_restoration_injection_with_isolated_argv(
        self,
    ):
        self.startup_hook()
        marker = Path(self.temporary) / "shared-restoration-hook-called"
        self.install_helper_hooks(
            {
                "--cleanup-result": "raise SystemExit(29)",
                "--restore-cleanup": f"Path({str(marker)!r}).write_text('called')",
            }
        )
        wrapper = self.bin / "python3"
        wrapper.write_text(
            wrapper.read_text().replace(f"#!{sys.executable}\n", f"#!{sys.executable} -I\n", 1)
        )
        _, raw = self.seed_stale_collection()
        result = self.run_suite(PYTHONPATH=str(self.startup), FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(marker.exists(), "shared restore hook must receive the real helper path")
        self.assert_restored(raw, "receipt", 0)
        self.assertFalse(self.startup_marker.exists())


if __name__ == "__main__":
    unittest.main()
