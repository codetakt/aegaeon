# ruff: noqa: PT009 - these controls run under unittest discovery
"""Exercise sanitizer Python startup isolation at real shell boundaries."""

from __future__ import annotations

import json
import os
import sys
import unittest

import test_sanitizers as sanitizer_fixture


class SanitizerPythonIsolationTests(unittest.TestCase):
    def fixture(self, *, logging=False, mutation="marker"):
        fixture = (
            sanitizer_fixture.SanitizerLoggingTests()
            if logging
            else sanitizer_fixture.SanitizerTests()
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        # Model Cargo, libtest, Nix and tee programs use Python too. Isolate
        # their startup independently so this probe measures owned shell calls.
        for path in fixture.root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                prefix = f"#!{sys.executable}\n".encode()
                if data.startswith(prefix):
                    path.write_bytes(data.replace(prefix, f"#!{sys.executable} -I\n".encode(), 1))
        startup = fixture.root / "python-startup"
        startup.mkdir()
        fixture.startup_marker = fixture.root / "startup-hook-called"
        fixture.python_calls = fixture.root / "python-calls.jsonl"
        hook = (
            "import fcntl, json, os, pathlib, shlex\n"
            f"pathlib.Path({str(fixture.startup_marker)!r}).write_text('called')\n"
        )
        if mutation == "flags":
            hook += "shlex.split = lambda value: []\n"
        elif mutation == "receipt":
            hook += (
                "original = json.dump\n"
                "def dump(value, *args, **kwargs):\n"
                " value['status'] = 'completed'\n"
                " return original(value, *args, **kwargs)\n"
                "json.dump = dump\n"
            )
        elif mutation == "descriptor":
            hook += (
                "original = fcntl.fcntl\n"
                "def flags(fd, operation, *args):\n"
                " value = original(fd, operation, *args)\n"
                " return value | os.O_APPEND if operation == fcntl.F_GETFL else value\n"
                "fcntl.fcntl = flags\n"
            )
        (startup / "sitecustomize.py").write_text(hook)
        fixture.environment["PYTHONPATH"] = str(startup)
        python = fixture.bin / "python3"
        python.unlink()
        python.write_text(
            f"#!{sys.executable} -I\n"
            "import json, os, pathlib, sys\n"
            f"with pathlib.Path({str(fixture.python_calls)!r}).open('a') as output:\n"
            " output.write(json.dumps(sys.argv[1:]) + chr(10))\n"
            f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n"
        )
        python.chmod(0o755)
        return fixture

    def isolated_calls(self, fixture):
        calls = [json.loads(line) for line in fixture.python_calls.read_text().splitlines()]
        self.assertTrue(calls)
        for arguments in calls:
            self.assertEqual(arguments[0], "-I", arguments)
        self.assertFalse(fixture.startup_marker.exists())
        return calls

    def seed_completed_receipt(self, fixture, *, logging=False):
        evidence = fixture.shared / "sanitizers" if logging else fixture.root / "evidence"
        evidence.mkdir(parents=True)
        summary = evidence / "run-summary.json"
        raw = b'{"status":"completed","commands":[],"units":[]}\n'
        summary.write_bytes(raw)
        return evidence, raw

    def test_inherited_startup_cannot_admit_forbidden_flags_before_tools_or_log(self):
        for logging in (False, True):
            with self.subTest(logging=logging):
                fixture = self.fixture(logging=logging, mutation="flags")
                evidence, raw = self.seed_completed_receipt(fixture, logging=logging)
                result = (
                    fixture.run_suite(SANITIZER_CARGO_FLAGS="--config=build.rustflags=[]")
                    if logging
                    else fixture.run_wrapper(SANITIZER_CARGO_FLAGS="--config=build.rustflags=[]")
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                summary = json.loads((evidence / "run-summary.json").read_text())
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["preflight_phase"], "cargo-flags")
                self.assertEqual(summary["exit_code"], result.returncode)
                self.assertEqual(
                    (evidence / summary["previous_attempt"] / "run-summary.json").read_bytes(),
                    raw,
                )
                self.assertFalse((fixture.root / "calls.jsonl").exists())
                self.assertFalse((fixture.root / "producer-called").exists())
                self.assertFalse((fixture.root / "target").exists())
                if logging:
                    self.assertFalse((fixture.shared / "summary/security.log").exists())
                calls = self.isolated_calls(fixture)
                self.assertTrue(
                    any(
                        arguments[1:2] == ["-"] and "--config=build.rustflags=[]" in arguments
                        for arguments in calls
                    )
                )

    def test_failed_preflight_receipt_ignores_inherited_status_mutation(self):
        fixture = self.fixture(mutation="receipt")
        evidence, raw = self.seed_completed_receipt(fixture)
        result = fixture.run_wrapper("rustc-version-failure")
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        summary = fixture.summary()
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["preflight_phase"], "rustc-version")
        self.assertEqual(summary["exit_code"], 23)
        self.assertEqual(
            (evidence / summary["previous_attempt"] / "run-summary.json").read_bytes(), raw
        )
        self.isolated_calls(fixture)

    def test_supported_controller_and_all_required_targets_ignore_startup(self):
        fixture = self.fixture()
        result = fixture.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = fixture.summary()
        self.assertEqual(summary["status"], "completed")
        targets = summary["units"][0]["targets"]
        self.assertEqual({target["name"] for target in targets}, set(sanitizer_fixture.TARGETS))
        self.assertTrue(all(target["status"] == "completed" for target in targets))
        self.assertEqual(sum(len(target["completed"]) for target in targets), 8)
        self.assertTrue(summary["commands"])
        calls = self.isolated_calls(fixture)
        # argv distinguishes receipt writer, flags validator and actual controller.
        self.assertTrue(
            any(arguments[1:2] == ["-"] and "initialize" in arguments for arguments in calls)
        )
        self.assertTrue(any(arguments == ["-I", "-", "", ""] for arguments in calls))
        self.assertTrue(any(arguments[1:4] == ["-", "address", "ffi"] for arguments in calls))

    def test_supported_log_opener_validator_and_bound_cleanup_ignore_startup(self):
        fixture = self.fixture(logging=True)
        result = fixture.run_suite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(fixture.shared_receipt()["status"], "completed")
        self.assertTrue((fixture.root / "producer-called").exists())
        log = (fixture.shared / "summary/security.log").read_text()
        self.assertIn("starting security suite", log)
        self.assertIn("inert modeled sanitizer output", log)
        self.assertIn("suite finished", log)
        self.assertFalse((fixture.root / "suite-target").exists())
        calls = self.isolated_calls(fixture)
        for operation in ("open-exec-bound", "validate"):
            self.assertTrue(
                any(
                    arguments[1].endswith("/open_security_log.py") and arguments[2] == operation
                    for arguments in calls
                ),
                operation,
            )
        for operation in ("prepare", "validate", "cleanup"):
            self.assertTrue(
                any(arguments[1:3] == ["-", operation] for arguments in calls), operation
            )

    def test_nonappend_log_descriptor_cannot_be_admitted_by_startup_hook(self):
        fixture = self.fixture(logging=True, mutation="descriptor")
        summary = fixture.shared / "summary"
        summary.mkdir(parents=True)
        log = summary / "security.log"
        original = b"retained bytes before rejected descriptor\n"
        log.write_bytes(original)
        descriptor = os.open(log, os.O_WRONLY)
        try:
            result = fixture.run_suite(
                pass_fds=(descriptor,), SANITIZER_SECURITY_LOG_FD=str(descriptor)
            )
        finally:
            os.close(descriptor)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(log.read_bytes(), original)
        self.assertFalse((fixture.root / "producer-called").exists())
        self.assertEqual(fixture.shared_receipt()["status"], "failed")
        calls = self.isolated_calls(fixture)
        self.assertTrue(
            any(
                arguments[1].endswith("/open_security_log.py") and arguments[2] == "validate"
                for arguments in calls
            )
        )

    def test_bound_cleanup_rejects_replacement_and_keeps_failed_receipt_without_startup(self):
        fixture = self.fixture(logging=True)
        result = fixture.run_suite(MODEL_CHILD="cleanup-swap")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((fixture.root / "suite-target").is_dir())
        self.assertTrue((fixture.root / "held-target").is_dir())
        self.assertEqual(fixture.shared_receipt()["status"], "failed")
        calls = self.isolated_calls(fixture)
        self.assertTrue(any(arguments[1:3] == ["-", "cleanup"] for arguments in calls))


if __name__ == "__main__":
    unittest.main()
