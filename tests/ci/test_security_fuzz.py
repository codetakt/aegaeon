# ruff: noqa: PT009 - these controls run under unittest discovery
"""Check required fuzz execution through the real security wrapper with controlled tools."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "fuzz_bearer_token",
    "fuzz_dpop_proof",
    "fuzz_pkce_verifier",
    "fuzz_jose_parsing",
    "fuzz_ffi_parsers",
    "fuzz_introspection",
    "fuzz_par",
)

CARGO = r"""
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
with (root / 'calls.jsonl').open('a') as out:
    out.write(json.dumps(args) + '\n')
if args == ['--version']:
    print('cargo fixture')
    raise SystemExit(0)
if args[:2] == ['fuzz', '--help']:
    raise SystemExit(19 if os.environ.get('CASE') == 'help-fail' else 0)
if args[:1] != ['fuzz']:
    raise SystemExit(0)
phase = args[1]
target = next(arg for arg in args if arg in os.environ['EXPECTED_TARGETS'].split())
mode = os.environ.get('CASE', 'ok') if target == os.environ.get('FAIL_TARGET', target) else 'ok'
if phase == 'build':
    if mode == 'build-fail':
        print('successful help does not imply build success')
        raise SystemExit(17)
    directory = pathlib.Path(args[args.index('--target-dir') + 1])
    binary = directory / args[args.index('--target') + 1] / 'release' / target
    binary.parent.mkdir(parents=True, exist_ok=True)
    if mode != 'missing-binary':
        binary.write_text('fixture executable for ' + target)
        binary.chmod(0o755)
    print('build complete')
else:
    if mode == 'malformed-evidence':
        pathlib.Path(os.environ['SECURITY_ARTIFACT_DIR'], 'fuzz/execution.json').write_text('{}')
    if mode == 'blocked-summary':
        pathlib.Path(os.environ['SECURITY_ARTIFACT_DIR'], 'fuzz/run_summary.json').mkdir()
    if mode == 'missing-log':
        pathlib.Path(os.environ['SECURITY_ARTIFACT_DIR'], 'fuzz', target, 'run.log').unlink()
    corpus = root / 'fuzz/corpus' / target
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / 'seed').write_text('input')
    if mode in ('run-fail', 'success-then-fail'):
        crash = root / 'fuzz/artifacts' / target
        crash.mkdir(parents=True, exist_ok=True)
        (crash / 'crash-input').write_text('preserve this crash')
    if mode != 'no-completion':
        seconds = args[-1].split('=')[1]
        print('Done 100 runs in ' + seconds + ' second(s)')
    if mode == 'success-then-fail':
        print('SUCCESS!')
    raise SystemExit(23 if mode in ('run-fail', 'success-then-fail') else 0)
"""

TIMEOUT = r"""
import os, signal, subprocess, sys
code = os.environ.get('TIMEOUT_CODE')
if code:
    raise SystemExit(int(code))
if os.environ.get('TIMEOUT_SIGNAL'):
    os.kill(os.getpid(), signal.SIGTERM)
raise SystemExit(subprocess.run(sys.argv[3:], check=False).returncode)
"""


class SecurityFuzzFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = self.enterContext(
            tempfile.TemporaryDirectory(prefix="security-fuzz-test-")
        )
        self.root = Path(self.temporary) / "source"
        self.root.mkdir()
        self.bin = Path(self.temporary) / "bin"
        self.bin.mkdir()
        self.artifacts = Path(self.temporary) / "artifacts"
        for name in (
            "bash",
            "git",
            "dirname",
            "mkdir",
            "rm",
            "tee",
            "cat",
            "find",
            "sort",
            "python3",
            "cc",
            "c++",
        ):
            command = shutil.which(name)
            if command:
                (self.bin / name).symlink_to(command)
        for name, code in (
            ("cargo", CARGO),
            ("timeout", TIMEOUT),
            ("rustc", "print('rustc fixture\\nhost: x86_64-unknown-linux-gnu')"),
            ("cargo-fuzz", "print('cargo-fuzz fixture')"),
            ("nix", "raise SystemExit(0)"),
            ("cargo-udeps", "raise SystemExit(0)"),
        ):
            self.install(name, code)
        for path in (
            "scripts/security/run_security_suite.sh",
            "scripts/fuzz/manage_fuzz_corpus.py",
            "Cargo.toml",
            "Cargo.lock",
            "fuzz/Cargo.toml",
            "fuzz/Cargo.lock",
            "flake.lock",
            "rust-toolchain.toml",
            *("fuzz/fuzz_targets/" + target + ".rs" for target in TARGETS),
        ):
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)
        # Other stages are controlled independently when checking aggregate dispatch.
        geiger = self.root / "scripts/security/run_geiger.sh"
        geiger.write_text("#!/usr/bin/env bash\nexit 0\n")
        geiger.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(self.bin),
            "CI": "",
            "FIXTURE_ROOT": str(self.root),
            "EXPECTED_TARGETS": " ".join(TARGETS),
            "SECURITY_ARTIFACT_DIR": str(self.artifacts),
            "SECURITY_HISTORY_DIR": str(Path(self.temporary) / "history"),
            "CARGO_TARGET_DIR": str(Path(self.temporary) / "target"),
        }
        for name in (
            "FUZZ_TARGETS",
            "FUZZ_LONG",
            "FUZZ_TIMEOUT",
            "FUZZ_MAX_TOTAL",
            "FUZZ_TOTAL_TIMEOUT",
            "FUZZ_TIMEOUT_OVERRIDE",
            "FUZZ_MAX_TOTAL_OVERRIDE",
            "FUZZ_TOTAL_TIMEOUT_OVERRIDE",
            "AEGAEON_DATABASE_URL",
            "AEGAEON_RUNTIME_ISSUER_HOST",
            "SECURITY_RUNTIME_ISSUER_HOST",
            "GIT_DIR",
            "GIT_WORK_TREE",
        ):
            self.env.pop(name, None)

    def install(self, name, code):
        destination = self.bin / name
        if destination.is_symlink():
            destination.unlink()
        destination.write_text(f"#!{sys.executable}\n" + code)
        destination.chmod(0o755)

    def run_suite(self, case="ok", *, aggregate=False, long=False, **environment):
        args = [] if aggregate else ["--stage", "fuzz"]
        if long:
            args.insert(0, "--fuzz-long")
        return subprocess.run(  # noqa: S603 - execute the real wrapper and controlled fixtures
            [
                str(self.bin / "bash"),
                str(self.root / "scripts/security/run_security_suite.sh"),
                *args,
            ],
            cwd=self.root,
            env={**self.env, "CASE": case, **environment},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def summary(self):
        return json.loads((self.artifacts / "fuzz/run_summary.json").read_text())

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def seed_stale_collection(self):
        marker = self.artifacts / "fuzz/collection.ok"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text('{"run_id":"previous-run","summary_file":"collected-summary.json"}')
        raw = {}
        for name in ("corpus", "artifacts", "corpus_archive"):
            path = self.root / "fuzz" / name / TARGETS[0] / "previous-input"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"preserve original " + name.encode())
            raw[path] = path.read_bytes()
        return marker, raw


class SecurityFuzzTests(SecurityFuzzFixture):
    def test_stale_receipt_removal_failure_preserves_raw_evidence_without_starting_stage(self):
        marker, raw = self.seed_stale_collection()
        stale_marker = marker.read_bytes()
        actual_rm = shutil.which("rm")
        self.install(
            "rm",
            "import os,sys\n"
            "if any(arg.endswith('/collection.ok') for arg in sys.argv[1:]):\n"
            " raise SystemExit(31)\n"
            f"os.execv({actual_rm!r}, [{actual_rm!r}] + sys.argv[1:])",
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual(marker.read_bytes(), stale_marker)
        self.assertNotIn(">>> cargo fuzz smoke", result.stdout + result.stderr)
        self.assertEqual(self.calls(), [])

    def test_stale_receipt_invalidated_before_stage_log_entry_failure(self):
        marker, raw = self.seed_stale_collection()
        actual_tee = shutil.which("tee")
        self.install(
            "tee",
            "import subprocess,sys\n"
            "data=sys.stdin.buffer.read()\n"
            "if b'>>> cargo fuzz smoke' in data:\n raise SystemExit(32)\n"
            f"raise SystemExit(subprocess.run([{actual_tee!r}] + sys.argv[1:], "
            "input=data).returncode)",
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse(marker.exists())
        self.assertEqual(self.calls(), [])

    def test_stale_receipt_invalidated_before_fuzz_directory_setup_failure(self):
        marker, raw = self.seed_stale_collection()
        actual_mkdir = shutil.which("mkdir")
        failed_directory = str(self.artifacts / "fuzz")
        self.install(
            "mkdir",
            "import os,sys\n"
            f"if {failed_directory!r} in sys.argv[1:]:\n raise SystemExit(33)\n"
            f"os.execv({actual_mkdir!r}, [{actual_mkdir!r}] + sys.argv[1:])",
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse(marker.exists())
        self.assertEqual(self.calls(), [])

    def test_default_executes_exactly_seven_targets_and_records_receipts(self):
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        execution = self.summary()["execution"]
        self.assertEqual(execution["coverage"], "full")
        self.assertEqual(execution["selected_targets"], list(TARGETS))
        self.assertEqual((execution["internal_seconds"], execution["watchdog_seconds"]), (30, 60))
        self.assertEqual(execution["status"], "passed")
        self.assertEqual(execution["cleanup_exit_code"], 0)
        directory = self.artifacts / "fuzz"
        marker = json.loads((directory / "collection.ok").read_text())
        collected = directory / marker["summary_file"]
        self.assertEqual(marker["run_id"], execution["run_id"])
        self.assertEqual(
            marker["summary_sha256"], hashlib.sha256(collected.read_bytes()).hexdigest()
        )
        self.assertEqual(json.loads(collected.read_text())["status"], "awaiting-cleanup")
        for row in execution["targets"]:
            self.assertEqual(row["build"]["status"], "passed")
            self.assertEqual(row["run"]["completed_runs"], 100)
            self.assertEqual(row["run"]["executable_sha256"], row["build"]["executable_sha256"])
        self.assertEqual(len([call for call in self.calls() if call[:2] == ["fuzz", "run"]]), 7)

    def test_mixed_results_fail_and_preserve_crashes_before_cleanup(self):
        result = self.run_suite("run-fail", FAIL_TARGET=TARGETS[1])
        self.assertNotEqual(result.returncode, 0)
        summary = self.summary()
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["execution"]["targets"][1]["run"]["exit_code"], 23)
        self.assertEqual(summary["execution"]["targets"][-1]["run"]["status"], "passed")
        with tarfile.open(self.artifacts / "fuzz" / summary["crash_archive"]) as archive:
            self.assertIn(TARGETS[1] + "/crash-input", archive.getnames())
        self.assertFalse((self.root / "fuzz/artifacts").exists())

    def test_disabled_archive_cannot_delete_required_corpus(self):
        result = self.run_suite(CORPUS_ARCHIVE_KEEP="0")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "fuzz/corpus").is_dir())
        self.assertFalse((self.artifacts / "fuzz/collection.ok").exists())

    def test_selected_and_aggregate_dispatch_preserve_failure_after_success_text(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                result = self.run_suite("success-then-fail", aggregate=aggregate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.summary()["status"], "failed")

    def test_successful_help_followed_by_build_failure_is_blocking(self):
        result = self.run_suite("build-fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(
            all(row["run"]["status"] == "not-run" for row in self.summary()["execution"]["targets"])
        )
        self.assertFalse(any(call[:2] == ["fuzz", "run"] for call in self.calls()))

    def test_missing_required_tools_leave_explicit_not_run_targets(self):
        for tool in ("cargo", "cargo-fuzz", "rustc", "timeout"):
            with self.subTest(tool=tool):
                (self.bin / tool).rename(self.bin / "saved-tool")
                result = self.run_suite()
                (self.bin / "saved-tool").rename(self.bin / tool)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(
                    all(
                        row["run"]["status"] == "not-run"
                        for row in self.summary()["execution"]["targets"]
                    )
                )
        self.assertFalse(any(call[:2] == ["fuzz", "build"] for call in self.calls()))

    def test_failed_cargo_fuzz_help_does_not_launch_build(self):
        result = self.run_suite("help-fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["fuzz", "build"] for call in self.calls()))

    def test_watchdog_reserved_codes_and_signal_are_failures(self):
        for code in (124, 125, 126, 127, 137, 143):
            with self.subTest(code=code):
                result = self.run_suite(TIMEOUT_CODE=str(code))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(
                    self.summary()["execution"]["targets"][0]["run"]["exit_code"], code
                )
        result = self.run_suite(TIMEOUT_SIGNAL="1")
        self.assertNotEqual(result.returncode, 0)

    def test_empty_unknown_duplicate_selection_and_invalid_budgets_fail_before_build(self):
        cases = (
            {"FUZZ_TARGETS": ""},
            {"FUZZ_TARGETS": "   "},
            {"FUZZ_TARGETS": "unknown"},
            {"FUZZ_TARGETS": f"{TARGETS[0]} {TARGETS[0]}"},
            {"FUZZ_TIMEOUT": ""},
            {"FUZZ_TIMEOUT": "0"},
            {"FUZZ_TIMEOUT": "-1"},
            {"FUZZ_TIMEOUT": "bad"},
            {"FUZZ_TIMEOUT": "30"},
            {"FUZZ_MAX_TOTAL": "0"},
            {"FUZZ_MAX_TOTAL": "-1"},
            {"FUZZ_MAX_TOTAL": "wrong"},
            {"FUZZ_MAX_TOTAL": ""},
            {"FUZZ_TOTAL_TIMEOUT": "100s"},
            {"FUZZ_TOTAL_TIMEOUT": "0"},
            {"FUZZ_TOTAL_TIMEOUT": "bad"},
        )
        for environment in cases:
            with self.subTest(environment=environment):
                result = self.run_suite(**environment)
                self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["fuzz", "build"] for call in self.calls()))

    def test_long_allocation_is_internal_only_and_preserves_watchdog_grace(self):
        result = self.run_suite(long=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        execution = self.summary()["execution"]
        self.assertEqual((execution["internal_seconds"], execution["watchdog_seconds"]), (85, 115))
        self.assertLessEqual(
            7 * execution["internal_seconds"], execution["aggregate_internal_allocation"]
        )
        result = self.run_suite(long=True, FUZZ_TOTAL_TIMEOUT_OVERRIDE="209s")
        self.assertNotEqual(result.returncode, 0)
        result = self.run_suite(long=True, FUZZ_TIMEOUT_OVERRIDE="85s")
        self.assertNotEqual(result.returncode, 0)

    def test_local_subset_is_identified_and_ci_requires_full_inventory(self):
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary()["execution"]["coverage"], "local-subset")
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0], CI="true")
        self.assertNotEqual(result.returncode, 0)

    def test_missing_execution_or_collection_evidence_is_blocking(self):
        for case in (
            "missing-binary",
            "no-completion",
            "malformed-evidence",
            "blocked-summary",
            "missing-log",
        ):
            with self.subTest(case=case):
                # Each case is isolated from successful cached binaries and old evidence.
                shutil.rmtree(Path(self.temporary) / "target", ignore_errors=True)
                shutil.rmtree(self.artifacts, ignore_errors=True)
                result = self.run_suite(case)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "fuzz/corpus").exists())

    def test_evidence_copy_failure_retains_original_crashes(self):
        history = Path(self.env["SECURITY_HISTORY_DIR"])
        history.mkdir()
        self.install(
            "python3",
            "import os,sys\nif '--finish-run' in sys.argv:\n raise SystemExit(29)\nos.execv("
            + repr(sys.executable)
            + ", ["
            + repr(sys.executable)
            + "] + sys.argv[1:])",
        )
        result = self.run_suite("run-fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / "fuzz/artifacts" / TARGETS[0] / "crash-input").exists())

    def test_missing_required_lock_or_source_fails_before_build(self):
        for name in ("fuzz/Cargo.lock", "Cargo.lock", "fuzz/fuzz_targets/fuzz_par.rs"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.unlink()
                result = self.run_suite()
                path.write_bytes(original)
                self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["fuzz", "build"] for call in self.calls()))

    def test_unsafe_or_missing_declared_target_source_fails_before_build(self):
        manifest = self.root / "fuzz/Cargo.toml"
        original = manifest.read_text()
        for value in ("", "../outside.rs", "/outside.rs", "fuzz_targets/absent.rs"):
            with self.subTest(value=value):
                manifest.write_text(original.replace("fuzz_targets/fuzz_par.rs", value))
                self.assertNotEqual(self.run_suite().returncode, 0)
        manifest.write_text(original)
        self.assertFalse(any(call[:2] == ["fuzz", "build"] for call in self.calls()))

    def test_cleanup_receipt_write_failure_cannot_leave_passed_status(self):
        self.install(
            "python3",
            "import os,sys\nif '--cleanup-result' in sys.argv:\n raise SystemExit(29)\nos.execv("
            + repr(sys.executable)
            + ", ["
            + repr(sys.executable)
            + "] + sys.argv[1:])",
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary()["status"], "awaiting-cleanup")
        self.assertNotIn("cleanup_exit_code", self.summary()["execution"])

    def test_cleanup_failure_is_blocking_and_recorded(self):
        actual_rm = shutil.which("rm")
        (self.bin / "rm").unlink()
        self.install(
            "rm",
            "import os,sys\nif 'fuzz/corpus' in sys.argv:\n raise SystemExit(31)\nos.execv("
            + repr(actual_rm)
            + ", ["
            + repr(actual_rm)
            + "] + sys.argv[1:])",
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.summary()["execution"]["cleanup_exit_code"], 31)
        self.assertEqual(self.summary()["status"], "failed")


if __name__ == "__main__":
    unittest.main()
