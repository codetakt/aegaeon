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

    def install_helper_hooks(self, hooks):
        self.install(
            "python3",
            "import os,runpy,sys\n"
            f"hooks={hooks!r}\n"
            "for action, code in hooks.items():\n"
            " if action in sys.argv:\n"
            "  namespace=runpy.run_path(sys.argv[1], run_name='fuzz_test_hook')\n"
            "  state=namespace['main'].__globals__\n"
            "  exec(code, state)\n"
            "  sys.argv=sys.argv[1:]\n"
            "  raise SystemExit(state['main']())\n"
            f"os.execv({sys.executable!r}, [{sys.executable!r}] + sys.argv[1:])",
        )

    def assert_backup(self):
        execution = self.summary()["execution"]
        backup = self.artifacts / "fuzz/cleanup-recovery" / execution["run_id"]
        manifest = json.loads((backup / "backup-ready.json").read_text())
        self.assertEqual(manifest["run_id"], execution["run_id"])
        self.assertEqual(manifest["source"], execution["source"]["files"])
        self.assertEqual(set(manifest["raw"]), {"corpus", "artifacts", "corpus_archive"})
        for name, expected_digest in manifest["evidence"].items():
            self.assertEqual(
                hashlib.sha256((backup / "evidence" / name).read_bytes()).hexdigest(),
                expected_digest,
            )
        original = json.loads((backup / "evidence/execution.json").read_text())
        self.assertEqual(original["run_id"], execution["run_id"])
        self.assertEqual(original["status"], "awaiting-cleanup")
        self.assertNotIn("cleanup_exit_code", original)
        self.assertEqual(
            json.loads((backup / "evidence/run_summary.json").read_text())["execution"], original
        )
        self.assertEqual(
            json.loads((backup / "evidence/collection.ok").read_text())["summary_sha256"],
            manifest["evidence"]["collection-summary.json"],
        )
        self.assertFalse((backup / "raw/target").exists())
        return backup, manifest

    def assert_restored(self, raw, reason, exit_code):
        summary = self.summary()
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["execution"]["status"], "failed")
        self.assertEqual(summary["execution"]["cleanup_exit_code"], exit_code)
        report = summary["execution"]["cleanup_recovery"]
        self.assertEqual(report["reason"], reason)
        self.assertEqual(report["status"], "restored")
        backup, _ = self.assert_backup()
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(
                (backup / "raw" / path.relative_to(self.root / "fuzz")).read_bytes(), content
            )
        for name in ("collection.ok", "collection-summary.json"):
            self.assertEqual(
                (self.artifacts / "fuzz" / name).read_bytes(),
                (backup / "evidence" / name).read_bytes(),
            )
        self.assertEqual(
            json.loads((self.artifacts / "fuzz/execution.json").read_text()), summary["execution"]
        )
        self.assertTrue(list(backup.glob("recovery-result-*.json")))
        self.assertEqual((self.root / "fuzz/corpus" / TARGETS[0] / "seed").read_bytes(), b"input")

    def install_cleanup_hook(self, code):
        actual_rm = shutil.which("rm")
        self.install(
            "rm",
            "import os,pathlib,shutil,sys\n"
            "if 'fuzz/corpus' in sys.argv[1:]:\n"
            " root=pathlib.Path(os.environ['FIXTURE_ROOT'])\n"
            " (root / 'cleanup-called').write_text('called')\n"
            + "\n".join(" " + line for line in code.splitlines())
            + "\n"
            + f"os.execv({actual_rm!r}, [{actual_rm!r}] + sys.argv[1:])",
        )


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

    def test_failed_target_with_current_collection_retains_raw_evidence(self):
        marker_path, _ = self.seed_stale_collection()
        result = self.run_suite("run-fail", FAIL_TARGET=TARGETS[1], CORPUS_ARCHIVE_KEEP="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        execution = summary["execution"]
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(execution["status"], "failed")
        self.assertNotEqual(execution["exit_code"], 0)
        self.assertEqual(execution["targets"][1]["run"]["exit_code"], 23)
        self.assertEqual(execution["targets"][-1]["run"]["status"], "passed")
        marker = json.loads(marker_path.read_text())
        self.assertNotEqual(marker["run_id"], "previous-run")
        self.assertEqual(marker["run_id"], execution["run_id"])
        collected = marker_path.parent / marker["summary_file"]
        self.assertEqual(
            marker["summary_sha256"], hashlib.sha256(collected.read_bytes()).hexdigest()
        )
        self.assertEqual(json.loads(collected.read_text()), summary)
        for key, member, content in (
            ("corpus_archive", "corpus/" + TARGETS[1] + "/seed", b"input"),
            ("crash_archive", TARGETS[1] + "/crash-input", b"preserve this crash"),
        ):
            archive_path = marker_path.parent / summary[key]
            self.assertEqual(
                archive_path.read_bytes(),
                (Path(self.env["SECURITY_HISTORY_DIR"]) / archive_path.name).read_bytes(),
            )
            with tarfile.open(archive_path) as archive:
                self.assertEqual(archive.extractfile(member).read(), content)
        for target in TARGETS:
            self.assertEqual((self.root / "fuzz/corpus" / target / "seed").read_bytes(), b"input")
        self.assertEqual(
            (self.root / "fuzz/artifacts" / TARGETS[1] / "crash-input").read_bytes(),
            b"preserve this crash",
        )
        local_archive = self.root / "fuzz/corpus_archive" / summary["corpus_archive"]
        self.assertEqual(
            local_archive.read_bytes(), (marker_path.parent / local_archive.name).read_bytes()
        )
        self.assertNotIn("cleanup_exit_code", execution)
        self.assertIn("retaining transient outputs", result.stderr)

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
                self.assertEqual(
                    (self.root / "fuzz/artifacts" / TARGETS[0] / "crash-input").read_bytes(),
                    b"preserve this crash",
                )
                self.assertEqual(
                    (self.root / "fuzz/corpus" / TARGETS[0] / "seed").read_bytes(), b"input"
                )
                self.assertNotIn("cleanup_exit_code", self.summary()["execution"])

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
        _, raw = self.seed_stale_collection()
        self.install_helper_hooks({"--cleanup-result": "raise SystemExit(29)"})
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                result = self.run_suite(aggregate=aggregate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_restored(raw, "receipt", 0)

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


class SecurityFuzzRecoveryTests(SecurityFuzzFixture):
    def test_empty_long_aggregate_with_explicit_overrides_fails_before_build(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                result = self.run_suite(
                    aggregate=aggregate,
                    long=True,
                    FUZZ_TOTAL_TIMEOUT_OVERRIDE="",
                    FUZZ_MAX_TOTAL_OVERRIDE="85",
                    FUZZ_TIMEOUT_OVERRIDE="115s",
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(call[:2] == ["fuzz", "build"] for call in self.calls()))

    def test_success_removes_originals_and_retains_bound_recovery_without_caches(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                _, raw = self.seed_stale_collection()
                cache = self.root / "fuzz/target/cache"
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_bytes(b"build cache excluded")
                result = self.run_suite(aggregate=aggregate)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                backup, manifest = self.assert_backup()
                for path, content in raw.items():
                    self.assertFalse(path.exists())
                    self.assertEqual(
                        (backup / "raw" / path.relative_to(self.root / "fuzz")).read_bytes(),
                        content,
                    )
                for name in manifest["raw"]:
                    self.assertFalse((self.root / "fuzz" / name).exists())
                    self.assertTrue(manifest["raw"][name]["present"])
                self.assertFalse(cache.exists())
                self.assertEqual(self.summary()["status"], "passed")
                self.assertFalse(list(backup.glob("recovery-result-*.json")))

    def test_absent_and_empty_raw_roots_preserve_presence_state(self):
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        backup, manifest = self.assert_backup()
        self.assertFalse(manifest["raw"]["artifacts"]["present"])
        self.assertFalse((backup / "raw/artifacts").exists())
        (self.root / "fuzz/artifacts").mkdir()
        self.install_helper_hooks({"--cleanup-result": "raise SystemExit(29)"})
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        backup, manifest = self.assert_backup()
        self.assertTrue(manifest["raw"]["artifacts"]["present"])
        self.assertEqual(manifest["raw"]["artifacts"]["inventory"], {})
        self.assertTrue((backup / "raw/artifacts").is_dir())
        self.assertTrue((self.root / "fuzz/artifacts").is_dir())

    def test_partial_receipt_write_restores_raw_and_failed_pre_cleanup_evidence(self):
        self.install_helper_hooks(
            {
                "--cleanup-result": """
original_write = write_json
def partial_write(path, data):
    if path.name == 'run_summary.json':
        path.write_text('{"status":"passed"')
        raise OSError('fixture partial receipt write')
    original_write(path, data)
write_json = partial_write
"""
            }
        )
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                _, raw = self.seed_stale_collection()
                result = self.run_suite(aggregate=aggregate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_restored(raw, "receipt", 0)

    def test_silent_corrupt_receipt_restores_raw_and_failed_status(self):
        for name in ("execution.json", "run_summary.json"):
            self.install_helper_hooks(
                {
                    "--cleanup-result": f"""
original_write = write_json
def silent_corruption(path, data):
    if path.name == {name!r}:
        data = dict(data, status='awaiting-cleanup')
    original_write(path, data)
write_json = silent_corruption
"""
                }
            )
            for aggregate in (False, True):
                with self.subTest(name=name, aggregate=aggregate):
                    _, raw = self.seed_stale_collection()
                    result = self.run_suite(aggregate=aggregate)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("cleanup receipt write did not preserve", result.stderr)
                    self.assert_restored(raw, "receipt", 0)

    def test_partial_removal_restores_deleted_corpus_and_keeps_crashes(self):
        self.install_cleanup_hook("shutil.rmtree(root / 'fuzz/corpus')\nraise SystemExit(31)")
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                _, raw = self.seed_stale_collection()
                result = self.run_suite(aggregate=aggregate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((self.root / "cleanup-called").exists())
                self.assert_restored(raw, "removal", 31)

    def test_backup_copy_failure_skips_removal_and_keeps_partial_copy(self):
        _, raw = self.seed_stale_collection()
        self.install_cleanup_hook("pass")
        self.install_helper_hooks(
            {
                "--backup-cleanup": """
def fail_copy(source, destination, **kwargs):
    destination.mkdir()
    (destination / 'partial-copy').write_bytes(b'partial')
    raise OSError('fixture copy failure')
shutil.copytree = fail_copy
"""
            }
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "cleanup-called").exists())
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)
        recovery = self.artifacts / "fuzz/cleanup-recovery" / self.summary()["execution"]["run_id"]
        self.assertFalse((recovery / "backup-ready.json").exists())
        self.assertEqual((recovery / "raw/corpus/partial-copy").read_bytes(), b"partial")

    def test_backup_detects_evidence_and_source_changes_before_removal(self):
        for changed in ("collection.ok", "fuzz/fuzz_targets/fuzz_par.rs"):
            with self.subTest(changed=changed):
                _, raw = self.seed_stale_collection()
                self.install_cleanup_hook("pass")
                self.install_helper_hooks(
                    {
                        "--backup-cleanup": f"""
original_copy = shutil.copytree
def change_after_copy(source, destination, *args, **kwargs):
    result = original_copy(source, destination, *args, **kwargs)
    changed = {changed!r}
    directory = Path(os.environ['SECURITY_ARTIFACT_DIR']) / 'fuzz'
    path = (directory / changed) if changed == 'collection.ok' else (ROOT / changed)
    path.write_bytes(path.read_bytes() + b'\\n')
    return result
shutil.copytree = change_after_copy
"""
                    }
                )
                result = self.run_suite()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                expected = (
                    "collection evidence changed during recovery copy"
                    if changed == "collection.ok"
                    else "source identity changed before cleanup"
                )
                self.assertIn(expected, result.stderr)
                self.assertFalse((self.root / "cleanup-called").exists())
                for path, content in raw.items():
                    self.assertEqual(path.read_bytes(), content)
                recovery = (
                    self.artifacts / "fuzz/cleanup-recovery" / self.summary()["execution"]["run_id"]
                )
                self.assertFalse((recovery / "backup-ready.json").exists())

    def test_restore_copy_failure_retains_verified_backup_and_failed_disposition(self):
        _, raw = self.seed_stale_collection()
        self.install_helper_hooks(
            {
                "--cleanup-result": "raise SystemExit(29)",
                "--restore-cleanup": """
def fail_copy(*args, **kwargs):
    raise OSError('fixture restoration failure')
shutil.copytree = fail_copy
""",
            }
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary()["status"], "failed")
        self.assertEqual(self.summary()["execution"]["cleanup_recovery"]["status"], "failed")
        backup, _ = self.assert_backup()
        for path, content in raw.items():
            self.assertFalse(path.exists())
            self.assertEqual(
                (backup / "raw" / path.relative_to(self.root / "fuzz")).read_bytes(), content
            )
        report = json.loads(next(backup.glob("recovery-result-*.json")).read_text())
        self.assertEqual(report["status"], "failed")
        self.assertIn("fixture restoration failure", report["error"])

    def test_restore_evidence_failure_retains_original_receipts_and_diagnostics(self):
        self.install_helper_hooks(
            {
                "--cleanup-result": "raise SystemExit(29)",
                "--restore-cleanup": """
original_write = write_json
def fail_evidence(path, data):
    if path.name == 'execution.json':
        raise OSError('fixture evidence restoration failure')
    original_write(path, data)
write_json = fail_evidence
""",
            }
        )
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        backup, _ = self.assert_backup()
        self.assertEqual((self.root / "fuzz/corpus" / TARGETS[0] / "seed").read_bytes(), b"input")
        report = json.loads(next(backup.glob("recovery-result-*.json")).read_text())
        self.assertEqual(report["status"], "failed")
        self.assertIn("fixture evidence restoration failure", report["evidence_error"])
        self.assertIn("original evidence retained", result.stderr)

    def test_restore_refuses_top_level_and_inner_existing_symlinks(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                outside = Path(self.temporary) / "outside"
                outside.mkdir(exist_ok=True)
                marker = outside / "preserve-marker"
                marker.write_bytes(b"owned external fixture remains unchanged")
                relative = "fuzz/corpus/link" if nested else "fuzz/corpus"
                self.install_cleanup_hook(
                    "shutil.rmtree(root / 'fuzz/corpus')\n"
                    + ("(root / 'fuzz/corpus').mkdir()\n" if nested else "")
                    + f"(root / {relative!r}).symlink_to({str(outside)!r})\n"
                    + "raise SystemExit(31)"
                )
                result = self.run_suite()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(marker.read_bytes(), b"owned external fixture remains unchanged")
                self.assertEqual(list(outside.iterdir()), [marker])
                backup, _ = self.assert_backup()
                self.assertEqual(
                    self.summary()["execution"]["cleanup_recovery"]["status"], "failed"
                )
                self.assertTrue(list(backup.glob("recovery-result-*.json")))
                corpus = self.root / "fuzz/corpus"
                if corpus.is_symlink():
                    corpus.unlink()
                else:
                    shutil.rmtree(corpus)

    def test_backup_rejects_top_level_raw_symlink_without_removal(self):
        outside = Path(self.temporary) / "outside"
        outside.mkdir()
        marker = outside / "preserve-marker"
        marker.write_bytes(b"external fixture")
        (self.root / "fuzz/artifacts").symlink_to(outside)
        self.install_cleanup_hook("pass")
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "cleanup-called").exists())
        self.assertTrue((self.root / "fuzz/artifacts").is_symlink())
        self.assertEqual(marker.read_bytes(), b"external fixture")
        self.assertIn("owned raw directory roots", result.stderr)

    def test_restore_rejects_missing_empty_backup_and_symlinked_containers(self):
        for mutation in ("missing-empty", "raw", "evidence"):
            with self.subTest(mutation=mutation):
                empty = self.root / "fuzz/artifacts"
                empty.mkdir(exist_ok=True)
                outside = Path(self.temporary) / ("outside-" + mutation)
                outside.mkdir()
                marker = outside / "preserve-marker"
                marker.write_bytes(b"external fixture")
                self.install_helper_hooks(
                    {
                        "--cleanup-result": "raise SystemExit(29)",
                        "--restore-cleanup": f"""
run_id = sys.argv[sys.argv.index('--restore-cleanup') + 2]
directory = Path(sys.argv[sys.argv.index('--restore-cleanup') + 1])
recovery = directory / 'cleanup-recovery' / run_id
mutation = {mutation!r}
if mutation == 'missing-empty':
    (recovery / 'raw/artifacts').rmdir()
else:
    container = recovery / mutation
    container.rename(recovery / (mutation + '-preserved'))
    container.symlink_to({str(outside)!r})
""",
                    }
                )
                result = self.run_suite()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotEqual(self.summary()["status"], "passed")
                self.assertEqual(marker.read_bytes(), b"external fixture")
                self.assertEqual(list(outside.iterdir()), [marker])
                self.assertFalse((self.root / "fuzz/corpus").exists())
                self.assertIn("fuzz recovery", result.stderr)

    def test_inner_symlinks_are_copied_and_restored_as_inert_links(self):
        outside = Path(self.temporary) / "outside"
        outside.mkdir()
        marker = outside / "preserve-marker"
        marker.write_bytes(b"external fixture")
        link = self.root / "fuzz/corpus/inert-link"
        link.parent.mkdir()
        link.symlink_to(outside)
        self.install_helper_hooks({"--cleanup-result": "raise SystemExit(29)"})
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        backup, manifest = self.assert_backup()
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.readlink(), outside)
        saved = backup / "raw/corpus/inert-link"
        self.assertTrue(saved.is_symlink())
        self.assertEqual(saved.readlink(), outside)
        self.assertEqual(manifest["raw"]["corpus"]["inventory"]["inert-link"]["type"], "symlink")
        self.assertNotIn("inert-link/preserve-marker", manifest["raw"]["corpus"]["inventory"])
        self.assertEqual(marker.read_bytes(), b"external fixture")
        self.assertEqual(self.summary()["execution"]["cleanup_recovery"]["status"], "restored")


if __name__ == "__main__":
    unittest.main()
