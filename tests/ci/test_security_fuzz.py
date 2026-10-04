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
with (root.parent / 'calls.jsonl').open('a') as out:
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
    if mode == 'transitive-source-change':
        changed = root / 'crates/server/src/web/par_endpoint.rs'
        changed.write_text('// changed during fuzz execution\n')
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
            "ar",
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
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/server", "crates/ffi"]\n'
            'exclude = ["crates/kani-harness"]\n'
        )
        for package in ("server", "ffi"):
            local = self.root / "crates" / package
            (local / "src").mkdir(parents=True)
            (local / "Cargo.toml").write_text(f'[package]\nname = "{package}"\nversion = "0.0.0"\n')
            (local / "src/lib.rs").write_text("// local implementation fixture\n")
        kani = self.root / "crates/kani-harness"
        kani.mkdir()
        (kani / "Cargo.toml").write_text('[package]\nname="fixture-kani"\nversion="0.0.0"\n')
        (kani / "kani").symlink_to("result/bin/cargo-kani")
        (self.root / ".cargo").mkdir()
        shutil.copyfile(ROOT / ".cargo/config.toml", self.root / ".cargo/config.toml")
        (self.root / "fuzz/Cargo.toml").write_text(
            '[package]\nname = "fixture-fuzz"\nversion = "0.0.0"\n'
            '[dependencies]\nserver = { path = "../crates/server" }\n'
            'ffi = { path = "../crates/ffi" }\n'
            + "".join(
                f'[[bin]]\nname = "{target}"\npath = "fuzz_targets/{target}.rs"\n'
                for target in TARGETS
            )
        )
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
            "CARGO_HOME": str(Path(self.temporary) / "cargo-home"),
            # Explicit effective fixture tools, rather than inherited native
            # compiler names that the real target configuration may override.
            "CC": str(self.bin / "cc"),
            "CXX": str(self.bin / "c++"),
            "AR": str(self.bin / "ar"),
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

    def run_suite(self, case="ok", *, aggregate=False, long=False, stages=None, **environment):
        args = [] if aggregate else ["--stage", "fuzz"]
        if stages is not None:
            args = [value for stage in stages for value in ("--stage", stage)]
        if long:
            args.insert(0, "--fuzz-long")
        return subprocess.run(  # noqa: S603 - execute the real wrapper and controlled fixtures
            [
                str(self.bin / "bash"),
                str(self.root / "scripts/security/run_security_suite.sh"),
                *args,
            ],
            cwd=getattr(self, "caller", self.root),
            env={**self.env, "CASE": case, **environment},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def summary(self):
        return json.loads((self.artifacts / "fuzz/run_summary.json").read_text())

    def calls(self):
        path = self.root.parent / "calls.jsonl"
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

    def seed_stale_results(self):
        marker, raw = self.seed_stale_collection()
        execution = {"status": "passed", "run_id": "previous-run", "targets": []}
        (marker.parent / "execution.json").write_text(json.dumps(execution))
        (marker.parent / "run_summary.json").write_text(
            json.dumps({"status": "passed", "execution": execution})
        )
        return marker, raw

    def assert_no_current_results(self):
        for name in ("collection.ok", "execution.json", "run_summary.json"):
            self.assertFalse((self.artifacts / "fuzz" / name).exists(), name)

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
            " (root.parent / 'cleanup-called').write_text('called')\n"
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
        _, raw = self.seed_stale_results()
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
        self.assert_no_current_results()
        self.assertEqual(self.calls(), [])

    def test_stale_receipt_invalidated_before_fuzz_directory_setup_failure(self):
        _, raw = self.seed_stale_results()
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
        self.assert_no_current_results()
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
                cache = Path(self.env["CARGO_TARGET_DIR"]) / "fuzz/cache"
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_bytes(b"build cache excluded")
                legacy = self.root / "fuzz/target/cache"
                legacy.parent.mkdir(parents=True, exist_ok=True)
                legacy.write_bytes(b"unrelated legacy cache")
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
                self.assertEqual(legacy.read_bytes(), b"unrelated legacy cache")
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
                self.assertTrue((self.root.parent / "cleanup-called").exists())
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
        self.assertFalse((self.root.parent / "cleanup-called").exists())
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
                self.assertFalse((self.root.parent / "cleanup-called").exists())
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

    def test_collection_rejects_top_level_raw_symlink_without_removal(self):
        outside = Path(self.temporary) / "outside"
        outside.mkdir()
        marker = outside / "preserve-marker"
        marker.write_bytes(b"external fixture")
        (self.root / "fuzz/artifacts").symlink_to(outside)
        self.install_cleanup_hook("pass")
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root.parent / "cleanup-called").exists())
        self.assertTrue((self.root / "fuzz/artifacts").is_symlink())
        self.assertEqual(marker.read_bytes(), b"external fixture")
        self.assertIn(
            "owned raw directory roots",
            (self.artifacts / "summary/security.log").read_text(),
        )

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


class SecurityFuzzCacheStartupTests(SecurityFuzzFixture):
    def protected_removal_interceptor(self):
        actual_rm = shutil.which("rm")
        self.install(
            "rm",
            "import json,os,pathlib,sys\n"
            "root=pathlib.Path(os.environ['FIXTURE_ROOT'])\n"
            "if '-rf' in sys.argv:\n"
            " (root / 'unsafe-removal-called').write_text(json.dumps(sys.argv[1:]))\n"
            " raise SystemExit(91)\n"
            f"os.execv({actual_rm!r}, [{actual_rm!r}] + sys.argv[1:])",
        )

    def test_configured_cache_cleanup_preserves_unrelated_caches(self):
        for configured in ("default", "relative spaced cache", "cache\nwith newline"):
            for aggregate in (False, True):
                with self.subTest(configured=configured, aggregate=aggregate):
                    self.env.pop("CARGO_TARGET_DIR", None)
                    if configured != "default":
                        self.env["CARGO_TARGET_DIR"] = configured
                    target = self.root / (
                        "target/security-suite" if configured == "default" else configured
                    )
                    sibling = target.parent / "unrelated-sibling/input"
                    sibling.parent.mkdir(parents=True, exist_ok=True)
                    sibling.write_bytes(b"preserve sibling")
                    legacy = self.root / "fuzz/target/input"
                    legacy.parent.mkdir(parents=True, exist_ok=True)
                    legacy.write_bytes(b"preserve legacy")
                    result = self.run_suite(aggregate=aggregate, FUZZ_TARGETS=TARGETS[0])
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    execution = self.summary()["execution"]
                    self.assertEqual(execution["target_dir"], str(target.resolve() / "fuzz"))
                    self.assertFalse((target / "fuzz").exists())
                    self.assertEqual(sibling.read_bytes(), b"preserve sibling")
                    self.assertEqual(legacy.read_bytes(), b"preserve legacy")
                    backup, _ = self.assert_backup()
                    self.assertFalse((backup / "raw/target").exists())

    def test_safe_legacy_cache_and_trailing_newline_alias_are_cleaned(self):
        for alias in (False, True):
            with self.subTest(alias=alias):
                base = self.root / "fuzz/target"
                base.mkdir(parents=True, exist_ok=True)
                actual = base / "fuzz"
                if alias:
                    actual = Path(self.temporary) / "actual cache\n"
                    actual.mkdir()
                    (base / "fuzz").symlink_to(actual)
                sibling = base / "unrelated/input"
                sibling.parent.mkdir(parents=True, exist_ok=True)
                sibling.write_bytes(b"preserve sibling")
                call_start = len(self.calls())
                result = self.run_suite(CARGO_TARGET_DIR=str(base), FUZZ_TARGETS=TARGETS[0])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.summary()["execution"]["target_dir"], str(actual))
                self.assertFalse(actual.exists())
                self.assertEqual(sibling.read_bytes(), b"preserve sibling")
                build = next(
                    call for call in self.calls()[call_start:] if call[:2] == ["fuzz", "build"]
                )
                self.assertEqual(build[build.index("--target-dir") + 1], str(actual))
                if alias:
                    (base / "fuzz").unlink()
                shutil.rmtree(base / "unrelated")

    def test_unsafe_cache_aliases_are_rejected_before_any_destructive_command(self):
        alias_base = Path(self.temporary) / "configured-cache"
        alias_base.mkdir()
        roots = (
            self.root,
            self.root.parent,
            Path("/"),
            self.root / "fuzz",
            self.root / "Cargo.toml",
            self.root / "fuzz/Cargo.lock",
            self.root / "crates",
            self.root / "scripts",
            self.root / "fuzz/fuzz_targets",
            self.root / "fuzz/corpus",
            self.root / "fuzz/artifacts",
            self.root / "fuzz/corpus_archive",
            self.artifacts,
            self.artifacts / "fuzz/cleanup-recovery",
        )
        self.protected_removal_interceptor()
        # If a guard regresses, the fake build refuses before following any alias.
        self.install("cargo", "raise SystemExit(87)")
        original = (self.root / "Cargo.toml").read_bytes()
        for target in roots:
            for aggregate in (False, True):
                with self.subTest(target=target, aggregate=aggregate):
                    self.seed_stale_results()
                    link = alias_base / "fuzz"
                    link.symlink_to(target)
                    result = self.run_suite(aggregate=aggregate, CARGO_TARGET_DIR=str(alias_base))
                    link.unlink()
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("[security] fuzz evidence failed:", result.stderr)
                    self.assert_no_current_results()
                    self.assertFalse((self.root / "unsafe-removal-called").exists())
                    self.assertEqual((self.root / "Cargo.toml").read_bytes(), original)
                    self.assertEqual(self.calls(), [])

    def test_cache_and_evidence_descendant_overlaps_are_rejected(self):
        self.protected_removal_interceptor()
        for case in ("source", "raw", "evidence", "evidence-inside-cache"):
            with self.subTest(case=case):
                base = {
                    "source": self.root / "crates/nested",
                    "raw": self.root / "fuzz/corpus/nested",
                    "evidence": self.artifacts / "nested",
                    "evidence-inside-cache": Path(self.temporary) / "cache-with-evidence",
                }[case]
                if case == "evidence-inside-cache":
                    self.artifacts = base / "fuzz/evidence"
                    self.env["SECURITY_ARTIFACT_DIR"] = str(self.artifacts)
                self.seed_stale_results()
                result = self.run_suite(CARGO_TARGET_DIR=str(base), FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("overlaps protected", result.stderr)
                self.assertFalse((self.root / "unsafe-removal-called").exists())
                self.assert_no_current_results()
                self.assertEqual(self.calls(), [])

    def test_external_git_metadata_cache_aliases_are_rejected(self):  # noqa: PLR0915 - bounded metadata layouts
        private = Path(self.temporary) / "private Git metadata"
        admin = private / "worktrees/fixture"
        admin.mkdir(parents=True)
        common = private / "shared\nmetadata"
        common.mkdir()
        marker = common / "preserve-marker"
        marker.write_bytes(b"owned Git metadata fixture")
        git_entry = self.root / ".git"
        configured = Path(self.temporary) / "configured-cache"
        configured.mkdir()
        self.protected_removal_interceptor()
        self.install("cargo", "raise SystemExit(87)")
        for relative in (False, True):
            pointer = os.path.relpath(admin, self.root) if relative else str(admin)
            git_entry.write_text("gitdir: " + pointer + "\n")
            common_pointer = os.path.relpath(common, admin) if relative else str(common)
            (admin / "commondir").write_text(common_pointer + "\n")
            for target in (admin, common, common / "objects", private):
                for aggregate in (False, True):
                    with self.subTest(relative=relative, target=target, aggregate=aggregate):
                        self.seed_stale_results()
                        link = configured / "fuzz"
                        link.symlink_to(target)
                        result = self.run_suite(
                            aggregate=aggregate, CARGO_TARGET_DIR=str(configured)
                        )
                        link.unlink()
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn("overlaps protected", result.stderr)
                        self.assert_no_current_results()
                        self.assertFalse((self.root / "unsafe-removal-called").exists())
                        self.assertEqual(marker.read_bytes(), b"owned Git metadata fixture")
                        self.assertEqual(git_entry.read_text(), "gitdir: " + pointer + "\n")
                        self.assertEqual(self.calls(), [])

        metadata_file = private / "regular-file"
        metadata_file.write_bytes(b"owned regular file")
        missing = private / "missing-directory"
        # CRLF must fail even if its stray carriage return names an existing directory.
        Path(str(admin) + "\r").mkdir()
        Path(str(common) + "\r").mkdir()
        pointers = (
            ("gitdir", b"invalid", f"{common}\n".encode()),
            ("commondir", f"gitdir: {admin}\n".encode(), b""),
            ("gitdir-missing", f"gitdir: {missing}\n".encode(), f"{common}\n".encode()),
            ("gitdir-file", f"gitdir: {metadata_file}\n".encode(), f"{common}\n".encode()),
            ("gitdir-crlf", f"gitdir: {admin}\r\n".encode(), f"{common}\n".encode()),
            ("commondir-missing", f"gitdir: {admin}\n".encode(), f"{missing}\n".encode()),
            ("commondir-file", f"gitdir: {admin}\n".encode(), f"{metadata_file}\n".encode()),
            ("commondir-crlf", f"gitdir: {admin}\n".encode(), f"{common}\r\n".encode()),
        )
        for malformed, git_record, common_record in pointers:
            with self.subTest(malformed=malformed):
                git_entry.write_bytes(git_record)
                (admin / "commondir").write_bytes(common_record)
                self.seed_stale_results()
                result = self.run_suite(CARGO_TARGET_DIR=str(configured))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("metadata pointer", result.stderr)
                self.assert_no_current_results()
                self.assertFalse((self.root / "unsafe-removal-called").exists())
                self.assertEqual(marker.read_bytes(), b"owned Git metadata fixture")
                self.assertEqual(metadata_file.read_bytes(), b"owned regular file")
                self.assertEqual(git_entry.read_bytes(), git_record)
                self.assertEqual((admin / "commondir").read_bytes(), common_record)
                self.assertEqual(self.calls(), [])

        self.install("cargo", CARGO)
        (self.bin / "rm").unlink()
        (self.bin / "rm").symlink_to(shutil.which("rm"))
        for layout in ("worktree", "none", "standalone"):
            with self.subTest(safe_layout=layout):
                if layout == "worktree":
                    git_entry.write_text(f"gitdir: {admin}\n")
                    (admin / "commondir").write_text(f"{common}\n")
                elif layout == "none":
                    git_entry.unlink()
                else:
                    git_entry.mkdir()
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(marker.read_bytes(), b"owned Git metadata fixture")
                self.assertFalse((self.root / "target/security-suite/fuzz").exists())

    def test_receipt_cache_mismatch_and_missing_cache_block_raw_deletion(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                _, raw = self.seed_stale_collection()
                code = (
                    "shutil.rmtree(Path(os.environ['CARGO_TARGET_DIR']) / 'fuzz')"
                    if missing
                    else "os.environ['CARGO_TARGET_DIR'] = str(ROOT / 'different-cache')"
                )
                self.install_helper_hooks({"--cleanup-cache": code})
                self.install_cleanup_hook("pass")
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("missing" if missing else "differs", result.stderr)
                self.assertFalse((self.root.parent / "cleanup-called").exists())
                self.assert_restored(raw, "removal", 1)

    def test_missing_cleanup_command_blocks_and_keeps_raw_recovery(self):
        for helper in (False, True):
            with self.subTest(helper=helper):
                _, raw = self.seed_stale_collection()
                if helper:
                    self.install_helper_hooks({"--cleanup-cache": "raise SystemExit(127)"})
                    self.install_cleanup_hook("pass")
                else:
                    self.install_cleanup_hook("raise SystemExit(127)")
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_restored(raw, "removal", 1 if helper else 127)

    def bootstrap_failure(self, failure):
        if failure == "log-truncation":
            (self.artifacts / "summary/security.log").mkdir(parents=True)
        elif failure in ("global-directory", "cargo-home"):
            actual_mkdir = shutil.which("mkdir")
            blocked = (
                (self.artifacts / "summary")
                if failure == "global-directory"
                else Path(self.env["CARGO_HOME"])
            )
            self.install(
                "mkdir",
                "import os,sys\n"
                f"if {str(blocked)!r} in sys.argv[1:]: raise SystemExit(33)\n"
                f"os.execv({actual_mkdir!r}, [{actual_mkdir!r}] + sys.argv[1:])",
            )
        else:
            actual_tee = shutil.which("tee")
            self.install(
                "tee",
                "import subprocess,sys\n"
                "data=sys.stdin.buffer.read()\n"
                "if b'starting security suite' in data: raise SystemExit(32)\n"
                f"raise SystemExit(subprocess.run([{actual_tee!r}] + sys.argv[1:], "
                "input=data).returncode)",
            )

    def test_fuzz_results_invalidated_before_each_global_bootstrap_failure(self):
        for failure in ("global-directory", "log-truncation", "global-log", "cargo-home"):
            for aggregate in (False, True):
                with self.subTest(failure=failure, aggregate=aggregate):
                    _, raw = self.seed_stale_results()
                    self.bootstrap_failure(failure)
                    result = self.run_suite(aggregate=aggregate)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assert_no_current_results()
                    for path, content in raw.items():
                        self.assertEqual(path.read_bytes(), content)
                    self.assertEqual(self.calls(), [])
                    for name in ("mkdir", "tee"):
                        command = self.bin / name
                        command.unlink()
                        command.symlink_to(shutil.which(name))
                    blocked = self.artifacts / "summary/security.log"
                    if blocked.is_dir():
                        blocked.rmdir()

    def test_invalidation_failure_prevents_bootstrap_and_children(self):
        _, raw = self.seed_stale_results()
        actual_rm = shutil.which("rm")
        self.install(
            "rm",
            "import os,sys\n"
            "if any(arg.endswith('/run_summary.json') for arg in sys.argv[1:]):\n"
            " raise SystemExit(31)\n"
            f"os.execv({actual_rm!r}, [{actual_rm!r}] + sys.argv[1:])",
        )
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                result = self.run_suite(aggregate=aggregate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("cannot invalidate previous fuzz results", result.stderr)
                self.assertFalse((self.artifacts / "summary").exists())
                self.assertFalse(Path(self.env["CARGO_HOME"]).exists())
                self.assertEqual(self.calls(), [])
                for path, content in raw.items():
                    self.assertEqual(path.read_bytes(), content)

    def test_nonfuzz_stage_preserves_previous_fuzz_results(self):
        marker, _ = self.seed_stale_results()
        original = {
            name: (marker.parent / name).read_bytes()
            for name in ("collection.ok", "execution.json", "run_summary.json")
        }
        result = self.run_suite(stages=["cargo-vet"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for name, content in original.items():
            self.assertEqual((marker.parent / name).read_bytes(), content)

    def test_relative_cargo_home_stays_anchored_to_the_caller(self):
        self.caller = self.root / "caller"
        self.caller.mkdir()
        self.install(
            "git",
            "import os,sys\n"
            "if '--show-toplevel' in sys.argv: print(os.environ['FIXTURE_ROOT'])\n"
            "else: raise SystemExit(1)",
        )
        result = self.run_suite(CARGO_HOME="relative cargo home", FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            self.summary()["execution"]["environment"]["CARGO_HOME"],
            str(self.caller / "relative cargo home"),
        )
        self.assertFalse((self.root / "relative cargo home").exists())


if __name__ == "__main__":
    unittest.main()


class SecurityFuzzReceiptBoundaryTests(SecurityFuzzFixture):
    def helper_python(self, code, **environment):
        return subprocess.run(  # noqa: S603 - isolated controlled helper and test code
            [sys.executable, "-c", code, str(self.root / "scripts/fuzz/manage_fuzz_corpus.py")],
            cwd=self.root,
            env={**self.env, **environment},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_exclusive_receipt_temporary_files_ignore_fixed_symlinks(self):
        directory = self.artifacts / "fuzz"
        directory.mkdir(parents=True)
        external = Path(self.temporary) / "external-input"
        external.write_bytes(b"preserve external input")
        for filename in ("execution.json", "run_summary.json"):
            temporary = directory / Path(filename).with_suffix(".tmp")
            temporary.symlink_to(external)
            result = self.helper_python(
                "import pathlib,runpy,sys\n"
                "helper=runpy.run_path(sys.argv[1])\n"
                f"destination=pathlib.Path({str(directory / filename)!r})\n"
                "helper['write_json'](destination, {'new': True})\n"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(external.read_bytes(), b"preserve external input")
            self.assertTrue(temporary.is_symlink())
            self.assertEqual(json.loads((directory / filename).read_text()), {"new": True})
            self.assertEqual(list(directory.glob("." + filename + ".*.tmp")), [])

    def test_failed_receipt_replace_cleans_only_its_exclusive_temporary(self):
        directory = self.artifacts / "fuzz"
        directory.mkdir(parents=True)
        destination = directory / "execution.json"
        destination.write_text('{"old": true}')
        unrelated = directory / "execution.tmp"
        unrelated.write_bytes(b"unrelated temporary input")
        result = self.helper_python(
            "import pathlib,runpy,sys\nfrom unittest.mock import patch\n"
            "helper=runpy.run_path(sys.argv[1])\n"
            "with patch.object(pathlib.Path, 'replace', side_effect=OSError('blocked replace')):\n"
            f" try: helper['write_json'](pathlib.Path({str(destination)!r}), {{'new': True}})\n"
            " except OSError: pass\n"
            " else: raise RuntimeError('replace unexpectedly passed')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(destination.read_text()), {"old": True})
        self.assertEqual(unrelated.read_bytes(), b"unrelated temporary input")
        self.assertEqual(list(directory.glob(".execution.json.*.tmp")), [])

    def test_git_identity_overrides_fail_before_discovery_or_receipt_removal(self):
        marker, raw = self.seed_stale_results()
        evidence = {path: path.read_bytes() for path in marker.parent.iterdir() if path.is_file()}
        external = Path(self.temporary) / "external-git-input"
        external.mkdir()
        owned = external / "owned"
        owned.write_bytes(b"preserve effective Git input")
        names = (
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
            "GIT_NAMESPACE",
            "GIT_SHALLOW_FILE",
            "GIT_REPLACE_REF_BASE",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
        )
        for name in names:
            with self.subTest(name=name):
                result = self.run_suite(**{name: str(external)})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("inherited Git identity overrides", result.stderr)
                self.assertEqual(self.calls(), [])
                for path, contents in {**evidence, **raw}.items():
                    self.assertEqual(path.read_bytes(), contents)
                self.assertEqual(owned.read_bytes(), b"preserve effective Git input")
                direct = self.helper_python(
                    "import pathlib,runpy,sys\n"
                    "helper=runpy.run_path(sys.argv[1])\n"
                    "helper['source_hashes'](list(helper['REQUIRED_TARGETS']))\n",
                    **{name: str(external)},
                )
                self.assertNotEqual(direct.returncode, 0)
                self.assertIn("inherited Git identity overrides", direct.stderr)

    def test_dirty_and_ignored_transitive_inputs_and_inventory_changes_are_bound(self):
        inputs = (
            "crates/server/src/web/par_endpoint.rs",
            "crates/ffi/build.rs",
            "crates/ffi/src/new_ignored.rs",
            ".cargo/config.toml",
            "generated/local/header.h",
            "c/local_bridge.c",
            "include/local_bridge.h",
            "scripts/extraction/local_generator.py",
            "tests/fixtures/local/input.json",
        )
        for name in inputs:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("original local build/source input\n")
        (self.root / ".gitignore").write_text("new_ignored.rs\n")
        self.install(
            "git",
            "import os,sys\n"
            "print(os.environ['FIXTURE_ROOT'] if '--show-toplevel' in sys.argv else "
            "'a7a0274fe1783a6d9055350c65ec52c765709739')\n",
        )
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = self.summary()["execution"]["source"]["files"]
        for name in inputs:
            self.assertEqual(
                inventory[name]["sha256"],
                hashlib.sha256((self.root / name).read_bytes()).hexdigest(),
            )
        receipt = self.artifacts / "fuzz/execution.json"
        baseline = json.loads(receipt.read_text())
        mutations = (
            "(root / 'crates/server/src/web/par_endpoint.rs').write_text('dirty PAR change')",
            "(root / 'crates/ffi/src/added.rs').write_text('new ignored implementation')",
            "(root / 'include/local_bridge.h').unlink()",
            "(root / 'crates/ffi/build.rs').chmod(0o755)",
            "(root / 'crates/ffi/build.rs').chmod(0o4755)",
            "(root / 'crates/ffi/src/new-empty-import-directory').mkdir()",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                result = self.helper_python(
                    "import json,pathlib,runpy,sys\nhelper=runpy.run_path(sys.argv[1])\n"
                    "root=helper['ROOT']\n"
                    f"before=helper['source_hashes'](list(helper['REQUIRED_TARGETS']))\n{mutation}\n"
                    "after=helper['source_hashes'](list(helper['REQUIRED_TARGETS']))\n"
                    "if before == after: raise RuntimeError('source change not detected')\n"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("source change not detected", result.stderr)
                self.assertEqual(
                    json.loads(receipt.read_text())["source"]["commit"]["output"].strip(),
                    baseline["source"]["commit"]["output"].strip(),
                )

    def test_transitive_changes_during_backup_block_destructive_cleanup(self):
        for mutation in (
            "(ROOT / 'crates/server/src/lib.rs').write_text('dirty server implementation')",
            "(ROOT / 'crates/ffi/src/ignored-new.rs').write_text('new ignored implementation')",
            "(ROOT / 'crates/ffi/src/lib.rs').unlink(missing_ok=True)",
        ):
            with self.subTest(mutation=mutation):
                _, raw = self.seed_stale_collection()
                self.install_cleanup_hook("pass")
                self.install_helper_hooks(
                    {
                        "--backup-cleanup": "original_copy = shutil.copytree\n"
                        "def mutate_after_copy(source, destination, *args, **kwargs):\n"
                        " result = original_copy(source, destination, *args, **kwargs)\n"
                        f" {mutation}\n"
                        " return result\n"
                        "shutil.copytree = mutate_after_copy\n"
                    }
                )
                result = self.run_suite()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("source identity changed before cleanup", result.stderr)
                self.assertFalse((self.root.parent / "cleanup-called").exists())
                for path, content in raw.items():
                    self.assertEqual(path.read_bytes(), content)
                self.assertTrue(Path(self.env["CARGO_TARGET_DIR"]).is_dir())

    def test_changed_server_par_source_rejects_successful_controlled_execution(self):
        par = self.root / "crates/server/src/web/par_endpoint.rs"
        par.parent.mkdir(parents=True)
        par.write_text("// PAR input before execution\n")
        result = self.run_suite(case="transitive-source-change")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "source identity changed during execution",
            (self.artifacts / "summary/security.log").read_text(),
        )
        self.assertEqual(par.read_text(), "// changed during fuzz execution\n")
        self.assertFalse((self.artifacts / "fuzz/collection.ok").exists())
        self.assertTrue(list((self.root / "fuzz/corpus").rglob("seed")))

    def test_external_missing_and_symlink_local_inputs_fail_closed(self):
        external = Path(self.temporary) / "external-source"
        external.mkdir()
        (external / "Cargo.toml").write_text('[package]\nname="external"\nversion="0.0.0"\n')
        declarations = (str(external), "../missing-crate", "../target/hidden-source")
        manifest = self.root / "crates/ffi/Cargo.toml"
        original = manifest.read_bytes()
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                manifest.write_text(
                    "[dependencies]\nother = { path = " + json.dumps(declaration) + " }\n"
                )
                result = self.helper_python(
                    "import runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
                    "h['source_hashes'](list(h['REQUIRED_TARGETS']))\n"
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("local Cargo source path", result.stderr)
        manifest.write_bytes(original)
        alias = self.root / "crates/ffi/src/external.rs"
        alias.symlink_to(external / "Cargo.toml")
        result = self.helper_python(
            "import runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
            "h['source_hashes'](list(h['REQUIRED_TARGETS']))\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink or external local source", result.stderr)

    def test_exact_kani_tool_pointer_is_recorded_without_traversal_and_changes_reject(self):
        pointer = self.root / "crates/kani-harness/kani"
        code = (
            "import runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
            "v=h['source_hashes'](list(h['REQUIRED_TARGETS']))\n"
            "print(v['crates/kani-harness/kani'])\n"
        )
        result = self.helper_python(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unrelated-tool-output-pointer", result.stdout)
        self.assertIn("result/bin/cargo-kani", result.stdout)
        self.assertIn(hashlib.sha256(b"result/bin/cargo-kani").hexdigest(), result.stdout)
        self.assertIn("120000", result.stdout)
        pointer.unlink()
        for kind in ("missing", "file", "changed-target"):
            with self.subTest(kind=kind):
                if kind == "file":
                    pointer.write_text("tool output")
                if kind == "changed-target":
                    pointer.symlink_to("different-tool")
                result = self.helper_python(code)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Kani output pointer is missing or changed", result.stderr)
                pointer.unlink(missing_ok=True)
        pointer.symlink_to("result/bin/cargo-kani")

    def test_kani_pointer_literal_environment_reference_rejects(self):
        code = (
            "import runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
            "h['source_hashes'](list(h['REQUIRED_TARGETS']))\n"
        )
        for name in ("RUSTC", "RUSTC_WRAPPER", "CARGO_ENCODED_RUSTFLAGS", "LOCAL_TOOL"):
            with self.subTest(name=name):
                result = self.helper_python(code, **{name: "crates/kani-harness/kani"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("build environment references", result.stderr)

    def test_kani_pointer_new_dependency_or_configuration_reference_rejects(self):
        code = (
            "import runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
            "h['source_hashes'](list(h['REQUIRED_TARGETS']))\n"
        )
        root_manifest = self.root / "Cargo.toml"
        original = root_manifest.read_bytes()
        root_manifest.write_text('[workspace]\nmembers = ["crates/server"]\n')
        result = self.helper_python(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no longer workspace-excluded", result.stderr)
        root_manifest.write_bytes(original)
        ffi_manifest = self.root / "crates/ffi/Cargo.toml"
        ffi_manifest.write_text('[dependencies]\nkani = { path="../kani-harness" }\n')
        result = self.helper_python(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("became relevant", result.stderr)
        root_manifest.write_text(
            original.decode() + '[workspace.dependencies]\nkani = { path="crates/kani-harness" }\n'
        )
        ffi_manifest.write_text("[dependencies]\nkani = { workspace=true }\n")
        result = self.helper_python(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("became relevant", result.stderr)
        root_manifest.write_bytes(original)
        ffi_manifest.write_text('[package]\nname="ffi"\nversion="0.0.0"\n')
        (self.root / ".cargo/config.toml").write_text("# kani-harness/kani tool reference\n")
        result = self.helper_python(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configuration references", result.stderr)


# This source is inserted into the existing fixture module; it is not a standalone test runner.
class SecurityFuzzCollectionCompilerTests(SecurityFuzzFixture):
    helper_python = SecurityFuzzReceiptBoundaryTests.helper_python

    def test_direct_collection_entrypoints_reject_all_raw_root_aliases_before_changes(self):
        outside = Path(self.temporary) / "outside"
        (outside / TARGETS[0] / "nested").mkdir(parents=True)
        sentinel = outside / TARGETS[0] / "nested/external-input"
        sentinel.write_bytes(b"external fixture must stay private")
        expressions = (
            "h['collect_corpus']()",
            "h['ensure_directories'](list(h['REQUIRED_TARGETS']))",
            "h['gather_stats'](list(h['REQUIRED_TARGETS']))",
            "h['create_archive']()",
            "h['gather_crash_stats']()",
            "h['archive_crashes']([h['CrashStat'](names[0],1,1,None,[])], None)",
        )
        for name in ("corpus", "artifacts", "corpus_archive"):
            raw = self.root / "fuzz" / name
            raw.symlink_to(outside)
            for expression in expressions:
                with self.subTest(raw=name, entrypoint=expression):
                    result = self.helper_python(
                        "import runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
                        "names=h['REQUIRED_TARGETS']\n" + expression + "\n"
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("owned raw directory roots", result.stderr)
                    self.assertEqual(sentinel.read_bytes(), b"external fixture must stay private")
                    self.assertEqual(
                        sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")),
                        [TARGETS[0], TARGETS[0] + "/nested", TARGETS[0] + "/nested/external-input"],
                    )
                    self.assertFalse((self.root / "fuzz/corpus_meta").exists())
                    self.assertFalse(self.artifacts.exists())
            raw.unlink()

    def test_passed_and_failed_collection_reject_raw_aliases_and_preserve_execution(self):
        outside = Path(self.temporary) / "outside"
        (outside / TARGETS[0] / "nested").mkdir(parents=True)
        sentinel = outside / TARGETS[0] / "nested/external-input"
        sentinel.write_bytes(b"never archive this external fixture")
        for name in ("corpus", "artifacts", "corpus_archive"):
            for case in ("ok", "run-fail"):
                with self.subTest(raw=name, case=case):
                    saved_raw = Path(self.temporary) / ("original-" + name)
                    self.install_helper_hooks(
                        {
                            "--finish-run": "original_collect=collect_corpus\n"
                            "def alias_collect(data):\n"
                            f" raw=FUZZ_DIR/{name!r}\n"
                            f" original=Path({str(saved_raw)!r})\n"
                            " if raw.exists(): raw.rename(original)\n"
                            f" raw.symlink_to({str(outside)!r})\n"
                            " original_collect(data)\n"
                            "collect_corpus=alias_collect\n"
                        }
                    )
                    result = self.run_suite(case, FAIL_TARGET=TARGETS[0])
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(
                        "owned raw directory roots",
                        (self.artifacts / "summary/security.log").read_text(),
                    )
                    directory = self.artifacts / "fuzz"
                    execution = json.loads((directory / "execution.json").read_text())
                    self.assertEqual(
                        execution["status"], "awaiting-cleanup" if case == "ok" else "failed"
                    )
                    self.assertEqual(
                        execution["targets"][0]["run"]["exit_code"], 0 if case == "ok" else 23
                    )
                    self.assertFalse((directory / "collection.ok").exists())
                    self.assertFalse((directory / "run_summary.json").exists())
                    self.assertFalse(list(directory.glob("*.tar.gz")))
                    self.assertFalse((self.root / "fuzz/corpus_meta").exists())
                    self.assertEqual(sentinel.read_bytes(), b"never archive this external fixture")
                    alias = self.root / "fuzz" / name
                    self.assertTrue(alias.is_symlink())
                    alias.unlink()
                    original = Path(self.temporary) / ("original-" + name)
                    if original.exists():
                        original.rename(alias)

    def test_nested_collection_links_are_inert_in_statistics_and_archives(self):
        outside = Path(self.temporary) / "outside"
        (outside / "nested").mkdir(parents=True)
        sentinel = outside / "nested/external-input"
        sentinel.write_bytes(b"external contents must not be collected")
        for name in ("corpus", "artifacts"):
            raw = self.root / "fuzz" / name
            target = raw / TARGETS[0]
            target.mkdir(parents=True)
            (target / "owned-input").write_bytes(b"owned")
            (target / "file-link").symlink_to(sentinel)
            (target / "directory-link").symlink_to(outside)
            (raw / TARGETS[1]).symlink_to(outside)
        result = self.helper_python(
            "import runpy,sys\nh=runpy.run_path(sys.argv[1])\nh['collect_corpus']()\n",
            FUZZ_RUN_ARTIFACT_DIR=str(self.artifacts),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads((self.artifacts / "run_summary.json").read_text())
        corpus = {row["name"]: row for row in summary["targets"]}
        self.assertEqual((corpus[TARGETS[0]]["files"], corpus[TARGETS[0]]["size_bytes"]), (1, 5))
        self.assertEqual(corpus[TARGETS[1]]["files"], 0)
        self.assertEqual(
            [(row["name"], row["files"], row["size_bytes"]) for row in summary["crashes"]],
            [(TARGETS[0], 1, 5)],
        )
        for key, prefix in (("corpus_archive", "corpus/"), ("crash_archive", "")):
            with tarfile.open(self.artifacts / summary[key]) as archive:
                names = archive.getnames()
                self.assertFalse(
                    any("external-input" in value or "/nested" in value for value in names)
                )
                for link in ("file-link", "directory-link"):
                    entry = archive.getmember(prefix + TARGETS[0] + "/" + link)
                    self.assertTrue(entry.issym())
                self.assertEqual(
                    archive.extractfile(prefix + TARGETS[0] + "/owned-input").read(), b"owned"
                )
        self.assertEqual(sentinel.read_bytes(), b"external contents must not be collected")

    def test_collection_summary_alias_blocks_marker_for_passed_and_failed_runs(self):
        outside = Path(self.temporary) / "external-summary"
        outside.write_bytes(b"preserve external summary")
        directory = self.artifacts / "fuzz"
        directory.mkdir(parents=True)
        alias = directory / "collection-summary.json"
        alias.symlink_to(outside)
        self.install_cleanup_hook("pass")
        for case in ("ok", "run-fail"):
            with self.subTest(case=case):
                result = self.run_suite(case, FAIL_TARGET=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(
                    "receipt destination is not a regular file",
                    (self.artifacts / "summary/security.log").read_text(),
                )
                self.assertTrue(alias.is_symlink())
                self.assertEqual(outside.read_bytes(), b"preserve external summary")
                self.assertFalse((directory / "collection.ok").exists())
                self.assertFalse((self.root.parent / "cleanup-called").exists())
                self.assertEqual(
                    self.summary()["status"], "awaiting-cleanup" if case == "ok" else "failed"
                )
                self.assertTrue(list((self.root / "fuzz/corpus").rglob("seed")))

    def test_collection_summary_mismatch_cannot_authorize_cleanup(self):
        self.install_helper_hooks(
            {
                "--finish-run": "original_collect=collect_corpus\n"
                "def mismatched_collect(data):\n"
                " original_collect(data)\n"
                " path=RUN_ARTIFACT_DIR/'run_summary.json'\n"
                " summary=json.loads(path.read_text())\n"
                " summary['execution']['run_id']='different-run'\n"
                " write_json(path,summary)\n"
                "collect_corpus=mismatched_collect\n"
            }
        )
        self.install_cleanup_hook("pass")
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "run summary differs from the verified execution",
            (self.artifacts / "summary/security.log").read_text(),
        )
        self.assertFalse((self.artifacts / "fuzz/collection.ok").exists())
        self.assertFalse((self.artifacts / "fuzz/collection-summary.json").exists())
        self.assertFalse((self.root.parent / "cleanup-called").exists())

    def test_compiler_overrides_reject_before_wrapper_mutation_and_direct_helper_actions(self):
        marker, raw = self.seed_stale_results()
        previous = {p: p.read_bytes() for p in marker.parent.iterdir() if p.is_file()}
        tool = Path(self.temporary) / "unsupported-compiler"
        tool.write_text(f"#!{sys.executable}\nraise SystemExit('unsupported compiler executed')\n")
        tool.chmod(0o755)
        actions = (
            ["--prepare-run", str(marker.parent)],
            ["--record-environment", str(marker.parent)],
            ["--execution-cache", str(marker.parent)],
            ["--cleanup-cache", str(marker.parent), "invalid-run"],
            ["--backup-cleanup", str(marker.parent)],
            ["--finish-run", str(marker.parent), "0"],
        )
        for name in (
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ):
            for value in ("", str(tool)):
                with self.subTest(override=name, present_empty=value == ""):
                    result = self.run_suite(**{name: value})
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("override is not supported", result.stderr)
                    self.assertEqual(self.calls(), [])
                    for action in actions:
                        direct = subprocess.run(  # noqa: S603 - owned helper with unsupported inputs
                            [
                                sys.executable,
                                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                                *action,
                            ],
                            cwd=self.root,
                            env={**self.env, name: value},
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.assertEqual(direct.returncode, 2, direct.stdout + direct.stderr)
                        self.assertIn("override is not supported", direct.stderr)
                    for p, expected in {**previous, **raw}.items():
                        self.assertEqual(p.read_bytes(), expected)
        for expression in (
            "h['prepare_run'](destination)",
            "h['configured_cache'](destination)",
            "h['load_execution'](destination)",
        ):
            result = self.helper_python(
                "import pathlib,runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
                f"destination=pathlib.Path({str(marker.parent)!r})\n" + expression,
                RUSTC="",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("override is not supported", result.stderr)

    def test_preflight_raw_aliases_leave_receipts_and_external_inputs_unchanged(self):
        marker, raw = self.seed_stale_results()
        prior = {path: path.read_bytes() for path in marker.parent.iterdir() if path.is_file()}
        for name in ("corpus", "artifacts", "corpus_archive"):
            with self.subTest(root=name):
                original = self.root / "fuzz" / name
                saved = original.with_name(name + "-saved")
                original.rename(saved)
                external = Path(self.temporary) / (name + "-external")
                external.mkdir()
                sentinel = external / "owned-input"
                sentinel.write_bytes(b"do not mutate external raw bytes")
                original.symlink_to(external, target_is_directory=True)
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("owned raw directory roots", result.stderr)
                self.assertEqual(self.calls(), [])
                self.assertFalse((self.artifacts / "summary/security.log").exists())
                self.assertEqual(sentinel.read_bytes(), b"do not mutate external raw bytes")
                for path, content in prior.items():
                    self.assertEqual(path.read_bytes(), content)
                direct = self.helper_python(
                    "import pathlib,runpy,sys\nh=runpy.run_path(sys.argv[1])\n"
                    f"h['prepare_run'](pathlib.Path({str(marker.parent)!r}))"
                )
                self.assertNotEqual(direct.returncode, 0, direct.stderr)
                self.assertEqual(self.calls(), [])
                original.unlink()
                saved.rename(original)
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)

    def test_evidence_route_alias_and_raw_source_overlaps_reject_before_invalidation(self):
        external = Path(self.temporary) / "external-evidence"
        (external / "latest/fuzz").mkdir(parents=True)
        sentinels = {}
        for name in ("collection.ok", "execution.json", "run_summary.json"):
            path = external / "latest/fuzz" / name
            path.write_bytes(b"private external old receipt")
            sentinels[path] = path.read_bytes()
        alias = Path(self.temporary) / "alias"
        alias.symlink_to(external, target_is_directory=True)
        raw = self.root / "fuzz/corpus/owned"
        raw.mkdir(parents=True)
        for name in ("collection.ok", "execution.json", "run_summary.json"):
            path = raw / "fuzz" / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b"private raw input")
            sentinels[path] = path.read_bytes()
        for route in (alias / "latest", raw, self.root / "crates/server", self.root / ".git"):
            with self.subTest(route=route):
                result = self.run_suite(SECURITY_ARTIFACT_DIR=str(route))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(), [])
                for path, content in sentinels.items():
                    self.assertEqual(path.read_bytes(), content)
                self.assertFalse((route / "summary/security.log").exists())
        marker, _unused_raw = self.seed_stale_results()
        history_alias = alias / "history"
        result = self.run_suite(SECURITY_HISTORY_DIR=str(history_alias))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(marker.exists())
        self.assertEqual(self.calls(), [])

    def test_metadata_history_and_summary_log_aliases_reject_before_any_mutation(self):
        marker, _unused_raw = self.seed_stale_results()
        prior = {path: path.read_bytes() for path in marker.parent.iterdir() if path.is_file()}
        external = Path(self.temporary) / "external-log"
        external.mkdir()
        sentinel = external / "private"
        sentinel.write_bytes(b"preserve external log and metadata bytes")
        destinations = (
            (self.root / "fuzz/corpus_meta", True),
            (self.root / "fuzz/corpus_meta/history.jsonl", False),
            (self.artifacts / "summary", True),
            (self.artifacts / "summary/security.log", False),
            (Path(self.env["SECURITY_HISTORY_DIR"]) / "fuzz_runs.jsonl", False),
        )
        for path, directory in destinations:
            with self.subTest(path=path):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(external if directory else sentinel, target_is_directory=directory)
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(), [])
                self.assertEqual(sentinel.read_bytes(), b"preserve external log and metadata bytes")
                for receipt, content in prior.items():
                    self.assertEqual(receipt.read_bytes(), content)
                path.unlink()

    def test_fresh_nested_cache_ancestors_are_bound_before_tool_creation(self):
        cache = self.root / "build/cache"
        self.assertFalse(cache.parent.exists())
        result = self.run_suite(CARGO_TARGET_DIR=str(cache), FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        execution = self.summary()["execution"]
        self.assertIn("build", execution["source"]["files"])
        self.assertEqual(execution["source"]["files"]["build"]["type"], "directory")
        self.assertNotIn("build/cache", execution["source"]["files"])
        self.assertEqual(execution["status"], "passed")
        self.assertTrue(cache.is_dir())
        self.assertFalse((cache / "fuzz").exists())

    def test_effective_forced_native_tools_and_linker_match_actual_config(self):
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = self.summary()["execution"]
        for name, command in (("cc", "cc"), ("cxx", "c++"), ("linker", "cc"), ("ar", "ar")):
            tool = data["tools"][name]
            self.assertEqual(tool["path"], str(self.bin / command))
            self.assertEqual(
                tool["sha256"], hashlib.sha256((self.bin / command).read_bytes()).hexdigest()
            )
            self.assertEqual(tool["exit_code"], 0)
        self.assertEqual(
            data["effective_native_commands"],
            {"cc": "cc", "cxx": "c++", "linker": "cc", "ar": "ar"},
        )
        self.assertIn(".cargo/config.toml", data["source"]["files"])

    def test_preflight_rejects_hardlinked_log_history_and_metadata_destinations(self):
        marker, _unused_raw = self.seed_stale_results()
        prior = {path: path.read_bytes() for path in marker.parent.iterdir() if path.is_file()}
        history = Path(self.env["SECURITY_HISTORY_DIR"])
        routes = (
            self.artifacts / "summary/security.log",
            history / "fuzz_runs.jsonl",
            self.root / "fuzz/corpus_meta/history.jsonl",
            self.root / "fuzz/corpus_meta/latest_run.json",
        )
        for index, route in enumerate(routes):
            with self.subTest(route=route.relative_to(Path(self.temporary))):
                route.parent.mkdir(parents=True, exist_ok=True)
                external = Path(self.temporary) / f"external-hardlink-{index}"
                external.write_bytes(b"external preserved hardlink bytes")
                os.link(external, route)
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(external.read_bytes(), b"external preserved hardlink bytes")
                self.assertEqual(self.calls(), [])
                for path, content in prior.items():
                    self.assertEqual(path.read_bytes(), content)
                route.unlink()

    def test_native_compiler_mismatch_and_unmodeled_config_reject_before_mutation(self):
        marker, _unused_raw = self.seed_stale_results()
        prior = {path: path.read_bytes() for path in marker.parent.iterdir() if path.is_file()}
        called = Path(self.temporary) / "native-called"
        custom = Path(self.temporary) / "custom-cc"
        custom.write_text(
            f"#!{sys.executable}\nimport pathlib\npathlib.Path({str(called)!r}).touch()\n"
        )
        custom.chmod(0o755)
        for name in (
            "CC",
            "CXX",
            "AR",
            "CC_x86_64_unknown_linux_gnu",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
        ):
            with self.subTest(override=name):
                result = self.run_suite(**{name: str(custom)})
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(called.exists())
                self.assertEqual(self.calls(), [])
                for path, content in prior.items():
                    self.assertEqual(path.read_bytes(), content)
        config = self.root / ".cargo/config.toml"
        previous = config.read_bytes()
        config.write_text('[build]\nrustc = "unmodeled-compiler"\n')
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        config.write_bytes(previous)
        nested = self.root / "fuzz/.cargo/config.toml"
        nested.parent.mkdir()
        nested.write_text('[target.x86_64-unknown-linux-gnu]\nlinker="unmodeled-linker"\n')
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        for path, content in prior.items():
            self.assertEqual(path.read_bytes(), content)


class SecurityFuzzOuterAppTests(SecurityFuzzFixture):
    def setUp(self):
        super().setUp()
        # The app script lives outside the checkout, as it does in the Nix store.
        self.outer = Path(self.temporary) / "store/bin/security-suite"
        self.outer.parent.mkdir(parents=True)
        outer_source = self.root / "scripts/flake/security_suite.sh"
        outer_source.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/flake/security_suite.sh", outer_source)
        shutil.copyfile(outer_source, self.outer)
        self.external = Path(self.temporary) / "external-repository"
        (self.external / "scripts/security").mkdir(parents=True)
        self.dispatch = Path(self.temporary) / "outer-dispatch.json"
        external_wrapper = self.external / "scripts/security/run_security_suite.sh"
        external_wrapper.write_text(
            f"#!{sys.executable}\n"
            "import json,os,pathlib,sys\n"
            f"pathlib.Path({str(self.dispatch)!r}).write_text(json.dumps({{"
            "'argv':sys.argv[1:],'cwd':os.getcwd(),'GIT_DIR':os.environ.get('GIT_DIR')}))\n"
        )
        external_wrapper.chmod(0o755)
        (self.external / "owned-input").write_bytes(b"preserve external input")
        (self.root / "scripts/security/run_security_suite.sh").chmod(0o755)
        self.install(
            "git",
            "import json,os,pathlib,sys\n"
            "root=pathlib.Path(os.environ['FIXTURE_ROOT'])\n"
            "with (root.parent/'outer-git-calls.jsonl').open('a') as out:\n"
            " out.write(json.dumps(sys.argv[1:])+'\\n')\n"
            "print(os.environ.get('GIT_DIR') or str(root) if '--show-toplevel' in sys.argv "
            "else 'a7a0274fe1783a6d9055350c65ec52c765709739')\n",
        )

    def run_outer(self, arguments, **environment):
        return subprocess.run(  # noqa: S603 - actual outer wrapper and owned controlled routes
            [str(self.bin / "bash"), str(self.outer), *arguments],
            cwd=self.root,
            env={**self.env, **environment},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_outer_fuzz_and_default_reject_overrides_before_git_or_external_dispatch(self):
        marker, raw = self.seed_stale_results()
        previous = {path: path.read_bytes() for path in marker.parent.iterdir() if path.is_file()}
        names = (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
            "GIT_NAMESPACE",
            "GIT_SHALLOW_FILE",
            "GIT_REPLACE_REF_BASE",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_CONFIG",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_CONFIG_KEY_custom",
            "GIT_CONFIG_VALUE_custom",
        )
        for arguments in ([], ["--stage", "fuzz"]):
            for name in names:
                for value in ("", str(self.external)):
                    with self.subTest(arguments=arguments, name=name, value=value):
                        result = self.run_outer(arguments, **{name: value})
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("inherited Git identity overrides", result.stderr)
                        self.assertFalse((self.root.parent / "outer-git-calls.jsonl").exists())
                        self.assertFalse(self.dispatch.exists())
                        for path, contents in {**previous, **raw}.items():
                            self.assertEqual(path.read_bytes(), contents)
                        self.assertEqual(
                            (self.external / "owned-input").read_bytes(), b"preserve external input"
                        )

    def test_outer_store_script_executes_controlled_fuzz_with_unchanged_arguments(self):
        result = self.run_outer(["--stage", "fuzz"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        execution = self.summary()["execution"]
        self.assertEqual(execution["status"], "passed")
        self.assertEqual(execution["selected_targets"], list(TARGETS))
        self.assertFalse(self.dispatch.exists())
        self.assertTrue((self.root.parent / "outer-git-calls.jsonl").exists())
        self.assertFalse((self.root / "fuzz/corpus").exists())

    def test_outer_nonfuzz_selected_dispatch_preserves_effective_git_route(self):
        for arguments in (
            ["--stage", "sbom"],
            ["--fuzz-long", "--stage", "sbom"],
            ["--stage", "sbom", "--", "--stage", "fuzz"],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_outer(arguments, GIT_DIR=str(self.external))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                data = json.loads(self.dispatch.read_text())
                self.assertEqual(data["argv"], arguments)
                self.assertEqual(data["cwd"], str(self.external))
                self.assertEqual(data["GIT_DIR"], str(self.external))
                self.assertEqual(
                    (self.external / "owned-input").read_bytes(), b"preserve external input"
                )

    def test_outer_default_and_mixed_argument_selection_reject_before_git(self):
        for arguments in (
            ["--fuzz-long"],
            ["--"],
            ["unknown-argument"],
            ["--stage", "sbom", "--stage", "fuzz"],
            ["--fuzz-long", "--stage", "fuzz"],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_outer(arguments, GIT_DIR=str(self.external))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("inherited Git identity overrides", result.stderr)
                self.assertFalse((self.root.parent / "outer-git-calls.jsonl").exists())
                self.assertFalse(self.dispatch.exists())

    def test_outer_compiler_overrides_reject_before_git_and_preserve_nonfuzz_dispatch(self):
        for name in (
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ):
            for value in ("", "unsupported-compiler-fixture"):
                for arguments in ([], ["--stage", "fuzz"], ["--stage", "sbom", "--stage", "fuzz"]):
                    with self.subTest(
                        override=name, arguments=arguments, present_empty=value == ""
                    ):
                        result = self.run_outer(arguments, **{name: value})
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn("inherited compiler overrides", result.stderr)
                        self.assertFalse((self.root.parent / "outer-git-calls.jsonl").exists())
                        self.assertFalse(self.dispatch.exists())
        arguments = ["--stage", "geiger"]
        result = self.run_outer(
            arguments, GIT_DIR=str(self.external), RUSTC="unsupported-compiler-fixture"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.dispatch.read_text())["argv"], arguments)
