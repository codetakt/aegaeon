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

    def saved_receipts(self):
        return {
            self.artifacts / "fuzz" / name: (self.artifacts / "fuzz" / name).read_bytes()
            for name in ("collection.ok", "execution.json", "run_summary.json")
        }

    def assert_receipts_unchanged(self, receipts):
        for path, content in receipts.items():
            self.assertEqual(path.read_bytes(), content)

    def assert_no_current_results(self):
        for name in ("collection.ok", "execution.json", "run_summary.json"):
            self.assertFalse((self.artifacts / "fuzz" / name).exists(), name)

    def install_helper_hooks(self, hooks):
        self.install(
            "python3",
            "import os,runpy,sys\n"
            f"hooks={hooks!r}\n"
            "arguments=sys.argv[1:]\n"
            "if arguments[:1] == ['-I']:\n arguments=arguments[1:]\n"
            "for action, code in hooks.items():\n"
            " if action in arguments:\n"
            "  sys.argv=[sys.argv[0], *arguments]\n"
            "  namespace=runpy.run_path(arguments[0], run_name='fuzz_test_hook')\n"
            "  state=namespace['main'].__globals__\n"
            "  exec(code, state)\n"
            "  sys.argv=arguments\n"
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
    def test_cleanup_backup_rejects_receipt_hardlinks_at_initial_and_post_copy_reads(self):
        for timing in ("initial", "post-copy"):
            for name in (
                "execution.json",
                "run_summary.json",
                "collection.ok",
                "collection-summary.json",
            ):
                with self.subTest(timing=timing, receipt=name):
                    shutil.rmtree(self.artifacts, ignore_errors=True)
                    _, raw = self.seed_stale_collection()
                    self.install_cleanup_hook("pass")
                    self.install_helper_hooks(
                        {
                            "--backup-cleanup": f"""
def alias_receipt():
    directory = Path(os.environ['SECURITY_ARTIFACT_DIR']) / 'fuzz'
    path = directory / {name!r}
    external = ROOT.parent / 'aliased-receipt'
    external.unlink(missing_ok=True)
    os.link(path, external)
if {timing!r} == 'initial':
    original_collected = collected_execution
    def collected_then_alias(directory):
        data = original_collected(directory)
        alias_receipt()
        return data
    collected_execution = collected_then_alias
else:
    original_copy = copy_raw_backups
    def copy_then_alias(recovery):
        records = original_copy(recovery)
        alias_receipt()
        return records
    copy_raw_backups = copy_then_alias
"""
                        }
                    )
                    result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("stable, unaliased regular file", result.stderr)
                    self.assertFalse((self.root.parent / "cleanup-called").exists())
                    self.assertFalse(
                        list(self.artifacts.glob("fuzz/cleanup-recovery/*/backup-ready.json"))
                    )
                    for path, content in raw.items():
                        self.assertEqual(path.read_bytes(), content)
                    external = self.root.parent / "aliased-receipt"
                    self.assertEqual(
                        external.read_bytes(), (self.artifacts / "fuzz" / name).read_bytes()
                    )
                    external.unlink()

    def test_recovery_rejects_hardlinked_manifest_and_saved_receipts_before_restoration(self):
        for name in (
            "backup-ready.json",
            "evidence/execution.json",
            "evidence/run_summary.json",
            "evidence/collection.ok",
            "evidence/collection-summary.json",
        ):
            with self.subTest(recovery_receipt=name):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                self.install_helper_hooks(
                    {
                        "--cleanup-result": "raise SystemExit(29)",
                        "--restore-cleanup": f"""
directory = Path(sys.argv[sys.argv.index('--restore-cleanup') + 1])
run_id = sys.argv[sys.argv.index('--restore-cleanup') + 2]
receipt = directory / 'cleanup-recovery' / run_id / {name!r}
external = ROOT.parent / 'aliased-recovery-receipt'
os.link(receipt, external)
""",
                    }
                )
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("stable, unaliased regular file", result.stderr)
                self.assertNotEqual(self.summary()["status"], "passed")
                self.assertFalse((self.root / "fuzz/corpus").exists())
                backup = next((self.artifacts / "fuzz/cleanup-recovery").iterdir())
                external = self.root.parent / "aliased-recovery-receipt"
                self.assertEqual(external.read_bytes(), (backup / name).read_bytes())
                self.assertTrue((backup / "backup-ready.json").is_file())
                self.assertFalse(list(backup.glob("recovery-result-*.json")))
                external.unlink()

    def test_recovery_hashes_and_restores_each_once_read_validated_snapshot(self):
        self.install_helper_hooks(
            {
                "--cleanup-result": "raise SystemExit(29)",
                "--restore-cleanup": """
original_snapshot = evidence_snapshot
reads = {}
def mutate_after_validated_read(path, expected=None):
    snapshot = original_snapshot(path, expected)
    if path.parent.name == 'evidence' and path.name in RECOVERY_EVIDENCE_NAMES:
        reads[path.name] = reads.get(path.name, 0) + 1
        (ROOT.parent / ('validated-' + path.name)).write_bytes(snapshot)
        path.write_bytes(b'changed after validated snapshot')
        (ROOT.parent / 'recovery-read-counts.json').write_text(json.dumps(reads))
    return snapshot
evidence_snapshot = mutate_after_validated_read
""",
            }
        )
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        counts = json.loads((self.root.parent / "recovery-read-counts.json").read_text())
        self.assertEqual(
            counts,
            dict.fromkeys(
                ("execution.json", "run_summary.json", "collection.ok", "collection-summary.json"),
                1,
            ),
        )
        directory = self.artifacts / "fuzz"
        for name in ("collection.ok", "collection-summary.json"):
            self.assertEqual(
                (directory / name).read_bytes(),
                (self.root.parent / ("validated-" + name)).read_bytes(),
            )
        summary = self.summary()
        original = json.loads((self.root.parent / "validated-run_summary.json").read_text())
        self.assertEqual(summary["targets"], original["targets"])
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["execution"]["cleanup_recovery"]["status"], "restored")
        self.assertEqual((self.root / "fuzz/corpus" / TARGETS[0] / "seed").read_bytes(), b"input")
        backup = next((directory / "cleanup-recovery").iterdir())
        for name in counts:
            self.assertEqual(
                (backup / "evidence" / name).read_bytes(), b"changed after validated snapshot"
            )
        self.assertTrue((backup / "backup-ready.json").is_file())

    def test_recovery_validates_both_collection_destinations_before_any_write(self):
        for name in ("collection.ok", "collection-summary.json"):
            with self.subTest(destination=name):
                shutil.rmtree(self.artifacts, ignore_errors=True)
                self.install_helper_hooks(
                    {
                        "--cleanup-result": "raise SystemExit(29)",
                        "--restore-cleanup": (
                            "directory = Path(sys.argv[sys.argv.index('--restore-cleanup') + 1])\n"
                            f"name = {name!r}\n"
                            "external = ROOT.parent / ('external-' + name)\n"
                            "external.write_bytes(b'external receipt preserved')\n"
                            "other = 'collection-summary.json' if name == 'collection.ok' "
                            "else 'collection.ok'\n"
                            "(directory / other).write_bytes(b'no partial restoration')\n"
                            "(directory / name).unlink()\n"
                            "os.link(external, directory / name)\n"
                        ),
                    }
                )
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                external = self.root.parent / ("external-" + name)
                self.assertEqual(external.read_bytes(), b"external receipt preserved")
                other = "collection-summary.json" if name == "collection.ok" else "collection.ok"
                self.assertEqual(
                    (self.artifacts / "fuzz" / other).read_bytes(), b"no partial restoration"
                )
                self.assertIn("fuzz evidence restoration failed", result.stderr)
                reports = list(
                    (self.artifacts / "fuzz/cleanup-recovery").glob("*/recovery-result-*.json")
                )
                self.assertEqual(len(reports), 1)
                report = json.loads(reports[0].read_text())
                self.assertEqual(report["status"], "failed")
                self.assertIn("evidence_error", report)
                self.assertEqual(report["cleanup_exit_code"], 0)
                self.assertTrue((reports[0].parent / "backup-ready.json").is_file())
                self.assertEqual(
                    (self.root / "fuzz/corpus" / TARGETS[0] / "seed").read_bytes(), b"input"
                )

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
        self.assertFalse((self.artifacts / "summary/security.log").exists())
        self.assertIn(
            "owned raw directory roots",
            result.stderr,
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
                    prior = self.saved_receipts()
                    link = alias_base / "fuzz"
                    link.symlink_to(target)
                    result = self.run_suite(aggregate=aggregate, CARGO_TARGET_DIR=str(alias_base))
                    link.unlink()
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("[security] fuzz evidence failed:", result.stderr)
                    self.assert_receipts_unchanged(prior)
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
                prior = self.saved_receipts()
                result = self.run_suite(CARGO_TARGET_DIR=str(base), FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("overlaps protected", result.stderr)
                self.assertFalse((self.root / "unsafe-removal-called").exists())
                self.assert_receipts_unchanged(prior)
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
                        prior = self.saved_receipts()
                        link = configured / "fuzz"
                        link.symlink_to(target)
                        result = self.run_suite(
                            aggregate=aggregate, CARGO_TARGET_DIR=str(configured)
                        )
                        link.unlink()
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn("overlaps protected", result.stderr)
                        self.assert_receipts_unchanged(prior)
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
                prior = self.saved_receipts()
                result = self.run_suite(CARGO_TARGET_DIR=str(configured))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("metadata pointer", result.stderr)
                self.assert_receipts_unchanged(prior)
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

    def test_fuzz_receipts_preserved_on_preflight_and_invalidated_on_bootstrap_failure(self):
        for failure in ("global-directory", "log-truncation", "global-log", "cargo-home"):
            for aggregate in (False, True):
                with self.subTest(failure=failure, aggregate=aggregate):
                    _, raw = self.seed_stale_results()
                    prior = self.saved_receipts()
                    self.bootstrap_failure(failure)
                    result = self.run_suite(aggregate=aggregate)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    if failure == "log-truncation":
                        self.assert_receipts_unchanged(prior)
                    else:
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


class SecurityFuzzPathDispatchTests(SecurityFuzzFixture):
    def test_explicit_and_modeled_default_cargo_home_cache_overlap_preserves_receipts(self):
        marker, _raw = self.seed_stale_results()
        previous = self.saved_receipts()
        cache = Path(self.env["CARGO_TARGET_DIR"]) / "fuzz"
        original_home = self.env.pop("CARGO_HOME")
        for kind, route in (
            ("equal", cache),
            ("descendant", cache / "cargo-home"),
            ("ancestor", cache.parent),
            ("default", cache / "modeled-home" / ".cargo"),
        ):
            with self.subTest(home_shape=kind):
                route.mkdir(parents=True, exist_ok=True)
                sentinel = route / "caller-owned-registry-sentinel"
                sentinel.write_bytes(b"owned registry fixture")
                environment = {"CARGO_HOME": str(route)}
                if kind == "default":
                    environment = {}
                    self.install_helper_hooks(
                        {
                            "--validate-preflight": (
                                "Path.home = classmethod(lambda cls: "
                                f"Path({str(route.parent)!r}))\n"
                            )
                        }
                    )
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0], **environment)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("overlaps", result.stderr)
                self.assert_receipts_unchanged(previous)
                self.assertEqual(self.calls(), [])
                self.assertEqual(sentinel.read_bytes(), b"owned registry fixture")
                self.assertTrue(marker.is_file())
        self.env["CARGO_HOME"] = original_home

    def test_explicit_and_modeled_default_cargo_home_aliases_preserve_receipts(self):
        self.seed_stale_results()
        previous = self.saved_receipts()
        self.env.pop("CARGO_HOME")
        external = Path(self.temporary) / "external-modeled-cargo-home"
        external.mkdir()
        sentinel = external / "preserved-registry-fixture"
        sentinel.write_bytes(b"owned home fixture")
        modeled_home = Path(self.temporary) / "modeled-home"
        modeled_home.mkdir()
        alias = modeled_home / ".cargo"
        alias.symlink_to(external, target_is_directory=True)
        for kind in ("explicit", "default"):
            with self.subTest(home_kind=kind):
                environment = {"CARGO_HOME": str(alias)} if kind == "explicit" else {}
                if kind == "default":
                    self.install_helper_hooks(
                        {
                            "--validate-preflight": (
                                "Path.home = classmethod(lambda cls: "
                                f"Path({str(modeled_home)!r}))\n"
                            )
                        }
                    )
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0], **environment)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("symlink components", result.stderr)
                for receipt in previous:
                    self.assertTrue(receipt.is_file(), "preflight invalidated the previous receipt")
                self.assert_receipts_unchanged(previous)
                self.assertEqual(self.calls(), [])
                self.assertEqual(list(external.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_bytes(), b"owned home fixture")
                self.assertTrue(alias.is_symlink())

    def test_selected_raw_target_directory_aliases_reject_before_execution_or_invalidation(self):
        marker, _raw = self.seed_stale_results()
        previous = self.saved_receipts()
        for name in ("corpus", "artifacts"):
            with self.subTest(raw_root=name):
                target = self.root / "fuzz" / name / TARGETS[0]
                shutil.rmtree(target)
                external = Path(self.temporary) / ("external-selected-" + name)
                external.mkdir()
                sentinel = external / "preserved-input"
                sentinel.write_bytes(b"external raw fixture")
                target.symlink_to(external, target_is_directory=True)
                result = self.run_suite("run-fail", FUZZ_TARGETS=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("symlink components", result.stderr)
                self.assert_receipts_unchanged(previous)
                self.assertEqual(self.calls(), [])
                self.assertEqual(list(external.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_bytes(), b"external raw fixture")
                self.assertTrue(target.is_symlink())
                self.assertTrue(marker.is_file())
                target.unlink()
                target.mkdir()

    def test_collect_only_selected_target_aliases_remain_inert_archive_entries(self):
        external = Path(self.temporary) / "external-collect-only"
        external.mkdir()
        sentinel = external / "private-input"
        sentinel.write_bytes(b"inert link fixture")
        for name in ("corpus", "artifacts"):
            base = self.root / "fuzz" / name
            base.mkdir()
            (base / TARGETS[0]).symlink_to(external, target_is_directory=True)
            (base / TARGETS[1]).mkdir()
            (base / TARGETS[1] / "owned").write_bytes(b"owned raw input")
        result = subprocess.run(  # noqa: S603 - actual collect-only helper and owned inert links
            [sys.executable, str(self.root / "scripts/fuzz/manage_fuzz_corpus.py")],
            cwd=self.root,
            env={
                **self.env,
                "FUZZ_RUN_ARTIFACT_DIR": str(self.artifacts / "fuzz"),
                "FUZZ_HISTORY_DIR": str(Path(self.temporary) / "history"),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        with tarfile.open(self.artifacts / "fuzz" / summary["corpus_archive"]) as archive:
            link = archive.getmember("corpus/" + TARGETS[0])
            self.assertTrue(link.issym())
            self.assertEqual(link.linkname, str(external))
            self.assertFalse(any("private-input" in name for name in archive.getnames()))
        with tarfile.open(self.artifacts / "fuzz" / summary["crash_archive"]) as archive:
            self.assertNotIn(TARGETS[0], archive.getnames())
            owned = archive.extractfile(TARGETS[1] + "/owned")
            self.assertIsNotNone(owned)
            self.assertEqual(owned.read(), b"owned raw input")
            self.assertFalse(any("private-input" in name for name in archive.getnames()))
        for name in ("corpus", "artifacts"):
            self.assertTrue((self.root / "fuzz" / name / TARGETS[0]).is_symlink())
            self.assertEqual(
                (self.root / "fuzz" / name / TARGETS[1] / "owned").read_bytes(),
                b"owned raw input",
            )
        self.assertEqual(sentinel.read_bytes(), b"inert link fixture")

    def test_empty_security_output_values_use_default_guards_before_invalidation(self):
        external = Path(self.temporary) / "default-output-external"
        external.mkdir()
        for variable, output, name in (
            ("SECURITY_ARTIFACT_DIR", "artifacts/security/latest", "summary/security.log"),
            ("SECURITY_HISTORY_DIR", "artifacts/security/history", "fuzz_runs.jsonl"),
        ):
            with self.subTest(empty_variable=variable):
                expected = self.root / "artifacts/security/latest/fuzz"
                expected.mkdir(parents=True, exist_ok=True)
                receipts = {}
                for filename in ("collection.ok", "execution.json", "run_summary.json"):
                    path = expected / filename
                    path.write_bytes(b"preserve previous default receipt")
                    receipts[path] = path.read_bytes()
                sentinel = external / variable
                sentinel.write_bytes(b"preserve default output sentinel")
                alias = self.root / output / name
                alias.parent.mkdir(parents=True, exist_ok=True)
                alias.symlink_to(sentinel)
                environment = {variable: ""}
                if variable == "SECURITY_HISTORY_DIR":
                    environment["SECURITY_ARTIFACT_DIR"] = ""
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0], **environment)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                for receipt in receipts:
                    self.assertTrue(receipt.is_file(), "preflight invalidated the previous receipt")
                self.assert_receipts_unchanged(receipts)
                self.assertEqual(sentinel.read_bytes(), b"preserve default output sentinel")
                self.assertEqual(self.calls(), [])
                alias.unlink()

    def test_relative_receipt_actions_pass_absolute_paths_to_every_dispatch_consumer(self):
        route = "action-evidence\n"
        expected = self.root / route
        observed = Path(self.temporary) / "action-dispatch.json"
        caller = self.root / "scripts"
        external = Path(self.temporary) / "external-action-route"
        external.mkdir()
        sentinel = external / "preserved"
        sentinel.write_bytes(b"external caller route")
        (caller / route).symlink_to(external, target_is_directory=True)
        actions = (
            ("--prepare-run", "prepare_run", []),
            ("--record-environment", "record_environment", []),
            ("--execution-cache", "execution_cache", []),
            ("--validate-cache", "configured_cache", []),
            ("--validate-preflight", "validate_preflight", []),
            ("--backup-cleanup", "backup_cleanup", []),
            ("--cleanup-cache", "cleanup_cache", ["00000000-0000-0000-0000-000000000001"]),
            ("--record-target", "record_target", [TARGETS[0], "run", "0"]),
            ("--finish-run", "finish_run", ["0"]),
            ("--cleanup-result", "cleanup_result", ["0"]),
            (
                "--restore-cleanup",
                "restore_cleanup",
                ["00000000-0000-0000-0000-000000000001", "1", "cleanup"],
            ),
        )
        for action, consumer, tail in actions:
            with self.subTest(action=action):
                code = (
                    "import json,pathlib,runpy,sys\n"
                    "h=runpy.run_path(sys.argv[1]); state=h['main'].__globals__\n"
                    "def consume(path,*args):\n"
                    f" pathlib.Path({str(observed)!r}).write_text(json.dumps({{"
                    "'absolute':path.is_absolute(),'path':str(path),'path_type':isinstance(path,pathlib.Path)}))\n"
                    " return path\n"
                    f"state[{consumer!r}]=consume\n"
                    "sys.argv=sys.argv[1:]\n"
                    "raise SystemExit(state['main']())\n"
                )
                result = subprocess.run(  # noqa: S603 - instrument only final consumers of actual CLI dispatch
                    [
                        sys.executable,
                        "-c",
                        code,
                        str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                        action,
                        route,
                        *tail,
                    ],
                    cwd=caller,
                    env=self.env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                record = json.loads(observed.read_text())
                self.assertTrue(record["absolute"])
                self.assertTrue(record["path_type"])
                self.assertEqual(record["path"], str(expected))
                self.assertEqual(sentinel.read_bytes(), b"external caller route")
                self.assertEqual(list(external.iterdir()), [sentinel])

    def test_relative_cleanup_result_updates_checked_receipts_and_preserves_caller_alias(self):
        self.artifacts = self.root / "artifacts/security/latest"
        self.env["SECURITY_ARTIFACT_DIR"] = str(self.artifacts)
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        backup, _manifest = self.assert_backup()
        directory = self.artifacts / "fuzz"
        for name in (
            "execution.json",
            "run_summary.json",
            "collection.ok",
            "collection-summary.json",
        ):
            (directory / name).write_bytes((backup / "evidence" / name).read_bytes())
        external = Path(self.temporary) / "external-caller-evidence"
        external.mkdir()
        shutil.copytree(self.root / "artifacts", external / "artifacts")
        preserved = {
            path: path.read_bytes()
            for path in (external / "artifacts/security/latest/fuzz").iterdir()
            if path.is_file()
        }
        caller = Path(self.temporary) / "caller"
        caller.mkdir()
        (caller / "artifacts").symlink_to(external / "artifacts", target_is_directory=True)
        updated = subprocess.run(  # noqa: S603 - actual receipt mutation through checked relative route
            [
                sys.executable,
                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                "--cleanup-result",
                "artifacts/security/latest/fuzz",
                "27",
            ],
            cwd=caller,
            env={**self.env, "FUZZ_TARGETS": TARGETS[0]},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        execution = json.loads((directory / "execution.json").read_text())
        self.assertEqual(execution["status"], "failed")
        self.assertEqual(execution["cleanup_exit_code"], 27)
        for path, content in preserved.items():
            self.assertEqual(path.read_bytes(), content)


class SecurityFuzzReceiptBoundaryTests(SecurityFuzzFixture):
    def test_source_inventory_rejects_external_hardlink_and_binds_regular_mode_bytes(self):
        path = self.root / "crates/server/src/lib.rs"
        original = path.read_bytes()
        original_mode = path.stat().st_mode & 0o777
        code = (
            "import runpy,sys,json\nh=runpy.run_path(sys.argv[1])\n"
            "value=h['local_source_inventory'](set(),h['kani_output_pointer']())\n"
            "print(json.dumps(value['crates/server/src/lib.rs']))\n"
        )
        result = self.helper_python(code)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {"type": "file", "mode": original_mode, "sha256": hashlib.sha256(original).hexdigest()},
        )
        external = self.root.parent / "external-source"
        external.write_bytes(b"external source preserved")
        path.unlink()
        os.link(external, path)
        result = self.helper_python(code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stable, unaliased regular file", result.stderr)
        self.assertEqual(external.read_bytes(), b"external source preserved")
        self.assertEqual(self.calls(), [])

    def test_source_inventory_rejects_open_and_read_replacements(self):
        path = self.root / "crates/server/src/lib.rs"
        original = path.read_bytes()
        external = self.root.parent / "external-source"
        external.write_bytes(b"external source preserved")
        for timing in ("open", "read"):
            for replacement in ("file", "symlink"):
                with self.subTest(timing=timing, replacement=replacement):
                    path.unlink()
                    path.write_bytes(original)
                    code = (
                        "import runpy,sys,os\nfrom pathlib import Path\n"
                        "h=runpy.run_path(sys.argv[1])\n"
                        "victim=h['ROOT']/'crates/server/src/lib.rs'\n"
                        f"external=Path({str(external)!r})\n"
                        f"timing={timing!r}\nreplacement={replacement!r}\n"
                        "def swap():\n"
                        " if replacement=='symlink':\n"
                        "  victim.unlink();victim.symlink_to(external)\n"
                        " else:\n"
                        "  pending=external.parent/'replacement-source'\n"
                        "  pending.write_bytes(b'replacement regular source')\n"
                        "  os.replace(pending,victim)\n"
                        "original_open=os.open\noriginal_fdopen=os.fdopen\n"
                        "def controlled_open(route,*args,**kwargs):\n"
                        " if Path(route)==victim and timing=='open': swap()\n"
                        " return original_open(route,*args,**kwargs)\n"
                        "class Reader:\n"
                        " def __init__(self,stream): self.stream=stream;self.changed=False\n"
                        " def __enter__(self): return self\n"
                        " def __exit__(self,*args): return self.stream.__exit__(*args)\n"
                        " def fileno(self): return self.stream.fileno()\n"
                        " def read(self,*args):\n"
                        "  content=self.stream.read(*args)\n"
                        "  if content and not self.changed:\n"
                        "   self.changed=True;swap()\n"
                        "  return content\n"
                        "def controlled_fdopen(fd,*args,**kwargs):\n"
                        " stream=original_fdopen(fd,*args,**kwargs)\n"
                        " info=os.fstat(fd);expected=victim.lstat()\n"
                        " if timing=='read' and (info.st_dev,info.st_ino)=="
                        "(expected.st_dev,expected.st_ino): return Reader(stream)\n"
                        " return stream\n"
                        "os.open=controlled_open;os.fdopen=controlled_fdopen\n"
                        "h['local_source_inventory'](set(),h['kani_output_pointer']())\n"
                    )
                    result = self.helper_python(code)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(external.read_bytes(), b"external source preserved")
                    self.assertEqual(self.calls(), [])

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

    def test_evidence_reads_reject_aliases_and_specials_while_tool_symlinks_are_supported(self):  # noqa: PLR0912 - bounded reader/alias matrix
        content = b"owned evidence snapshot"
        external = self.root.parent / "external-read-control"
        external.write_bytes(content)
        for action in ("digest", "evidence_snapshot", "evidence_text"):
            for kind in ("symlink", "hardlink", "fifo", "directory", "parent-symlink"):
                with self.subTest(reader=action, alias=kind):
                    folder = self.root.parent / (action + "-" + kind)
                    if kind == "parent-symlink":
                        folder.symlink_to(external.parent, target_is_directory=True)
                        path = folder / external.name
                    else:
                        folder.mkdir()
                        path = folder / "input"
                        if kind == "symlink":
                            path.symlink_to(external)
                        elif kind == "hardlink":
                            os.link(external, path)
                        elif kind == "fifo":
                            os.mkfifo(path)
                        else:
                            path.mkdir()
                    result = self.helper_python(
                        "import pathlib,runpy,sys\n"
                        "h=runpy.run_path(sys.argv[1])\n"
                        f"try: h[{action!r}](pathlib.Path({str(path)!r}))\n"
                        "except (ValueError,OSError): pass\n"
                        "else: raise RuntimeError('aliased evidence read succeeded')\n"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(external.read_bytes(), content)
                    if kind == "hardlink":
                        path.unlink()
        result = self.helper_python(
            "import hashlib,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1])\n"
            f"path=pathlib.Path({str(external)!r}); expected={content!r}\n"
            "if h['digest'](path)!=hashlib.sha256(expected).hexdigest(): raise "
            "RuntimeError('digest')\n"
            "if h['evidence_snapshot'](path)!=expected: raise RuntimeError('snapshot')\n"
            "if h['evidence_text'](path)!=expected.decode('utf-8'): raise RuntimeError('text')\n"
            "link=path.parent/'intentional-tool-alias'; link.symlink_to(path)\n"
            "if h['tool_digest'](link)!=hashlib.sha256(expected).hexdigest(): raise "
            "RuntimeError('tool alias')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def compiled_control(self, body, label):
        directory = self.root.parent / ("compiled-control-" + label)
        directory.mkdir()
        base = directory / "cargo-target"
        code = (
            "import hashlib,os,pathlib,runpy,sys\nfrom unittest.mock import patch\n"
            "h=runpy.run_path(sys.argv[1])\n"
            f"directory=pathlib.Path({str(directory)!r})\n"
            f"name={TARGETS[0]!r}; triple='x86_64-unknown-linux-gnu'\n"
            "evidence=directory/'evidence/fuzz'; cache=directory/'cargo-target/fuzz'\n"
            "binary=cache/triple/'release'/name; binary.parent.mkdir(parents=True)\n"
            "original=b'owned compiled artifact bytes'; binary.write_bytes(original)\n"
            "binary.chmod(0o755); deps=binary.parent/'deps'; deps.mkdir()\n"
            "peer=deps/(name.replace('-','_')+'-0123456789abcdef')\n"
            "data={'target_dir':str(cache),'target_triple':triple,'selected_targets':[name]}\n"
        )
        return self.helper_python(code + body, FUZZ_TARGETS=TARGETS[0], CARGO_TARGET_DIR=str(base))

    def test_compiled_artifacts_admit_only_accounted_owned_cargo_peers(self):
        for links in (1, 2):
            with self.subTest(owned_links=links):
                result = self.compiled_control(
                    ("os.link(binary,peer)\n" if links == 2 else "")
                    + "value=h['compiled_artifact_digest'](evidence,data,name,binary)\n"
                    "if value!=hashlib.sha256(original).hexdigest(): "
                    "raise RuntimeError('artifact digest')\n"
                    + (
                        "try: h['digest'](binary)\n"
                        "except ValueError: pass\n"
                        "else: raise RuntimeError('generic evidence accepted a Cargo hardlink')\n"
                        if links == 2
                        else "if h['digest'](binary)!=value: "
                        "raise RuntimeError('singlelink digest')\n"
                    ),
                    "owned-" + str(links),
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_compiled_artifacts_reject_foreign_graphs_and_tainted_record_paths(self):
        cases = {
            "external-extra": "os.link(binary,peer); os.link(binary,directory/'external')",
            "wrong-name": "os.link(binary,deps/'other_target-0123456789abcdef')",
            "wrong-hash": "os.link(binary,deps/(name+'-short-hash'))",
            "missing-peer": "os.link(binary,directory/'unaccounted')",
            "symlink-binary": (
                "binary.rename(directory/'saved'); binary.symlink_to(directory/'saved')"
            ),
            "symlink-peer": (
                "os.link(binary,directory/'saved-peer'); peer.symlink_to(directory/'saved-peer')"
            ),
            "parent-alias": (
                "deps.rename(directory/'saved-deps'); deps.symlink_to(directory/'saved-deps')"
            ),
            "mode": "binary.chmod(0o644)",
            "special": "binary.unlink(); os.mkfifo(binary)",
            "cache-mismatch": "data['target_dir']=str(directory/'other-cache')",
            "target-mismatch": "data['target_triple']='unmodeled-target'",
            "unselected-name": "data['selected_targets']=[]",
            "record-route": (
                "other=directory/'other-executable'; other.write_bytes(original); "
                "other.chmod(0o755); binary=other"
            ),
        }
        for label, mutation in cases.items():
            with self.subTest(rejected_graph=label):
                result = self.compiled_control(
                    mutation + "\ntry: h['compiled_artifact_digest'](evidence,data,name,binary)\n"
                    "except (ValueError,OSError): pass\n"
                    "else: raise RuntimeError('untrusted compiled artifact admitted')\n",
                    label,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        result = self.compiled_control(
            r"""
original_lstat=pathlib.Path.lstat
def foreign_owner(path,*args,**kwargs):
    info=original_lstat(path,*args,**kwargs)
    if path==binary:
        fields=list(info); fields[4]=os.geteuid()+1
        return os.stat_result(fields)
    return info
with patch.object(pathlib.Path,'lstat',new=foreign_owner):
    try: h['compiled_artifact_digest'](evidence,data,name,binary)
    except ValueError: pass
    else: raise RuntimeError('foreign compiled artifact owner admitted')
""",
            "foreign-owner",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_compiled_artifact_descriptor_and_peer_mutations_reject_before_return(self):
        for timing in ("open", "read"):
            for mutation in (
                "contents",
                "mode",
                "replacement",
                "peer-replacement",
                "peer-removal",
                "extra-peer",
                "parent-alias",
            ):
                with self.subTest(timing=timing, mutation=mutation):
                    result = self.compiled_control(
                        f"timing={timing!r}; mutation={mutation!r}\n"
                        r"""
os.link(binary,peer)
changed=False
def mutate():
    global changed
    if changed: return
    changed=True
    if mutation=='contents': binary.write_bytes(b'changed artifact contents')
    elif mutation=='mode': binary.chmod(0o600)
    elif mutation=='replacement':
        other=directory/'replacement'; other.write_bytes(original); other.chmod(0o755)
        other.replace(binary)
    elif mutation=='peer-replacement':
        peer.unlink(); peer.write_bytes(original); peer.chmod(0o755)
    elif mutation=='peer-removal': peer.unlink()
    elif mutation=='extra-peer': os.link(binary,directory/'external')
    else:
        deps.rename(directory/'saved-deps'); deps.symlink_to(directory/'saved-deps')
original_open=os.open
original_fdopen=os.fdopen
identity=(binary.stat().st_dev,binary.stat().st_ino)
def controlled_open(path,*args,**kwargs):
    descriptor=original_open(path,*args,**kwargs)
    if pathlib.Path(path)==binary and timing=='open': mutate()
    return descriptor
class Reader:
    def __init__(self,stream): self.stream=stream
    def __enter__(self): return self
    def __exit__(self,*args): return self.stream.__exit__(*args)
    def fileno(self): return self.stream.fileno()
    def read(self,*args):
        content=self.stream.read(*args)
        if content and timing=='read': mutate()
        return content
def controlled_fdopen(fd,*args,**kwargs):
    stream=original_fdopen(fd,*args,**kwargs)
    info=os.fstat(fd)
    return Reader(stream) if (info.st_dev,info.st_ino)==identity else stream
with (
    patch.object(os,'open',side_effect=controlled_open),
    patch.object(os,'fdopen',side_effect=controlled_fdopen),
):
    try: h['compiled_artifact_digest'](evidence,data,name,binary)
    except (ValueError,OSError): pass
    else: raise RuntimeError('mutated artifact or peer returned a digest')
""",
                        timing + "-" + mutation,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_cargo_output_peers_are_recorded_and_readmitted_before_cleanup(self):
        cargo = CARGO.replace(
            "binary.chmod(0o755)",
            "binary.chmod(0o755)\n"
            "        peer=binary.parent/'deps'/(target.replace('-','_')+'-0123456789abcdef')\n"
            "        peer.parent.mkdir(exist_ok=True)\n"
            "        os.link(binary,peer)",
        )
        self.install("cargo", cargo)
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row = self.summary()["execution"]["targets"][0]
        self.assertEqual(row["build"]["executable_sha256"], row["run"]["executable_sha256"])
        self.assertEqual(row["run"]["status"], "passed")
        shutil.rmtree(self.artifacts)
        self.install_helper_hooks(
            {
                "--finish-run": """
directory=Path(sys.argv[sys.argv.index('--finish-run')+1])
data=load_execution(directory)
binary=Path(data['target_dir'])/data['target_triple']/'release'/data['selected_targets'][0]
os.link(binary,ROOT.parent/'external-compiled-artifact')
"""
            }
        )
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "compiled artifact",
            (self.artifacts / "summary/security.log").read_text(),
        )
        self.assertTrue((self.root / "fuzz/corpus" / TARGETS[0] / "seed").is_file())
        self.assertFalse(list(self.artifacts.glob("fuzz/cleanup-recovery/*/backup-ready.json")))

    def test_evidence_read_mutations_cannot_return_hash_or_snapshot(self):
        for action in ("digest", "evidence_snapshot", "evidence_text"):
            for mutation in ("overwrite", "replacement", "hardlink", "mode", "parent-alias"):
                with self.subTest(reader=action, mutation=mutation):
                    folder = self.root.parent / ("mutation-" + action + "-" + mutation)
                    folder.mkdir()
                    path = folder / "input"
                    path.write_bytes(b"original stable bytes")
                    result = self.helper_python(
                        "import os,pathlib,runpy,sys\nfrom unittest.mock import patch\n"
                        "h=runpy.run_path(sys.argv[1]); original_fdopen=os.fdopen\n"
                        f"victim=pathlib.Path({str(path)!r}); mutation={mutation!r}\n"
                        "class Reader:\n"
                        " def __init__(self,stream): self.stream=stream; self.changed=False\n"
                        " def __enter__(self): return self\n"
                        " def __exit__(self,*args): return self.stream.__exit__(*args)\n"
                        " def fileno(self): return self.stream.fileno()\n"
                        " def read(self,*args):\n"
                        "  content=self.stream.read(*args)\n"
                        "  if not self.changed:\n"
                        "   self.changed=True\n"
                        "   if mutation=='overwrite': victim.write_bytes(b'changed contents')\n"
                        "   elif mutation=='replacement':\n"
                        "    other=victim.parent/'replacement'; "
                        "other.write_bytes(b'original stable bytes'); "
                        "other.replace(victim)\n"
                        "   elif mutation=='hardlink': os.link(victim,victim.parent/'alias')\n"
                        "   elif mutation=='mode': victim.chmod(0o600)\n"
                        "   else:\n"
                        "    parent=victim.parent; moved=parent.with_name(parent.name+'-moved')\n"
                        "    parent.rename(moved); parent.symlink_to(moved,"
                        "target_is_directory=True)\n"
                        "  return content\n"
                        "def fdopen(fd,*args,**kwargs): return Reader(original_fdopen(fd,"
                        "*args,**kwargs))\n"
                        "with patch.object(os,'fdopen',side_effect=fdopen):\n"
                        f" try: h[{action!r}](victim)\n"
                        " except ValueError: pass\n"
                        " else: raise RuntimeError('unstable evidence returned a value')\n"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_target_completion_and_log_digest_use_one_validated_snapshot(self):
        result = self.helper_python(
            "import hashlib,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); state=h['record_target'].__globals__\n"
            "directory=h['ROOT'].parent/'record-control'; directory.mkdir()\n"
            f"name={TARGETS[0]!r}; triple='x86_64-unknown-linux-gnu'\n"
            "cache=directory/'cache'; binary=cache/triple/'release'/name\n"
            "binary.parent.mkdir(parents=True); binary.write_bytes(b'owned executable'); "
            "binary.chmod(0o755)\n"
            "log=directory/name/'run.log'; log.parent.mkdir(); original=b'Done 100 runs "
            "in 30 second(s)\\n'\n"
            "log.write_bytes(original); "
            "binary_hash=hashlib.sha256(binary.read_bytes()).hexdigest()\n"
            "data={'target_dir':str(cache),'target_triple':triple,'watchdog_seconds':60,"
            "'internal_seconds':30,\n"
            " 'targets':[{'name':name,'build':{'status':'passed',"
            "'executable_sha256':binary_hash}}]}\n"
            "state['load_execution']=lambda directory:data\n"
            "data['selected_targets']=[name]; state['configured_cache']=lambda directory:cache\n"
            "actual=state['evidence_snapshot']; calls=[]\n"
            "def read_then_mutate(path,expected=None):\n"
            " snapshot=actual(path,expected)\n"
            " if path==log: calls.append(str(path)); path.write_bytes(b'no completion in "
            "later pathname')\n"
            " return snapshot\n"
            "state['evidence_snapshot']=read_then_mutate\n"
            "if not h['record_target'](directory,name,'run',0): raise "
            "RuntimeError('snapshot completion rejected')\n"
            "record=data['targets'][0]['run']\n"
            "if calls!=[str(log)]: raise RuntimeError('log was read more than once')\n"
            "if record['log_sha256']!=hashlib.sha256(original).hexdigest(): raise "
            "RuntimeError('different digest bytes')\n"
            "if record['completed_runs']!=100 or record['reported_seconds']!=30: raise "
            "RuntimeError('different completion bytes')\n"
            "try: h['validate_phase'](directory,data['targets'][0],'run')\n"
            "except ValueError: pass\n"
            "else: raise RuntimeError('later changed log was admitted')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_execution_and_collection_json_reads_reject_receipt_aliases(self):
        for name in (
            "execution.json",
            "run_summary.json",
            "collection.ok",
            "collection-summary.json",
        ):
            for kind in ("symlink", "hardlink"):
                with self.subTest(receipt=name, alias=kind):
                    result = self.helper_python(
                        "import json,os,pathlib,runpy,sys\n"
                        "h=runpy.run_path(sys.argv[1]); state=h['load_execution'].__globals__\n"
                        f"name={name!r}; kind={kind!r}\n"
                        "directory=h['ROOT'].parent/(name+'-'+kind); directory.mkdir()\n"
                        "data={'run_id':'fixture'}; summary={'execution':data}\n"
                        "for receipt in ('run_summary.json','collection-summary.json',"
                        "'collection.ok'):\n"
                        " (directory/receipt).write_text(json.dumps(summary))\n"
                        "external=directory/'external'; external.write_text(json.dumps(summary))\n"
                        "path=directory/name; path.unlink(missing_ok=True)\n"
                        "if kind=='symlink': path.symlink_to(external)\n"
                        "else: os.link(external,path)\n"
                        "state['validate_compiler_environment']=lambda:None\n"
                        "if name!='execution.json': state['load_execution']=lambda directory:data\n"
                        "try:\n"
                        " if name=='execution.json': h['load_execution'](directory)\n"
                        " else: h['collected_execution'](directory)\n"
                        "except (ValueError,OSError): pass\n"
                        "else: raise RuntimeError('receipt alias was admitted')\n"
                        "if external.read_text()!=json.dumps(summary): raise "
                        "RuntimeError('external receipt changed')\n"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_target_record_rejects_aliased_log_and_executable(self):
        for selected in ("log", "executable"):
            for kind in ("symlink", "hardlink"):
                with self.subTest(evidence=selected, alias=kind):
                    result = self.helper_python(
                        "import os,pathlib,runpy,sys\n"
                        "h=runpy.run_path(sys.argv[1]); state=h['record_target'].__globals__\n"
                        f"selected={selected!r}; kind={kind!r}; name={TARGETS[0]!r}\n"
                        "directory=h['ROOT'].parent/(selected+'-'+kind); directory.mkdir()\n"
                        "cache=directory/'cache'; triple='x86_64-unknown-linux-gnu'\n"
                        "binary=cache/triple/'release'/name; binary.parent.mkdir(parents=True)\n"
                        "binary.write_bytes(b'owned executable'); binary.chmod(0o755)\n"
                        "log=directory/name/'build.log'; log.parent.mkdir(); "
                        "log.write_bytes(b'build complete')\n"
                        "external=directory/'external'; external.write_bytes(b'external "
                        "bytes remain private'); external.chmod(0o755)\n"
                        "path=log if selected=='log' else binary; path.unlink()\n"
                        "if kind=='symlink': path.symlink_to(external)\n"
                        "else: os.link(external,path)\n"
                        "data={'target_dir':str(cache),'target_triple':triple,"
                        "'targets':[{'name':name}]}\n"
                        "state['load_execution']=lambda directory:data\n"
                        "data['selected_targets']=[name]\n"
                        "state['configured_cache']=lambda directory:cache\n"
                        "try: passed=h['record_target'](directory,name,'build',0)\n"
                        "except (ValueError,OSError): passed=False\n"
                        "if passed: raise RuntimeError('aliased target evidence passed')\n"
                        "if external.read_bytes()!=b'external bytes remain private': "
                        "raise RuntimeError('external bytes changed')\n"
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_upload_archive_digest_rejects_late_hardlink_before_manifest_publication(self):
        result = self.helper_python(
            "import os,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); state=h['package_upload'].__globals__\n"
            "source=h['ROOT']/'artifacts/security/latest'; source.mkdir(parents=True)\n"
            "(source/'input').write_bytes(b'owned upload evidence')\n"
            "output=h['ROOT']/'artifacts/upload-control'; actual=state['upload_inventory']\n"
            "calls=0; alias=h['ROOT'].parent/'late-upload-alias'\n"
            "def alias_before_publication():\n"
            " global calls\n"
            " calls+=1; inventory=actual()\n"
            " if calls==2:\n"
            "  temporary=next(output.glob('.archive-*')); os.link(temporary,alias)\n"
            " return inventory\n"
            "state['upload_inventory']=alias_before_publication\n"
            "try: h['package_upload'](output)\n"
            "except ValueError: pass\n"
            "else: raise RuntimeError('hardlinked upload archive passed')\n"
            "if (output/'manifest.json').exists(): raise RuntimeError('invalid upload "
            "manifest published')\n"
            "if (output/'security-evidence.tar.gz').exists(): raise "
            "RuntimeError('aliased archive published')\n"
            "if not alias.is_file() or alias.stat().st_nlink!=1: raise "
            "RuntimeError('held alias was removed or own temporary leaked')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_whole_cargo_target_sibling_overlaps_preserve_previous_evidence(self):
        base = Path(self.temporary) / "aggregate-target"
        for role in ("evidence", "history", "cargo-home", "git-metadata"):
            with self.subTest(protected_role=role):
                self.artifacts = Path(self.temporary) / "artifacts"
                environment = {"CARGO_TARGET_DIR": str(base)}
                protected = base / role
                protected.mkdir(parents=True, exist_ok=True)
                sentinel = protected / "owned-sentinel"
                sentinel.write_bytes(b"preserve protected sibling")
                if role == "evidence":
                    self.artifacts = protected
                    environment["SECURITY_ARTIFACT_DIR"] = str(protected)
                elif role == "history":
                    environment["SECURITY_HISTORY_DIR"] = str(protected)
                elif role == "cargo-home":
                    environment["CARGO_HOME"] = str(protected)
                else:
                    (self.root / ".git").write_text("gitdir: " + str(protected) + "\n")
                self.seed_stale_results()
                prior = self.saved_receipts()
                result = self.run_suite(aggregate=True, FUZZ_TARGETS=TARGETS[0], **environment)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("overlaps protected", result.stderr)
                self.assert_receipts_unchanged(prior)
                self.assertEqual(sentinel.read_bytes(), b"preserve protected sibling")
                self.assertEqual(self.calls(), [])
                self.assertFalse((self.artifacts / "summary/security.log").exists())
                if role == "git-metadata":
                    (self.root / ".git").unlink()

    def test_cargo_fuzz_aliases_reject_before_execution_or_receipt_invalidation(self):
        config = self.root / ".cargo/config.toml"
        original = config.read_text()
        self.seed_stale_results()
        prior = self.saved_receipts()
        for kind, value in (
            ("environment", ""),
            ("environment", "unsupported-dispatch"),
            ("config", '""'),
            ("config", '"unsupported-dispatch"'),
            ("config", '["unsupported-dispatch"]'),
        ):
            for aggregate in (False, True):
                with self.subTest(alias_origin=kind, empty=value == "", aggregate=aggregate):
                    environment = {"CARGO_ALIAS_FUZZ": value} if kind == "environment" else {}
                    if kind == "config":
                        config.write_text(
                            original.replace("[alias]", "[alias]\nfuzz = " + value, 1)
                            if "[alias]" in original
                            else original + "\n[alias]\nfuzz = " + value + "\n"
                        )
                    result = self.run_suite(aggregate=aggregate, **environment)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assert_receipts_unchanged(prior)
                    self.assertEqual(self.calls(), [])
                    self.assertFalse((self.artifacts / "summary/security.log").exists())
                    config.write_text(original)

    def test_unrelated_cargo_alias_preserves_supported_execution(self):
        self.env.pop("CARGO_ALIAS_FUZZ", None)
        config = self.root / ".cargo/config.toml"
        original = config.read_text()
        entry = 'xtask_control = "check"'
        config.write_text(
            original.replace("[alias]", "[alias]\n" + entry, 1)
            if "[alias]" in original
            else original + "\n[alias]\n" + entry + "\n"
        )
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0], CARGO_ALIAS_XTASK_CONTROL="check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary()["execution"]["status"], "passed")

    def test_evidence_scan_errors_and_missing_entries_cannot_complete_packaging(self):
        source = self.root / "artifacts/security/latest"
        nested = source / "nested"
        nested.mkdir(parents=True)
        (nested / "owned-input").write_bytes(b"owned evidence")
        output = self.root / "artifacts/upload-control"
        for action in ("inventory", "package", "missing-root"):
            with self.subTest(action=action):
                result = self.helper_python(
                    "import os,pathlib,runpy,sys\nfrom unittest.mock import patch\n"
                    "h=runpy.run_path(sys.argv[1]); actual=os.scandir\n"
                    f"source=pathlib.Path({str(source)!r}); nested=source/'nested'\n"
                    "def blocked(path):\n"
                    " if pathlib.Path(path)==nested:\n"
                    "  raise PermissionError('controlled scan failure')\n"
                    " return actual(path)\n"
                    "with patch.object(os,'scandir',side_effect=blocked):\n"
                    " try:\n"
                    + {
                        "inventory": "  h['raw_inventory'](source)\n",
                        "package": f"  h['package_upload'](pathlib.Path({str(output)!r}))\n",
                        "missing-root": "  h['raw_inventory'](source/'missing-root')\n",
                    }[action]
                    + " except OSError: pass\n"
                    " else: raise RuntimeError('incomplete evidence was admitted')\n"
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(output.exists())

    def test_replaced_evidence_file_rejects_opened_descriptor_identity(self):
        source = self.root / "fuzz/corpus"
        source.mkdir()
        entry = source / "input"
        entry.write_bytes(b"owned evidence")
        result = self.helper_python(
            "import os,pathlib,runpy,sys\nfrom unittest.mock import patch\n"
            "h=runpy.run_path(sys.argv[1]); actual=os.open\n"
            f"source=pathlib.Path({str(source)!r}); entry=source/'input'\n"
            "def replace_after_open(path,*args,**kwargs):\n"
            " descriptor=actual(path,*args,**kwargs)\n"
            " if pathlib.Path(path)==entry:\n"
            "  replacement=source/'replacement'; replacement.write_bytes(b'owned evidence')\n"
            "  replacement.replace(entry)\n"
            " return descriptor\n"
            "with patch.object(os,'open',side_effect=replace_after_open):\n"
            " try: h['raw_inventory'](source)\n"
            " except ValueError: pass\n"
            " else: raise RuntimeError('replaced evidence was admitted')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_external_hardlinks_reject_before_inventory_hashing(self):
        outside = Path(self.temporary) / "external-input"
        outside.write_bytes(b"external hardlink fixture")
        for relative in (
            "fuzz/corpus/input",
            "artifacts/security/latest/nested/input",
            "security-artifacts/security_status.jsonl",
        ):
            for action in ("raw", "upload"):
                with self.subTest(relative=relative, inventory=action):
                    entry = self.root / relative
                    entry.parent.mkdir(parents=True, exist_ok=True)
                    os.link(outside, entry)
                    result = self.helper_python(
                        "import hashlib,pathlib,runpy,sys\nfrom unittest.mock import patch\n"
                        "h=runpy.run_path(sys.argv[1])\n"
                        "failure=RuntimeError('hash started')\n"
                        "with patch.object(hashlib,'sha256',side_effect=failure):\n"
                        " try:\n"
                        + (
                            f"  h['raw_inventory'](pathlib.Path({str(entry.parent)!r}))\n"
                            if action == "raw"
                            else "  h['upload_inventory']()\n"
                        )
                        + " except ValueError: pass\n"
                        " else: raise RuntimeError('hardlink was admitted')\n"
                    )
                    entry.unlink()
                    self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside.read_bytes(), b"external hardlink fixture")

    def test_late_external_hardlinks_reject_before_copy_or_archive_content(self):
        source = self.root / "fuzz/corpus"
        source.mkdir()
        entry = source / "input"
        entry.write_bytes(b"owned evidence")
        outside = Path(self.temporary) / "external-input"
        outside.write_bytes(b"external hardlink fixture")
        recovery = self.artifacts / "recovery"
        recovery.mkdir(parents=True)
        result = self.helper_python(
            "import os,pathlib,runpy,sys,shutil\nfrom unittest.mock import patch\n"
            "h=runpy.run_path(sys.argv[1]); actual=shutil.copytree\n"
            f"entry=pathlib.Path({str(entry)!r}); outside=pathlib.Path({str(outside)!r})\n"
            "def replace_before_copy(*args,**kwargs):\n"
            " entry.unlink(); os.link(outside,entry)\n"
            " return actual(*args,**kwargs)\n"
            "with patch.object(shutil,'copytree',side_effect=replace_before_copy):\n"
            f" try: h['copy_raw_backups'](pathlib.Path({str(recovery)!r}))\n"
            " except ValueError: pass\n"
            " else: raise RuntimeError('hardlink copy was admitted')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((recovery / "raw/corpus/input").exists())
        result = self.helper_python(
            "import io,pathlib,runpy,sys,tarfile\nfrom unittest.mock import patch\n"
            "h=runpy.run_path(sys.argv[1])\n"
            "with tarfile.open(fileobj=io.BytesIO(),mode='w') as archive:\n"
            " with patch.object(archive,'addfile') as addfile:\n"
            f"  try: h['add_upload_entry'](archive,pathlib.Path({str(entry)!r}),"
            f"{{'type':'file','sha256':{hashlib.sha256(b'owned evidence').hexdigest()!r}}})\n"
            "  except ValueError: pass\n"
            "  else: raise RuntimeError('hardlink archive was admitted')\n"
            "  if addfile.called: raise RuntimeError('hardlink archive content was read')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside.read_bytes(), b"external hardlink fixture")

    def test_in_repository_canonical_cache_alias_is_excluded_from_both_snapshots(self):
        base = self.root / "fuzz/target"
        base.mkdir()
        cache = self.root / "build-cache"
        cache.mkdir()
        (base / "fuzz").symlink_to(cache, target_is_directory=True)
        sibling = self.root / "build-cache-sibling"
        sibling.mkdir()
        (sibling / "owned-input").write_bytes(b"bound local input")
        result = self.run_suite(CARGO_TARGET_DIR=str(base), FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        execution = self.summary()["execution"]
        self.assertEqual(execution["target_dir"], str(cache))
        self.assertFalse(
            any(name.startswith("build-cache/") for name in execution["source"]["files"])
        )
        self.assertNotIn("build-cache", execution["source"]["files"])
        self.assertIn("build-cache-sibling/owned-input", execution["source"]["files"])
        self.assertEqual(execution["status"], "passed")
        self.assertFalse(cache.exists())
        self.assertTrue((base / "fuzz").is_symlink())

    def test_prepare_run_git_identity_uses_root_from_foreign_or_noncheckout_cwd(self):
        self.install(
            "git",
            "import os,pathlib,sys\n"
            "args=sys.argv[1:]; root=pathlib.Path(os.environ['FIXTURE_ROOT'])\n"
            "selected=pathlib.Path(args[1]) if args[:1]==['-C'] else pathlib.Path.cwd()\n"
            "if selected==root: print('1'*40 if args[-1]=='HEAD' else '2'*40)\n"
            "elif (selected/'.git').exists(): print('3'*40)\n"
            "else: raise SystemExit(128)\n",
        )
        for kind in ("foreign-checkout", "outside-checkout"):
            with self.subTest(caller=kind):
                caller = Path(self.temporary) / kind
                caller.mkdir()
                if kind == "foreign-checkout":
                    (caller / ".git").mkdir()
                directory = self.artifacts / "fuzz"
                directory.mkdir(parents=True, exist_ok=True)
                result = subprocess.run(  # noqa: S603 - fixed helper, controlled Git and owned cwd
                    [
                        sys.executable,
                        str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                        "--prepare-run",
                        str(directory),
                    ],
                    cwd=caller,
                    env={**self.env, "FUZZ_TARGETS": TARGETS[0]},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                source = json.loads((directory / "execution.json").read_text())["source"]
                self.assertEqual(source["commit"]["output"], "1" * 40 + "\n")
                self.assertEqual(source["tree"]["output"], "2" * 40 + "\n")
                self.assertEqual(source["commit"]["exit_code"], 0)
                self.assertEqual(source["tree"]["exit_code"], 0)

    def test_raw_corpus_and_crash_archives_reject_hardlinks_before_content(self):
        outside = Path(self.temporary) / "external-input"
        outside.write_bytes(b"external hardlink fixture")
        for action in ("corpus", "crash"):
            with self.subTest(raw_archive=action):
                source = self.root / "fuzz" / ("corpus" if action == "corpus" else "artifacts")
                entry = source / TARGETS[0] / "input"
                entry.parent.mkdir(parents=True)
                os.link(outside, entry)
                result = self.helper_python(
                    "import pathlib,runpy,sys,tarfile\nfrom unittest.mock import patch\n"
                    "h=runpy.run_path(sys.argv[1]); actual=tarfile.TarFile.addfile\n"
                    "content_calls=[]\n"
                    "def record(tar,info,content=None):\n"
                    " if content is not None: content_calls.append(info.name)\n"
                    " return actual(tar,info,content)\n"
                    "with patch.object(tarfile.TarFile,'addfile',new=record):\n"
                    " try:\n"
                    + (
                        "  h['create_archive']()\n"
                        if action == "corpus"
                        else "  h['archive_crashes'](h['gather_crash_stats'](),None)\n"
                    )
                    + " except ValueError: pass\n"
                    " else: raise RuntimeError('raw hardlink archive was admitted')\n"
                    "if content_calls: raise "
                    "RuntimeError('external raw archive content was read')\n"
                )
                entry.unlink()
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside.read_bytes(), b"external hardlink fixture")

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
            if name != ".cargo/config.toml":
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
        for kind in ("file", "changed-target"):
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
                if name == "LOCAL_TOOL":
                    self.assertIn("build environment references", result.stderr)
                else:
                    self.assertIn(
                        f"inherited {name} override is not supported for fuzz execution or cleanup",
                        result.stderr,
                    )

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
    def test_build_tool_aliases_admit_same_tools_and_reject_empty_or_split_overrides(self):
        selected = {
            "CC_FOR_BUILD": self.bin / "cc",
            "CXX_FOR_BUILD": self.bin / "c++",
            "AR_FOR_BUILD": self.bin / "ar",
        }
        for route in ("same-path", "resolved-path", "symlink"):
            with self.subTest(valid_route=route):
                environment = {}
                for name, path in selected.items():
                    routed = path
                    if route == "resolved-path":
                        routed = path.resolve()
                    elif route == "symlink":
                        alias = self.bin / ("selected-" + name.lower())
                        alias.symlink_to(path)
                        routed = alias
                    environment[name] = str(routed)
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0], **environment)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.summary()["status"], "passed")
        self.seed_stale_results()
        receipts = self.saved_receipts()
        calls = self.calls()
        called = self.root.parent / "unselected-build-tool-called"
        alternate = self.bin / "alternate-build-tool"
        alternate.write_text(
            f"#!{sys.executable}\nimport pathlib\npathlib.Path({str(called)!r}).touch()\n"
        )
        alternate.chmod(0o755)
        for name in selected:
            for value in ("", str(alternate)):
                with self.subTest(invalid_alias=name, empty=value == ""):
                    environment = {key: str(path) for key, path in selected.items()}
                    environment[name] = value
                    result = self.run_suite(FUZZ_TARGETS=TARGETS[0], **environment)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("override differs from effective supported tool", result.stderr)
                    self.assertFalse(called.exists())
                    self.assertEqual(self.calls(), calls)
                    self.assert_receipts_unchanged(receipts)

    def test_handled_wasi_compilers_clear_before_selected_and_default_preflight(self):
        marker, raw = self.seed_stale_results()
        previous = self.saved_receipts()
        admitted = Path(self.temporary) / "native-preflight.json"
        self.install_helper_hooks(
            {
                "--validate-preflight": (
                    "import json,os,sys\n"
                    "validate_preflight(Path(sys.argv[-1]))\n"
                    f"Path({str(admitted)!r}).write_text(json.dumps({{"
                    "'cc_cleared': 'CC' not in os.environ, "
                    "'cxx_cleared': 'CXX' not in os.environ, "
                    "'native': effective_native_commands()}))\n"
                    "raise SystemExit(37)\n"
                )
            }
        )
        for aggregate in (False, True):
            with self.subTest(default_dispatch=aggregate):
                if admitted.exists():
                    admitted.unlink()
                result = self.run_suite(
                    aggregate=aggregate,
                    CC="/handled/wasm32-unknown-wasi/bin/clang",
                    CXX="/handled/wasm32-unknown-wasi/bin/clang++",
                )
                # The wrapper normalizes our intentional helper stop to exit1.
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertTrue(admitted.is_file(), result.stdout + result.stderr)
                observation = json.loads(admitted.read_text())
                self.assertTrue(observation["cc_cleared"])
                self.assertTrue(observation["cxx_cleared"])
                self.assertEqual(
                    observation["native"],
                    {"cc": "cc", "cxx": "c++", "linker": "cc", "ar": "ar"},
                )
                self.assert_receipts_unchanged(previous)
                self.assertTrue(marker.is_file())
                for path, content in raw.items():
                    self.assertEqual(path.read_bytes(), content)
                self.assertEqual(self.calls(), [])

    def test_handled_wasi_compilers_use_bound_native_tools_for_selected_execution(self):
        result = self.run_suite(
            FUZZ_TARGETS=TARGETS[0],
            CC="/handled/wasm32-unknown-wasi/bin/clang",
            CXX="/handled/wasm32-unknown-wasi/bin/clang++",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        execution = self.summary()["execution"]
        self.assertEqual(execution["status"], "passed")
        self.assertEqual(execution["selected_targets"], [TARGETS[0]])
        for name, command in (("cc", "cc"), ("cxx", "c++")):
            tool = execution["tools"][name]
            self.assertEqual(tool["path"], str(self.bin / command))
            self.assertEqual(
                tool["sha256"], hashlib.sha256((self.bin / command).read_bytes()).hexdigest()
            )

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
        self.install_cleanup_hook("pass")
        self.install_helper_hooks(
            {
                "--finish-run": "directory=Path(os.environ['FUZZ_RUN_ARTIFACT_DIR'])\n"
                "(directory/'collection-summary.json').symlink_to(ROOT.parent/'external-summary')\n"
                "(ROOT.parent/'late-summary-alias-hook').write_text('--finish-run')\n"
            }
        )
        for case in ("ok", "run-fail"):
            with self.subTest(case=case):
                alias.unlink(missing_ok=True)
                hook_marker = self.root.parent / "late-summary-alias-hook"
                hook_marker.unlink(missing_ok=True)
                result = self.run_suite(case, FAIL_TARGET=TARGETS[0])
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(hook_marker.read_text(), "--finish-run")
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

    def test_preexisting_collection_summary_alias_preserves_prior_evidence(self):
        _, raw = self.seed_stale_results()
        previous = self.saved_receipts()
        outside = Path(self.temporary) / "external-preflight-summary"
        outside.write_bytes(b"preserve external preflight summary")
        alias = self.artifacts / "fuzz/collection-summary.json"
        alias.symlink_to(outside)
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "owned output destination cannot be a symlink or special entry", result.stderr
        )
        self.assert_receipts_unchanged(previous)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(outside.read_bytes(), b"preserve external preflight summary")
        for path, content in raw.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.artifacts / "summary").exists())
        self.assertFalse(Path(self.env["CARGO_HOME"]).exists())
        self.assertFalse((self.root.parent / "cleanup-called").exists())

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

    def test_configuration_sources_reject_before_preflight_or_receipt_mutation(self):
        marker, _unused_raw = self.seed_stale_results()
        external = Path(self.temporary) / "external-crate"
        (external / "src").mkdir(parents=True)
        (external / "Cargo.toml").write_text('[package]\nname="server"\nversion="0.0.0"\n')
        (external / "src/lib.rs").write_bytes(b"// external replacement implementation\n")
        included = Path(self.temporary) / "external-source-config.toml"
        included.write_text('[patch.crates-io]\nserver={path="external-crate"}\n')
        credentials = Path(self.env["CARGO_HOME"]) / "credentials.toml"
        credentials.parent.mkdir()
        credentials.write_bytes(b"dummy caller credentials only\n")
        history = Path(self.env["SECURITY_HISTORY_DIR"])
        history.mkdir()
        (history / "previous.json").write_bytes(b"dummy previous history\n")
        config = self.root / ".cargo/config.toml"
        original = config.read_bytes()
        overrides = (
            'paths=["../external-crate"]\n',
            '[patch.crates-io]\nserver={path="../external-crate"}\n',
            (
                '[patch."https://example.invalid/registry"]\n'
                'server={git="https://example.invalid/crate"}\n'
            ),
            (
                '[source.crates-io]\nreplace-with="replacement"\n'
                '[source.replacement]\ndirectory="../external-crate"\n'
            ),
            '[source.replacement]\nlocal-registry="../external-registry"\n',
            '[source.replacement]\nregistry="https://example.invalid/index"\n',
            '[source.replacement]\ngit="https://example.invalid/crate"\nbranch="replacement"\n',
            '[replace]\n"server:0.0.0"={path="../external-crate"}\n',
            '[registry]\nindex="https://example.invalid/index"\n',
            '[registries.replacement]\nindex="https://example.invalid/index"\n',
            'include=["../../external-source-config.toml"]\n[unstable]\nconfig-include=true\n',
            'include="../../external-source-config.toml"\n',
            'include=[{path="../../external-source-config.toml",optional=true}]\n',
            'paths=""\n',
            "paths=false\n",
            "paths=0\n",
            "paths={}\n",
            "patch=[]\n",
            'patch=""\n',
            "source=[]\n",
            "replace=false\n",
            "include={}\n",
            'include=""\n',
            "include=false\n",
            "include=0\n",
            "registry=[]\n",
            "registries=[]\n",
            "registries.replacement=false\n",
            '[registry]\nindex=""\n',
        )
        for override in overrides:
            with self.subTest(configuration=override):
                config.write_bytes(override.encode() + original)
                before = {
                    path: path.read_bytes()
                    for root in (self.root, self.artifacts, external, credentials.parent, history)
                    for path in root.rglob("*")
                    if path.is_file() and not path.is_symlink()
                }
                before[included] = included.read_bytes()
                before_paths = {
                    root: sorted(str(path.relative_to(root)) for path in root.rglob("*"))
                    for root in (self.root, self.artifacts, external, credentials.parent, history)
                }
                for shared in (False, True):
                    with self.subTest(shared=shared):
                        result = (
                            self.run_suite(FUZZ_TARGETS=TARGETS[0])
                            if shared
                            else subprocess.run(  # noqa: S603 - actual owned helper preflight
                                [
                                    sys.executable,
                                    str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                                    "--validate-preflight",
                                    str(marker.parent),
                                ],
                                cwd=self.root,
                                env=self.env,
                                capture_output=True,
                                text=True,
                                timeout=30,
                                check=False,
                            )
                        )
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn(
                            "unmodeled Cargo dependency source configuration", result.stderr
                        )
                        self.assertEqual(self.calls(), [])
                        for path, data in before.items():
                            self.assertEqual(path.read_bytes(), data, str(path))
                        for root, paths in before_paths.items():
                            self.assertEqual(
                                sorted(str(path.relative_to(root)) for path in root.rglob("*")),
                                paths,
                            )
                        self.assertFalse(Path(self.env["CARGO_TARGET_DIR"]).exists())
        config.write_bytes(original)

    def test_registry_index_environment_rejects_before_preflight_or_receipt_mutation(self):
        marker, _unused_raw = self.seed_stale_results()
        credentials = Path(self.env["CARGO_HOME"]) / "credentials.toml"
        credentials.parent.mkdir()
        credentials.write_bytes(b"dummy caller credentials only\n")
        history = Path(self.env["SECURITY_HISTORY_DIR"])
        history.mkdir()
        (history / "previous.json").write_bytes(b"dummy previous history\n")
        roots = (self.root, self.artifacts, credentials.parent, history)
        before = {
            path: path.read_bytes()
            for root in roots
            for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        before_paths = {
            root: sorted(str(path.relative_to(root)) for path in root.rglob("*")) for root in roots
        }
        for name in (
            "CARGO_REGISTRIES_CRATES_IO_INDEX",
            "CARGO_REGISTRIES_REPLACEMENT_INDEX",
            "CARGO_REGISTRIES_FUTURE_NAME_INDEX",
            "CARGO_REGISTRY_INDEX",
        ):
            for value in ("https://example.invalid/index", ""):
                for shared in (False, True):
                    with self.subTest(variable=name, empty=value == "", shared=shared):
                        result = (
                            self.run_suite(FUZZ_TARGETS=TARGETS[0], **{name: value})
                            if shared
                            else subprocess.run(  # noqa: S603 - actual owned helper preflight
                                [
                                    sys.executable,
                                    str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                                    "--validate-preflight",
                                    str(marker.parent),
                                ],
                                cwd=self.root,
                                env={**self.env, name: value},
                                capture_output=True,
                                text=True,
                                timeout=30,
                                check=False,
                            )
                        )
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn(
                            "unmodeled Cargo dependency source environment override", result.stderr
                        )
                        self.assertEqual(self.calls(), [])
                        for path, data in before.items():
                            self.assertEqual(path.read_bytes(), data, str(path))
                        for root, paths in before_paths.items():
                            self.assertEqual(
                                sorted(str(path.relative_to(root)) for path in root.rglob("*")),
                                paths,
                            )
                        self.assertFalse(Path(self.env["CARGO_TARGET_DIR"]).exists())

    def test_registry_credentials_and_non_source_environment_keep_native_execution(self):
        credentials = Path(self.env["CARGO_HOME"]) / "credentials.toml"
        credentials.parent.mkdir()
        previous = b"dummy caller credentials only\n"
        credentials.write_bytes(previous)
        result = self.run_suite(
            FUZZ_TARGETS=TARGETS[0],
            CARGO_REGISTRY_TOKEN="dummy-registry-token",  # noqa: S106 - nonsecret fixture
            CARGO_REGISTRIES_CRATES_IO_TOKEN="dummy-crates-io-token",  # noqa: S106 - nonsecret fixture
            CARGO_REGISTRIES_REPLACEMENT_TOKEN="dummy-replacement-token",  # noqa: S106 - nonsecret fixture
            CARGO_REGISTRIES_REPLACEMENT_CREDENTIAL_PROVIDER="cargo:token",
            CARGO_HTTP_TIMEOUT="30",
            CARGO_NET_RETRY="2",
            CARGO_TERM_COLOR="never",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary()["execution"]["status"], "passed")
        self.assertEqual(credentials.read_bytes(), previous)
        self.assertEqual(
            self.summary()["execution"]["effective_native_commands"],
            {"cc": "cc", "cxx": "c++", "linker": "cc", "ar": "ar"},
        )

    def test_empty_source_containers_and_non_source_settings_keep_native_execution(self):
        config = self.root / ".cargo/config.toml"
        config.write_text(
            "paths=[]\npatch={}\nsource={}\nreplace={}\ninclude=[]\n"
            "[http]\ntimeout=30\n"
            "[net]\nretry=2\noffline=true\n"
            '[term]\ncolor="never"\n'
            '[registry]\ndefault="crates-io"\nglobal-credential-providers=["cargo:token"]\n'
            '[registries.crates-io]\ncredential-provider="cargo:token"\n' + config.read_text()
        )
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        data = self.summary()["execution"]
        self.assertEqual(data["status"], "passed")
        self.assertEqual(
            data["effective_native_commands"],
            {"cc": "cc", "cxx": "c++", "linker": "cc", "ar": "ar"},
        )
        self.assertIn(".cargo/config.toml", data["source"]["files"])

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


class SecurityFuzzPreflightConsistencyTests(SecurityFuzzFixture):
    def test_all_selected_fuzz_log_aliases_reject_before_receipt_invalidation(self):
        paths = (
            "run.log",
            "cargo-fuzz-help.log",
            TARGETS[0] + "/build.log",
            TARGETS[0] + "/run.log",
        )
        for relative in paths:
            for kind in ("symlink", "hardlink", "directory"):
                with self.subTest(path=relative, kind=kind):
                    self.seed_stale_results()
                    prior = self.saved_receipts()
                    route = self.artifacts / "fuzz" / relative
                    route.parent.mkdir(parents=True, exist_ok=True)
                    route.unlink(missing_ok=True)
                    external = self.root.parent / "external-log"
                    external.write_bytes(b"preserve external log bytes")
                    if kind == "symlink":
                        route.symlink_to(external)
                    elif kind == "hardlink":
                        os.link(external, route)
                    else:
                        route.mkdir()
                    try:
                        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(external.read_bytes(), b"preserve external log bytes")
                        self.assert_receipts_unchanged(prior)
                        self.assertEqual(self.calls(), [])
                    finally:
                        if route.is_dir():
                            route.rmdir()
                        else:
                            route.unlink()

    def test_selected_target_log_parent_alias_rejects_without_external_writes(self):
        self.seed_stale_results()
        prior = self.saved_receipts()
        external = self.root.parent / "external-log-parent"
        external.mkdir()
        (external / "build.log").write_bytes(b"private build bytes")
        (external / "run.log").write_bytes(b"private run bytes")
        (self.artifacts / "fuzz" / TARGETS[0]).symlink_to(external)
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((external / "build.log").read_bytes(), b"private build bytes")
        self.assertEqual((external / "run.log").read_bytes(), b"private run bytes")
        self.assertEqual({path.name for path in external.iterdir()}, {"build.log", "run.log"})
        self.assert_receipts_unchanged(prior)
        self.assertEqual(self.calls(), [])

    def test_invalid_stages_launch_no_tools_or_setup_and_preserve_receipts(self):
        _marker, raw = self.seed_stale_results()
        prior = self.saved_receipts()
        called = self.root.parent / "unexpected-tool"
        bootstrap_calls = self.root.parent / "bootstrap-calls"
        bootstrap = [
            "-I",
            "-c",
            (
                'import os, sys; sys.exit(any(key.startswith("BASH_FUNC_") '
                'and key.endswith("%%") for key in os.environ))'
            ),
        ]
        for tool in ("git", "python3", "mkdir", "cargo"):
            command = sys.executable if tool == "python3" else shutil.which(tool)
            code = "import os,pathlib,sys\n"
            if tool == "python3":
                # Admit only the exact pre-command key scan; all later helpers
                # still record an unexpected call before executing.
                code += (
                    f"if sys.argv[1:] == {bootstrap!r}:\n"
                    f" with pathlib.Path({str(bootstrap_calls)!r}).open('a') as out:\n"
                    "  out.write('bootstrap\\n')\n"
                    f" os.execv({command!r}, [{command!r}] + sys.argv[1:])\n"
                )
            code += f"pathlib.Path({str(called)!r}).write_text('called')\n"
            if tool == "git":
                code += (
                    "print(os.environ['FIXTURE_ROOT']) if '--show-toplevel' in sys.argv else None\n"
                )
            elif tool != "cargo":
                code += f"os.execv({command!r}, [{command!r}] + sys.argv[1:])\n"
            self.install(tool, code)
        for index, stages in enumerate((("unknown",), ("fuzz", "unknown"))):
            with self.subTest(stages=stages):
                result = self.run_suite(stages=stages)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("unknown stage", result.stderr)
                self.assert_receipts_unchanged(prior)
                for path, content in raw.items():
                    self.assertEqual(path.read_bytes(), content)
                self.assertEqual(
                    bootstrap_calls.read_text().splitlines(), ["bootstrap"] * (index + 1)
                )
                self.assertFalse(called.exists())
                self.assertFalse((self.artifacts / "summary").exists())
                self.assertFalse(Path(self.env["CARGO_HOME"]).exists())
                called.unlink(missing_ok=True)

    def test_relative_cargo_home_caller_alias_rejects_before_any_mutation(self):
        self.caller = self.root.parent / "caller"
        self.caller.mkdir()
        external = self.root.parent / "external-home"
        external.mkdir()
        marker = external / "private-marker"
        marker.write_bytes(b"preserve caller alias destination")
        (self.caller / "relative-home").symlink_to(external)
        self.install(
            "git",
            "import os,sys\n"
            "if '--show-toplevel' in sys.argv: print(os.environ['FIXTURE_ROOT'])\n"
            "else: raise SystemExit(1)",
        )
        self.seed_stale_results()
        prior = self.saved_receipts()
        result = self.run_suite(CARGO_HOME="relative-home", FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(marker.read_bytes(), b"preserve caller alias destination")
        self.assertEqual(list(external.iterdir()), [marker])
        self.assert_receipts_unchanged(prior)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.root / "relative-home").exists())


class SecurityFuzzArtifactDestinationTests(SecurityFuzzFixture):
    def setUp(self):
        super().setUp()
        for tool in ("cc", "c++", "ar"):
            self.install(tool, "print('nonsecret native-version fixture')")

    def test_packaging_rejects_both_cargo_home_overlaps_before_entry_reads(self):
        result = SecurityFuzzReceiptBoundaryTests.helper_python(
            self,
            "import os,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); state=h['package_upload'].__globals__\n"
            "root=h['ROOT']; output=root/'artifacts/upload-control'\n"
            "def forbidden_inventory(): raise RuntimeError('unsafe entry inventory reached')\n"
            "state['upload_inventory']=forbidden_inventory\n"
            "for name in h['UPLOAD_ROOTS']:\n"
            " source=root/name\n"
            " for home in (source,source/'cargo-home',source.parent):\n"
            "  os.environ['CARGO_HOME']=str(home)\n"
            "  try: h['package_upload'](output)\n"
            "  except ValueError as error:\n"
            "   if str(error)!='upload paths overlap Cargo home': raise\n"
            "  else: raise RuntimeError('Cargo home overlap admitted')\n"
            "for home in (output,output/'cargo-home',output.parent):\n"
            " os.environ['CARGO_HOME']=str(home)\n"
            " try: h['package_upload'](output)\n"
            " except ValueError as error:\n"
            "  if str(error)!='upload paths overlap Cargo home': raise\n"
            " else: raise RuntimeError('output Cargo home overlap admitted')\n"
            "if output.exists(): raise RuntimeError('rejected upload output was created')\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_packaging_default_home_and_home_alias_reject_before_inventory(self):
        result = SecurityFuzzReceiptBoundaryTests.helper_python(
            self,
            "import os,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); state=h['package_upload'].__globals__\n"
            "root=h['ROOT']; output=root/'artifacts/upload-default-control'\n"
            "def forbidden_inventory(): raise RuntimeError('unsafe entry inventory reached')\n"
            "state['upload_inventory']=forbidden_inventory\n"
            "os.environ.pop('CARGO_HOME',None)\n"
            "pathlib.Path.home=classmethod(lambda cls: root/'artifacts/security/latest')\n"
            "try: h['package_upload'](output)\n"
            "except ValueError as error:\n"
            " if str(error)!='upload paths overlap Cargo home': raise\n"
            "else: raise RuntimeError('default Cargo home overlap admitted')\n"
            "home=root.parent/'owned-cargo-home'; home.mkdir()\n"
            "(home/'credentials.toml').write_bytes(b'nonsecret credential fixture')\n"
            "alias=root.parent/'cargo-home-alias'; alias.symlink_to(home)\n"
            "os.environ['CARGO_HOME']=str(alias)\n"
            "try: h['package_upload'](output)\n"
            "except ValueError as error:\n"
            " if 'symlink components' not in str(error): raise\n"
            "else: raise RuntimeError('Cargo home alias admitted')\n"
            "if output.exists(): raise RuntimeError('rejected upload output was created')\n"
            "if (home/'credentials.toml').read_bytes()!=b'nonsecret credential fixture':\n"
            " raise RuntimeError('fixture credentials changed')\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_collection_summary_destinations_reject_before_retiring_receipts(self):
        self.seed_stale_results()
        previous = self.saved_receipts()
        summary = self.artifacts / "fuzz/collection-summary.json"
        sentinel = Path(self.temporary) / "summary-sentinel"
        sentinel.write_bytes(b"preserve nonsecret summary sentinel")
        for kind in ("symlink", "hardlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    summary.symlink_to(sentinel)
                elif kind == "hardlink":
                    os.link(sentinel, summary)
                elif kind == "directory":
                    summary.mkdir()
                else:
                    os.mkfifo(summary)
                try:
                    result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("owned output destination", result.stderr)
                    self.assert_receipts_unchanged(previous)
                    self.assertEqual(self.calls(), [])
                    self.assertFalse((self.artifacts / "summary/security.log").exists())
                    self.assertEqual(sentinel.read_bytes(), b"preserve nonsecret summary sentinel")
                finally:
                    if kind == "directory":
                        summary.rmdir()
                    else:
                        summary.unlink()

    def test_safe_packaging_preserves_inert_cargo_links_without_reading_credentials(self):
        result = SecurityFuzzReceiptBoundaryTests.helper_python(
            self,
            "import os,pathlib,runpy,sys,tarfile\n"
            "h=runpy.run_path(sys.argv[1]); state=h['package_upload'].__globals__\n"
            "root=h['ROOT']; home=root.parent/'owned-cargo-home'; home.mkdir()\n"
            "credential=home/'credentials.toml'\n"
            "credential.write_bytes(b'nonsecret credential fixture')\n"
            "os.environ['CARGO_HOME']=str(home)\n"
            "source=root/'artifacts/security/latest'; source.mkdir(parents=True)\n"
            "(source/'owned').write_bytes(b'owned upload evidence')\n"
            "(source/'inert-cargo-link').symlink_to(home)\n"
            "actual=state['open_evidence_file']\n"
            "def no_credentials(path,*args,**kwargs):\n"
            " if path.is_relative_to(home): raise RuntimeError('credential read attempted')\n"
            " return actual(path,*args,**kwargs)\n"
            "state['open_evidence_file']=no_credentials\n"
            "output=root/'artifacts/upload-safe-control'; h['package_upload'](output)\n"
            "with tarfile.open(output/'security-evidence.tar.gz') as archive:\n"
            " link=archive.getmember('artifacts/security/latest/inert-cargo-link')\n"
            " if not link.issym() or link.linkname!=str(home):\n"
            "  raise RuntimeError('inert link identity changed')\n"
            " if any('credentials.toml' in name for name in archive.getnames()):\n"
            "  raise RuntimeError('credentials entered upload archive')\n"
            "if not (output/'manifest.json').is_file(): raise RuntimeError('manifest missing')\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_effective_suite_outputs_remain_identical_through_cleanup(self):
        for route in ("collection-history", "collection-evidence"):
            path = self.root / route
            path.mkdir()
            (path / "existing").write_bytes(b"unchanged inherited route input")
        phases = (
            "--validate-preflight",
            "--prepare-run",
            "--record-environment",
            "--record-target",
            "--finish-run",
            "--backup-cleanup",
            "--cleanup-cache",
            "--cleanup-result",
        )
        self.install_helper_hooks(
            {
                phase: "with (ROOT.parent/'effective-routes.jsonl').open('a') as stream:\n"
                f" stream.write(json.dumps({{'action': {phase!r}, "
                "'artifact': os.environ.get('FUZZ_RUN_ARTIFACT_DIR'), "
                "'history': os.environ.get('FUZZ_HISTORY_DIR')})+'\\n')\n"
                for phase in phases
            }
        )
        result = self.run_suite(
            FUZZ_TARGETS=TARGETS[0],
            FUZZ_HISTORY_DIR="collection-history",
            FUZZ_RUN_ARTIFACT_DIR="collection-evidence",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        observations = [
            json.loads(line)
            for line in (self.root.parent / "effective-routes.jsonl").read_text().splitlines()
        ]
        self.assertEqual({record["action"] for record in observations}, set(phases))
        for record in observations:
            self.assertEqual(record["artifact"], str(self.artifacts / "fuzz"))
            self.assertEqual(record["history"], self.env["SECURITY_HISTORY_DIR"])
        self.assertEqual(self.summary()["status"], "passed")
        self.assert_backup()
        for route in ("collection-history", "collection-evidence"):
            self.assertIn(route + "/existing", self.summary()["execution"]["source"]["files"])
            self.assertEqual(
                (self.root / route / "existing").read_bytes(), b"unchanged inherited route input"
            )

    def test_collect_only_cargo_home_overlaps_preserve_all_roots(self):
        artifact = self.artifacts / "fuzz"
        history = Path(self.temporary) / "history"
        roots = [
            self.root / "fuzz" / name
            for name in ("corpus", "artifacts", "corpus_archive", "corpus_meta")
        ]
        roots.extend((artifact, history))
        for root in roots:
            root.mkdir(parents=True, exist_ok=True)
            (root / "prior-owned-input").write_bytes(b"unchanged owned input\n")

        def snapshot():
            result = {}
            for root in roots:
                for path in [root, *root.rglob("*")]:
                    result[str(path)] = None if path.is_dir() else path.read_bytes()
            return result

        for index, root in enumerate(roots):
            for relation in ("equal", "child", "parent"):
                with self.subTest(root=str(root), relation=relation):
                    home = (
                        root
                        if relation == "equal"
                        else root / "fuzz_par/cargo-home"
                        if relation == "child"
                        else root.parent
                    )
                    home.mkdir(parents=True, exist_ok=True)
                    credential = home / "credentials.toml"
                    credential.write_bytes(b"nonsecret collection credential fixture\n")
                    before = snapshot()
                    result = subprocess.run(  # noqa: S603 - real collect-only helper and dummy credentials
                        [sys.executable, str(self.root / "scripts/fuzz/manage_fuzz_corpus.py")],
                        cwd=self.root,
                        env={
                            **self.env,
                            "CARGO_HOME": str(home),
                            "FUZZ_RUN_ARTIFACT_DIR": str(artifact),
                            "FUZZ_HISTORY_DIR": str(history),
                        },
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                    (Path(self.temporary) / f"cargo-overlap-{index}-{relation}.json").write_text(
                        json.dumps(
                            {
                                "home": str(home),
                                "root": str(root),
                                "exit": result.returncode,
                                "stdout": result.stdout,
                                "stderr": result.stderr,
                            }
                        )
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("collection paths overlap Cargo home", result.stderr)
                    self.assertEqual(snapshot(), before)
                    self.assertEqual(
                        credential.read_bytes(), b"nonsecret collection credential fixture\n"
                    )
                    self.assertEqual(self.calls(), [])

    def test_collection_cargo_home_default_relative_and_alias_fail_before_reads(self):
        result = SecurityFuzzReceiptBoundaryTests.helper_python(
            self,
            "import os,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); state=h['collect_corpus'].__globals__; root=h['ROOT']\n"
            "def forbidden_read(*args): raise RuntimeError('collection read reached')\n"
            "state['load_targets']=forbidden_read\n"
            "for mode in ('relative','default','alias'):\n"
            " if mode=='relative': os.environ['CARGO_HOME']='fuzz/corpus/fuzz_par/cargo-home'\n"
            " elif mode=='default':\n"
            "  os.environ.pop('CARGO_HOME',None)\n"
            "  pathlib.Path.home=classmethod(lambda cls: root/'fuzz/corpus/fuzz_par')\n"
            " else:\n"
            "  home=root.parent/'disjoint-cargo-home'; home.mkdir()\n"
            "  credential=home/'credentials.toml'\n"
            "  credential.write_bytes(b'nonsecret alias credential fixture')\n"
            "  alias=root.parent/'cargo-home-alias'; alias.symlink_to(home)\n"
            "  os.environ['CARGO_HOME']=str(alias)\n"
            " try: h['collect_corpus']()\n"
            " except ValueError as error:\n"
            "  expected=('symlink components' if mode=='alias'\n"
            "   else 'collection paths overlap Cargo home')\n"
            "  if expected not in str(error): raise\n"
            " else: raise RuntimeError('unsafe collection Cargo home admitted')\n"
            "if (root/'fuzz/corpus_meta').exists():\n"
            " raise RuntimeError('collection output created')\n"
            "if credential.read_bytes()!=b'nonsecret alias credential fixture':\n"
            " raise RuntimeError('credential changed')\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_collection_entrypoints_and_preflight_reject_cargo_home_before_effects(self):
        result = SecurityFuzzReceiptBoundaryTests.helper_python(
            self,
            "import os,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); root=h['ROOT']; state=h['collect_corpus'].__globals__\n"
            "os.environ['CARGO_HOME']=str(root/'fuzz/corpus/fuzz_par/cargo-home')\n"
            "entries=[lambda:h['collect_corpus'](),lambda:h['ensure_directories'](list(h['REQUIRED_TARGETS'])),\n"
            " lambda:h['gather_stats'](list(h['REQUIRED_TARGETS'])),lambda:h['create_archive'](),\n"
            " lambda:h['gather_crash_stats'](),lambda:h['archive_crashes']([],None)]\n"
            "for action in entries:\n"
            " try: action()\n"
            " except ValueError as error:\n"
            "  if str(error)!='collection paths overlap Cargo home': raise\n"
            " else: raise RuntimeError('collection entrypoint admitted Cargo home')\n"
            "output=root.parent/'preflight-output'\n"
            "state['RUN_ARTIFACT_DIR']=None; state['HISTORY_OUT_DIR']=None\n"
            "os.environ['CARGO_HOME']=str(output/'cargo-home')\n"
            "try: h['validate_preflight'](output)\n"
            "except ValueError as error:\n"
            " if str(error)!='collection paths overlap Cargo home': raise\n"
            "else: raise RuntimeError('preflight output Cargo home admitted')\n"
            "if output.exists() or (root/'fuzz/corpus').exists():\n"
            " raise RuntimeError('rejected output created')\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_disjoint_collection_preserves_cargo_credentials_and_inert_links(self):
        home = Path(self.temporary) / "disjoint-cargo-home"
        home.mkdir()
        credential = home / "credentials.toml"
        credential.write_bytes(b"nonsecret disjoint credential fixture\n")
        for name in ("corpus", "artifacts"):
            raw = self.root / "fuzz" / name / TARGETS[0]
            raw.mkdir(parents=True)
            (raw / "owned").write_bytes(b"owned collection input\n")
            (raw / "inert-cargo-link").symlink_to(home)
        artifact = self.artifacts / "fuzz"
        history = Path(self.temporary) / "history"
        result = subprocess.run(  # noqa: S603 - real collect-only helper with disjoint dummy credential route
            [sys.executable, str(self.root / "scripts/fuzz/manage_fuzz_corpus.py")],
            cwd=self.root,
            env={
                **self.env,
                "CARGO_HOME": str(home),
                "FUZZ_RUN_ARTIFACT_DIR": str(artifact),
                "FUZZ_HISTORY_DIR": str(history),
            },
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        for directory in (artifact, history):
            for kind in ("corpus_archive", "crash_archive"):
                with tarfile.open(directory / summary[kind]) as archive:
                    self.assertFalse(any("credentials.toml" in name for name in archive.getnames()))
                    prefix = "corpus/" if kind == "corpus_archive" else ""
                    link = archive.getmember(prefix + TARGETS[0] + "/inert-cargo-link")
                    self.assertTrue(link.issym())
                    self.assertEqual(link.linkname, str(home))
        self.assertEqual(credential.read_bytes(), b"nonsecret disjoint credential fixture\n")
        self.assertTrue((history / "fuzz_runs.jsonl").is_file())
        self.assertEqual(self.calls(), [])


class SecurityFuzzPreflightSourceHistoryTests(SecurityFuzzFixture):
    def setUp(self):
        super().setUp()
        for tool in ("cc", "c++", "ar"):
            self.install(tool, "print('nonsecret native-version fixture')")

    def test_collection_history_overlap_preserves_previous_receipts(self):
        self.seed_stale_results()
        previous = self.saved_receipts()
        collection = self.artifacts / "fuzz"
        for history in (collection, collection / "history", self.artifacts):
            with self.subTest(history=history):
                result = self.run_suite(FUZZ_TARGETS=TARGETS[0], SECURITY_HISTORY_DIR=str(history))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("collection and history directories overlap", result.stderr)
                self.assert_receipts_unchanged(previous)
                self.assertEqual(self.calls(), [])
                self.assertFalse((self.artifacts / "summary").exists())
                self.assertFalse(Path(self.env["CARGO_HOME"]).exists())

    def test_transitive_source_alias_rejects_before_retiring_previous_receipts(self):
        self.seed_stale_results()
        previous = self.saved_receipts()
        sentinel = Path(self.temporary) / "transitive-source-sentinel"
        sentinel.write_bytes(b"unchanged transitive source sentinel\n")
        for package in ("server", "ffi"):
            with self.subTest(package=package):
                alias = self.root / "crates" / package / "src" / "unmodeled.rs"
                alias.symlink_to(sentinel)
                try:
                    result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("symlink or external local source input", result.stderr)
                    self.assert_receipts_unchanged(previous)
                    self.assertEqual(self.calls(), [])
                    self.assertFalse((self.artifacts / "summary").exists())
                    self.assertFalse(Path(self.env["CARGO_HOME"]).exists())
                    self.assertEqual(
                        sentinel.read_bytes(), b"unchanged transitive source sentinel\n"
                    )
                finally:
                    alias.unlink()

    def test_retired_kani_pointer_absence_is_bound_without_tool_traversal(self):
        (self.root / "crates/kani-harness/kani").unlink()
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = self.summary()
        self.assertEqual(summary["status"], "passed")
        self.assertNotIn("crates/kani-harness/kani", summary["execution"]["source"]["files"])
        self.assertFalse((self.root / "crates/kani-harness/result").exists())


class SecurityFuzzReceiptTokenizerTests(SecurityFuzzFixture):
    def setUp(self):
        super().setUp()
        for tool in ("cc", "c++", "ar"):
            self.install(tool, "print('nonsecret native-version fixture')")

    def test_all_collection_receipt_destinations_reject_before_retirement(self):
        _, raw = self.seed_stale_results()
        collection = self.artifacts / "fuzz"
        names = ("collection.ok", "execution.json", "run_summary.json", "collection-summary.json")
        (collection / names[-1]).write_bytes(b"unchanged prior collection summary\n")
        previous = {name: (collection / name).read_bytes() for name in names}
        for name in names:
            with self.subTest(name=name):
                invalid = collection / name
                invalid.unlink()
                invalid.mkdir()
                sentinel = invalid / "prior-evidence"
                sentinel.write_bytes(b"unchanged invalid receipt directory\n")
                try:
                    result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("owned output destination", result.stderr)
                    self.assertEqual(
                        sentinel.read_bytes(), b"unchanged invalid receipt directory\n"
                    )
                    self.assertEqual(list(invalid.iterdir()), [sentinel])
                    for other in names:
                        if other != name:
                            self.assertEqual((collection / other).read_bytes(), previous[other])
                    for path, content in raw.items():
                        self.assertEqual(path.read_bytes(), content)
                    self.assertEqual(self.calls(), [])
                    self.assertFalse((self.artifacts / "summary").exists())
                    self.assertFalse(Path(self.env["CARGO_HOME"]).exists())
                finally:
                    sentinel.unlink()
                    invalid.rmdir()
                    invalid.write_bytes(previous[name])

    def test_collect_only_overlaps_reject_before_any_collection_write(self):
        def snapshot(directory):
            return {
                str(path.relative_to(directory)): None if path.is_dir() else path.read_bytes()
                for path in directory.rglob("*")
            }

        crash = self.root / "fuzz/artifacts" / TARGETS[0] / "owned-crash"
        for with_crash in (False, True):
            if with_crash:
                crash.parent.mkdir(parents=True)
                crash.write_bytes(b"unchanged owned crash input\n")
            for relation in ("equal", "history-child", "history-parent"):
                with self.subTest(with_crash=with_crash, relation=relation):
                    base = Path(self.temporary) / f"collect-overlap-{with_crash}-{relation}"
                    artifact = base / "artifact"
                    history = {
                        "equal": artifact,
                        "history-child": artifact / "history",
                        "history-parent": base,
                    }[relation]
                    artifact.mkdir(parents=True)
                    history.mkdir(parents=True, exist_ok=True)
                    (artifact / "prior-artifact").write_bytes(b"unchanged prior artifact\n")
                    (history / "prior-history").write_bytes(b"unchanged prior history\n")
                    before = snapshot(base), snapshot(self.root / "fuzz")
                    result = subprocess.run(  # noqa: S603 - actual helper with owned fixture routes
                        [sys.executable, str(self.root / "scripts/fuzz/manage_fuzz_corpus.py")],
                        cwd=self.root,
                        env={
                            **self.env,
                            "FUZZ_RUN_ARTIFACT_DIR": str(artifact),
                            "FUZZ_HISTORY_DIR": str(history),
                        },
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("collection and history directories overlap", result.stderr)
                    self.assertEqual((snapshot(base), snapshot(self.root / "fuzz")), before)
                    self.assertEqual(self.calls(), [])

    def test_unicode_whitespace_selection_executes_each_validated_target(self):
        for separator in ("\v", "\u00a0"):
            with self.subTest(separator=repr(separator)):
                calls = self.root.parent / "calls.jsonl"
                if calls.exists():
                    calls.unlink()
                result = self.run_suite(FUZZ_TARGETS=separator.join(TARGETS[:2]))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                execution = self.summary()["execution"]
                self.assertEqual(execution["selected_targets"], list(TARGETS[:2]))
                self.assertEqual(execution["status"], "passed")
                self.assertEqual(execution["coverage"], "local-subset")
                self.assertEqual([row["name"] for row in execution["targets"]], list(TARGETS[:2]))
                self.assertTrue(
                    all(row["run"]["completed_runs"] == 100 for row in execution["targets"])
                )
                self.assertEqual(
                    [call[6] for call in self.calls() if call[:2] == ["fuzz", "run"]],
                    list(TARGETS[:2]),
                )

    def test_unicode_whitespace_selection_preserves_required_ci_inventory(self):
        self.seed_stale_results()
        previous = self.saved_receipts()
        for separator in ("\v", "\u00a0"):
            with self.subTest(separator=repr(separator), selection="subset"):
                result = self.run_suite(FUZZ_TARGETS=separator.join(TARGETS[:2]), CI="true")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("full seven-target fuzz inventory", result.stderr)
                self.assert_receipts_unchanged(previous)
                self.assertEqual(self.calls(), [])
        result = self.run_suite(FUZZ_TARGETS="\u00a0".join(TARGETS), CI="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        execution = self.summary()["execution"]
        self.assertEqual(execution["selected_targets"], list(TARGETS))
        self.assertEqual(execution["coverage"], "full")
        self.assertEqual(execution["status"], "passed")
        self.assertEqual(
            [call[6] for call in self.calls() if call[:2] == ["fuzz", "run"]], list(TARGETS)
        )


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

    def test_outer_unknown_stages_reject_before_git_discovery_or_external_dispatch(self):
        marker, raw = self.seed_stale_results()
        previous = self.saved_receipts()
        for arguments in (
            ["--stage", "unknown"],
            ["--stage", "sbom", "--stage", "unknown"],
            ["--stage", "unknown", "--stage", "fuzz"],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_outer(
                    arguments,
                    GIT_DIR=str(self.external),
                    GIT_WORK_TREE=str(self.external),
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("unknown stage", result.stderr)
                self.assertFalse((self.root.parent / "outer-git-calls.jsonl").exists())
                self.assertFalse(self.dispatch.exists())
                self.assert_receipts_unchanged(previous)
                self.assertTrue(marker.is_file())
                for path, content in raw.items():
                    self.assertEqual(path.read_bytes(), content)

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


class SecurityFuzzRestoreOwnershipTests(SecurityFuzzFixture):
    helper_python = SecurityFuzzReceiptBoundaryTests.helper_python

    def setUp(self):
        super().setUp()
        for tool in ("cc", "c++", "ar"):
            self.install(tool, "print('nonsecret native-version fixture')")

    def prepare_owned_backup(self):
        for name in ("corpus", "artifacts", "corpus_archive"):
            raw = self.root / "fuzz" / name
            raw.mkdir(parents=True, exist_ok=True)
            (raw / "credentials.toml").write_bytes(b"nonsecret recovery fixture\n")
        self.install_helper_hooks({"--cleanup-result": "raise SystemExit(29)"})
        result = self.run_suite(FUZZ_TARGETS=TARGETS[0])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.summary()["execution"]["cleanup_recovery"]["status"], "restored")
        backup, _ = self.assert_backup()
        self.install_helper_hooks({})
        return self.artifacts / "fuzz", backup

    def test_restore_cargo_home_overlaps_preserve_raw_receipts_and_dummy_credentials(self):
        directory, backup = self.prepare_owned_backup()
        roots = [self.root / "fuzz" / name for name in ("corpus", "artifacts", "corpus_archive")]
        roots.append(directory)

        def snapshot():
            result = {}
            for root in roots:
                for path in [root, *root.rglob("*")]:
                    result[str(path)] = None if path.is_dir() else path.read_bytes()
            return result

        for index, root in enumerate(roots):
            for relation in ("equal", "child", "parent"):
                with self.subTest(root=str(root), relation=relation):
                    home = (
                        root
                        if relation == "equal"
                        else root / "cargo-home"
                        if relation == "child"
                        else root.parent
                    )
                    home.mkdir(parents=True, exist_ok=True)
                    credential = home / "credentials.toml"
                    credential.write_bytes(b"preserve nonsecret Cargo credential fixture\n")
                    before = snapshot()
                    calls = self.calls()
                    result = subprocess.run(  # noqa: S603 - actual restore CLI with dummy credential routes
                        [
                            sys.executable,
                            str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                            "--restore-cleanup",
                            str(directory),
                            backup.name,
                            "29",
                            "receipt",
                        ],
                        cwd=self.root,
                        env={**self.env, "CARGO_HOME": str(home)},
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                    (Path(self.temporary) / f"restore-overlap-{index}-{relation}.json").write_text(
                        json.dumps(
                            {
                                "home": str(home),
                                "root": str(root),
                                "exit": result.returncode,
                                "stdout": result.stdout,
                                "stderr": result.stderr,
                                "credential_after": credential.read_text(),
                            }
                        )
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("restoration paths overlap Cargo home", result.stderr)
                    self.assertEqual(snapshot(), before)
                    self.assertEqual(
                        credential.read_bytes(), b"preserve nonsecret Cargo credential fixture\n"
                    )
                    self.assertEqual(self.calls(), calls)

    def test_restore_cargo_home_guard_precedes_dispatch_and_direct_backup_reads(self):
        result = self.helper_python(
            "import os,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); state=h['restore_cleanup'].__globals__\n"
            "original_restore=h['restore_cleanup']\n"
            "root=h['ROOT']; output=root.parent/'owned-restore-output'\n"
            "def forbidden(*args): raise RuntimeError('restoration dispatch/read reached')\n"
            "state['load_cleanup_backup']=forbidden\n"
            "for mode in ('relative','default','receipt-child'):\n"
            " if mode=='relative': os.environ['CARGO_HOME']='fuzz/corpus'\n"
            " elif mode=='default':\n"
            "  os.environ.pop('CARGO_HOME',None)\n"
            "  pathlib.Path.home=classmethod(lambda cls: root/'fuzz/corpus')\n"
            " else: os.environ['CARGO_HOME']=str(output/'cargo-home')\n"
            " try: h['restore_cleanup'](output,'unused-run-id',29,'receipt')\n"
            " except ValueError as error:\n"
            "  if str(error)!='restoration paths overlap Cargo home': raise\n"
            " else: raise RuntimeError('direct unsafe restore admitted')\n"
            " state['restore_cleanup']=forbidden\n"
            " sys.argv=[sys.argv[1],'--restore-cleanup',str(output),\n"
            "  'unused-run-id','29','receipt']\n"
            " if h['main']()!=h['EVIDENCE_ERROR']:\n"
            "  raise RuntimeError('unsafe CLI restore admitted')\n"
            " state['restore_cleanup']=original_restore\n"
            "if output.exists(): raise RuntimeError('rejected receipt output created')\n",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    FOREIGN_OWNER_MODEL = """
from types import SimpleNamespace
from unittest.mock import patch
original_lstat=pathlib.Path.lstat
original_fstat=os.fstat
victim_info=original_lstat(victim)
victim_identity=(victim_info.st_dev,victim_info.st_ino)
def foreign(info):
    values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
    values['st_uid']=os.geteuid()+1
    return SimpleNamespace(**values)
def modeled_lstat(path,*args,**kwargs):
    info=original_lstat(path,*args,**kwargs)
    return foreign(info) if (info.st_dev,info.st_ino)==victim_identity else info
def modeled_fstat(fd):
    info=original_fstat(fd)
    return foreign(info) if (info.st_dev,info.st_ino)==victim_identity else info
"""

    def test_shared_reader_rejects_stable_foreign_uid_before_yield_or_read(self):
        result = self.helper_python(
            "import hashlib,json,os,pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); root=h['ROOT']\n"
            "victim=root/'artifacts/security/latest/foreign-input'\n"
            "victim.parent.mkdir(parents=True)\n"
            "victim.write_bytes(b'nonsecret foreign UID fixture')\n"
            + self.FOREIGN_OWNER_MODEL
            + """
reads=[]; original_fdopen=os.fdopen
class Probe:
    def __init__(self,stream): self.stream=stream
    def __enter__(self): return self
    def __exit__(self,*args): return self.stream.__exit__(*args)
    def fileno(self): return self.stream.fileno()
    def read(self,*args): reads.append('read'); return self.stream.read(*args)
def observed_fdopen(fd,*args,**kwargs):
    stream=original_fdopen(fd,*args,**kwargs); info=original_fstat(fd)
    return Probe(stream) if (info.st_dev,info.st_ino)==victim_identity else stream
def direct_context():
    with h['open_evidence_file'](victim): reads.append('yield')
actions={
    'context':direct_context,
    'snapshot':lambda:h['evidence_snapshot'](victim),
    'text':lambda:h['evidence_text'](victim),
    'digest':lambda:h['evidence_digest'](victim),
    'source':lambda:h['local_source_inventory'](set(),h['kani_output_pointer']()),
    'raw':lambda:h['raw_inventory'](victim.parent),
    'copy':lambda:h['copy_evidence_file'](str(victim),str(root.parent/'rejected-copy')),
    'upload':lambda:h['package_upload'](root/'artifacts/rejected-upload'),
}
outcomes=[]
for name,action in actions.items():
    reads.clear()
    with patch.object(pathlib.Path,'lstat',modeled_lstat), \
            patch.object(os,'fstat',modeled_fstat), patch.object(os,'fdopen',observed_fdopen):
        try: action()
        except ValueError as error:
            if 'stable, unaliased regular file' not in str(error): raise
        else: raise RuntimeError('stable foreign owner admitted: '+name)
    if reads: raise RuntimeError('foreign owner yielded or read: '+name)
    outcomes.append(name)
if (root.parent/'rejected-copy').exists(): raise RuntimeError('rejected copy created')
if victim.read_bytes()!=b'nonsecret foreign UID fixture': raise RuntimeError('fixture changed')
if h['evidence_snapshot'](victim)!=b'nonsecret foreign UID fixture':
    raise RuntimeError('owned positive snapshot rejected')
owned_copy=root.parent/'owned-copy'
h['copy_evidence_file'](str(victim),str(owned_copy))
if owned_copy.read_bytes()!=victim.read_bytes(): raise RuntimeError('owned copy mismatch')
h['package_upload'](root/'artifacts/owned-upload')
(root.parent/'foreign-reader-controls.json').write_text(json.dumps(outcomes))
""",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_foreign_recovery_readers_preserve_backup_and_raw_destinations(self):
        directory, backup = self.prepare_owned_backup()
        for relative in (
            "backup-ready.json",
            "evidence/execution.json",
            "evidence/run_summary.json",
            "evidence/collection.ok",
            "evidence/collection-summary.json",
        ):
            with self.subTest(receipt=relative):
                result = self.helper_python(
                    "import os,pathlib,runpy,sys\n"
                    "h=runpy.run_path(sys.argv[1]); root=h['ROOT']\n"
                    f"directory=pathlib.Path({str(directory)!r}); run_id={backup.name!r}\n"
                    f"victim=directory/'cleanup-recovery'/run_id/{relative!r}\n"
                    "roots=[directory,*[root/'fuzz'/name for name in "
                    "('corpus','artifacts','corpus_archive')]]\n"
                    "def snapshot():\n"
                    " return {str(p):p.read_bytes() for base in roots "
                    "for p in base.rglob('*') if p.is_file()}\n"
                    "before=snapshot()\n"
                    + self.FOREIGN_OWNER_MODEL
                    + """
with patch.object(pathlib.Path,'lstat',modeled_lstat), patch.object(os,'fstat',modeled_fstat):
    try: h['restore_cleanup'](directory,run_id,29,'receipt')
    except ValueError as error:
        if 'stable, unaliased regular file' not in str(error): raise
    else: raise RuntimeError('foreign saved recovery receipt admitted')
after=snapshot()
if after!=before: raise RuntimeError('rejected foreign recovery changed receipts')
""",
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class SecurityFuzzCliDirectoryCargoHomeTests(SecurityFuzzFixture):
    ACTIONS = (
        ("--prepare-run", "prepare_run", []),
        ("--record-environment", "record_environment", []),
        ("--execution-cache", "execution_cache", []),
        ("--validate-cache", "configured_cache", []),
        ("--validate-preflight", "validate_preflight", []),
        ("--backup-cleanup", "backup_cleanup", []),
        ("--cleanup-cache", "cleanup_cache", ["00000000-0000-0000-0000-000000000001"]),
        ("--record-target", "record_target", [TARGETS[0], "run", "0"]),
        ("--finish-run", "finish_run", ["0"]),
        ("--cleanup-result", "cleanup_result", ["0"]),
    )

    def cli_environment(self, home):
        environment = {**self.env, "CARGO_HOME": str(home)}
        for name in (
            "SECURITY_ARTIFACT_DIR",
            "SECURITY_HISTORY_DIR",
            "FUZZ_RUN_ARTIFACT_DIR",
            "FUZZ_HISTORY_DIR",
        ):
            environment.pop(name, None)
        return environment

    def cli_action(self, code, action, directory, tail, home):
        return subprocess.run(  # noqa: S603 - instrument actual CLI action dispatch in owned fixture
            [
                sys.executable,
                *(["-O"] if sys.flags.optimize else []),
                "-c",
                code,
                str(self.root / "scripts/fuzz/manage_fuzz_corpus.py"),
                action,
                str(directory),
                *tail,
            ],
            cwd=self.root,
            env=self.cli_environment(home),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def test_cli_directory_actions_reject_cargo_home_before_source_receipt_or_dispatch(self):
        self.seed_stale_results()
        receipts = self.saved_receipts()
        directory = self.root / "cli-action-evidence"
        directory.mkdir()
        for name in ("execution.json", "run_summary.json", "collection.ok"):
            (directory / name).write_bytes(b"preserve previous CLI receipt\n")
        callback = Path(self.temporary) / "forbidden-action-read"
        consumers = [consumer for _, consumer, _ in self.ACTIONS]
        guarded_callbacks = [
            *consumers,
            "validate_collection_roots",
            "load_execution",
            "evidence_text",
            "source_hashes",
        ]
        code = (
            "import pathlib,runpy,sys\n"
            "h=runpy.run_path(sys.argv[1]); state=h['main'].__globals__\n"
            "def forbidden(*args,**kwargs):\n"
            f" pathlib.Path({str(callback)!r}).write_text('unexpected access')\n"
            " raise RuntimeError('action guard did not precede access')\n"
            f"for name in {guarded_callbacks!r}:\n"
            " state[name]=forbidden\n"
            "sys.argv=sys.argv[1:]\n"
            "raise SystemExit(state['main']())\n"
        )

        def snapshot():
            result = {}
            for path in Path(self.temporary).rglob("*"):
                result[str(path)] = (
                    ("link", str(path.readlink()))
                    if path.is_symlink()
                    else ("directory", path.stat().st_mode)
                    if path.is_dir()
                    else ("file", path.stat().st_mode, path.read_bytes())
                )
            return result

        for relation, home in (
            ("same", directory),
            ("Cargo-home-ancestor", directory.parent),
            ("Cargo-home-descendant", directory / "cargo-home"),
        ):
            home.mkdir(parents=True, exist_ok=True)
            credential = home / "credentials.toml"
            credential.write_bytes(b"preserve nonsecret Cargo credential fixture\n")
            before = snapshot()
            for action, _consumer, tail in self.ACTIONS:
                for route in (directory, directory.relative_to(self.root)):
                    with self.subTest(action=action, relation=relation, route=str(route)):
                        result = self.cli_action(code, action, route, tail, home)
                        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                        self.assertIn("execution paths overlap Cargo home", result.stderr)
                        self.assertFalse(callback.exists())
                        self.assertEqual(snapshot(), before)
                        self.assert_receipts_unchanged(receipts)
                        self.assertEqual(self.calls(), [])

    def test_cli_directory_actions_admit_disjoint_normalized_routes_without_receipt_env(self):
        self.seed_stale_results()
        receipts = self.saved_receipts()
        directory = self.root / "cli-disjoint-evidence"
        home = Path(self.temporary) / "disjoint-cargo-home"
        home.mkdir()
        credential = home / "credentials.toml"
        credential.write_bytes(b"preserve disjoint nonsecret Cargo fixture\n")
        observed = Path(self.temporary) / "admitted-action.json"
        for action, consumer, tail in self.ACTIONS:
            with self.subTest(action=action):
                code = (
                    "import json,pathlib,runpy,sys\n"
                    "h=runpy.run_path(sys.argv[1]); state=h['main'].__globals__\n"
                    "def consume(path,*args):\n"
                    f" pathlib.Path({str(observed)!r}).write_text(json.dumps({{"
                    "'path':str(path),'absolute':path.is_absolute(),"
                    "'path_type':isinstance(path,pathlib.Path)}))\n"
                    " return path\n"
                    f"state[{consumer!r}]=consume\n"
                    "def forbidden(*args): raise RuntimeError('disjoint dispatch read receipt')\n"
                    "state['load_execution']=state['evidence_text']=forbidden\n"
                    "sys.argv=sys.argv[1:]\n"
                    "raise SystemExit(state['main']())\n"
                )
                result = self.cli_action(code, action, directory.relative_to(self.root), tail, home)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                record = json.loads(observed.read_text())
                self.assertEqual(record["path"], str(directory))
                self.assertTrue(record["absolute"])
                self.assertTrue(record["path_type"])
                self.assertFalse(directory.exists())
                self.assertEqual(
                    credential.read_bytes(), b"preserve disjoint nonsecret Cargo fixture\n"
                )
                self.assert_receipts_unchanged(receipts)
                self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
