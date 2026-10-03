# ruff: noqa: PT009 - these controls run under unittest discovery
"""Exercise sanitizer status preservation through the real security dispatcher."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest

import test_security_fuzz as fuzz_fixture

NIX = r"""
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
args = sys.argv[1:]
expected = ['develop', '.#asan', '--command', 'bash', 'scripts/sanitizers/run_sanitizers.sh']
sanitizer = args == expected
code = int(os.environ.get('SANITIZER_CHILD_EXIT' if sanitizer else 'SBOM_EXIT', '0'))
with (root / 'dispatch-calls.jsonl').open('a') as out:
    out.write(json.dumps({'kind': 'sanitizer' if sanitizer else 'nix-other',
                         'args': args, 'exit_code': code}) + '\n')
if sanitizer:
    directory = pathlib.Path(os.environ['SANITIZER_ARTIFACT_DIR'])
    (directory / 'child-receipt.json').write_text(json.dumps({'exit_code': code}))
    scratch = root / 'target/sanitizers'
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / 'child-output').write_text('transient sanitizer output')
    print('sanitizer child diagnostic: SUCCESS! exit=' + str(code))
else:
    print('optional SBOM fixture exit=' + str(code))
raise SystemExit(code)
"""

RM = r"""
import json, os, pathlib, sys
args = sys.argv[1:]
if 'target/sanitizers' in args:
    root = pathlib.Path(os.environ['FIXTURE_ROOT'])
    code = int(os.environ.get('SANITIZER_CLEANUP_EXIT', '0'))
    with (root / 'dispatch-calls.jsonl').open('a') as out:
        out.write(json.dumps({'kind': 'cleanup', 'args': args, 'exit_code': code}) + '\n')
    if code:
        print('sanitizer cleanup failed with exit=' + str(code), file=sys.stderr)
        raise SystemExit(code)
os.execv(ACTUAL_RM, [ACTUAL_RM] + args)
"""

TEE = r"""
import os, subprocess, sys
text = sys.stdin.read()
marker = os.environ.get('SANITIZER_LOG_FAILURE', '')
if marker and marker in text:
    print('controlled sanitizer log write failure', file=sys.stderr)
    raise SystemExit(74)
raise SystemExit(subprocess.run([ACTUAL_TEE] + sys.argv[1:], input=text, text=True).returncode)
"""

VET = r"""
import json, os, pathlib, sys
if sys.argv[1:2] == ['vet']:
    code = int(os.environ.get('VET_EXIT', '0'))
    with (pathlib.Path(os.environ['FIXTURE_ROOT']) / 'dispatch-calls.jsonl').open('a') as out:
        out.write(json.dumps({'kind': 'vet', 'exit_code': code}) + '\n')
    print('optional cargo vet fixture exit=' + str(code))
    raise SystemExit(code)
"""


class SanitizerDispatchTests(unittest.TestCase):
    def fixture(self):
        fixture = fuzz_fixture.SecurityFuzzTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.install("nix", NIX)
        fixture.install("rm", "ACTUAL_RM = " + repr(shutil.which("rm")) + "\n" + RM)
        fixture.install("tee", "ACTUAL_TEE = " + repr(shutil.which("tee")) + "\n" + TEE)
        fixture.install("cargo", VET + fuzz_fixture.CARGO)
        return fixture

    def run_suite(self, fixture, *, aggregate=False, case="ok", **environment):
        return subprocess.run(  # noqa: S603 - real wrapper with controlled fixture tools
            [
                str(fixture.bin / "bash"),
                str(fixture.root / "scripts/security/run_security_suite.sh"),
                *([] if aggregate else ["--stage", "sanitizers"]),
            ],
            cwd=fixture.root,
            env={**fixture.env, "CASE": case, **environment},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def calls(self, fixture, kind):
        path = fixture.root / "dispatch-calls.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [row for row in rows if row["kind"] == kind]

    def receipt(self, fixture):
        return json.loads((fixture.artifacts / "sanitizers/child-receipt.json").read_text())

    def test_selected_and_aggregate_success_preserve_artifacts_after_cleanup(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(fixture, aggregate=aggregate)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                self.assertEqual(len(self.calls(fixture, "sanitizer")), 1)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
                self.assertFalse((fixture.root / "target/sanitizers").exists())

    def test_child_failure_code_survives_successful_or_failed_cleanup(self):
        for aggregate in (False, True):
            for cleanup in (0, 79):
                with self.subTest(aggregate=aggregate, cleanup=cleanup):
                    fixture = self.fixture()
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SANITIZER_CHILD_EXIT="71",
                        SANITIZER_CLEANUP_EXIT=str(cleanup),
                    )
                    self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], 71)
                    self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], cleanup)
                    self.assertEqual((fixture.root / "target/sanitizers").exists(), cleanup != 0)

    def test_cleanup_failure_blocks_a_successful_child(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(fixture, aggregate=aggregate, SANITIZER_CLEANUP_EXIT="79")
                self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 79)
                self.assertTrue((fixture.root / "target/sanitizers/child-output").is_file())

    def test_artifact_directory_failure_does_not_launch_the_child(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                fixture.artifacts.mkdir()
                (fixture.artifacts / "sanitizers").write_text("not a directory")
                result = self.run_suite(fixture, aggregate=aggregate)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.calls(fixture, "sanitizer"), [])
                self.assertEqual((fixture.artifacts / "sanitizers").read_text(), "not a directory")

    def test_entry_and_completion_log_write_failures_are_blocking(self):
        for aggregate in (False, True):
            for marker, launched in (
                (">>> sanitizer smoke", False),
                ("<<< sanitizer smoke: ok", True),
            ):
                with self.subTest(aggregate=aggregate, marker=marker):
                    fixture = self.fixture()
                    result = self.run_suite(
                        fixture, aggregate=aggregate, SANITIZER_LOG_FAILURE=marker
                    )
                    self.assertEqual(result.returncode, 74, result.stdout + result.stderr)
                    self.assertEqual(bool(self.calls(fixture, "sanitizer")), launched)
                    if launched:
                        self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)

    def test_failed_diagnostic_write_does_not_replace_the_child_failure(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(
                    fixture,
                    aggregate=aggregate,
                    SANITIZER_CHILD_EXIT="71",
                    SANITIZER_LOG_FAILURE="<<< sanitizer smoke: failed",
                )
                self.assertEqual(result.returncode, 71, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 71)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)

    def test_aggregate_runs_sanitizers_after_fuzz_failure_and_preserves_both_results(self):
        fixture = self.fixture()
        result = self.run_suite(
            fixture,
            aggregate=True,
            case="run-fail",
            FAIL_TARGET=fuzz_fixture.TARGETS[0],
            SANITIZER_CHILD_EXIT="71",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(fixture.summary()["status"], "failed")
        self.assertEqual(fixture.summary()["execution"]["targets"][0]["run"]["exit_code"], 23)
        self.assertEqual(self.receipt(fixture)["exit_code"], 71)
        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
        log = (fixture.artifacts / "summary/security.log").read_text()
        self.assertLess(log.index("cargo fuzz smoke: failed"), log.index(">>> sanitizer smoke"))
        self.assertIn("sanitizer smoke: failed (exit=71)", log)
        self.assertTrue((fixture.artifacts / "fuzz/collection.ok").is_file())

    def test_optional_vet_and_sbom_findings_remain_non_blocking(self):
        fixture = self.fixture()
        result = self.run_suite(fixture, aggregate=True, VET_EXIT="37", SBOM_EXIT="43")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.receipt(fixture)["exit_code"], 0)
        self.assertTrue(self.calls(fixture, "vet"))
        self.assertTrue(all(row["exit_code"] == 37 for row in self.calls(fixture, "vet")))
        self.assertEqual(self.calls(fixture, "nix-other")[0]["exit_code"], 43)
        log = (fixture.artifacts / "summary/security.log").read_text()
        self.assertIn("cargo vet check: reported findings (non-blocking)", log)
        self.assertIn("SBOM scan: reported findings (non-blocking)", log)


if __name__ == "__main__":
    unittest.main()
