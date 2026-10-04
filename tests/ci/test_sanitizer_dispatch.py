# ruff: noqa: PT009 - these controls run under unittest discovery
"""Exercise sanitizer status preservation through the real security dispatcher."""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

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
    if not os.environ.get('SANITIZER_UNSAFE_TARGET_TEST'):
        scratch = (root / (os.environ.get('SANITIZER_TARGET_DIR') or 'target/sanitizers')).resolve()
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
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
workspace = root.resolve()
artifacts = (root / os.environ['SECURITY_ARTIFACT_DIR']).resolve()
recursive = any(arg == '--recursive' or
                (arg.startswith('-') and not arg.startswith('--') and 'r' in arg[1:])
                for arg in args)
for arg in args:
    if arg.startswith('-'):
        continue
    resolved = (root / arg).resolve()
    if resolved == workspace or resolved in workspace.parents:
        with (root / 'dispatch-calls.jsonl').open('a') as out:
            out.write(json.dumps({'kind': 'unsafe-cleanup', 'args': args,
                                 'exit_code': 83}) + '\n')
        print('intercepted dangerous cleanup; no deletion delegated', file=sys.stderr)
        raise SystemExit(83)
    overlaps = (resolved == artifacts or resolved in artifacts.parents
                or artifacts in resolved.parents)
    if recursive and overlaps:
        with (root / 'dispatch-calls.jsonl').open('a') as out:
            out.write(json.dumps({'kind': 'artifact-overlap-cleanup', 'args': args,
                                 'exit_code': 84}) + '\n')
        print('intercepted artifact overlap; no deletion delegated', file=sys.stderr)
        raise SystemExit(84)
target = str((root / (os.environ.get('SANITIZER_TARGET_DIR') or 'target/sanitizers')).resolve())
if target in args:
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
        # Aggregate dispatch runs fuzz preflight with controlled fixture tools.
        # Remove inherited native target overrides, retaining the fixture's
        # explicit CC/CXX/AR and owned CARGO_TARGET_DIR from SecurityFuzzFixture.
        for name in tuple(fixture.env):
            if name != "CARGO_TARGET_DIR" and name.startswith(
                (
                    "CC_",
                    "CXX_",
                    "AR_",
                    "CARGO_TARGET_",
                    "TARGET_CC",
                    "TARGET_CXX",
                    "TARGET_AR",
                    "HOST_CC",
                    "HOST_CXX",
                    "HOST_AR",
                )
            ):
                fixture.env.pop(name)
        fixture.env.pop("SANITIZER_TARGET_DIR", None)
        fixture.env.pop("SANITIZER_UNSAFE_TARGET_TEST", None)
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

    def target_directory(self, fixture, setting):
        if setting == "absolute":
            return str(Path(fixture.temporary) / "custom sanitizer outputs")
        if setting == "symlink":
            directory = Path(fixture.temporary) / "resolved sanitizer outputs"
            directory.mkdir()
            (fixture.root / "sanitizer-link").symlink_to(directory, target_is_directory=True)
            return "sanitizer-link"
        return setting

    def unsafe_target_directory(self, fixture, setting):
        if setting in ("workspace-absolute", "parent-absolute"):
            directory = fixture.root if setting == "workspace-absolute" else fixture.root.parent
            return str(directory)
        if setting in ("workspace-symlink", "parent-symlink"):
            destination = fixture.root if setting == "workspace-symlink" else fixture.root.parent
            link = fixture.root / setting
            link.symlink_to(destination, target_is_directory=True)
            return setting
        return setting

    def artifact_target_directory(self, fixture, setting):
        artifact_name = "retained artifacts/security evidence\n"
        fixture.artifacts = fixture.root / artifact_name
        # Resolve the same relative/absolute artifact semantics as ARTIFACT_BASE.
        fixture.env["SECURITY_ARTIFACT_DIR"] = artifact_name
        fixture.artifacts.mkdir(parents=True)
        destinations = {
            "root": fixture.artifacts,
            "descendant": fixture.artifacts / "sanitizers",
            "ancestor": fixture.artifacts.parent,
            "absolute-artifacts": fixture.artifacts / "sanitizers",
        }
        aliases = {
            "root-symlink": fixture.artifacts,
            "ancestor-symlink": fixture.artifacts.parent,
            "descendant-symlink": fixture.artifacts / "sanitizers",
        }
        if setting in destinations:
            target = str(destinations[setting])
            if setting == "absolute-artifacts":
                fixture.env["SECURITY_ARTIFACT_DIR"] = str(fixture.artifacts)
        elif setting == "normalized":
            target = artifact_name + "/missing-parent/.."
        elif setting in aliases:
            destination = aliases[setting]
            destination.mkdir(parents=True, exist_ok=True)
            (fixture.root / setting).symlink_to(destination, target_is_directory=True)
            target = setting
        elif setting == "artifact-symlink":
            (fixture.root / "artifact-alias").symlink_to(
                fixture.artifacts, target_is_directory=True
            )
            fixture.env["SECURITY_ARTIFACT_DIR"] = "artifact-alias"
            target = str(fixture.artifacts)
        else:
            raise ValueError(setting)
        return target

    def seed_retained_evidence(self, fixture):
        files = {
            "sanitizers/run-summary.json": '{"status": "retained"}',
            "sanitizers/raw.stderr.log": "retained sanitizer raw diagnostic",
            "prior-stage/raw.log": "retained earlier-stage evidence",
        }
        for path, text in files.items():
            destination = fixture.artifacts / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)
        return files

    def test_artifact_overlap_cleanup_is_rejected_and_all_evidence_is_preserved(self):
        for aggregate in (False, True):
            for setting in (
                "root",
                "descendant",
                "ancestor",
                "normalized",
                "root-symlink",
                "ancestor-symlink",
                "descendant-symlink",
                "artifact-symlink",
                "absolute-artifacts",
            ):
                for child in (0, 71):
                    with self.subTest(aggregate=aggregate, setting=setting, child=child):
                        fixture = self.fixture()
                        target = self.artifact_target_directory(fixture, setting)
                        retained = self.seed_retained_evidence(fixture)
                        result = self.run_suite(
                            fixture,
                            aggregate=aggregate,
                            SANITIZER_TARGET_DIR=target,
                            SANITIZER_CHILD_EXIT=str(child),
                            SANITIZER_UNSAFE_TARGET_TEST="1",
                        )
                        self.assertEqual(
                            result.returncode, child or 1, result.stdout + result.stderr
                        )
                        self.assertEqual(self.receipt(fixture)["exit_code"], child)
                        self.assertEqual(self.calls(fixture, "cleanup"), [])
                        self.assertEqual(self.calls(fixture, "unsafe-cleanup"), [])
                        self.assertEqual(self.calls(fixture, "artifact-overlap-cleanup"), [])
                        for path, text in retained.items():
                            self.assertEqual((fixture.artifacts / path).read_text(), text)
                        log = (fixture.artifacts / "summary/security.log").read_text()
                        self.assertIn(
                            "sanitizer target overlaps security artifacts; refusing cleanup", log
                        )
                        self.assertIn(
                            "sanitizer child diagnostic: SUCCESS! exit=" + str(child), log
                        )
                        if aggregate:
                            self.assertTrue((fixture.artifacts / "fuzz/collection.ok").is_file())

    def test_sibling_target_cleanup_preserves_retained_evidence(self):
        for aggregate in (False, True):
            for child in (0, 71):
                with self.subTest(aggregate=aggregate, child=child):
                    fixture = self.fixture()
                    self.artifact_target_directory(fixture, "root")
                    retained = self.seed_retained_evidence(fixture)
                    # Preserve similarly named artifact root ending in a newline.
                    target = str(fixture.artifacts).rstrip("\n")
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SANITIZER_TARGET_DIR=target,
                        SANITIZER_CHILD_EXIT=str(child),
                    )
                    self.assertEqual(result.returncode, child, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], child)
                    self.assertFalse(Path(target).exists())
                    self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 0)
                    self.assertEqual(self.calls(fixture, "artifact-overlap-cleanup"), [])
                    for path, text in retained.items():
                        self.assertEqual((fixture.artifacts / path).read_text(), text)
                    self.assertTrue((fixture.artifacts / "summary/security.log").is_file())

    def test_unsafe_target_cleanup_is_rejected_without_removal(self):
        for aggregate in (False, True):
            for setting in (
                ".",
                "workspace-absolute",
                "..",
                "parent-absolute",
                "/",
                "workspace-symlink",
                "parent-symlink",
                "missing-parent/..",
                "missing-parent/../..",
            ):
                for child in (0, 71):
                    with self.subTest(aggregate=aggregate, setting=setting, child=child):
                        fixture = self.fixture()
                        target = self.unsafe_target_directory(fixture, setting)
                        marker = fixture.root / "workspace-marker"
                        marker.write_text("preserve checkout")
                        parent_marker = fixture.root.parent / "parent-marker"
                        parent_marker.write_text("preserve parent")
                        result = self.run_suite(
                            fixture,
                            aggregate=aggregate,
                            SANITIZER_TARGET_DIR=target,
                            SANITIZER_CHILD_EXIT=str(child),
                            SANITIZER_UNSAFE_TARGET_TEST="1",
                        )
                        self.assertEqual(
                            result.returncode, child or 1, result.stdout + result.stderr
                        )
                        self.assertEqual(self.receipt(fixture)["exit_code"], child)
                        self.assertEqual(self.calls(fixture, "cleanup"), [])
                        self.assertEqual(self.calls(fixture, "unsafe-cleanup"), [])
                        self.assertEqual(marker.read_text(), "preserve checkout")
                        self.assertEqual(parent_marker.read_text(), "preserve parent")
                        log = (fixture.artifacts / "summary/security.log").read_text()
                        self.assertIn("unsafe sanitizer target directory; refusing cleanup", log)

    def test_configured_target_cleanup_preserves_unrelated_directories(self):
        for aggregate in (False, True):
            for setting in (
                None,
                "",
                "target/sanitizers",
                "custom sanitizer outputs",
                "absolute",
                "symlink",
                "missing-parent/../normalized outputs",
                "-custom",
            ):
                with self.subTest(aggregate=aggregate, setting=setting):
                    fixture = self.fixture()
                    target = self.target_directory(fixture, setting)
                    default = fixture.root / "target/sanitizers"
                    if target and target != "target/sanitizers":
                        default.mkdir(parents=True)
                        (default / "unrelated-output").write_text("keep default directory")
                    unrelated = fixture.root / "target/unrelated-output"
                    unrelated.parent.mkdir(parents=True, exist_ok=True)
                    unrelated.write_text("keep unrelated output")
                    environment = {} if target is None else {"SANITIZER_TARGET_DIR": target}
                    result = self.run_suite(fixture, aggregate=aggregate, **environment)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                    expected = str((fixture.root / (target or "target/sanitizers")).resolve())
                    cleanup = self.calls(fixture, "cleanup")
                    self.assertEqual(len(cleanup), 1)
                    self.assertEqual(cleanup[0]["args"], ["-rf", "--", expected])
                    self.assertFalse(Path(expected).exists())
                    if setting == "symlink":
                        self.assertTrue((fixture.root / target).is_symlink())
                    self.assertEqual(unrelated.read_text(), "keep unrelated output")
                    if target and target != "target/sanitizers":
                        self.assertEqual(
                            (default / "unrelated-output").read_text(), "keep default directory"
                        )

    def test_trailing_newline_target_cleanup_preserves_similarly_named_sibling(self):
        for aggregate in (False, True):
            for suffix in ("\n", "\n\n"):
                with self.subTest(aggregate=aggregate, suffix=suffix):
                    fixture = self.fixture()
                    target = "custom sanitizer outputs" + suffix
                    sibling = fixture.root / target.rstrip("\n")
                    sibling.mkdir()
                    preserved = sibling / "unrelated-output"
                    preserved.write_text("keep similarly named sibling")
                    result = self.run_suite(
                        fixture, aggregate=aggregate, SANITIZER_TARGET_DIR=target
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                    self.assertEqual(preserved.read_text(), "keep similarly named sibling")
                    expected = str((fixture.root / target).resolve())
                    cleanup = self.calls(fixture, "cleanup")
                    self.assertEqual(len(cleanup), 1)
                    self.assertEqual(cleanup[0]["args"], ["-rf", "--", expected])
                    self.assertFalse(Path(expected).exists())

    def test_custom_target_failure_codes_and_outputs_are_preserved(self):
        for aggregate in (False, True):
            for setting in ("custom sanitizer outputs", "absolute", "symlink", "newline outputs\n"):
                for child, cleanup in ((71, 0), (71, 79), (0, 79)):
                    with self.subTest(
                        aggregate=aggregate, setting=setting, child=child, cleanup=cleanup
                    ):
                        fixture = self.fixture()
                        target = self.target_directory(fixture, setting)
                        result = self.run_suite(
                            fixture,
                            aggregate=aggregate,
                            SANITIZER_TARGET_DIR=target,
                            SANITIZER_CHILD_EXIT=str(child),
                            SANITIZER_CLEANUP_EXIT=str(cleanup),
                        )
                        self.assertEqual(
                            result.returncode, child or cleanup, result.stdout + result.stderr
                        )
                        self.assertEqual(self.receipt(fixture)["exit_code"], child)
                        self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], cleanup)
                        output = fixture.root / target / "child-output"
                        self.assertEqual(output.exists(), cleanup != 0)
                        if cleanup:
                            self.assertEqual(output.read_text(), "transient sanitizer output")

    def test_resolution_failure_preserves_outputs_and_child_status(self):
        for aggregate in (False, True):
            for child in (0, 71):
                with self.subTest(aggregate=aggregate, child=child):
                    fixture = self.fixture()
                    fixture.install(
                        "python3",
                        "import os, sys\n"
                        "if sys.argv[1:2] == ['-c'] "
                        "and 'Path(sys.argv[1]).resolve()' in sys.argv[2]:\n"
                        "    print('controlled target resolution failure', file=sys.stderr)\n"
                        "    raise SystemExit(81)\n"
                        "os.execv(sys.executable, [sys.executable] + sys.argv[1:])\n",
                    )
                    result = self.run_suite(
                        fixture,
                        aggregate=aggregate,
                        SANITIZER_TARGET_DIR="custom sanitizer outputs",
                        SANITIZER_CHILD_EXIT=str(child),
                    )
                    self.assertEqual(result.returncode, child or 81, result.stdout + result.stderr)
                    self.assertEqual(self.receipt(fixture)["exit_code"], child)
                    self.assertEqual(self.calls(fixture, "cleanup"), [])
                    self.assertTrue(
                        (fixture.root / "custom sanitizer outputs/child-output").is_file()
                    )

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
                log = (fixture.artifacts / "summary/security.log").read_text()
                self.assertEqual(log.count("<<< sanitizer smoke: ok"), 1)
                self.assertNotIn("sanitizer cleanup: failed", log)

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
                    log = (fixture.artifacts / "summary/security.log").read_text()
                    self.assertNotIn("<<< sanitizer smoke: ok", log)
                    self.assertIn("sanitizer smoke: failed (exit=71)", log)
                    if cleanup:
                        self.assertIn(f"sanitizer cleanup: failed (exit={cleanup})", log)

    def test_cleanup_failure_blocks_a_successful_child(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(fixture, aggregate=aggregate, SANITIZER_CLEANUP_EXIT="79")
                self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 79)
                self.assertTrue((fixture.root / "target/sanitizers/child-output").is_file())
                log = (fixture.artifacts / "summary/security.log").read_text()
                self.assertNotIn("<<< sanitizer smoke: ok", log)
                self.assertIn("sanitizer cleanup: failed (exit=79)", log)

    def test_failed_cleanup_diagnostic_write_preserves_cleanup_status(self):
        for aggregate in (False, True):
            with self.subTest(aggregate=aggregate):
                fixture = self.fixture()
                result = self.run_suite(
                    fixture,
                    aggregate=aggregate,
                    SANITIZER_CLEANUP_EXIT="79",
                    SANITIZER_LOG_FAILURE="<<< sanitizer cleanup: failed",
                )
                self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
                self.assertEqual(self.receipt(fixture)["exit_code"], 0)
                self.assertEqual(self.calls(fixture, "cleanup")[0]["exit_code"], 79)
                self.assertTrue((fixture.root / "target/sanitizers/child-output").is_file())
                log = (fixture.artifacts / "summary/security.log").read_text()
                self.assertNotIn("<<< sanitizer smoke: ok", log)

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
