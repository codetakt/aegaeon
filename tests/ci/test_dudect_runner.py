# ruff: noqa: PT009, PT027, S603 - unittest assertions and controlled tool argv
"""Fresh native execution, failed evidence retention and required caller behavior."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from dudect_fixture import ROOT, NativeFixture

sys.path.insert(0, str(ROOT / "scripts/ci"))
from collect_dudect_nix_output import (
    CORE_TIMING_CHECKS,
    collect_core_outputs,
    collect_output,
    store_output,
)

sys.path.insert(0, str(ROOT / "tests/constant_time"))
import run_contract
from run_contract import execute, validate_report_file


class DudectRunnerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = NativeFixture(self)

    def assert_failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.fixture.report_path().exists())
        evidence = self.fixture.evidence()
        if evidence:
            self.assertFalse(json.loads((evidence[-1] / "status.json").read_text())["accepted"])

    def test_each_required_source_must_be_present(self):
        for relative in (
            "c/dudect.h",
            "tests/constant_time/contracts/case-contract-candidate.json",
            "flake.lock",
        ):
            path = self.fixture.root / relative
            original = path.read_bytes()
            path.unlink()
            # Missing headers cannot disappear silently from the checked input manifest.
            if relative == "c/dudect.h":
                path.symlink_to(self.fixture.directory / "absent")
            self.assert_failed(self.fixture.invoke("--suite", "nix"))
            path.unlink(missing_ok=True)
            path.write_bytes(original)

    def test_bad_compiler_outputs_never_execute_prior_binary(self):
        stale = self.fixture.root / "dudect_test"
        stale.write_text("stale build output")
        for options in (
            {"compiler_exit": 31},
            {"omit_binary": True},
            {"empty_binary": True},
            {"nonexecutable_binary": True},
            {"directory_binary": True},
        ):
            with self.subTest(options=options):
                result = self.fixture.invoke("--suite", "nix", **options)
                self.assert_failed(result)
                self.assertFalse(self.fixture.events.exists())
                self.assertEqual(stale.read_text(), "stale build output")
                if "compiler_exit" in options:
                    self.assertEqual(result.returncode, 31)

    def test_process_failures_and_malformed_streams_retain_raw_evidence(self):
        for options in (
            {"exit": 43},
            {"signal": True},
            {"empty": True},
            {"invalid": True},
            {"trailing": True},
            {"late_exit": True},
        ):
            with self.subTest(options=options):
                result = self.fixture.invoke("--suite", "nix", **options)
                self.assert_failed(result)
                native = self.fixture.evidence()[-1] / "executions/dudect_controls"
                self.assertTrue((native / "native.stdout").is_file())
                self.assertTrue((native / "process.json").is_file())
                if options.get("exit"):
                    self.assertEqual(result.returncode, 43)
                if options.get("signal"):
                    self.assertEqual(result.returncode, 143)

    def test_stale_report_is_archived_before_build_failure(self):
        self.fixture.report_path().parent.mkdir()
        self.fixture.report_path().write_text("old accepted report")
        self.assert_failed(self.fixture.invoke("--suite", "nix", compiler_exit=31))
        self.assertEqual(
            (self.fixture.evidence()[-1] / "previous-results/report.json").read_text(),
            "old accepted report",
        )

    def test_both_profiles_and_adapters_preserve_native_binding(self):
        for profile, adapter in (("pr", "shell"), ("periodic", "xtask")):
            result = self.fixture.invoke("--profile", profile, "--adapter", adapter)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            validate_report_file(self.fixture.root, self.fixture.report_path())
            evidence = self.fixture.evidence()[-1]
            manifest = json.loads(
                (evidence / "package/native/compare/build-manifest.json").read_text()
            )
            self.assertEqual(Path(manifest["compiler"]).name, "cc" if adapter == "shell" else "gcc")

    def test_native_package_reuse_still_executes_and_rejects_changed_source(self):
        result = self.fixture.invoke("--suite", "nix")
        self.assertEqual(result.returncode, 0, result.stderr)
        package = self.fixture.evidence()[-1] / "package"
        before = len(self.fixture.events.read_text().splitlines())
        result = self.fixture.invoke("--suite", "nix", "--native-package", str(package))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.fixture.events.read_text().splitlines()), before + 2)
        path = self.fixture.root / "c/dudect.h"
        path.write_text(path.read_text() + "\n")
        self.assert_failed(self.fixture.invoke("--suite", "nix", "--native-package", str(package)))
        self.assertEqual(len(self.fixture.events.read_text().splitlines()), before + 2)

    def test_wrapper_requires_environment_and_preserves_exit(self):
        for variable in ("OUT_DIR", "EVERCRYPT_DIST"):
            with patch.dict("os.environ", {}):
                env = self.fixture.environment()
                env.pop(variable)
                result = subprocess.run(
                    [shutil.which("bash"), "scripts/flake/verify_dudect.sh"],
                    cwd=self.fixture.root,
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
        result = self.fixture.invoke(wrapper=True, exit=43)
        self.assertEqual(result.returncode, 43)
        self.assertIn("Dudect failed:", (self.fixture.output / "dudect.log").read_text())

    def test_failed_status_or_report_publication_cannot_leave_success(self):
        args = SimpleNamespace(suite="nix", profile="pr", adapter="shell", native_package=None)
        original = run_contract.write_json

        def fail_accepted_status(path, data):
            if path.name == "status.json" and data.get("accepted") is True:
                message = "injected status write failure"
                raise OSError(message)
            original(path, data)

        for failure in ("status", "publish"):
            replacement = (
                patch.object(run_contract, "write_json", side_effect=fail_accepted_status)
                if failure == "status"
                else patch.object(
                    run_contract, "publish", side_effect=OSError("injected publish failure")
                )
            )
            with (
                patch.dict("os.environ", self.fixture.environment()),
                replacement,
                self.assertRaises(OSError),
            ):
                execute(self.fixture.root, args, self.fixture.output / "evidence")
            self.assertFalse(self.fixture.report_path().exists())
            evidence = self.fixture.evidence()[-1]
            self.assertFalse(json.loads((evidence / "status.json").read_text())["accepted"])
            with self.assertRaisesRegex(ValueError, "did not finish"):
                validate_report_file(self.fixture.root, evidence / "report.json")

    def test_shared_lock_rejects_a_concurrent_run_without_archiving_report(self):
        output = self.fixture.report_path().parent
        output.mkdir()
        self.fixture.report_path().write_text("previous report")
        with (output / ".legacy-run.lock").open("a") as lock:
            run_contract.fcntl.flock(lock.fileno(), run_contract.fcntl.LOCK_EX)
            result = self.fixture.invoke("--suite", "nix")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Another dudect run", result.stderr)
        self.assertEqual(self.fixture.report_path().read_text(), "previous report")

    def test_actual_workflow_collects_current_source_bound_legacy_evidence(self):
        document = yaml.safe_load((ROOT / ".github/workflows/verification.yml").read_text())
        step = next(
            row
            for row in document["jobs"]["verified-reqs"]["steps"]
            if row.get("name") == "Collect fresh legacy timing observations"
        )
        command = shlex.split(step["run"])
        prefix = ["nix", "develop", ".#verification", "--command"]
        self.assertEqual(command[:4], prefix)
        result = subprocess.run(
            command[4:],
            cwd=self.fixture.root,
            env=self.fixture.environment(),
            capture_output=True,
            text=True,
            check=False,
            timeout=40,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        validate_report_file(
            self.fixture.root, self.fixture.root / "artifacts/ct/dudect/report.json"
        )

    def caller_script(self):
        source = (ROOT / "flake.nix").read_text().split("mkVerification =", 1)[1]
        source = source.split("mkLightVerification =", 1)[0]
        script = re.search(r"''\n(.*?)\n\s*'';", source, re.DOTALL).group(1)
        substitutions = {
            "src": self.fixture.root,
            "haclStar": self.fixture.directory,
            "steel": self.fixture.directory,
            "evercryptDist": self.fixture.directory,
            "pkgs.bash": Path(shutil.which("bash")).parents[1],
            "scriptPath": self.fixture.root / "scripts/flake/verify_dudect.sh",
        }
        for name, value in substitutions.items():
            script = script.replace("${" + name + "}", shlex.quote(str(value)))
        self.assertNotIn("${", script)
        return script

    def test_verified_reqs_retains_bundle_outside_temporary_build_source(self):
        source = (ROOT / "scripts/flake/verify_reqs.sh").read_text()
        start = source.index("\tdudect_output=")
        script = source[start : source.index('\n\techo ""', start)]
        validator = self.fixture.root / "scripts/validation/check_dudect.py"
        validator.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / "scripts/validation/check_dudect.py", validator)
        for position, options in enumerate(({"compiler_exit": 31}, {"exit": 43}, {})):
            self.fixture.options.write_text(json.dumps(options))
            output = self.fixture.directory / f"retained output {position}"
            output.mkdir()
            result = subprocess.run(
                [shutil.which("bash"), "-e", "-o", "pipefail", "-c", script],
                cwd=self.fixture.root,
                env={**self.fixture.environment(), "OUT_DIR": str(output)},
                capture_output=True,
                text=True,
                check=False,
                timeout=40,
            )
            report = output / "dudect/report.json"
            self.assertEqual(result.returncode == 0, not options, result.stdout + result.stderr)
            self.assertEqual(report.exists(), not options)
            runs = list((output / "dudect/runs").iterdir())
            self.assertEqual(len(runs), 1)
            status = json.loads((runs[0] / "status.json").read_text())
            self.assertEqual(status["accepted"], not options)
        # The build workspace can disappear; native sources, executables and
        # stdout must still be sufficient for validation against current inputs.
        shutil.rmtree(self.fixture.root)
        validate_report_file(ROOT, report)

    def test_actual_nix_caller_marks_success_only_after_valid_observations(self):
        for position, options in enumerate(({"compiler_exit": 31}, {"exit": 43}, {})):
            self.fixture.options.write_text(json.dumps(options))
            build = self.fixture.directory / f"build-{position}"
            build.mkdir()
            output = self.fixture.directory / f"caller-{position}"
            result = subprocess.run(
                [shutil.which("bash"), "-e", "-o", "pipefail", "-c", self.caller_script()],
                cwd=build,
                env={**self.fixture.environment(), "out": str(output), "TMPDIR": str(build)},
                capture_output=True,
                text=True,
                check=False,
                timeout=40,
            )
            self.assertEqual(
                (output / "success").exists(), not options, result.stdout + result.stderr
            )
            self.assertEqual(result.returncode == 0, not options, result.stdout + result.stderr)


class DudectNixRetentionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def finalize_output(self, output, status, *, nix=True, extra_env=None):
        environment = {**os.environ, "OUT_DIR": str(output)}
        environment.pop("out", None)
        if nix:
            environment["out"] = str(output)
        environment.update(extra_env or {})
        script = "source " + shlex.quote(str(ROOT / "scripts/flake/dudect_output_permissions.sh"))
        return subprocess.run(
            [shutil.which("bash"), "-euo", "pipefail", "-c", script + f"\nexit {status}"],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def test_builder_exits_publish_private_evidence_without_changing_status_or_bytes(self):
        for status, nix in ((0, True), (23, True), (23, False)):
            with self.subTest(status=status, nix=nix):
                output = self.root / f"output-{status}-{nix}"
                run = output / "runs/private-run"
                run.mkdir(parents=True, mode=0o700)
                samples = run / "native.samples"
                samples.write_bytes(b"partial original evidence")
                samples.chmod(0o600)
                result = self.finalize_output(output, status, nix=nix)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(run.stat().st_mode & 0o777, 0o755 if nix else 0o700)
                self.assertEqual(samples.stat().st_mode & 0o777, 0o644 if nix else 0o600)
                self.assertEqual(samples.read_bytes(), b"partial original evidence")

    def test_permission_failure_cannot_publish_success_or_replace_original_failure(self):
        output = self.root / "output"
        output.mkdir()
        tools = self.root / "tools"
        tools.mkdir()
        chmod = tools / "chmod"
        chmod.write_text("#!" + shutil.which("bash") + "\nexit 41\n")
        chmod.chmod(0o755)
        for status in (0, 23):
            result = self.finalize_output(
                output, status, extra_env={"PATH": str(tools) + os.pathsep + os.environ["PATH"]}
            )
            self.assertEqual(result.returncode, 1 if status == 0 else status, result.stderr)
            self.assertIn("Could not make Dudect Nix evidence readable", result.stderr)

    def test_permission_finalization_does_not_follow_output_symlinks(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        secret = outside / "private"
        secret.write_bytes(b"unrelated private data")
        secret.chmod(0o600)
        output = self.root / "output"
        output.mkdir()
        (output / "link").symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.finalize_output(output, 23).returncode, 23)
        self.assertEqual(outside.stat().st_mode & 0o777, 0o700)
        self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
        root_link = self.root / "root-link"
        root_link.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.finalize_output(root_link, 0).returncode, 1)
        self.assertEqual(outside.stat().st_mode & 0o777, 0o700)

    def test_failed_build_output_preserves_partial_native_evidence(self):
        source = self.root / "failed-output"
        source.mkdir()
        (source / "native.samples").write_bytes(b"partial original samples")
        (source / "native.stderr").write_text("native failure")
        destination = self.root / "retained"
        collect_output(source, "failure", destination)
        self.assertEqual(
            (destination / "nix-output/native.samples").read_bytes(),
            b"partial original samples",
        )
        record = json.loads((destination / "collection.json").read_text())
        self.assertTrue(record["output_retained"])
        self.assertEqual(record["build_step_outcome"], "failure")
        self.assertFalse(record["fresh_timing_asserted"])
        with self.assertRaises(FileExistsError):
            collect_output(source, "success", destination)

    def test_failure_before_output_creation_records_absence(self):
        destination = self.root / "absent"
        collect_output(None, "failure", destination)
        record = json.loads((destination / "collection.json").read_text())
        self.assertTrue(record["missing_output"])
        self.assertFalse(record["output_retained"])
        with self.assertRaises(ValueError):
            collect_output(self.root / "missing", "success", self.root / "bad-success")

    def test_copy_failure_is_recorded_and_cannot_claim_retention(self):
        source = self.root / "source"
        source.mkdir()
        destination = self.root / "copy-failure"
        with (
            patch("collect_dudect_nix_output.shutil.copytree", side_effect=OSError("disk full")),
            self.assertRaises(OSError),
        ):
            collect_output(source, "failure", destination)
        record = json.loads((destination / "collection.json").read_text())
        self.assertEqual(record["collection_error"], "disk full")
        self.assertFalse(record["output_retained"])

    def test_output_paths_and_symlinks_cannot_redirect_collection(self):
        self.assertIsNone(store_output(""))
        for path in ("/etc", "/nix/store/../etc", "/nix/store/" + "a" * 32 + "-unrelated"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                store_output(path)
        for name in ("verify-reqs", "verify-dudect"):
            path = "/nix/store/" + "a" * 32 + "-" + name
            self.assertEqual(store_output(path), Path(path))
        source = self.root / "links"
        source.mkdir()
        (source / "redirect").symlink_to(self.root / "outside")
        with self.assertRaises(ValueError):
            collect_output(source, "failure", self.root / "rejected")

    def test_workflow_collects_and_uploads_after_attempted_nix_build(self):
        document = yaml.safe_load((ROOT / ".github/workflows/verification.yml").read_text())
        steps = document["jobs"]["verified-reqs"]["steps"]
        build = next(i for i, row in enumerate(steps) if row.get("id") == "verified-reqs-nix")
        self.assertIn("nix eval --raw .#verified-reqs.outPath", steps[build]["run"])
        self.assertIn("nix build .#verified-reqs --keep-failed -L", steps[build]["run"])
        collect, upload = steps[build + 1 : build + 3]
        self.assertIn("collect_dudect_nix_output.py", collect["run"])
        self.assertIn("always()", collect["if"])
        self.assertEqual(collect["if"], upload["if"])
        self.assertIn('["success", "failure", "cancelled"]', collect["if"])
        self.assertEqual(upload["with"]["path"], "artifacts/ct/dudect-nix-gate/")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

    def core_outputs(self, outcomes):
        rows = {
            name: {
                "store_output": "/nix/store/" + "a" * 32 + "-" + package,
                "build_step_outcome": outcome,
            }
            for (name, package), outcome in zip(CORE_TIMING_CHECKS.items(), outcomes, strict=True)
        }
        record = self.root / "core-outputs.json"
        record.write_text(json.dumps(rows))
        return record, rows

    def test_core_collector_preserves_failure_and_unstarted_state(self):
        record, rows = self.core_outputs(("failure", "not_started"))
        destination = self.root / "core-collected"
        with patch("collect_dudect_nix_output.collect_output") as collect:
            collect_core_outputs(record, destination)
        self.assertEqual(collect.call_count, 2)
        for call, (name, row) in zip(collect.call_args_list, rows.items(), strict=True):
            self.assertEqual(
                call.args,
                (Path(row["store_output"]), row["build_step_outcome"], destination / name),
            )
        # An unstarted gate must not copy pre-existing cache output.
        source = self.root / "cached-output"
        source.mkdir()
        (source / "old-evidence").write_text("old")
        collect_output(source, "not_started", self.root / "unstarted")
        state = json.loads((self.root / "unstarted/collection.json").read_text())
        self.assertTrue(state["not_attempted"])
        self.assertFalse(state["output_retained"])
        self.assertFalse((self.root / "unstarted/nix-output").exists())

    def test_core_collection_error_does_not_discard_other_gate_output(self):
        record, _ = self.core_outputs(("failure", "in_progress"))
        with (
            patch(
                "collect_dudect_nix_output.collect_output", side_effect=[OSError("denied"), None]
            ) as collect,
            self.assertRaisesRegex(ValueError, "verifyDudect: denied"),
        ):
            collect_core_outputs(record, self.root / "core-errors")
        self.assertEqual(collect.call_count, 2)
        self.assertEqual(collect.call_args_list[1].args[1], "in_progress")

    def test_core_collector_validates_complete_inventory_before_copying(self):
        record, rows = self.core_outputs(("success", "failure"))
        mutations = [
            {"verifyDudect": rows["verifyDudect"]},
            {**rows, "other": rows["verifyDudect"]},
            {
                **rows,
                "verifyDudect": {
                    **rows["verifyDudect"],
                    "store_output": rows["verified-reqs"]["store_output"],
                },
            },
            {**rows, "verifyDudect": {**rows["verifyDudect"], "build_step_outcome": "passed"}},
        ]
        for changed in mutations:
            with (
                self.subTest(changed=changed),
                patch("collect_dudect_nix_output.collect_output") as collect,
            ):
                record.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    collect_core_outputs(record, self.root / "invalid-core")
                collect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
