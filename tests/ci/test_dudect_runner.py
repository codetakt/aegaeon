# ruff: noqa: PT009, PT027, S603 - unittest assertions and controlled tool argv
"""Fresh native execution, failed evidence retention and required caller behavior."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from dudect_fixture import ROOT, NativeFixture

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


if __name__ == "__main__":
    unittest.main()
