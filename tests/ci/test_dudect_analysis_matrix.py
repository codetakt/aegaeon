"""Matrix admission failures; full packaged replay is checked on retained raw separately."""

# This module uses the repository's unittest runner, including under python -O.
# ruff: noqa: PT009, PT027
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "matrix", ROOT / "scripts/ci/verify_dudect_analysis_matrix.py"
)
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.output = self.root / "output"
        self.output.mkdir()
        self.analysis = self.root / "analysis"
        command = self.analysis / "bin/dudect-analysis"
        command.parent.mkdir(parents=True)
        command.write_text("pinned verifier fixture\n")
        contract = json.loads(
            (ROOT / "tests/constant_time/contracts/case-contract-candidate.json").read_text()
        )
        path = (
            self.analysis
            / "libexec/dudect-analysis/source/tests/constant_time/contracts"
            / "case-contract-candidate.json"
        )
        write(path, contract)
        self.plan = {
            "schema": matrix.PLAN_SCHEMA,
            "adopted": False,
            "cycles": ["r1"],
            "packet": "fixed-campaign",
            "mode": "distributed",
            "analysis_package": {
                "path": str(self.analysis),
                "executable_sha256": matrix.sha256(command),
            },
            "case_contract_sha256": matrix.sha256(path),
            "native_packages": {},
            "units": [],
        }
        for compiler, suite in sorted(matrix.CELLS):
            self.add_cell(compiler, suite, contract)
        self.addCleanup(patch.stopall)
        # Only immutable path syntax and the packaged replay boundary are mocked.
        # Real index/contract/report reads, hashes and all aggregation logic run.
        patch.object(matrix, "store_path", side_effect=Path).start()
        self.run = patch.object(matrix.subprocess, "run", side_effect=self.replay).start()

    def add_cell(self, compiler, suite, contract):
        cell = f"{compiler}-{suite}"
        names = [
            r["stable_id"].split("/")[1]
            for r in contract["cases"]
            if r["stable_id"].split("/")[0] == suite
        ]
        package = self.root / cell
        index = {
            "suite": suite,
            "contract_sha256": self.plan["case_contract_sha256"],
            "executables": [{"cases": names, "sha256": compiler}],
        }
        write(package / "package.json", index)
        self.plan["native_packages"][cell] = {
            "path": str(package),
            "index_sha256": matrix.sha256(package / "package.json"),
        }
        unit = {"id": f"r1-{cell}", "cycle": "r1", "compiler": compiler, "suite": suite}
        unit["analysis"] = {
            "packet": self.plan["packet"],
            "unit": unit["id"],
            "mode": "distributed",
            "adopted": False,
            "implementation": "pinned",
        }
        self.plan["units"].append(unit)
        report = {
            "kind": matrix.REPORT_KIND,
            "adopted": False,
            "profile": "pr",
            "suite": suite,
            "analysis": unit["analysis"],
            "native_package": index,
            "gate_satisfied": True,
            "assessment": [
                {"case_id": f"{suite}/{n}", "requirement_satisfied": True} for n in names
            ],
        }
        write(self.path(unit), report)

    def path(self, unit=None):
        return self.evidence / (unit or self.plan["units"][0])["id"] / "gate/research-report.json"

    def change_report(self, function):
        path = self.path()
        report = json.loads(path.read_text())
        function(report)
        write(path, report)

    def replay(self, argv, **kwargs):
        self.assertEqual(argv[1], "--output")
        self.assertEqual(argv[3:], ["--verify-only"])
        report = json.loads((Path(argv[2]) / "research-report.json").read_text())
        return subprocess.CompletedProcess(argv, 0 if report["gate_satisfied"] else 1)

    def aggregate(self):
        return matrix.aggregate(self.plan, self.evidence, self.output)

    def test_complete_matrix_remains_research_only(self):
        result = self.aggregate()
        self.assertTrue(result["research_requirements_satisfied"])
        self.assertTrue(result["verification_complete"])
        self.assertFalse(result["ci_admission"])
        self.assertFalse(result["fresh_measurements"])
        self.assertEqual(sum(len(r["assessment"]) for r in result["units"]), 42)
        self.assertEqual(self.run.call_count, 4)

    def test_missing_or_duplicate_matrix_cell(self):
        original = copy.deepcopy(self.plan)
        for change in (lambda p: p["units"].pop(), lambda p: p["units"].append(p["units"][0])):
            self.plan = copy.deepcopy(original)
            change(self.plan)
            with self.assertRaises(ValueError):
                self.aggregate()
        self.run.assert_not_called()

    def test_missing_evidence_does_not_hide_other_units(self):
        self.path().unlink()
        result = self.aggregate()
        self.assertFalse(result["verification_complete"])
        self.assertFalse(result["research_requirements_satisfied"])
        self.assertEqual(len(result["units"]), 4)
        self.assertEqual(self.run.call_count, 3)

    def test_report_mutations_are_rejected(self):
        original = json.loads(self.path().read_text())
        mutations = [
            lambda r: r["assessment"].pop(),
            lambda r: r["assessment"].append(r["assessment"][0]),
            lambda r: r["assessment"].reverse(),
            lambda r: r.update(profile="periodic"),
            lambda r: r.update(adopted=True),
            lambda r: r.update(gate_satisfied=1),
            lambda r: r["analysis"].update(unit="another-run"),
            lambda r: r["analysis"].update(mode="interval-only"),
            lambda r: r["native_package"]["executables"][0].update(sha256="another-compiler"),
        ]
        for change in mutations:
            with self.subTest(change=change):
                write(self.path(), original)
                self.change_report(change)
                result = self.aggregate()
                self.assertFalse(result["units"][0]["evidence_verified"])
                self.assertFalse(result["research_requirements_satisfied"])

    def test_statistical_failure_is_verified_but_not_passed(self):
        self.change_report(lambda r: r["assessment"][0].update(requirement_satisfied=False))
        self.change_report(lambda r: r.update(gate_satisfied=False))
        result = self.aggregate()
        self.assertTrue(result["verification_complete"])
        self.assertFalse(result["research_requirements_satisfied"])
        self.assertEqual(self.run.call_count, 4)

    def test_gate_flag_cannot_override_failed_role(self):
        self.change_report(lambda r: r["assessment"][0].update(requirement_satisfied=False))
        result = self.aggregate()
        self.assertFalse(result["verification_complete"])

    def test_replay_exception_exit_one_is_not_a_verified_statistical_failure(self):
        self.change_report(lambda r: r.update(gate_satisfied=False))
        self.change_report(lambda r: r["assessment"][0].update(requirement_satisfied=False))

        def failure(argv, **kwargs):
            kwargs["stdout"].write(b"Traceback: corrupted proof\n")
            return subprocess.CompletedProcess(argv, 1)

        self.run.side_effect = failure
        result = self.aggregate()
        self.assertFalse(result["verification_complete"])
        self.assertEqual(len(result["units"]), 4)

    def test_replay_failure_timeout_and_signal(self):
        for failure in (subprocess.CompletedProcess([], -9), subprocess.TimeoutExpired([], 900)):
            with self.subTest(failure=failure):
                self.run.side_effect = failure if isinstance(failure, Exception) else None
                self.run.return_value = failure
                self.assertFalse(self.aggregate()["verification_complete"])

    def test_execution_failure_marker_is_not_ignored(self):
        write(self.path().parent / "execution-failure.json", {"error": "interrupted"})
        self.assertFalse(self.aggregate()["verification_complete"])

    def test_report_change_during_replay_rejected(self):
        def changing(argv, **kwargs):
            result = self.replay(argv, **kwargs)
            path = Path(argv[2]) / "research-report.json"
            path.write_text(path.read_text() + "\n")
            return result

        self.run.side_effect = changing
        self.assertFalse(self.aggregate()["verification_complete"])

    def test_package_or_contract_change_rejected_before_replay(self):
        pin = self.plan["native_packages"]["gcc-nix"]
        path = Path(pin["path"]) / "package.json"
        path.write_text(path.read_text() + "\n")
        with self.assertRaises(ValueError):
            self.aggregate()
        self.run.assert_not_called()

    def test_analysis_policy_mixture_rejected(self):
        self.plan["units"][0]["analysis"]["implementation"] = "changed"
        with self.assertRaises(ValueError):
            self.aggregate()

    def test_cli_rejects_plan_digest_and_retains_failure(self):
        path = self.root / "plan.json"
        write(path, self.plan)
        output = self.root / "cli-output"
        with patch.object(
            sys,
            "argv",
            [
                "verify",
                "--plan",
                str(path),
                "--plan-sha256",
                "wrong",
                "--evidence",
                str(self.evidence),
                "--output",
                str(output),
            ],
        ):
            self.assertEqual(matrix.main(), 1)
        self.assertTrue((output / "verification-failure.json").is_file())
        self.run.assert_not_called()

    def test_cli_does_not_write_inside_source_evidence(self):
        output = self.evidence / "new-output"
        with (
            patch.object(
                sys,
                "argv",
                [
                    "verify",
                    "--plan",
                    "unused",
                    "--plan-sha256",
                    "unused",
                    "--evidence",
                    str(self.evidence),
                    "--output",
                    str(output),
                ],
            ),
            self.assertRaises(ValueError),
        ):
            matrix.main()
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
