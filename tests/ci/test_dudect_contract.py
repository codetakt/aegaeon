# ruff: noqa: PT009, PT027, S603 - unittest behavioral controls
"""Per-case obligations and source-bound evidence cannot be substituted."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest

from dudect_fixture import ROOT, NativeFixture

sys.path.insert(0, str(ROOT / "tests/constant_time"))
from dudect_candidate import CANDIDATE_CASES, CandidateAdmission
from dudect_contract import assess_case, contract_roles
from run_contract import contract_at, validate_report_file
from test_dudect_candidate import observation


class ContractTests(unittest.TestCase):
    def test_ci_inventory_matches_active_observation_contract(self):
        inventory = json.loads((ROOT / "ci/ci-expected-inventory.json").read_text())
        recorded = inventory["families"]["dudect"]
        self.assertEqual(recorded["schema_version"], 4)
        self.assertEqual(recorded["family_cases"], sum(map(len, CANDIDATE_CASES.values())))
        self.assertEqual(
            recorded["cases_by_suite"],
            {suite: list(cases) for suite, cases in CANDIDATE_CASES.items()},
        )
        self.assertEqual(
            {
                suite + "/" + name
                for suite, names in recorded["cases_by_suite"].items()
                for name in names
            },
            set(contract_roles(contract_at(ROOT))),
        )

    def test_public_detection_is_retained_but_cannot_admit_protected_input(self):
        row = observation("ed25519", look=1, effect=True)
        admission = CandidateAdmission("ed25519", "pr", binding=row["binding"])
        history = [
            admission.admit(observation("ed25519", look=i, effect=i == 1)) for i in range(1, 8)
        ]
        result = assess_case("legacy/ed25519", "public_fixture_characterization", history, "pr")
        self.assertEqual(result["statistical_outcome"], "leakage_detected")
        self.assertEqual(result["product_assurance"], "not_established")
        with self.assertRaisesRegex(ValueError, "leakage_detected"):
            assess_case("legacy/ed25519", "protected_input_observation", history, "pr")

    def test_positive_variance_control_requires_the_second_order_statistic(self):
        row = observation("control_variance_shift", effect=True)
        admission = CandidateAdmission(row["case"], "pr", binding=row["binding"])
        history = [
            admission.admit(observation(row["case"], look=i, effect=True)) for i in range(1, 8)
        ]
        with self.assertRaisesRegex(ValueError, "statistic 101"):
            assess_case(
                "legacy/control_variance_shift", "measurement_positive_control", history, "pr"
            )
        history[0]["tests"][101]["p"] = 0
        self.assertTrue(
            assess_case(
                "legacy/control_variance_shift", "measurement_positive_control", history, "pr"
            )["requirement_satisfied"]
        )
        history[-1]["raw_class_counts"][0] = 1
        with self.assertRaisesRegex(ValueError, "floor"):
            assess_case(
                "legacy/control_variance_shift", "measurement_positive_control", history, "pr"
            )

    def test_missing_control_or_changed_numerics_is_rejected(self):
        contract = contract_at(ROOT)
        self.assertEqual(len(contract_roles(contract)), 21)
        for mutation in ("missing", "duplicate", "numeric"):
            bad = copy.deepcopy(contract)
            if mutation == "missing":
                bad["cases"].pop()
            if mutation == "duplicate":
                bad["cases"].append(bad["cases"][0])
            if mutation == "numeric":
                bad["numerical_candidate"]["implementation_sha256"] = "a" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                contract_roles(bad)

    def test_missing_or_truncated_original_samples_cannot_publish_success(self):
        for option in ("omit_trace", "truncate_trace"):
            with self.subTest(option=option):
                fixture = NativeFixture(self)
                result = fixture.invoke("--suite", "nix", **{option: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(fixture.report_path().exists())
                output = fixture.evidence()[-1] / "executions/dudect_harness"
                process = json.loads((output / "process.json").read_text())
                self.assertFalse(process["collection_complete"])
                self.assertIn("samples", process["diagnostics"])
                self.assertTrue((output / "native.stdout").is_file())

    def test_all_case_timing_is_required_even_without_ct128(self):
        for option in ("omit_timing", "truncate_timing"):
            with self.subTest(option=option):
                fixture = NativeFixture(self)
                result = fixture.invoke("--suite", "legacy", **{option: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(fixture.report_path().exists())
                output = fixture.evidence()[-1] / "executions/dudect_controls"
                process = json.loads((output / "process.json").read_text())
                self.assertFalse(process["collection_complete"])
                self.assertIn("timing", process["diagnostics"])
                self.assertTrue((output / "native.stdout").is_file())

    def test_report_binds_artifact_sources_native_stdout_and_assessment(self):
        fixture = NativeFixture(self)
        result = fixture.invoke("--suite", "nix")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        path = fixture.report_path()
        validate_report_file(fixture.root, path)
        cli = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validation/check_dudect.py"), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
        self.assertIn("observation contract satisfied", cli.stdout)
        evidence = fixture.evidence()[-1]
        mutations = [
            evidence / "package/sources/c/dudect.h",
            evidence / "package/native/dudect_harness/dudect_harness",
            evidence / "package/native/dudect_harness/build-manifest.json",
            evidence / "executions/dudect_harness/native.samples",
            evidence / "executions/dudect_harness/native.timing",
            evidence / "executions/dudect_harness/runtime.jsonl",
            evidence / "executions/dudect_harness/native.stdout",
            evidence / "executions/dudect_harness/observations.json",
            evidence / "executions/dudect_harness/process.json",
            path,
        ]
        for target in mutations:
            original = target.read_bytes()
            mode = target.stat().st_mode
            target.chmod(0o700)
            if target.name == "process.json":
                data = json.loads(original)
                data["exit"] = 17
                changed = json.dumps(data).encode()
            elif target == path:
                data = json.loads(original)
                data["assessment"][0]["product_assurance"] = "established"
                changed = json.dumps(data).encode()
            else:
                changed = original + b"{}\n"
            target.write_bytes(changed)
            with self.subTest(target=target), self.assertRaises((ValueError, OSError)):
                validate_report_file(fixture.root, path)
            target.write_bytes(original)
            target.chmod(mode)
        validate_report_file(fixture.root, path)
        validate_report_file(fixture.root, evidence / "report.json")


if __name__ == "__main__":
    unittest.main()
