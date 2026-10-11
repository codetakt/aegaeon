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
from dudect_contract import ObservationError, assess_case, contract_roles
from run_contract import contract_at, validate_report_file
from test_dudect_candidate import observation, support


class ContractTests(unittest.TestCase):
    def test_failed_controls_and_targets_collect_later_cases_without_admission(self):
        fixture = NativeFixture(self)
        self.add_statistical_failures(fixture)
        result = fixture.invoke("--suite", "legacy")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(fixture.report_path().exists())
        evidence = fixture.evidence()[-1]
        self.assertFalse(json.loads((evidence / "status.json").read_text())["accepted"])
        self.assertFalse((evidence / "report.json").exists())
        diagnostic = json.loads((evidence / "diagnostics.json").read_text())
        self.assertTrue(diagnostic["collection_complete"])
        self.assertEqual(diagnostic["uncompleted_cases"], [])
        self.assertEqual(diagnostic["admission"], "inactive")
        cases = diagnostic["cases"]
        self.assertEqual(set(cases), set(CANDIDATE_CASES["legacy"]))
        failures = {name for name, case in cases.items() if not case["requirement_satisfied"]}
        self.assertEqual(
            failures, {"compare", "control_mean_shift", "hmac_key_reject", "compare_product_32"}
        )
        self.assertEqual(cases["compare"]["looks"][0]["detected_statistics"][0]["id"], 0)
        sparse = cases["hmac_key_reject"]["looks"][-1]
        self.assertEqual(sparse["ineligible_statistics"][0]["class_counts"], [2100, 2100])
        self.assertEqual(sparse["retained_counts_since_previous_look"][1], [300, 300])
        self.assertEqual(sparse["ineligible_statistics"][0]["reason"], "insufficient_count")
        degenerate = cases["compare_product_32"]["looks"][-1]["ineligible_statistics"][0]
        self.assertEqual(degenerate["reason"], "degenerate_variance")
        self.assertEqual(degenerate["native_support"][0]["tick_min"], 100)
        self.assertEqual(degenerate["native_support"][0]["tick_max"], 100)
        self.assertEqual(len(json.loads((evidence / "collection.json").read_text())["cases"]), 11)
        self.assertTrue(
            json.loads((evidence / "executions/jwe_key_reject/process.json").read_text())[
                "collection_complete"
            ]
        )

    def add_statistical_failures(self, fixture):
        rows = json.loads(fixture.rows.read_text())
        for row in rows["dudect_controls"]["pr"]:
            if row["case"] == "control_mean_shift":
                row["statistics"][0][2] = 100
        for row in rows["compare"]["pr"]:
            row["statistics"][0][2] = 103
        for row in rows["hmac_key_reject"]["pr"]:
            count = row["look"] * 300
            row["statistics"][1][:2] = [count, count]
            for pair in row["support"][1]:
                pair["count"] = count
        for row in rows["compare_product_32"]["pr"]:
            count = row["statistics"][1][0]
            row["statistics"][1][4] = 0
            row["support"][1][0] = support(count, 100, 100, 100, 100)
        fixture.rows.write_text(json.dumps(rows))

    def test_malformed_later_case_aborts_and_preserves_prior_statistical_failure(self):
        fixture = NativeFixture(self)
        rows = json.loads(fixture.rows.read_text())
        for row in rows["compare"]["pr"]:
            row["statistics"][0][2] = 103
        fixture.rows.write_text(json.dumps(rows))
        result = fixture.invoke("--suite", "legacy", invalid_binary="hmac")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(fixture.report_path().exists())
        evidence = fixture.evidence()[-1]
        diagnostic = json.loads((evidence / "diagnostics.json").read_text())
        self.assertFalse(diagnostic["collection_complete"])
        self.assertIn("legacy/hmac", diagnostic["uncompleted_cases"])
        self.assertFalse(diagnostic["cases"]["compare"]["requirement_satisfied"])
        self.assertFalse((evidence / "executions/ed25519").exists())
        self.assertFalse((evidence / "collection.json").exists())

    def test_incomplete_schedule_and_unknown_role_are_not_statistical_failures(self):
        row = observation()
        history = [CandidateAdmission("compare", "pr", binding=row["binding"]).admit(row)]
        with self.assertRaises(ValueError) as error:
            assess_case("legacy/compare", "measurement_negative_control", history, "pr")
        self.assertNotIsInstance(error.exception, ObservationError)
        contract = contract_at(ROOT)
        contract["cases"][0]["proposed_role"] = "unknown"
        with self.assertRaisesRegex(ValueError, "Unknown observation role"):
            contract_roles(contract)

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
            evidence / "diagnostics.json",
            evidence / "collection.json",
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
        self.assert_clock_summary_is_bound(fixture, evidence, path)

    def assert_clock_summary_is_bound(self, fixture, evidence, path):
        validate_report_file(fixture.root, evidence / "report.json")
        process_path = evidence / "executions/dudect_harness/process.json"
        original = process_path.read_bytes()
        process = json.loads(original)
        process["diagnostics"]["timing"]["clock_batches"]["ct_eq_128"][0]["delta_gcd"] = 26
        process_path.write_text(json.dumps(process))
        with self.assertRaises(ValueError):
            validate_report_file(fixture.root, path)
        process_path.write_bytes(original)
        for field in ("distribution", "context", "scope"):
            process = json.loads(original)
            timing = process["diagnostics"]["timing"]
            row = timing["distribution_batches"]["ct_eq_128"][0]
            if field == "distribution":
                row["blocks"][0]["classes"][0]["count"] += 1
            elif field == "context":
                row["context"]["cpus"][0] = 123
            else:
                timing["distribution_scope"] = "all_samples"
            process_path.write_text(json.dumps(process))
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_report_file(fixture.root, path)
            process_path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
