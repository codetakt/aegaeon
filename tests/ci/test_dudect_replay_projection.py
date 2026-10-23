"""An authenticated report's correspondence is not a new measurement or a pass."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import project_dudect_replay as projection


def fixture():
    sha = "1" * 64
    invocation = {
        "kind": "ordinary",
        "suite": "nix",
        "compiler": "gcc",
        "unit": "unit-1",
        "packet": "original-packet",
        "case_order": ["hmac_sha256"],
        "package_sha256": sha,
        "binary_sha256": sha,
        "analysis": {"id": "original"},
    }
    inv = projection.canonical(invocation)
    receipt = {
        "schema": "ordinary-local-replay-receipt/1",
        "invocation_sha256": projection.digest(inv),
        "analysis_sha256": projection.digest(projection.canonical(invocation["analysis"])),
        "native_package_sha256": sha,
        "native_elf_sha256": sha,
        "case_order": invocation["case_order"],
        "checks_completed": projection.CHECKS[:],
        "files": {
            name: {"sha256": sha}
            for name in (
                "native.timing",
                "decisions.json",
                "effective-decisions.json",
                "qualification.json",
            )
        },
    }
    receipt_sha = projection.digest(projection.canonical(receipt))
    report = {
        "schema": "ordinary-replay-report/1",
        "replay_receipt": receipt,
        "replay_receipt_sha256": receipt_sha,
        "ci_admission": False,
        "original_assessments_modified": False,
        "new_physical_trials": 0,
        "qualification_passed": True,
        "cases": [
            {
                "case_id": "nix/hmac_sha256",
                "role": "protected_input_observation",
                "expected_identity": {
                    "replay_receipt_sha256": receipt_sha,
                    "analysis_sha256": receipt["analysis_sha256"],
                    "assessment_sha256": sha,
                    "contract_sha256": sha,
                },
                "axes": {"qualification_passed": True},
                "detection_changes": {"original_detected_statistic_looks": 3},
            }
        ],
    }
    return report, inv


def project(report, inv):
    data = projection.canonical(report)
    return projection.project_process(data, projection.digest(data), inv)


class ProjectionTests(unittest.TestCase):
    def test_success_preserves_original_unit_and_detections(self):
        report, inv = fixture()
        rows = project(report, inv)
        assert len(rows) == 1
        assert rows[0]["packet"] == "original-packet"
        assert rows[0]["original_detections"] == 3
        assert rows[0]["qualification"] == "observation_contract_satisfied"

    def test_failed_role_not_converted_to_complete_numeric_pass(self):
        report, inv = fixture()
        report["qualification_passed"] = False
        report["cases"][0]["axes"]["qualification_passed"] = False
        rows = project(report, inv)
        assert rows[0]["qualification"] == "not_satisfied"
        assert rows[0]["numeric_validity"] == "not_established"

    def test_changed_bytes_and_invocation_rejected(self):
        report, inv = fixture()
        data = projection.canonical(report)
        with pytest.raises(ValueError, match="report digest"):
            projection.project_process(data + b" ", projection.digest(data), inv)
        with pytest.raises(ValueError, match="invocation"):
            projection.project_process(data, projection.digest(data), inv + b" ")

    def test_rebound_receipt_does_not_override_case_binding(self):
        report, inv = fixture()
        report["replay_receipt"]["files"]["native.timing"]["sha256"] = "2" * 64
        report["replay_receipt_sha256"] = projection.digest(
            projection.canonical(report["replay_receipt"])
        )
        with pytest.raises(ValueError, match="case replay"):
            project(report, inv)

    def test_forged_claims_missing_case_and_aggregate_mismatch(self):
        for key, value in (
            ("ci_admission", True),
            ("original_assessments_modified", True),
            ("new_physical_trials", 1),
            ("qualification_passed", False),
            ("cases", []),
        ):
            report, inv = fixture()
            report[key] = value
            with (
                self.subTest(key=key),
                pytest.raises(ValueError, match=r"claim|modified|observation|qualification|order"),
            ):
                project(report, inv)

    def test_incomplete_check_history_rejected_even_with_rebound_digest(self):
        report, inv = fixture()
        report["replay_receipt"]["checks_completed"].remove("raw_prefix_replay")
        report["replay_receipt_sha256"] = projection.digest(
            projection.canonical(report["replay_receipt"])
        )
        with pytest.raises(ValueError, match="checks incomplete"):
            project(report, inv)

    def test_case_identity_and_duplicate_rejected(self):
        report, inv = fixture()
        report["cases"][0]["expected_identity"]["analysis_sha256"] = "2" * 64
        with pytest.raises(ValueError, match="case analysis"):
            project(report, inv)
        report, inv = fixture()
        report["cases"].append(copy.deepcopy(report["cases"][0]))
        with pytest.raises(ValueError, match="case order"):
            project(report, inv)


if __name__ == "__main__":
    unittest.main()
