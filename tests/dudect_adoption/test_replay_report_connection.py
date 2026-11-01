# unittest checks must run without pytest and under Python -O.
# ruff: noqa: PT009, PT027
"""Fault injection at the reporting/replay boundary, not numerical verification."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_optional_reporting import REPORT, assessment, proofs


class ReplayConnectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name)
        self.calls = []
        self.result = assessment() | {
            "case_id": "nix/ct_eq_32",
            "role": "measurement_negative_control",
            "contract_sha256": "a" * 64,
        }
        self.inv = {
            "kind": "ordinary",
            "profile": "ordinary",
            "suite": "nix",
            "analysis": {"profile": "ordinary"},
            "package": "/pinned/package",
            "executable": "provider",
            "case_order": ["ct_eq_32"],
        }
        self.index = {
            "executables": [{"name": "provider", "cases": ["ct_eq_32"], "sha256": "e" * 64}]
        }
        self.inv.update(
            package_sha256=REPORT.digest(REPORT.canonical(self.index)), binary_sha256="e" * 64
        )
        self.write("invocation.json", self.inv)
        self.expected = REPORT.file_digest(self.output / "invocation.json")
        self.write("process.json", {"exit": 0, "collection_complete": True})
        self.write("observations.json", {"ct_eq_32": [1]})
        (self.output / "native.stdout").write_bytes(b"1\n")
        (self.output / "native.timing").write_bytes(
            b"synthetic boundary fixture; not timing evidence"
        )
        (self.output / "analysis-prefixes.jsonl").write_bytes(
            b"\n".join(REPORT.canonical({"proof": p}) for p in proofs())
        )
        self.save_result()
        self.modules = {
            "ordinary": SimpleNamespace(__file__=REPORT.__file__, evaluate_proofs=self.evaluate),
            "run_candidate": SimpleNamespace(current_sources=lambda _: {}),
            "analysis_contract": SimpleNamespace(
                SOURCE="fixture", significant=lambda t: t["detected"]
            ),
            "dudect_diagnostics": SimpleNamespace(
                validate_diagnostics=lambda *_: self.calls.append("diagnostics")
            ),
            "dudect_package": SimpleNamespace(
                checked_package=lambda *_: self.index,
                expected_bindings=lambda *_: {
                    "bindings": {"ct_eq_32": {"case_id": "nix/ct_eq_32"}}
                },
            ),
            "live_runtime": SimpleNamespace(validate_identity=lambda _: None, replay=self.replay),
        }

    def write(self, name, data):
        (self.output / name).write_bytes(REPORT.canonical(data))

    def save_result(self):
        self.write(
            "qualification.json",
            {"assessment": [self.result], "qualified": self.result["qualification_passed"]},
        )

    def replay(self, *_):
        self.calls.append("replay")

    def evaluate(self, *_):
        self.assertEqual(self.calls, ["diagnostics", "replay"])
        self.calls.append("evaluate")
        return [copy.deepcopy(self.result)]

    def verify(self, expected=None):
        with patch.dict("sys.modules", self.modules):
            return REPORT.verify_process(self.output, expected or self.expected)

    def test_report_binds_completed_replay_and_preserves_assessment(self):
        before = (self.output / "qualification.json").read_bytes()
        result = self.verify()
        receipt = result["replay_receipt"]
        self.assertEqual(REPORT.digest(REPORT.canonical(receipt)), result["replay_receipt_sha256"])
        self.assertEqual(
            result["cases"][0]["expected_identity"]["replay_receipt_sha256"],
            result["replay_receipt_sha256"],
        )
        self.assertEqual(
            result["cases"][0]["expected_identity"]["assessment_sha256"],
            REPORT.digest(REPORT.canonical(self.result)),
        )
        self.assertFalse(receipt["producer_authentication_performed"])
        self.assertFalse(receipt["external_lifecycle_verified"])
        self.assertFalse(result["ci_admission"])
        self.assertEqual((self.output / "qualification.json").read_bytes(), before)

    def test_wrong_invocation_never_replays(self):
        with self.assertRaisesRegex(ValueError, "planned invocation"):
            self.verify("0" * 64)
        self.assertEqual(self.calls, [])

    def test_rebound_wrong_artifact_is_rejected(self):
        for field in ("package_sha256", "binary_sha256"):
            with self.subTest(field=field):
                inv = self.inv | {field: "0" * 64}
                self.write("invocation.json", inv)
                sha = REPORT.file_digest(self.output / "invocation.json")
                with self.assertRaisesRegex(ValueError, "artifact identity"):
                    self.verify(sha)
                self.assertEqual(self.calls, [])

    def test_replay_failure_never_evaluates(self):
        self.modules["live_runtime"].replay = lambda *_: REPORT.require(False, "prefix mismatch")
        with self.assertRaisesRegex(ValueError, "prefix mismatch"):
            self.verify()
        self.assertNotIn("evaluate", self.calls)

    def test_changed_evidence_during_replay_rejected(self):
        def changed(*_):
            self.replay()
            (self.output / "native.timing").write_bytes(b"changed")

        self.modules["live_runtime"].replay = changed
        with self.assertRaisesRegex(ValueError, "changed during replay"):
            self.verify()

    def test_saved_success_flag_cannot_replace_failed_assessment(self):
        self.write("qualification.json", {"assessment": [self.result], "qualified": False})
        with self.assertRaisesRegex(ValueError, "Changed saved result"):
            self.verify()

    def test_incomplete_process_rejected_before_replay(self):
        self.write("process.json", {"exit": 0, "collection_complete": False})
        with self.assertRaisesRegex(ValueError, "Incomplete process"):
            self.verify()
        self.assertEqual(self.calls, [])

    def test_replay_can_report_a_retained_role_failure(self):
        self.result.update(raw_floor_met=False, qualification_passed=False)
        self.result["effective_result"]["requirement_satisfied"] = False
        self.save_result()
        result = self.verify()
        self.assertFalse(result["qualification_passed"])
        self.assertEqual(result["cases"][0]["axes"]["observation"], "not_evaluable")

    def test_reporter_changed_after_import_rejected(self):
        with (
            patch.object(REPORT, "REPORTER_SHA256", "0" * 64),
            self.assertRaisesRegex(ValueError, "Reporter changed"),
        ):
            self.verify()
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
