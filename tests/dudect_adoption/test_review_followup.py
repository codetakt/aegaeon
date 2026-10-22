# unittest checks also run without pytest and under Python -O.
# ruff: noqa: PT009, PT027
"""Check review-receipt integrity without new timing or admission."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "review_followup", ROOT / "scripts/validation/verify_dudect_review_followup.py"
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class FollowupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        checkpoint = ROOT / "ci/evidence/dudect-calibration-qualification-20261021.json"
        source = json.loads(checkpoint.read_bytes())["publication_source_correspondence"]["files"]
        paths = [ROOT / item["path"] for item in source]
        paths += list((ROOT / "ci/contracts/dudect-baremetal-v1").glob("*.json"))
        paths += [
            checkpoint,
            ROOT / "ci/evidence/dudect-contract-review-followup-20261022.json",
            ROOT / "ci/evidence/dudect-measured-source-20261021.tar.gz",
        ]
        for path in paths:
            target = self.root / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)

    def test_complete_public_correction(self):
        report = CHECK.verify(self.root)
        self.assertEqual(report["source_files"], 54)
        self.assertEqual(report["python_files"], 44)
        self.assertEqual(report["normalized_AST_equal"], 42)
        self.assertFalse(report["ci_admission"])

    def test_modified_source_rejected(self):
        path = self.root / "tests/dudect_sensitivity_operations/ordinary.py"
        path.write_bytes(path.read_bytes() + b"\n# changed\n")
        with self.assertRaisesRegex(ValueError, "Published hash"):
            CHECK.verify(self.root)

    def test_modified_archive_rejected(self):
        path = self.root / "ci/evidence/dudect-measured-source-20261021.tar.gz"
        path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, "archive changed"):
            CHECK.verify(self.root)

    def test_scope_mismatch_even_after_local_rebinding(self):
        folder = self.root / "ci/contracts/dudect-baremetal-v1"
        path = folder / "scope.json"
        scope = json.loads(path.read_bytes())
        scope["cases"].pop()
        path.write_text(json.dumps(scope))
        contract_path = folder / "contract.json"
        contract = json.loads(contract_path.read_bytes())
        contract["documents"]["scope"]["sha256"] = CHECK.sha(path.read_bytes())
        contract_path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "Seven-case scope"):
            CHECK.verify(self.root)

    def test_wrong_entry_rejected(self):
        path = self.root / "ci/contracts/dudect-baremetal-v1/contract.json"
        contract = json.loads(path.read_bytes())
        contract["entry"]["ordinary"] = "tests/dudect_analysis/run_analysis.py"
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "Wrong limited-monitoring entry"):
            CHECK.verify(self.root)

    def test_receipt_cannot_admit_ci(self):
        path = self.root / "ci/evidence/dudect-contract-review-followup-20261022.json"
        receipt = json.loads(path.read_bytes())
        receipt["ci_admission"] = True
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "unreviewed adoption"):
            CHECK.verify(self.root)

    def test_normalization_preserves_import_order_and_expressions(self):
        self.assertEqual(CHECK.syntax(b"import a,b"), CHECK.syntax(b"import a\nimport b"))
        self.assertNotEqual(CHECK.syntax(b"import a,b"), CHECK.syntax(b"import b,a"))
        self.assertNotEqual(CHECK.syntax(b"value=1+2"), CHECK.syntax(b"value=1-2"))


if __name__ == "__main__":
    unittest.main()
