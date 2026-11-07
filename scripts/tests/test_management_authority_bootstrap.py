"""Bootstrap transport failures preserve the exact request and prior receipt."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).parents[1] / "operations/bootstrap-management-authority.py"
SPEC = importlib.util.spec_from_file_location("management_bootstrap", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    message = "bootstrap operator module is unavailable"
    raise RuntimeError(message)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class BootstrapTransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.request = self.root / "request.json"
        self.receipt = self.root / "receipt.json"
        self.value = {
            "installation_id": "installation",
            "operation_id": "operation",
            "grant_id": "grant",
            "principal_id": "principal",
            "principal_kind": "HUMAN",
            "adopt_installation": True,
        }
        self.request.write_text(json.dumps(self.value))
        self.receipt.write_text("previous verified receipt\n")
        self.original_request = self.request.read_bytes()
        self.original_receipt = self.receipt.read_bytes()

    def unchanged(self):
        self.assertEqual(self.request.read_bytes(), self.original_request)
        self.assertEqual(self.receipt.read_bytes(), self.original_receipt)

    def test_lost_response_cannot_publish_a_receipt_or_replace_the_request(self):
        with (
            patch.object(
                bootstrap.subprocess, "run", side_effect=subprocess.TimeoutExpired("psql", 35)
            ),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            bootstrap.run(self.request, self.receipt)
        self.unchanged()

    def test_refusal_or_wrong_identity_keeps_the_existing_receipt(self):
        wrong = {
            "operationId": "different-operation",
            "grantId": "grant",
            "revision": 1,
            "delegationEpoch": 1,
        }
        for completed in (
            subprocess.CompletedProcess("psql", 1, "", "private server detail"),
            subprocess.CompletedProcess("psql", 0, json.dumps(wrong), ""),
        ):
            with (
                self.subTest(returncode=completed.returncode),
                patch.object(bootstrap.subprocess, "run", return_value=completed),
                self.assertRaises(ValueError),
            ):
                bootstrap.run(self.request, self.receipt)
            self.unchanged()

    def test_same_input_output_and_oversized_requests_never_connect(self):
        with patch.object(bootstrap.subprocess, "run") as execute:
            with self.assertRaises(ValueError):
                bootstrap.run(self.request, self.request)
            self.unchanged()
            self.request.write_bytes(b" " * (bootstrap.MAX_REQUEST_BYTES + 1))
            with self.assertRaises(ValueError):
                bootstrap.run(self.request, self.receipt)
            execute.assert_not_called()
            self.assertEqual(self.receipt.read_bytes(), self.original_receipt)

    def test_success_receipt_atomically_replaces_public_mode_with_private_mode(self):
        self.receipt.chmod(0o644)
        expected = {
            "operationId": "operation",
            "grantId": "grant",
            "revision": 1,
            "delegationEpoch": 1,
        }
        with patch.object(
            bootstrap.subprocess,
            "run",
            return_value=subprocess.CompletedProcess("psql", 0, json.dumps(expected), ""),
        ):
            bootstrap.run(self.request, self.receipt)
        self.assertEqual(json.loads(self.receipt.read_text()), expected)
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.request.read_bytes(), self.original_request)


if __name__ == "__main__":
    unittest.main()
