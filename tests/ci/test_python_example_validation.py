"""Failure controls for the installed-graph audit and command runner."""
# unittest assertions must remain effective when Python runs with -O.
# ruff: noqa: PT009, PT027

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from validate_python_example import (
    EXPECTED_TESTS,
    Validation,
    audit_verdict,
    installed_graph,
    require_tests,
)


def entry(name="flask", version="3.1.3", **extra):
    return {"name": name, "version": version, "vulns": [], **extra}


class ValidationControls(unittest.TestCase):
    def test_audit_requires_exact_installed_graph(self):
        graph = {"flask": "3.1.3", "werkzeug": "3.1.8"}
        result = {"dependencies": [entry(), entry("werkzeug", "3.1.8")]}
        self.assertEqual(audit_verdict(result, graph, 0)["status"], "passed")
        for invalid in [
            {},
            {"dependencies": []},
            {"dependencies": [entry()]},
            {"dependencies": [entry(), entry("werkzeug", "3.1.7")]},
            {"dependencies": [entry(), entry()]},
            {"dependencies": [entry(skip_reason="not found"), entry("werkzeug", "3.1.8")]},
            {"dependencies": [entry(vulns=None), entry("werkzeug", "3.1.8")]},
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                audit_verdict(invalid, graph, 0)

    def test_findings_and_tool_failures_cannot_pass(self):
        graph = {"flask": "3.1.3"}
        vulnerable = {"dependencies": [entry(vulns=[{"id": "TEST-ADVISORY"}])]}
        self.assertEqual(audit_verdict(vulnerable, graph, 1)["status"], "vulnerable")
        with self.assertRaises(ValueError):
            audit_verdict(vulnerable, graph, 0)
        for code in [1, 2, 124, -15]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                audit_verdict({"dependencies": [entry()]}, graph, code)

    def test_installed_graph_rejects_empty_duplicate_and_malformed_entries(self):
        self.assertEqual(installed_graph([entry("PyJWT", "2.10.1")]), {"pyjwt": "2.10.1"})
        for invalid in [
            [],
            {},
            [entry(), entry("Flask")],
            [{"name": "flask"}],
            [entry("--index-url")],
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                installed_graph(invalid)

    def test_missing_command_and_failed_command_preserve_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            validator = Validation(root, root, Path(sys.executable))
            with self.assertRaisesRegex(ValueError, "failed with exit"):
                validator.command("unavailable", [str(root / "missing-tool")])
            with self.assertRaisesRegex(ValueError, "failed with exit 7"):
                validator.command("failure", [sys.executable, "-c", "raise SystemExit(7)"])
            receipt = json.loads((root / "receipt.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual([command["exit_code"] for command in receipt["commands"]], [124, 7])
            self.assertTrue(all(command["log_sha256"] for command in receipt["commands"]))

    def test_exact_test_inventory_and_success_are_required(self):
        identifiers = sorted(EXPECTED_TESTS)
        result = {
            "status": "passed",
            "tests_run": len(identifiers),
            "test_ids": identifiers,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        }
        require_tests(result, 0)
        for changed in [
            {},
            {"tests_run": 0},
            {"tests_run": True},
            {"skipped": 1},
            {"failures": 1},
            {"errors": 1},
            {"status": "failed"},
            {"test_ids": identifiers[:-1]},
            {"test_ids": [identifiers[0]] * len(identifiers)},
            {"test_ids": [*identifiers[:-1], "unknown.test"]},
            {"test_ids": identifiers[:1], "tests_run": 1},
            {"test_ids": None},
        ]:
            invalid = {**result, **changed} if changed else {}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                require_tests(invalid, 0)
        with self.assertRaises(ValueError):
            require_tests(result, 1)
