"""Failure controls for the installed-graph audit and command runner."""
# unittest assertions must remain effective when Python runs with -O.
# ruff: noqa: PT009, PT027

from __future__ import annotations

import ast
import io
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
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        require_tests(result, 0)
        for changed in [
            {},
            {"tests_run": 0},
            {"tests_run": True},
            {"skipped": 1},
            {"failures": 1},
            {"errors": 1},
            {"expected_failures": 1},
            {"unexpected_successes": 1},
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

    def test_result_counters_require_exact_nonnegative_integers(self):
        valid = {
            "status": "passed",
            "tests_run": len(EXPECTED_TESTS),
            "test_ids": sorted(EXPECTED_TESTS),
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        for key in (
            "tests_run",
            "failures",
            "errors",
            "skipped",
            "expected_failures",
            "unexpected_successes",
        ):
            for counter in (False, True, 0.0, float(len(EXPECTED_TESTS)), "0", None, -1):
                with self.subTest(key=key, counter=counter), self.assertRaises(ValueError):
                    require_tests({**valid, key: counter}, 0)
            missing = valid.copy()
            del missing[key]
            with self.subTest(key=key, missing=True), self.assertRaises(ValueError):
                require_tests(missing, 0)
        require_tests(valid, 0)

    def test_actual_expected_failure_and_unexpected_success_cannot_pass(self):
        root = Path(__file__).resolve().parents[2]
        source = root / "tests/examples/minimal_rp/check_flow.py"
        # Exercise the actual pure producer definitions without importing its
        # Flask/JWT application before the workflow installs those dependencies.
        names = {"InventoryResult", "test_outcome"}
        definitions = [
            node
            for node in ast.parse(source.read_text()).body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names
        ]
        self.assertEqual({node.name for node in definitions}, names)
        self.assertEqual(len(definitions), len(names))
        namespace = {"unittest": unittest}
        exec(  # noqa: S102 - only two fixed definitions from the actual repository producer
            compile(ast.Module(body=definitions, type_ignores=[]), str(source), "exec"), namespace
        )
        for succeeds, counter in ((False, "expected_failures"), (True, "unexpected_successes")):
            with self.subTest(counter=counter):

                class ControlledOutcome(unittest.TestCase):
                    @unittest.expectedFailure
                    def test_expected(self, succeeds=succeeds):
                        self.assertTrue(succeeds)

                result = unittest.TextTestRunner(
                    stream=io.StringIO(), resultclass=namespace["InventoryResult"]
                ).run(unittest.TestSuite([ControlledOutcome("test_expected")]))
                outcome = namespace["test_outcome"](result)
                self.assertEqual(outcome["status"], "failed")
                self.assertEqual(outcome[counter], 1)
                self.assertIs(type(outcome[counter]), int)
                # Keep the expected inventory/status valid to isolate the nonzero outcome.
                with self.assertRaises(ValueError):
                    require_tests(
                        {
                            **outcome,
                            "status": "passed",
                            "tests_run": len(EXPECTED_TESTS),
                            "test_ids": sorted(EXPECTED_TESTS),
                        },
                        0,
                    )
