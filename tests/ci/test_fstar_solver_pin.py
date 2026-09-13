# ruff: noqa: PT009, PT027 - unittest discovery without a pytest runtime dependency
"""Check that invocation evidence identifies an explicit executable, not ambient Z3."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/validation"))
import assumption_graph as graph  # noqa: E402
import run_fstar_invocation as runner  # noqa: E402


class SolverPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.ambient = self.root / "z3"
        self.ambient.write_text("#!/bin/sh\necho ambient\n")
        self.ambient.chmod(0o755)
        self.pinned = self.root / "pinned z3"
        self.pinned.write_text("#!/bin/sh\necho pinned\n")
        self.pinned.chmod(0o755)

    def test_ambient_solver_does_not_establish_the_verifiers_choice(self) -> None:
        with patch.dict(os.environ, {"PATH": str(self.root)}):
            self.assertIsNone(runner.requested_solver(["fstar.exe", "M.fst"]))

    def test_explicit_solver_records_its_bytes_despite_a_different_path_solver(self) -> None:
        with patch.dict(os.environ, {"PATH": str(self.root)}):
            identity = runner.requested_solver(["fstar.exe", "--smt", str(self.pinned), "M.fst"])
        self.assertEqual(
            identity,
            {
                "path": str(self.pinned),
                "sha256": hashlib.sha256(self.pinned.read_bytes()).hexdigest(),
            },
        )

    def test_symlink_records_the_selected_file(self) -> None:
        link = self.root / "selected"
        link.symlink_to(self.pinned)
        self.assertEqual(
            runner.requested_solver(["fstar.exe", "--smt", str(link)]),
            runner.requested_solver(["fstar.exe", "--smt", str(self.pinned)]),
        )

    def test_missing_nonexecutable_and_relative_paths_are_rejected(self) -> None:
        ordinary = self.root / "ordinary"
        ordinary.write_text("not executable")
        for value in ("z3", str(self.root / "missing"), str(ordinary), str(self.root)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.requested_solver(["fstar.exe", "--smt", value])

    def test_ambiguous_and_missing_arguments_are_rejected(self) -> None:
        for args in (
            ["--smt"],
            ["--smt", str(self.pinned), "--smt", str(self.ambient)],
            ["--smt=" + str(self.pinned)],
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                runner.requested_solver(["fstar.exe", *args])

    @staticmethod
    def start_line(path: Path, version: str = "4.13.3") -> str:
        return f'Creating new z3proc (cmd=[("{path}", ["-smt2", "-in"])], version=["{version}"])\n'

    def test_identical_restarts_and_executable_aliases_remain_acceptable(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.pinned)
        text = self.start_line(self.pinned) + self.start_line(alias)
        log = self.root / "output.log"
        log.write_text(text)
        for actual in (
            runner.effective_solver(log, self.root / "verifier"),
            graph.effective_solver(text, self.root / "verifier"),
        ):
            self.assertEqual(actual["path"], str(self.pinned))
            self.assertEqual(actual["arguments"], ["-smt2", "-in"])
            self.assertEqual(actual["process_count"], 2)

    def test_changed_solver_arguments_cannot_reuse_the_pinned_executable_identity(self) -> None:
        for arguments in [
            "[]",
            '["-smt2"]',
            '["-in", "-smt2"]',
            '["-smt2", "-in", "smt.random_seed=1"]',
            '["-smt2", "-in", "-in"]',
            '["-smt2", "-in", garbage]',
        ]:
            changed = self.start_line(self.pinned).replace('["-smt2", "-in"]', arguments)
            for text in (changed, self.start_line(self.pinned) + changed):
                with self.subTest(arguments=arguments, restart=text != changed):
                    log = self.root / "output.log"
                    log.write_text(text)
                    with self.assertRaisesRegex(ValueError, "malformed solver process"):
                        runner.effective_solver(log, self.root / "verifier")
                    with self.assertRaisesRegex(graph.GraphError, "malformed solver process"):
                        graph.effective_solver(text, self.root / "verifier")

    def test_later_different_unknown_or_malformed_starts_are_rejected(self) -> None:
        first = self.start_line(self.pinned)
        for tail in (
            self.start_line(self.ambient),
            self.start_line(self.pinned, "different-version"),
            self.start_line(self.root / "missing"),
            "Creating new z3proc (unrecognized format)\n",
            self.start_line(self.pinned).rstrip("\n") + " trailing garbage\n",
            "unexpected prefix " + self.start_line(self.pinned),
            self.start_line(self.pinned).rstrip("\n") + self.start_line(self.pinned),
        ):
            with self.subTest(tail=tail):
                text = first + tail
                log = self.root / "output.log"
                log.write_text(text)
                with self.assertRaises(ValueError):
                    runner.effective_solver(log, self.root / "verifier")
                with self.assertRaises(graph.GraphError):
                    graph.effective_solver(text, self.root / "verifier")


if __name__ == "__main__":
    unittest.main()
