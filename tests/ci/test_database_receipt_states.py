"""Fixed DB obligations retain explicit unstarted/started evidence across interruption."""

from __future__ import annotations

# ruff: noqa: PT009 - assertions survive Python -O.
import json
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts/ci"), str(ROOT / "scripts/validation")]
import database_execution as execution  # noqa: E402
import run_database_lanes as lanes  # noqa: E402


class DatabaseReceiptStateTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.plan_path = self.directory / "plan.json"
        self.plan_path.write_text('{"fixture":"planned-receipts"}\n')
        self.results = self.directory / "results"
        self.plan = {
            "context": {},
            "build_sha256": "fixture",
            "package": "/unbuilt",
            "suites": dict.fromkeys(execution.selectors()),
            "auxiliaries": list(execution.AUXILIARIES),
        }
        self.enterContext(mock.patch.object(execution, "load_plan", return_value=self.plan))
        self.enterContext(mock.patch.object(lanes, "load_plan", return_value=self.plan))

    def initialize(self):
        execution.initialize_receipts(self.plan_path, self.results)

    def record(self):
        return execution.not_started_receipt(self.plan_path, self.plan, "postgres")

    def test_all_planned_states_exist_and_missing_is_never_unstarted(self):
        self.initialize()
        expected = set(self.plan["suites"]) | set(self.plan["auxiliaries"])
        self.assertEqual(len(expected), 12)
        self.assertEqual({p.stem for p in self.results.glob("*.json")}, expected)
        with execution.pinned_results_directory(self.results) as identity:
            execution.confirm_lane_cleanup(
                self.plan_path, self.results, "all", expected_identity=identity
            )
            unknown = self.results / "unknown.json"
            unknown.write_text("{}")
            with pytest.raises(ValueError, match="unknown database cleanup receipt"):
                execution.confirm_lane_cleanup(
                    self.plan_path, self.results, "all", expected_identity=identity
                )
            unknown.unlink()
            (self.results / "postgres.json").unlink()
            for strict in (False, True):
                with (
                    self.subTest(strict=strict),
                    pytest.raises(ValueError, match="cleanup receipt"),
                ):
                    execution.confirm_lane_cleanup(
                        self.plan_path,
                        self.results,
                        "postgres",
                        require_all=strict,
                        expected_identity=identity,
                    )

    def test_unstarted_records_require_exact_booleans_and_source_schema(self):
        self.initialize()
        path = self.results / "postgres.json"
        for field, value in (
            ("complete", 0),
            ("complete", 0.0),
            ("process_cleanup_confirmed", 0),
            ("process_cleanup_confirmed", 0.0),
            ("extra", "unexpected"),
            ("context", {"foreign": "run"}),
        ):
            with self.subTest(field=field, value=value):
                row = {**self.record(), field: value}
                path.write_text(json.dumps(row))
                with (
                    pytest.raises(FileExistsError),
                    execution.claim_receipt(self.plan_path, self.plan, self.results, self.record()),
                ):
                    self.fail("invalid initial state was claimed")
                with (
                    execution.pinned_results_directory(self.results) as identity,
                    pytest.raises(ValueError, match="cleanup is unconfirmed"),
                ):
                    execution.confirm_lane_cleanup(
                        self.plan_path, self.results, "postgres", expected_identity=identity
                    )
                self.assertEqual(json.loads(path.read_text()), row)

    def test_partial_initialization_starts_no_lane(self):
        real_replace = execution.replace_receipt
        written = 0
        interruption = OSError("controlled initialization interruption")

        def fail_after_one(*args):
            nonlocal written
            if written:
                raise interruption
            real_replace(*args)
            written += 1

        with (
            mock.patch.object(execution, "replace_receipt", side_effect=fail_after_one),
            pytest.raises(OSError, match="interruption"),
        ):
            self.initialize()
        with (
            mock.patch.dict(
                "os.environ",
                {
                    "AEGAEON_DATABASE_EXECUTION_PLAN": str(self.plan_path),
                    "AEGAEON_DATABASE_EXECUTION_RESULTS": str(self.results),
                },
            ),
            mock.patch.object(lanes, "bind_package"),
            mock.patch.object(lanes.signal, "signal"),
            mock.patch.object(lanes, "ThreadPoolExecutor") as executor,
            pytest.raises(FileExistsError),
        ):
            lanes.main()
        executor.assert_not_called()

    def test_concurrent_duplicate_start_has_one_owner(self):
        self.initialize()
        barrier = threading.Barrier(2)

        def claim():
            row = self.record()
            barrier.wait(timeout=2)
            try:
                with execution.claim_receipt(self.plan_path, self.plan, self.results, row):
                    return row["invocation_id"]
            except FileExistsError:
                return "refused"

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(claim) for _ in range(2)]
            values = [future.result(timeout=3) for future in futures]
        self.assertEqual(values.count("refused"), 1)
        row = json.loads((self.results / "postgres.json").read_text())
        self.assertTrue(execution.started_receipt(row))
        self.assertIn(row["invocation_id"], values)

    def test_finalization_does_not_recreate_missing_or_foreign_state(self):
        for fault in ("missing", "foreign", "partial"):
            with self.subTest(fault=fault):
                self.results = self.directory / fault
                self.initialize()
                row = self.record()
                with execution.claim_receipt(
                    self.plan_path, self.plan, self.results, row
                ) as descriptor:
                    path = self.results / "postgres.json"
                    if fault == "missing":
                        path.unlink()
                    elif fault == "partial":
                        path.write_text("{")
                    else:
                        changed = {**row, "invocation_id": "0" * 32}
                        path.write_text(json.dumps(changed))
                    before = path.read_bytes() if path.exists() else None
                    with pytest.raises(
                        ValueError, match=r"cleanup receipt|receipt changed|Expecting property"
                    ):
                        execution.finish_receipt(self.results, descriptor, row)
                    self.assertEqual(path.read_bytes() if path.exists() else None, before)

    def test_pre_spawn_interruption_keeps_started_uncertainty(self):
        self.initialize()
        command = ["/unbuilt/fixture"]
        with (
            mock.patch.object(execution, "bind_package"),
            mock.patch.object(execution, "owned_command", return_value=command),
            mock.patch.object(execution, "owned_cwd", return_value=self.directory),
            mock.patch.object(
                execution, "check_cancellation", side_effect=[None, ValueError("before spawn")]
            ),
            mock.patch.object(execution.subprocess, "Popen") as spawned,
            pytest.raises(ValueError, match="before spawn"),
        ):
            execution.execute(self.plan_path, self.results, "postgres", command, test_suite=True)
        spawned.assert_not_called()
        row = json.loads((self.results / "postgres.json").read_text())
        self.assertTrue(execution.started_receipt(row))
        self.assertIs(row["process_cleanup_confirmed"], False)
        with (
            execution.pinned_results_directory(self.results) as identity,
            pytest.raises(ValueError, match="cleanup is unconfirmed"),
        ):
            execution.confirm_lane_cleanup(
                self.plan_path, self.results, "postgres", expected_identity=identity
            )

    def test_unknown_states_and_invalid_invocation_ids_never_certify_execution(self):
        for state in (None, False, "finished", "not_started", "started"):
            for invocation in (None, False, 123, "", "x" * 32):
                with self.subTest(state=state, invocation=invocation):
                    self.assertFalse(
                        execution.started_receipt(
                            {"execution_state": state, "invocation_id": invocation}
                        )
                    )


if __name__ == "__main__":
    unittest.main()
