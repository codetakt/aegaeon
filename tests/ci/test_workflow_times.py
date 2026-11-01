"""Offline timing accounting must not turn partial or mixed runs into comparisons."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/ci"))
import pytest
from report_workflow_times import job_report, main, summarize


def fixture():
    run = {
        "id": 10,
        "run_attempt": 2,
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-23T00:00:00Z",
        "run_started_at": "2026-10-24T00:00:00Z",
        "event": "merge_group",
    }
    job = {
        "id": 20,
        "run_id": 10,
        "run_attempt": 2,
        "head_sha": "a" * 40,
        "name": "build and test",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-24T00:00:02Z",
        "started_at": "2026-10-24T00:00:05Z",
        "completed_at": "2026-10-24T00:00:25Z",
        "steps": [
            {
                "number": 1,
                "name": "setup",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-10-24T00:00:06Z",
                "completed_at": "2026-10-24T00:00:10Z",
            },
            {
                "number": 2,
                "name": "test",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-10-24T00:00:10Z",
                "completed_at": "2026-10-24T00:00:24Z",
            },
        ],
    }
    parallel = copy.deepcopy(job)
    parallel["id"] = 21
    parallel["name"] = "parallel"
    return run, {"total_count": 2, "jobs": [job, parallel]}


class WorkflowTimesTests(unittest.TestCase):
    def test_parallel_time_is_not_elapsed_or_previous_attempt_time(self):
        run, jobs = fixture()
        report = summarize(run, jobs)
        assert report["complete"]
        assert report["attempt_elapsed_seconds"] == 25
        assert report["completed_job_seconds"] == 40
        assert report["attempt_to_first_job_seconds"] == 5
        assert report["jobs"][0]["created_to_start_seconds"] == 3
        assert report["jobs"][0]["unattributed_job_seconds"] == 2

    def test_pages_preserve_each_unique_job(self):
        run, jobs = fixture()
        pages = [{"total_count": 2, "jobs": [job]} for job in jobs["jobs"]]
        assert summarize(run, jobs) == summarize(run, pages)

    def test_run_identity_is_required_with_or_without_jobs(self):
        invalid = {
            "id": (None, True, 10.0, "10", 0, -1),
            "head_sha": (None, "", "a" * 39, "x" * 40, []),
            "run_attempt": (None, True, 2.0, "2", 0, -1),
            "event": (None, "", []),
            "status": ("unknown", [], 1),
            "conclusion": ([], 1, ""),
            "created_at": (),
        }
        for empty in (True, False):
            for field, values in invalid.items():
                for value in (*values, "omit"):
                    with self.subTest(empty=empty, field=field, value=value):
                        run, jobs = fixture()
                        if empty:
                            jobs = {"total_count": 0, "jobs": []}
                            run["conclusion"] = "cancelled"
                        if value == "omit":
                            del run[field]
                        else:
                            run[field] = value
                        with pytest.raises(
                            ValueError, match=r"invalid run|missing run|unknown run"
                        ):
                            summarize(run, jobs)

    def test_job_identity_uses_strict_types_before_equality(self):
        for field in ("id", "run_id", "run_attempt"):
            for value in (None, True, 0, -1, "10", 10.0 if field == "run_id" else 2.0):
                with self.subTest(field=field, value=value):
                    run, jobs = fixture()
                    jobs["jobs"][0][field] = value
                    with pytest.raises(ValueError, match="invalid job"):
                        summarize(run, jobs)

    def test_invalid_inventory_shapes_and_page_count_types_are_rejected(self):
        run, jobs = fixture()
        invalid = (
            None,
            [],
            {},
            {"total_count": 0},
            {"jobs": []},
            {"total_count": 0, "jobs": {}},
            {"total_count": 0, "jobs": None},
            {"total_count": 1, "jobs": [None]},
            {"total_count": 1, "jobs": [{"id": []}]},
            [{"total_count": 2, "jobs": jobs["jobs"]}, {"total_count": 2.0, "jobs": []}],
        )
        for pages in invalid:
            with (
                self.subTest(pages=pages),
                pytest.raises(ValueError, match=r"must be|missing|invalid|empty"),
            ):
                summarize(run, pages)

    def test_unstarted_and_skipped_jobs_can_omit_steps_without_mutating_input(self):
        for status in ("queued", "requested", "waiting", "pending", "completed"):
            with self.subTest(status=status):
                run, jobs = fixture()
                run.update(status="in_progress", conclusion=None)
                job = jobs["jobs"][0]
                job.update(
                    status=status,
                    conclusion="skipped" if status == "completed" else None,
                    completed_at=None,
                )
                del job["steps"]
                report = summarize(run, jobs)
                assert "steps" not in job
                assert report["jobs"][0]["steps"] == []
                assert report["jobs"][0]["timestamp_error"] is None
                assert report["jobs"][0]["created_to_start_seconds"] is None

    def test_started_job_cannot_claim_omitted_steps_are_empty(self):
        for status in ("in_progress", "completed"):
            with self.subTest(status=status):
                run, jobs = fixture()
                run.update(status=status, conclusion="success" if status == "completed" else None)
                job = jobs["jobs"][0]
                job["status"] = status
                del job["steps"]
                with pytest.raises(ValueError, match="missing steps for started job"):
                    summarize(run, jobs)

    def test_unstarted_timestamp_placeholder_does_not_establish_start_delay(self):
        run, jobs = fixture()
        run.update(status="in_progress", conclusion=None)
        jobs["jobs"][0].update(status="queued", conclusion=None, completed_at=None, steps=[])
        report = summarize(run, jobs)
        assert report["jobs"][0]["created_to_start_seconds"] is None
        assert report["attempt_to_first_job_seconds"] is None

    def test_missing_duplicate_changed_total_and_foreign_identity_rejected(self):
        run, original = fixture()
        for mutation in ("missing", "duplicate", "run_id", "run_attempt", "head_sha"):
            with self.subTest(mutation=mutation):
                jobs = copy.deepcopy(original)
                if mutation == "missing":
                    jobs["jobs"].pop()
                elif mutation == "duplicate":
                    jobs["jobs"][1]["id"] = jobs["jobs"][0]["id"]
                else:
                    jobs["jobs"][1][mutation] = "foreign"
                with pytest.raises(
                    ValueError,
                    match=r"incomplete job|duplicate job|job run/attempt/head|invalid job",
                ):
                    summarize(run, jobs)
        with pytest.raises(ValueError, match="job totals changed"):
            summarize(
                run,
                [
                    {"total_count": 1, "jobs": [original["jobs"][0]]},
                    {"total_count": 2, "jobs": [original["jobs"][1]]},
                ],
            )

    def test_failed_cancelled_skipped_jobs_remain_visible(self):
        run, jobs = fixture()
        run["conclusion"] = "failure"
        jobs["jobs"][0]["conclusion"] = "failure"
        jobs["jobs"][1]["conclusion"] = "cancelled"
        skipped = copy.deepcopy(jobs["jobs"][0])
        skipped.update(id=22, conclusion="skipped", steps=[], started_at=None, completed_at=None)
        jobs["jobs"].append(skipped)
        jobs["total_count"] += 1
        report = summarize(run, jobs)
        assert report["job_outcomes"] == {"failure": 1, "cancelled": 1, "skipped": 1}
        assert report["completed_job_seconds"] == 40

    def test_running_snapshot_has_no_final_elapsed_or_running_duration(self):
        run, jobs = fixture()
        run.update(status="in_progress", conclusion=None)
        jobs["jobs"][1].update(status="in_progress", conclusion=None, completed_at=None)
        report = summarize(run, jobs)
        assert not report["complete"]
        assert report["attempt_elapsed_seconds"] is None
        assert report["completed_job_seconds"] == 20
        assert report["jobs"][1]["occupied_seconds"] is None
        run.update(status="completed", conclusion="success")
        with pytest.raises(ValueError, match="completed run has unfinished"):
            summarize(run, jobs)

    def test_timestamp_errors_and_overlaps_are_not_silently_summed(self):
        for mutation in ("missing", "naive", "reverse", "overlap", "outside"):
            with self.subTest(mutation=mutation):
                run, jobs = fixture()
                job = jobs["jobs"][0]
                if mutation == "missing":
                    job["completed_at"] = None
                elif mutation == "naive":
                    job["started_at"] = "2026-10-24T00:00:05"
                elif mutation == "reverse":
                    job["completed_at"] = "2026-10-24T00:00:04Z"
                elif mutation == "overlap":
                    job["steps"][1]["started_at"] = "2026-10-24T00:00:09Z"
                elif mutation == "outside":
                    job["steps"][1]["completed_at"] = "2026-10-24T00:00:26Z"
                with pytest.raises(ValueError, match=r"timestamp|step number|steps exceed"):
                    job_report(job, run["run_started_at"])
                report = summarize(run, jobs)
                assert not report["complete"]
                assert report["unaccounted_job_ids"] == [20]
                assert report["attempt_elapsed_seconds"] is None
                assert report["completed_job_seconds"] == 20
                assert report["job_outcomes"] == {"success": 2}

    def test_invalid_earliest_job_cannot_make_later_start_look_like_first(self):
        run, jobs = fixture()
        jobs["jobs"][0]["completed_at"] = None
        jobs["jobs"][1].update(started_at="2026-10-24T00:00:15Z", steps=[])
        report = summarize(run, jobs)
        assert report["unaccounted_job_ids"] == [20]
        assert report["completed_job_seconds"] == 10
        assert report["attempt_to_first_job_seconds"] is None

    def test_invalid_or_unfinished_timing_cannot_identify_last_completed_job(self):
        for mutation in ("completion", "step", "unfinished", "run_start"):
            with self.subTest(mutation=mutation):
                run, jobs = fixture()
                last = jobs["jobs"][1]
                last["completed_at"] = "2026-10-24T00:00:30Z"
                if mutation == "completion":
                    last["completed_at"] = None
                elif mutation == "step":
                    last["steps"][0]["started_at"] = None
                elif mutation == "unfinished":
                    run.update(status="in_progress", conclusion=None)
                    last.update(status="in_progress", conclusion=None, completed_at=None)
                else:
                    run["run_started_at"] = None
                report = summarize(run, jobs)
                assert report["last_completed_job_id"] is None
                assert not report["complete"]
                assert report["completed_job_seconds"] == (45 if mutation == "run_start" else 20)

    def test_last_completed_job_requires_unique_latest_timestamp(self):
        run, jobs = fixture()
        report = summarize(run, jobs)
        assert report["complete"]
        assert report["attempt_elapsed_seconds"] == 25
        assert report["last_completed_job_id"] is None
        jobs["jobs"][1]["completed_at"] = "2026-10-24T09:00:25+09:00"
        assert summarize(run, jobs)["last_completed_job_id"] is None
        jobs["jobs"][1]["completed_at"] = "2026-10-24T00:00:26Z"
        report = summarize(run, jobs)
        assert report["last_completed_job_id"] == 21
        assert report["attempt_elapsed_seconds"] == 26

    def test_requested_run_and_job_remain_visible(self):
        run, jobs = fixture()
        run.update(status="requested", conclusion=None)
        for job in jobs["jobs"]:
            job.update(status="requested", conclusion=None, completed_at=None, steps=[])
        report = summarize(run, jobs)
        assert report["run"]["status"] == "requested"
        assert report["job_outcomes"] == {"requested": 2}
        assert not report["complete"]

    def test_unstarted_job_prevents_claiming_later_job_started_first(self):
        for status in ("in_progress", "queued"):
            with self.subTest(status=status):
                run, jobs = fixture()
                run.update(status="in_progress", conclusion=None)
                jobs["jobs"][0].update(
                    status=status, conclusion=None, started_at=None, completed_at=None, steps=[]
                )
                jobs["jobs"][1].update(started_at="2026-10-24T00:00:15Z", steps=[])
                report = summarize(run, jobs)
                assert report["attempt_to_first_job_seconds"] is None
                assert report["completed_job_seconds"] == 10
                assert report["unaccounted_job_ids"] == [20]
                if status == "in_progress":
                    assert "missing" in report["jobs"][0]["timestamp_error"]
                else:
                    assert report["jobs"][0]["timestamp_error"] is None

    def test_missing_run_start_preserves_snapshot_without_attempt_timing(self):
        for status, conclusion in (("queued", None), (None, None), ("completed", "cancelled")):
            for omit in (True, False):
                with self.subTest(status=status, omit=omit):
                    run, _ = fixture()
                    run.update(status=status, conclusion=conclusion, run_started_at=None)
                    if omit:
                        del run["run_started_at"]
                    report = summarize(run, {"total_count": 0, "jobs": []})
                    assert report["run"]["status"] == status
                    assert report["run"]["conclusion"] == conclusion
                    assert not report["complete"]
                    assert "missing" in report["run_timestamp_error"]
                    assert report["attempt_to_first_job_seconds"] is None
                    assert report["attempt_elapsed_seconds"] is None
                    assert report["completed_job_seconds"] == 0

    def test_invalid_run_start_preserves_valid_job_intervals(self):
        for value in (None, "", "2026-10-22T00:00:00Z", "2026-10-24T00:00:00"):
            with self.subTest(value=value):
                run, jobs = fixture()
                run["run_started_at"] = value
                report = summarize(run, jobs)
                assert not report["complete"]
                assert report["run_timestamp_error"]
                assert report["attempt_to_first_job_seconds"] is None
                assert report["attempt_elapsed_seconds"] is None
                assert report["completed_job_seconds"] == 40

    def test_unfinished_step_timestamp_errors_remain_visible(self):
        for mutation in ("missing", "malformed", "before_job", "ended", "overlap"):
            with self.subTest(mutation=mutation):
                run, jobs = fixture()
                run.update(status="in_progress", conclusion=None)
                job = jobs["jobs"][0]
                job.update(status="in_progress", conclusion=None, completed_at=None)
                step = job["steps"][1]
                step.update(status="in_progress", conclusion=None, completed_at=None)
                if mutation == "missing":
                    del step["started_at"]
                elif mutation == "malformed":
                    step["started_at"] = ""
                elif mutation == "before_job":
                    step["started_at"] = "2026-10-24T00:00:04Z"
                elif mutation == "ended":
                    step["completed_at"] = "2026-10-24T00:00:24Z"
                else:
                    step["started_at"] = "2026-10-24T00:00:09Z"
                report = summarize(run, jobs)
                assert report["jobs"][0]["timestamp_error"]
                assert report["attempt_to_first_job_seconds"] is None
                assert report["completed_job_seconds"] == 20

    def test_queued_step_can_omit_both_optional_timestamps(self):
        run, jobs = fixture()
        run.update(status="in_progress", conclusion=None)
        job = jobs["jobs"][0]
        job.update(status="in_progress", conclusion=None, completed_at=None)
        job["steps"][1].update(status="queued", conclusion=None)
        del job["steps"][1]["started_at"]
        del job["steps"][1]["completed_at"]
        report = summarize(run, jobs)
        assert report["jobs"][0]["timestamp_error"] is None
        assert report["jobs"][0]["steps"][1]["seconds"] is None
        job["steps"][1]["status"] = "pending"
        report = summarize(run, jobs)
        assert report["jobs"][0]["timestamp_error"] is None
        assert report["jobs"][0]["steps"][1]["seconds"] is None

    def test_cancelled_api_timestamp_contradiction_remains_visible(self):
        run, jobs = fixture()
        run["conclusion"] = "cancelled"
        jobs["jobs"][0].update(
            conclusion="cancelled", steps=[], completed_at="2026-10-24T00:00:04Z"
        )
        report = summarize(run, jobs)
        assert report["job_outcomes"] == {"cancelled": 1, "success": 1}
        assert report["jobs"][0]["timestamp_error"] == "reversed timestamp interval"
        assert not report["complete"]

    def test_completed_job_cannot_hide_unfinished_step(self):
        run, jobs = fixture()
        jobs["jobs"][0]["steps"][0]["status"] = "in_progress"
        with pytest.raises(ValueError, match="completed job has an unfinished step"):
            summarize(run, jobs)

    def test_invalid_metadata_is_not_a_timestamp_error(self):
        for mutation in ("missing", "name", "status", "duplicate"):
            with self.subTest(mutation=mutation):
                run, jobs = fixture()
                step = jobs["jobs"][0]["steps"][0]
                if mutation == "missing":
                    del step["name"]
                elif mutation == "name":
                    step["name"] = 7
                elif mutation == "status":
                    step["status"] = "unknown"
                else:
                    step["number"] = 2
                with pytest.raises(
                    ValueError, match=r"step field|step name|step status|step number"
                ):
                    summarize(run, jobs)

    def test_all_skipped_run_has_no_elapsed_measurement(self):
        run, jobs = fixture()
        for job in jobs["jobs"]:
            job.update(conclusion="skipped", steps=[], started_at=None, completed_at=None)
        # GitHub can report reversed placeholder intervals for work never started.
        jobs["jobs"][0].update(
            started_at="2026-10-24T00:00:05Z", completed_at="2026-10-24T00:00:04Z"
        )
        report = summarize(run, jobs)
        assert report["complete"]
        assert report["attempt_elapsed_seconds"] is None
        assert report["completed_job_seconds"] == 0

    def test_zero_job_snapshots_preserve_outcome_without_elapsed_measurement(self):
        run, _ = fixture()
        jobs = {"total_count": 0, "jobs": []}
        for status, conclusion in (("completed", "cancelled"), ("in_progress", None)):
            with self.subTest(status=status):
                run.update(status=status, conclusion=conclusion)
                report = summarize(run, jobs)
                assert report["run"]["status"] == status
                assert report["run"]["conclusion"] == conclusion
                assert report["complete"] == (status == "completed")
                assert report["job_outcomes"] == {}
                assert report["completed_job_seconds"] == 0
                assert report["attempt_elapsed_seconds"] is None
                assert report["attempt_to_first_job_seconds"] is None
        with pytest.raises(ValueError, match=r"invalid.*job inventory"):
            summarize(run, {"total_count": -1, "jobs": []})

    def test_cli_refuses_input_overwrite_through_direct_symlink_or_hardlink(self):
        run, jobs = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = json.dumps(run).encode()
            (root / "run.json").write_bytes(original)
            (root / "jobs.json").write_text(json.dumps(jobs))
            (root / "symlink").symlink_to(root / "run.json")
            (root / "hardlink").hardlink_to(root / "run.json")
            for name in ("run.json", "symlink", "hardlink", "jobs.json"):
                with (
                    self.subTest(name=name),
                    patch.object(
                        sys,
                        "argv",
                        [
                            "report",
                            "--run-json",
                            str(root / "run.json"),
                            "--jobs-json",
                            str(root / "jobs.json"),
                            "--output",
                            str(root / name),
                        ],
                    ),
                    patch("sys.stderr"),
                    pytest.raises(SystemExit) as error,
                ):
                    main()
                assert error.value.code == 2
                assert (root / "run.json").read_bytes() == original

    def test_cli_binds_retained_inputs_without_network_or_workflow_execution(self):
        run, jobs = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_data, jobs_data = json.dumps(run).encode(), json.dumps(jobs).encode()
            (root / "run.json").write_bytes(run_data)
            (root / "jobs.json").write_bytes(jobs_data)
            with patch.object(
                sys,
                "argv",
                [
                    "report",
                    "--run-json",
                    str(root / "run.json"),
                    "--jobs-json",
                    str(root / "jobs.json"),
                    "--output",
                    str(root / "times.json"),
                ],
            ):
                main()
            report = json.loads((root / "times.json").read_text())
            assert report["input_sha256"] == {
                "run": hashlib.sha256(run_data).hexdigest(),
                "jobs": hashlib.sha256(jobs_data).hexdigest(),
            }


if __name__ == "__main__":
    unittest.main()
