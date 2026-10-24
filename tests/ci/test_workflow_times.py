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
                    ValueError, match=r"incomplete job|duplicate job|job run/attempt/head"
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
        report = summarize(run, jobs)
        assert report["complete"]
        assert report["attempt_elapsed_seconds"] is None
        assert report["completed_job_seconds"] == 0

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
