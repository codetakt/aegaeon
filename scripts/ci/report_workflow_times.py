"""Summarize retained GitHub REST run/job timestamps without executing CI."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

from pr_plan import unique_json_object

STATUSES = {"queued", "waiting", "pending", "in_progress", "completed"}


def require(condition: object, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def timestamp(value: object) -> datetime:
    require(isinstance(value, str), "missing timestamp")
    result = datetime.fromisoformat(cast("str", value))
    require(result.tzinfo is not None, "timestamp requires a timezone")
    return result.astimezone(UTC)


def interval(start: object, end: object) -> float:
    seconds = (timestamp(end) - timestamp(start)).total_seconds()
    require(seconds >= 0, "reversed timestamp interval")
    return seconds


def validate_job(job: dict[str, Any]) -> None:
    require(isinstance(job, dict), "job must be an object")
    require(
        {
            "id",
            "name",
            "status",
            "conclusion",
            "created_at",
            "started_at",
            "completed_at",
            "run_id",
            "run_attempt",
            "head_sha",
            "steps",
        }
        <= job.keys(),
        "missing job field",
    )
    require(type(job["id"]) is int and job["id"] > 0, "invalid job ID")
    require(isinstance(job["name"], str) and bool(job["name"]), "invalid job name")
    require(isinstance(job["status"], str) and job["status"] in STATUSES, "unknown job status")
    require(job["conclusion"] is None or isinstance(job["conclusion"], str), "invalid job outcome")
    require(job["status"] != "completed" or bool(job["conclusion"]), "missing job outcome")
    require(isinstance(job["steps"], list), "job steps must be an array")
    numbers = set()
    for step in job["steps"]:
        require(isinstance(step, dict), "step must be an object")
        require(
            {"number", "name", "status", "conclusion", "started_at", "completed_at"} <= step.keys(),
            "missing step field",
        )
        require(
            type(step["number"]) is int and step["number"] > 0 and step["number"] not in numbers,
            "invalid or duplicate step number",
        )
        numbers.add(step["number"])
        require(isinstance(step["name"], str) and bool(step["name"]), "invalid step name")
        require(
            isinstance(step["status"], str) and step["status"] in STATUSES, "unknown step status"
        )
        require(
            step["conclusion"] is None or isinstance(step["conclusion"], str),
            "invalid step outcome",
        )
        require(step["status"] != "completed" or bool(step["conclusion"]), "missing step outcome")
        require(
            job["status"] != "completed" or step["status"] == "completed",
            "completed job has an unfinished step",
        )


def job_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = []
    intervals: list[tuple[datetime, datetime]] = []
    for step in job["steps"]:
        number = step["number"]
        timed = step.get("conclusion") != "skipped" and step["status"] == "completed"
        seconds = interval(step.get("started_at"), step.get("completed_at")) if timed else None
        if timed:
            interval(job.get("started_at"), step["started_at"])
            if job.get("completed_at"):
                interval(step["completed_at"], job["completed_at"])
            intervals.append((timestamp(step["started_at"]), timestamp(step["completed_at"])))
        steps.append(
            {
                "number": number,
                "name": step["name"],
                "status": step["status"],
                "conclusion": step.get("conclusion"),
                "seconds": seconds,
            }
        )
    # Second-resolution timestamps may touch. Overlap must not inflate accounted time.
    intervals.sort()
    require(
        all(left[1] <= right[0] for left, right in pairwise(intervals)),
        "overlapping step timestamps",
    )
    return steps


def job_report(job: dict[str, Any], attempt_start: str) -> dict[str, Any]:
    """Keep running/skipped jobs visible; do not estimate their occupied time."""
    skipped = job.get("conclusion") == "skipped"
    completed = job["status"] == "completed"
    started = job.get("started_at")
    ended = job.get("completed_at")
    duration = None
    if completed and not skipped:
        require(bool(job.get("conclusion")), "completed job has no conclusion")
        duration = interval(started, ended)
    if started:
        interval(attempt_start, started)
    queue_delay = interval(job["created_at"], started) if started and not skipped else None
    steps = job_steps(job)
    step_seconds = sum(step["seconds"] for step in steps if step["seconds"] is not None)
    if duration is not None:
        require(step_seconds <= duration, "steps exceed the job interval")
    return {
        "id": job["id"],
        "name": job["name"],
        "status": job["status"],
        "conclusion": job.get("conclusion"),
        "labels": job.get("labels", []),
        "created_at": job["created_at"],
        "started_at": started,
        "completed_at": ended,
        "created_to_start_seconds": queue_delay,
        "occupied_seconds": duration,
        "completed_step_seconds": step_seconds,
        "unattributed_job_seconds": duration - step_seconds if duration is not None else None,
        "steps": steps,
    }


def retained_job_report(job: dict[str, Any], attempt_start: str) -> dict[str, Any]:
    try:
        return {**job_report(job, attempt_start), "timestamp_error": None}
    except ValueError as error:
        # Keep the failed/cancelled record even when GitHub's timestamps conflict.
        return {
            **{
                key: job.get(key)
                for key in (
                    "id",
                    "name",
                    "status",
                    "conclusion",
                    "labels",
                    "created_at",
                    "started_at",
                    "completed_at",
                )
            },
            "occupied_seconds": None,
            "created_to_start_seconds": None,
            "completed_step_seconds": None,
            "unattributed_job_seconds": None,
            "steps": None,
            "timestamp_error": str(error),
        }


def summarize(
    run: dict[str, Any], job_pages: dict[str, Any] | list[dict[str, Any]]
) -> dict[str, Any]:
    """Accept one REST page or the array produced by gh --paginate --slurp."""
    pages = job_pages if isinstance(job_pages, list) else [job_pages]
    require(bool(pages), "empty job response")
    total = pages[0]["total_count"]
    require(type(total) is int and total > 0, "invalid or empty job inventory")
    require(all(page["total_count"] == total for page in pages), "job totals changed between pages")
    jobs = [job for page in pages for job in page["jobs"]]
    require(len(jobs) == total, "incomplete job pagination")
    require(len({job["id"] for job in jobs}) == total, "duplicate job IDs")
    require(type(run["run_attempt"]) is int and run["run_attempt"] > 0, "invalid run attempt")
    require(isinstance(run["status"], str) and run["status"] in STATUSES, "unknown run status")
    for job in jobs:
        validate_job(job)
        require(
            job["run_id"] == run["id"]
            and job["run_attempt"] == run["run_attempt"]
            and job["head_sha"] == run["head_sha"],
            "job run/attempt/head mismatch",
        )
    attempt_start = run["run_started_at"]
    interval(run["created_at"], attempt_start)
    rows = [retained_job_report(job, attempt_start) for job in jobs]
    finished_run = run["status"] == "completed" and all(
        row["status"] == "completed" for row in rows
    )
    if run["status"] == "completed":
        require(
            finished_run and bool(run.get("conclusion")),
            "completed run has unfinished jobs/outcome",
        )
    timing_valid = not any(row["timestamp_error"] for row in rows)
    complete = finished_run and timing_valid
    finished = [row for row in rows if row["occupied_seconds"] is not None]
    last = max(finished, key=lambda row: timestamp(row["completed_at"])) if finished else None
    first = min(
        (
            row["started_at"]
            for row in rows
            if row["started_at"] and row["conclusion"] != "skipped" and not row["timestamp_error"]
        ),
        key=timestamp,
        default=None,
    )
    return {
        "schema": "aegaeon-workflow-times-v1",
        "run": {
            key: run.get(key)
            for key in (
                "id",
                "run_attempt",
                "name",
                "event",
                "head_sha",
                "path",
                "status",
                "conclusion",
                "created_at",
                "run_started_at",
                "html_url",
                "referenced_workflows",
            )
        },
        "complete": complete,
        "unaccounted_job_ids": [
            row["id"]
            for row in rows
            if row["occupied_seconds"] is None and row["conclusion"] != "skipped"
        ],
        "job_outcomes": dict(
            sorted(Counter(row["conclusion"] or row["status"] for row in rows).items())
        ),
        "attempt_to_first_job_seconds": interval(attempt_start, first)
        if first and timing_valid
        else None,
        "attempt_elapsed_seconds": interval(attempt_start, last["completed_at"])
        if complete and last
        else None,
        "completed_job_seconds": sum(row["occupied_seconds"] for row in finished),
        "last_completed_job_id": last["id"] if last else None,
        "jobs": rows,
        "limits": [
            "Incomplete/invalid snapshots have no final elapsed; totals exclude unaccounted jobs.",
            "Job intervals are occupied wall time, not CPU time or billed minutes.",
            "Created-to-start delay does not isolate dependency waiting or runner allocation.",
            "The last completed job and longest job do not establish the dependency critical path.",
            "Step times cannot separate compilation, tests, caches, transfers or service waits.",
            "Run head_sha is event identity; checkout/artifact identity needs separate evidence.",
            "Different sources, events, runners or caches permit descriptive comparisons only.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-json", required=True, type=Path)
    parser.add_argument("--jobs-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        for source in (args.run_json, args.jobs_json):
            require(
                args.output.resolve() != source.resolve()
                and not (args.output.exists() and args.output.samefile(source)),
                "output must not replace an input",
            )
        run_bytes = args.run_json.read_bytes()
        job_bytes = args.jobs_json.read_bytes()
        report = summarize(
            json.loads(run_bytes, object_pairs_hook=unique_json_object),
            json.loads(job_bytes, object_pairs_hook=unique_json_object),
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    report["input_sha256"] = {
        "run": hashlib.sha256(run_bytes).hexdigest(),
        "jobs": hashlib.sha256(job_bytes).hexdigest(),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
