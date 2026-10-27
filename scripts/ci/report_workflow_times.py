"""Summarize retained GitHub REST run/job timestamps without executing CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

from pr_plan import unique_json_object

STATUSES = {"queued", "requested", "waiting", "pending", "in_progress", "completed"}
PRESTART_STATUSES = STATUSES - {"in_progress", "completed"}


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


def observed_interval(record: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    """Validate available timestamps even when an interval is not yet complete."""
    if record["conclusion"] == "skipped":
        return None, None
    start, end = record.get("started_at"), record.get("completed_at")
    started = timestamp(start) if start is not None else None
    ended = timestamp(end) if end is not None else None
    completed = record["status"] == "completed"
    timed = completed and record["conclusion"] != "skipped"
    require(
        not (timed or record["status"] == "in_progress") or started is not None,
        "missing start timestamp",
    )
    require(not timed or ended is not None, "missing completion timestamp")
    require(ended is None or completed, "unfinished work has a completion timestamp")
    if ended is not None:
        interval(start, end)
    return started, ended


def run_start(run: dict[str, Any]) -> tuple[str | None, str | None]:
    try:
        interval(run["created_at"], run.get("run_started_at"))
    except ValueError as error:
        return None, str(error)
    return cast("str", run["run_started_at"]), None


def require_fields(record: dict[str, Any], fields: set[str], kind: str) -> None:
    require(isinstance(record, dict), f"{kind} must be an object")
    require(fields <= record.keys(), f"missing {kind} field")


def validate_identity(record: dict[str, Any], kind: str) -> None:
    fields = ("id", "run_attempt") if kind == "run" else ("id", "run_id", "run_attempt")
    for field in fields:
        require(type(record[field]) is int and record[field] > 0, f"invalid {kind} {field}")
    require(
        isinstance(record["head_sha"], str)
        and re.fullmatch(r"[0-9a-fA-F]{40}", record["head_sha"]),
        f"invalid {kind} head_sha",
    )


def validate_state(record: dict[str, Any], kind: str) -> None:
    status, outcome = record["status"], record["conclusion"]
    require(
        (kind == "run" and status is None) or (isinstance(status, str) and status in STATUSES),
        f"unknown {kind} status",
    )
    require(
        outcome is None or (isinstance(outcome, str) and bool(outcome)), f"invalid {kind} outcome"
    )
    require(status != "completed" or outcome is not None, f"missing {kind} outcome")


def validate_run(run: dict[str, Any]) -> None:
    require_fields(
        run, {"id", "run_attempt", "head_sha", "status", "conclusion", "created_at", "event"}, "run"
    )
    validate_identity(run, "run")
    validate_state(run, "run")
    require(isinstance(run["event"], str) and bool(run["event"]), "invalid run event")


def validate_job(job: dict[str, Any]) -> dict[str, Any]:
    require_fields(
        job,
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
        },
        "job",
    )
    validate_identity(job, "job")
    require(isinstance(job["name"], str) and bool(job["name"]), "invalid job name")
    validate_state(job, "job")
    if "steps" not in job:
        unstarted = job["status"] in PRESTART_STATUSES and job["conclusion"] is None
        require(unstarted or job["conclusion"] == "skipped", "missing steps for started job")
        job = {**job, "steps": []}
    require(isinstance(job["steps"], list), "job steps must be an array")
    numbers = set()
    for step in job["steps"]:
        require_fields(step, {"number", "name", "status", "conclusion"}, "step")
        require(
            type(step["number"]) is int and step["number"] > 0 and step["number"] not in numbers,
            "invalid or duplicate step number",
        )
        numbers.add(step["number"])
        require(isinstance(step["name"], str) and bool(step["name"]), "invalid step name")
        validate_state(step, "step")
        require(
            job["status"] != "completed" or step["status"] == "completed",
            "completed job has an unfinished step",
        )
    return job


def validated_jobs(job_pages: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    pages = job_pages if isinstance(job_pages, list) else [job_pages]
    require(bool(pages), "empty job response")
    for page in pages:
        require_fields(page, {"total_count", "jobs"}, "job page")
        require(
            type(page["total_count"]) is int and page["total_count"] >= 0, "invalid job inventory"
        )
        require(isinstance(page["jobs"], list), "job inventory must be an array")
    total = pages[0]["total_count"]
    require(all(page["total_count"] == total for page in pages), "job totals changed between pages")
    jobs = [validate_job(job) for page in pages for job in page["jobs"]]
    require(len(jobs) == total, "incomplete job pagination")
    require(len({job["id"] for job in jobs}) == total, "duplicate job IDs")
    return jobs


def job_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = []
    intervals: list[tuple[datetime, datetime]] = []
    for step in job["steps"]:
        number = step["number"]
        started, ended = observed_interval(step)
        timed = step.get("conclusion") != "skipped" and step["status"] == "completed"
        seconds = interval(step.get("started_at"), step.get("completed_at")) if timed else None
        if started is not None:
            interval(job.get("started_at"), step["started_at"])
            if job.get("completed_at") is not None:
                interval(step["started_at"], job["completed_at"])
            intervals.append((started, ended or started))
        if ended is not None and job.get("completed_at") is not None:
            interval(step["completed_at"], job["completed_at"])
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


def job_report(job: dict[str, Any], attempt_start: str | None) -> dict[str, Any]:
    """Keep running/skipped jobs visible; do not estimate their occupied time."""
    skipped = job.get("conclusion") == "skipped"
    completed = job["status"] == "completed"
    started = job.get("started_at")
    ended = job.get("completed_at")
    observed_interval(job)
    timestamp(job["created_at"])
    duration = None
    if completed and not skipped:
        require(bool(job.get("conclusion")), "completed job has no conclusion")
        duration = interval(started, ended)
    if started is not None and attempt_start is not None and not skipped:
        interval(attempt_start, started)
    queue_delay = (
        interval(job["created_at"], started)
        if started and not skipped and job["status"] not in PRESTART_STATUSES
        else None
    )
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


def retained_job_report(job: dict[str, Any], attempt_start: str | None) -> dict[str, Any]:
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
    validate_run(run)
    jobs = validated_jobs(job_pages)
    for job in jobs:
        require(
            job["run_id"] == run["id"]
            and job["run_attempt"] == run["run_attempt"]
            and job["head_sha"] == run["head_sha"],
            "job run/attempt/head mismatch",
        )
    attempt_start, run_timestamp_error = run_start(run)
    rows = [retained_job_report(job, attempt_start) for job in jobs]
    finished_run = run["status"] == "completed" and all(
        row["status"] == "completed" for row in rows
    )
    if run["status"] == "completed":
        require(
            finished_run and bool(run.get("conclusion")),
            "completed run has unfinished jobs/outcome",
        )
    timing_valid = run_timestamp_error is None and not any(row["timestamp_error"] for row in rows)
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
        "run_timestamp_error": run_timestamp_error,
        "unaccounted_job_ids": [
            row["id"]
            for row in rows
            if row["occupied_seconds"] is None and row["conclusion"] != "skipped"
        ],
        "job_outcomes": dict(
            sorted(Counter(row["conclusion"] or row["status"] for row in rows).items())
        ),
        "attempt_to_first_job_seconds": interval(attempt_start, first)
        if first
        and timing_valid
        and all(
            (row["started_at"] is not None and row["status"] not in PRESTART_STATUSES)
            or row["conclusion"] == "skipped"
            for row in rows
        )
        else None,
        "attempt_elapsed_seconds": interval(attempt_start, last["completed_at"])
        if complete and last
        else None,
        "completed_job_seconds": sum(row["occupied_seconds"] for row in finished),
        "last_completed_job_id": last["id"]
        if complete
        and last
        and sum(
            timestamp(row["completed_at"]) == timestamp(last["completed_at"]) for row in finished
        )
        == 1
        else None,
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
