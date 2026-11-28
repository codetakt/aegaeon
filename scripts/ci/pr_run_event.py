"""Read the original GitHub PR event preserved by a specific workflow attempt."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from datetime import datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

from check_preview_ci import REPOSITORY, attempt_interval

if TYPE_CHECKING:
    from check_merge_readiness import Reader

PRODUCT = ".github/workflows/pr.yml"
INFRASTRUCTURE = ".github/workflows/infrastructure-validation.yml"
MAX_RECEIPT_BYTES = 16 * 1024
MAX_PLAN_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXPANDED_PLAN_BYTES = 128 * 1024 * 1024
SHA256 = re.compile(r"[a-f0-9]{64}")


class MissingArtifactError(ValueError):
    """This run has no retained artifact with the requested name."""


class StaleTestBaseError(ValueError):
    """GitHub supplied a merge commit whose first parent differs from the event base."""


def archive_member(archive: zipfile.ZipFile, name: str, maximum: int) -> zipfile.ZipInfo:
    entries = [entry for entry in archive.infolist() if entry.filename == name]
    if len(entries) != 1 or not 0 < entries[0].file_size <= maximum:
        raise ValueError(f"Expected one bounded {name} record")
    return entries[0]


def verify_plan_files(archive: zipfile.ZipFile, admission: dict[str, Any]) -> None:
    members = {"ci-plan.json": "component_plan_sha256", "ci-input-union.json": "input_union_sha256"}
    for name, field in members.items():
        entry = archive_member(archive, name, MAX_EXPANDED_PLAN_BYTES)
        with archive.open(entry) as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != admission[field]:
                raise ValueError(f"Archived {name} differs from the protected plan admission")


def read_member(
    reader: Reader, run: dict[str, Any], artifact_name: str, member: str, maximum: int
) -> dict[str, Any]:
    endpoint = f"actions/runs/{run['id']}/artifacts?name={artifact_name}"
    rows = reader.pages(endpoint, "artifacts")
    if not rows:
        raise MissingArtifactError(f"Missing {artifact_name} on the selected run")
    if len(rows) != 1 or rows[0]["name"] != artifact_name:
        raise ValueError(f"Expected exactly one {artifact_name} artifact on the selected run")
    row = rows[0]
    origin = row["workflow_run"]
    if (
        type(row["expired"]) is not bool
        or not 0 < row["size_in_bytes"] <= maximum
        or origin["id"] != run["id"]
        or origin["head_sha"] != run["head_sha"]
        or origin["repository_id"] != run["repository"]["id"]
        or origin["head_repository_id"] != run["head_repository"]["id"]
    ):
        raise ValueError("Artifact is unavailable or belongs to another workflow run")
    if row["expired"] is True:
        raise MissingArtifactError(f"Expired {artifact_name} on the selected run")
    blob = reader.archive(row["id"])
    if (
        len(blob) != row["size_in_bytes"]
        or "sha256:" + hashlib.sha256(blob).hexdigest() != row["digest"]
    ):
        raise ValueError("Downloaded archive differs from the immutable GitHub artifact")
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            data = json.loads(archive.read(archive_member(archive, member, MAX_RECEIPT_BYTES)))
            if not isinstance(data, dict):
                raise TypeError(f"Invalid {member} object")
            if artifact_name == "pr-ci-plan":
                verify_plan_files(archive, data)
    except zipfile.BadZipFile as exc:
        raise ValueError("Malformed workflow artifact archive") from exc
    return data


def original_event(
    reader: Reader, run: dict[str, Any], pr: dict[str, Any], job: str
) -> dict[str, Any]:
    attempt = run["run_attempt"]
    event = read_member(
        reader, run, f"native-pr-event-{job}-{attempt}", "native-pr-event.json", MAX_RECEIPT_BYTES
    )
    expected = {
        "version": 1,
        "repository": REPOSITORY,
        "workflow_ref": f"{REPOSITORY}/{run['path']}@refs/pull/{pr['number']}/merge",
        "run_id": run["id"],
        "run_attempt": attempt,
        "job": job,
        "number": pr["number"],
        "head": pr["head"]["sha"],
        "merged": False,
    }
    if any(
        event[key] != value or type(event[key]) is not type(value)
        for key, value in expected.items()
    ):
        raise ValueError("Original event does not identify the selected candidate and attempt")
    if not isinstance(event["base"], str) or not event["base"]:
        raise ValueError("Original event has no target branch")
    if not SHA256.fullmatch(event["event_sha256"]):
        raise ValueError("Invalid digest for original event")
    return event


def only_title_or_body(event: dict[str, Any]) -> bool:
    return (
        event["action"] == "edited"
        and event["previous_base"] is None
        and event["change_keys"] in (["body"], ["title"], ["body", "title"])
    )


def product_plan(reader: Reader, run: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    plan = read_member(
        reader, run, "pr-ci-plan", "ci-transport-admission.json", MAX_PLAN_ARCHIVE_BYTES
    )
    if (
        plan["admission"] != "protected-v2-conservative-full"
        or plan["event"] != "pull_request"
        or plan["base"] != event["base_sha"]
        or plan["event_base"] != event["base_sha"]
        or plan["source_head"] != event["head"]
        or plan["test_sha"] != event["test_sha"]
        or not re.fullmatch(r"[a-f0-9]{40}", plan["test_sha"])
    ):
        raise ValueError("Protected product plan differs from the original event")
    producer = plan["producer"]
    # A failed-jobs-only rerun can retain the successful plan from a prior attempt.
    if (
        producer["repository"] != REPOSITORY
        or producer["job"] != "plan"
        or producer["run_id"] != str(run["id"])
        or type(producer["run_attempt"]) is not int
        or not 1 <= producer["run_attempt"] <= run["run_attempt"]
        or producer["event_payload_sha256"] != event["event_sha256"]
    ):
        raise ValueError("Protected product plan comes from another GitHub delivery")
    commit = reader.get(f"git/commits/{plan['test_sha']}")
    if (
        commit["sha"] != plan["test_sha"]
        or commit["tree"]["sha"] != plan["test_tree"]
        or len(commit["parents"]) != 2
        or commit["parents"][1]["sha"] != plan["source_head"]
    ):
        raise ValueError("The recorded test tree or merge parents differ from GitHub")
    if commit["parents"][0]["sha"] != plan["base"]:
        raise StaleTestBaseError("The actual merge base differs from the recorded event base")
    return plan


BASE_HISTORY = """
query($number:Int!) {
  repository(owner:"codetakt",name:"aegaeon") {
    pullRequest(number:$number) {
      timelineItems(last:100, itemTypes:[BASE_REF_CHANGED_EVENT, REOPENED_EVENT]) {
        pageInfo { hasPreviousPage }
        nodes {
          __typename
          ... on BaseRefChangedEvent { id createdAt actor{login} previousRefName currentRefName }
          ... on ReopenedEvent { id createdAt actor{login} }
        }
      }
    }
  }
}
"""


def attempt_jobs(reader: Reader, run: dict[str, Any]) -> list[dict[str, Any]]:
    return reader.pages(f"actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")


def executed_job(reader: Reader, run: dict[str, Any], jobs: list[dict[str, Any]], name: str) -> int:
    (job,) = [job for job in jobs if job["name"] == name]
    if (job["run_id"], job["run_attempt"], job["head_sha"]) != (
        run["id"],
        run["run_attempt"],
        run["head_sha"],
    ) or (job["status"], job["conclusion"]) != ("completed", "success"):
        raise ValueError(f"{name} did not execute successfully on this attempt")
    check = reader.get(f"check-runs/{job['id']}")
    if (
        (check["id"], check["name"], check["head_sha"]) != (job["id"], name, run["head_sha"])
        or check["app"]["id"] != 15368
        or check["check_suite"]["id"] != run["check_suite_id"]
        or (check["status"], check["conclusion"]) != ("completed", "success")
    ):
        raise ValueError(f"{name} has no matching successful GitHub Actions check")
    return int(job["id"])


def classify_workflows(
    reader: Reader, runs: list[dict[str, Any]], checks: list[dict[str, Any]], pr: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[int]]:
    """Exclude only successful runs that positively identify an original metadata edit."""
    retained = []
    metadata = []
    for run in runs:
        if (
            run["status"] != "completed"
            or run["conclusion"] != "success"
            or run["event"] != "pull_request"
            or run["path"] not in {PRODUCT, INFRASTRUCTURE}
            or [r["number"] for r in run["pull_requests"]] != [pr["number"]]
        ):
            retained.append(run)
            continue
        names = {
            check["name"]
            for check in checks
            if check["app"]["id"] == 15368 and check["check_suite"]["id"] == run["check_suite_id"]
        }
        marker = "PR metadata edit" if run["path"] == PRODUCT else "Classify infrastructure edit"
        # A failed-jobs-only retry may inherit the edit classifier from an
        # older attempt. A run with actual infrastructure execution is a
        # product run regardless of which attempt classified its edit.
        infrastructure_ran = run["path"] == INFRASTRUCTURE and any(
            check["check_suite"]["id"] == run["check_suite_id"]
            and check["app"]["id"] == 15368
            and check["name"] == "OpenTofu modules and template contracts"
            and check["conclusion"] not in {"skipped", "neutral"}
            for check in checks
        )
        if marker not in names or infrastructure_ran:
            retained.append(run)
            continue
        jobs = attempt_jobs(reader, run)
        job_id = executed_job(reader, run, jobs, marker)
        role = "required" if run["path"] == PRODUCT else "edit"
        event = original_event(reader, run, pr, role)
        # Infrastructure also subscribes to edits targeting other branches. Its
        # classifier runs there even when the PR later returns with the same SHA.
        other_target = (
            run["path"] == INFRASTRUCTURE
            and event["action"] == "edited"
            and event["base"] != "main"
        )
        if not (other_target or (event["base"] == "main" and only_title_or_body(event))):
            if run["path"] == PRODUCT:
                raise ValueError("Product checks mislabeled as a metadata edit")
            retained.append(run)
            continue
        if (run["path"] == PRODUCT and "Required checks" in names) or any(
            j["conclusion"] != "skipped" for j in jobs if j["id"] != job_id
        ):
            raise ValueError("A metadata edit also reported product or infrastructure execution")
        metadata.append(run["id"])
    return retained, metadata


def recovered_classifier_checks(
    reader: Reader,
    inventory: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    pr: dict[str, Any],
) -> dict[int, int]:
    """Map terminal classifier failures to actual full jobs on the same PR and workflow."""
    routes = {
        "PR metadata edit": (PRODUCT, "required", "Required checks"),
        "Classify infrastructure edit": (
            INFRASTRUCTURE,
            "infrastructure",
            "OpenTofu modules and template contracts",
        ),
    }
    owners = {
        run["check_suite_id"]: run
        for run in inventory
        if run["event"] == "pull_request"
        and run["path"] in (PRODUCT, INFRASTRUCTURE)
        and [item["number"] for item in run["pull_requests"]] == [pr["number"]]
        and run["head_sha"] == pr["head"]["sha"]
        and run["repository"]["full_name"] == REPOSITORY
        and run["head_repository"]["full_name"] == pr["head"]["repo"]["full_name"]
    }
    recovered = {}
    verified_jobs: dict[str, int] = {}
    for check in checks:
        if (
            check["name"] not in routes
            or check["app"]["id"] != 15368
            or check["status"] != "completed"
            or check["conclusion"] not in {"failure", "cancelled", "timed_out"}
            or check["head_sha"] != pr["head"]["sha"]
        ):
            continue
        path, role, name = routes[check["name"]]
        failed = owners.get(check["check_suite"]["id"])
        if failed is None or failed["path"] != path:
            continue
        candidates = [r for r in selected if r["event"] == "pull_request" and r["path"] == path]
        (later,) = candidates
        if (
            owners.get(later["check_suite_id"]) != later
            or later["status"] != "completed"
            or later["conclusion"] != "success"
            or attempt_interval(later)[0] <= datetime.fromisoformat(check["completed_at"])
        ):
            continue
        if path not in verified_jobs:
            event = original_event(reader, later, pr, role)
            if event["base"] != "main" or only_title_or_body(event):
                raise ValueError("Classifier recovery requires a full validation on main")
            job = executed_job(reader, later, attempt_jobs(reader, later), name)
            if role == "required":
                product_plan(reader, later, event)
            verified_jobs[path] = job
        recovered[check["id"]] = verified_jobs[path]
    return recovered


def match_return(event: dict[str, Any], history: list[dict[str, Any]]) -> str | None:
    """Match the original delivery to the latest return to main or a subsequent reopen."""
    changes = [i for i, row in enumerate(history) if row["__typename"] == "BaseRefChangedEvent"]
    if not changes or event["base"] != "main":
        return None
    last = changes[-1]
    if history[last]["currentRefName"] != "main":
        raise ValueError("The latest base transition is away from main")
    matches = []
    for i, row in enumerate(history):
        if (row["createdAt"], row["actor"]["login"]) != (event["updated_at"], event["sender"]):
            continue
        if row["__typename"] == "ReopenedEvent":
            if event["action"] == "reopened" and event["previous_base"] is None:
                matches.append(i)
        elif (
            event["action"] == "edited"
            and "base" in event["change_keys"]
            and row["currentRefName"] == event["base"]
            and row["previousRefName"] == event["previous_base"]
        ):
            matches.append(i)
    if len(matches) != 1 or matches[0] < last:
        return None
    return str(history[matches[0]]["id"])


def original_return_source(
    reader: Reader, pr: dict[str, Any], history: list[dict[str, Any]]
) -> dict[str, Any]:
    """Identify the source on the original return, independently of the recovery run."""
    last = next(row for row in reversed(history) if row["__typename"] == "BaseRefChangedEvent")
    # The time filter only bounds discovery. The native delivery must still match
    # the exact timeline event. A later push can restore the original source SHA.
    query = urlencode(
        {"event": "pull_request", "branch": pr["head"]["ref"], "created": ">=" + last["createdAt"]}
    )
    runs = reader.pages(
        f"actions/workflows/infrastructure-validation.yml/runs?{query}", "workflow_runs"
    )
    sources = {}
    for run in runs:
        if (
            run["event"] != "pull_request"
            or run["path"] != INFRASTRUCTURE
            or run["repository"]["full_name"] != REPOSITORY
            or run["head_repository"]["full_name"] != pr["head"]["repo"]["full_name"]
            or [p["number"] for p in run["pull_requests"]] != [pr["number"]]
        ):
            continue
        previous = {**pr, "head": {**pr["head"], "sha": run["head_sha"]}}
        event = recorded_event(reader, run, previous, "edit")
        if event is None:
            event = recorded_event(reader, run, previous, "infrastructure")
        if event is not None and match_return(event, history) == last["id"]:
            sources[event["head"]] = {
                "run_id": run["id"],
                "attempt": run["run_attempt"],
                "head": event["head"],
                "event": event["event_sha256"],
                "transition": last["id"],
            }
    if len(sources) != 1:
        raise ValueError("Cannot identify the source commit at the original base change")
    return next(iter(sources.values()))


def recorded_event(
    reader: Reader, run: dict[str, Any], pr: dict[str, Any], job: str
) -> dict[str, Any] | None:
    try:
        return original_event(reader, run, pr, job)
    except MissingArtifactError:
        return None


def later_push(event: dict[str, Any], history: list[dict[str, Any]]) -> bool:
    last = next(row for row in reversed(history) if row["__typename"] == "BaseRefChangedEvent")
    return (
        event["action"] == "synchronize"
        and event["previous_base"] is None
        and last["currentRefName"] == event["base"]
        and datetime.fromisoformat(event["updated_at"]) > datetime.fromisoformat(last["createdAt"])
    )


def add_return_proof(
    reader: Reader,
    run: dict[str, Any],
    pr: dict[str, Any],
    history: list[dict[str, Any]],
    proofs: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    role = "required" if run["path"] == PRODUCT else "infrastructure"
    event = recorded_event(reader, run, pr, role)
    if event is None or event["base"] != "main":
        return
    transition = match_return(event, history)
    if transition is None:
        if not later_push(event, history):
            return
        transition = "synchronize"
    key = (transition, event["event_sha256"], event["test_sha"])
    proof = proofs.setdefault(key, {})
    name = "Required checks" if role == "required" else "OpenTofu modules and template contracts"
    job = executed_job(reader, run, attempt_jobs(reader, run), name)
    details = {}
    if role == "required":
        try:
            plan = product_plan(reader, run, event)
        except (MissingArtifactError, StaleTestBaseError):
            # An authentic stale synthetic merge is ineligible. A later reopen may
            # independently validate the intended base even when both trees match.
            return
        details = {"tree": plan["test_tree"], "base": plan["base"]}
    if role in proof:
        raise ValueError("Ambiguous execution for the same native base change")
    proof.update(details)
    proof[role] = {"run_id": run["id"], "attempt": run["run_attempt"], "job": job}


def check_return(
    reader: Reader, runs: list[dict[str, Any]], pr: dict[str, Any]
) -> dict[str, Any] | None:
    """Find a successful product and infrastructure pair for the actual return event."""
    page = reader.timeline(BASE_HISTORY, pr["number"])
    history = page["nodes"]
    if page["pageInfo"]["hasPreviousPage"]:
        raise ValueError("Base transition inventory exceeds the observation bound")
    if not any(row["__typename"] == "BaseRefChangedEvent" for row in history):
        return None
    proofs: dict[tuple[str, str, str], dict[str, Any]] = {}
    for run in runs:
        if (
            run["event"] == "pull_request"
            and run["path"] in {PRODUCT, INFRASTRUCTURE}
            and [r["number"] for r in run["pull_requests"]] == [pr["number"]]
            and run["head_sha"] == pr["head"]["sha"]
            and run["conclusion"] == "success"
        ):
            add_return_proof(reader, run, pr, history, proofs)
    matched = [
        (key, proof)
        for key, proof in proofs.items()
        if {"required", "infrastructure"} <= proof.keys()
    ]
    if not matched:
        raise ValueError(
            "Missing successful product and infrastructure evidence for the return to main"
        )
    positions = {row["id"]: i for i, row in enumerate(history)}
    key, proof = max(matched, key=lambda pair: positions.get(pair[0][0], -1))
    last = next(row for row in reversed(history) if row["__typename"] == "BaseRefChangedEvent")
    if key[0] != last["id"]:
        anchor = original_return_source(reader, pr, history)
        return {
            "transition": anchor["transition"],
            "return_source": anchor,
            "recovery": key[0],
            "event": key[1],
            "test_sha": key[2],
            **proof,
        }
    return {"transition": key[0], "event": key[1], "test_sha": key[2], **proof}
