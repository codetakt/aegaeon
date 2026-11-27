"""Check PR event receipts through repeated base changes, retries and metadata edits."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import check_group_base_changes as group
import pytest
from check_preview_ci import REPOSITORY
from pr_run_event import (
    INFRASTRUCTURE,
    PRODUCT,
    check_return,
    classify_workflows,
    match_return,
    original_event,
    product_plan,
    read_member,
)

BASE, HEAD, MERGE, TREE = (c * 40 for c in "abcd")
EVENT_DIGEST = "f" * 64
PR = {
    "number": 21,
    "head": {"sha": HEAD, "ref": "topic", "repo": {"full_name": REPOSITORY}},
    "base": {"ref": "main"},
}
SOURCE = "2026-11-27T03:47:24Z"
RETURN = {
    "__typename": "BaseRefChangedEvent",
    "createdAt": SOURCE,
    "id": "return",
    "previousRefName": "parent",
    "currentRefName": "main",
    "actor": {"login": "owner"},
}


def run(path, number, attempt=1):
    return {
        "id": number,
        "run_attempt": attempt,
        "pull_requests": [{"number": 21}],
        "repository": {"id": 1, "full_name": REPOSITORY},
        "head_repository": {"id": 1, "full_name": REPOSITORY},
        "head_sha": HEAD,
        "path": path,
        "event": "pull_request",
        "check_suite_id": number + 100,
        "conclusion": "success",
        "status": "completed",
    }


def receipt(r, job):
    return {
        "version": 1,
        "repository": REPOSITORY,
        "workflow_ref": f"{REPOSITORY}/{r['path']}@refs/pull/21/merge",
        "run_id": r["id"],
        "run_attempt": r["run_attempt"],
        "job": job,
        "number": 21,
        "head": r["head_sha"],
        "base": "main",
        "merged": False,
        "base_sha": BASE,
        "test_sha": MERGE,
        "event_sha256": EVENT_DIGEST,
        "updated_at": SOURCE,
        "sender": "owner",
        "previous_base": "parent",
        "change_keys": ["base"],
        "action": "edited",
    }


def plan(r):
    return {
        "version": 1,
        "admission": "protected-v2-conservative-full",
        "component_plan_sha256": hashlib.sha256(b"plan").hexdigest(),
        "input_union_sha256": hashlib.sha256(b"union").hexdigest(),
        "base": BASE,
        "event": "pull_request",
        "source_head": HEAD,
        "event_base": BASE,
        "test_sha": MERGE,
        "test_tree": TREE,
        "producer": {
            "repository": REPOSITORY,
            "job": "plan",
            "run_id": str(r["id"]),
            "run_attempt": 1,
            "event_payload_sha256": EVENT_DIGEST,
        },
    }


class Reader:
    def __init__(self):
        self.listings = {}
        self.archives = {}
        self.checks = {}
        self.history = [RETURN]
        self.commit = {
            "sha": MERGE,
            "tree": {"sha": TREE},
            "parents": [{"sha": BASE}, {"sha": HEAD}],
        }

    def store(self, r, name, member, value):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr(member, json.dumps(value))
            if name == "pr-ci-plan":
                z.writestr("ci-plan.json", b"plan")
                z.writestr("ci-input-union.json", b"union")
        blob = out.getvalue()
        aid = len(self.archives) + 1
        self.archives[aid] = blob
        record = {
            "id": aid,
            "name": name,
            "expired": False,
            "size_in_bytes": len(blob),
            "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
            "workflow_run": {
                "id": r["id"],
                "head_sha": r["head_sha"],
                "repository_id": 1,
                "head_repository_id": 1,
            },
        }
        self.listings[f"actions/runs/{r['id']}/artifacts?name={name}"] = [record]
        return record

    def successful_job(self, r, name):
        job_id = 10 * r["id"]
        job = {
            "id": job_id,
            "name": name,
            "head_sha": r["head_sha"],
            "run_id": r["id"],
            "run_attempt": r["run_attempt"],
            "conclusion": "success",
            "status": "completed",
        }
        self.listings[f"actions/runs/{r['id']}/attempts/{r['run_attempt']}/jobs"] = [job]
        self.checks[f"check-runs/{job_id}"] = {
            **job,
            "app": {"id": 15368},
            "check_suite": {"id": r["check_suite_id"]},
        }
        return job

    def native(self, r, job, **changes):
        if job in {"required", "infrastructure"}:
            self.successful_job(
                r,
                "Required checks"
                if job == "required"
                else "OpenTofu modules and template contracts",
            )
        return self.store(
            r,
            f"native-pr-event-{job}-{r['run_attempt']}",
            "native-pr-event.json",
            receipt(r, job) | changes,
        )

    def pages(self, endpoint, key):
        return self.listings.get(endpoint, [])

    def get(self, endpoint):
        if endpoint.startswith("check-runs/"):
            return self.checks[endpoint]
        assert endpoint == f"git/commits/{MERGE}"
        return self.commit

    def archive(self, aid):
        return self.archives[aid]

    def timeline(self, query, number):
        assert number == PR["number"]
        return {"nodes": self.history, "pageInfo": {"hasPreviousPage": False}}


def test_repeated_return_and_reopen_use_native_identity():
    older = RETURN | {"id": "previous", "createdAt": "2026-11-27T03:46:04Z"}
    away = RETURN | {"id": "away", "currentRefName": "parent", "previousRefName": "main"}
    reopen = RETURN | {
        "__typename": "ReopenedEvent",
        "id": "reopened",
        "createdAt": "2026-11-27T03:49:00Z",
    }
    history = [older, away, RETURN, reopen]
    e = receipt(run(PRODUCT, 1), "required")
    assert match_return(e, history) == "return"
    assert match_return(e | {"updated_at": older["createdAt"]}, history) is None
    assert (
        match_return(
            e | {"updated_at": reopen["createdAt"], "action": "reopened", "previous_base": None},
            history,
        )
        == "reopened"
    )
    assert match_return(e | {"sender": "other"}, history) is None
    assert match_return(e, [*history, RETURN]) is None
    with pytest.raises(ValueError, match="away from main"):
        match_return(e, [older, away])


def test_return_requires_both_workflows_and_the_same_delivery():
    a, b = run(PRODUCT, 1, 2), run(INFRASTRUCTURE, 2)
    reader = Reader()
    reader.native(a, "required")
    reader.store(a, "pr-ci-plan", "ci-transport-admission.json", plan(a))
    with pytest.raises(ValueError, match="Missing successful"):
        check_return(reader, [a, b], PR)
    reader.native(b, "infrastructure", event_sha256="e" * 64)
    with pytest.raises(ValueError, match="Missing successful"):
        check_return(reader, [a, b], PR)
    reader.native(b, "infrastructure")
    proof = check_return(reader, [a, b], PR)
    assert proof["tree"] == TREE
    assert proof["transition"] == "return"
    assert proof["required"] == {"run_id": 1, "attempt": 2, "job": 10}
    reader.commit["parents"].reverse()
    with pytest.raises(ValueError, match="merge parents"):
        check_return(reader, [a, b], PR)


def test_older_rerun_with_same_head_and_tree_cannot_supply_a_return():
    r = run(PRODUCT, 1, 3)
    reader = Reader()
    reader.history.append(RETURN | {"createdAt": "2026-11-27T03:49:00Z", "id": "later"})
    reader.native(r, "required")
    with pytest.raises(ValueError, match="Missing successful"):
        check_return(reader, [r], PR)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("run_id", 9),
        ("run_attempt", 2),
        ("number", 20),
        ("workflow_ref", "other@refs/heads/main"),
        ("version", True),
        ("merged", 0),
        ("job", "plan"),
    ],
)
def test_receipt_rejects_wrong_identity(key, value):
    r = run(PRODUCT, 1)
    reader = Reader()
    e = receipt(r, "required") | {key: value}
    reader.store(r, "native-pr-event-required-1", "native-pr-event.json", e)
    with pytest.raises(ValueError, match="identify"):
        original_event(reader, r, PR, "required")


def test_artifact_is_immutable_bounded_and_bound_to_its_origin():
    r = run(PRODUCT, 1)
    reader = Reader()
    meta = reader.native(r, "required")
    meta["workflow_run"]["head_sha"] = BASE
    with pytest.raises(ValueError, match="another workflow"):
        original_event(reader, r, PR, "required")
    meta["workflow_run"]["head_sha"] = HEAD
    reader.archives[meta["id"]] += b"x"
    with pytest.raises(ValueError, match="immutable"):
        original_event(reader, r, PR, "required")
    reader.store(r, "test", "file.json", {"data": "x" * 20000})
    with pytest.raises(ValueError, match="bounded"):
        read_member(reader, r, "test", "file.json", 16384)


@pytest.mark.parametrize(
    "change", [{"run_attempt": 3}, {"run_id": "2"}, {"event_payload_sha256": "e" * 64}]
)
def test_copied_plan_requires_the_original_run_delivery(change):
    r = run(PRODUCT, 1, 2)
    reader = Reader()
    p = plan(r)
    p["producer"].update(change)
    reader.store(r, "pr-ci-plan", "ci-transport-admission.json", p)
    with pytest.raises(ValueError, match="another GitHub delivery"):
        product_plan(reader, r, receipt(r, "required"))


@pytest.mark.parametrize(
    ("path", "job", "name"),
    [
        (PRODUCT, "required", "PR metadata edit"),
        (INFRASTRUCTURE, "edit", "Classify infrastructure edit"),
    ],
)
def test_lightweight_runs_require_positive_native_and_job_evidence(path, job, name):
    r = run(path, 2)
    reader = Reader()
    rows = [{"name": name, "app": {"id": 15368}, "check_suite": {"id": 102}}]
    reader.native(r, job, change_keys=["body"], previous_base=None)
    marker = reader.successful_job(r, name)
    skipped = {"id": 6, "name": "Select checks", "conclusion": "skipped"}
    reader.listings["actions/runs/2/attempts/1/jobs"].append(skipped)
    assert classify_workflows(reader, [r], [], PR) == ([r], [])
    assert classify_workflows(reader, [r], rows, PR) == ([], [2])
    skipped["conclusion"] = "failure"
    with pytest.raises(ValueError, match="also reported"):
        classify_workflows(reader, [r], rows, PR)
    marker["conclusion"] = "skipped"
    with pytest.raises(ValueError, match="did not execute"):
        classify_workflows(reader, [r], rows, PR)


def test_plan_digest_binds_the_two_retained_documents():
    r = run(PRODUCT, 1)
    reader = Reader()
    p = plan(r) | {"input_union_sha256": "0" * 64}
    reader.store(r, "pr-ci-plan", "ci-transport-admission.json", p)
    with pytest.raises(ValueError, match="differs from the protected plan"):
        product_plan(reader, r, receipt(r, "required"))


def test_partial_infrastructure_retry_retains_real_execution_without_reclassifying():
    r = run(INFRASTRUCTURE, 3, 2)
    checks = [
        {"app": {"id": 15368}, "name": name, "check_suite": {"id": 103}, "conclusion": "success"}
        for name in ("Classify infrastructure edit", "OpenTofu modules and template contracts")
    ]
    assert classify_workflows(Reader(), [r], checks, PR) == ([r], [])


def test_group_requires_the_same_evidence_for_a_queue_member(monkeypatch):
    reader = Reader()
    monkeypatch.setattr(group, "group_members", lambda *_: [(21, HEAD)])
    monkeypatch.setattr(group, "candidate", lambda *_: PR)
    # Current state has a return to main but no matching product run.
    with pytest.raises(ValueError, match="inventory is incomplete"):
        group.group_returns(reader, {}, MERGE)
    reader.history.clear()
    assert group.group_returns(reader, {}, MERGE) == {21: None}
    members = iter([[(21, HEAD)], [(23, BASE)]])
    monkeypatch.setattr(group, "group_members", lambda *_: next(members))
    with pytest.raises(ValueError, match="group changed"):
        group.group_returns(reader, {}, MERGE)


def test_new_head_requires_an_independent_anchor_for_the_return_to_main():
    reader = Reader()
    a, b = run(PRODUCT, 1), run(INFRASTRUCTURE, 2)
    push = {
        "action": "synchronize",
        "change_keys": [],
        "previous_base": None,
        "updated_at": "2026-11-27T03:48:01Z",
    }
    reader.native(a, "required", **push)
    reader.native(b, "infrastructure", **push)
    reader.store(a, "pr-ci-plan", "ci-transport-admission.json", plan(a))
    with pytest.raises(ValueError, match="source commit at the original base change"):
        check_return(reader, [a, b], PR)
    prior = run(INFRASTRUCTURE, 9) | {"head_sha": "e" * 40}
    reader.native(prior, "edit", event_sha256="1" * 64)
    reader.listings[
        "actions/workflows/infrastructure-validation.yml/runs?"
        "event=pull_request&branch=topic&created=%3E%3D2026-11-27T03%3A47%3A24Z"
    ] = [prior]
    proof = check_return(reader, [a, b], PR)
    assert proof["return_source"]["head"] == prior["head_sha"]
    assert proof["transition"] == RETURN["id"]
    reader.native(prior, "edit", previous_base="wrong")
    with pytest.raises(ValueError, match="source commit at the original base change"):
        check_return(reader, [a, b], PR)


@pytest.mark.parametrize("path", [PRODUCT, INFRASTRUCTURE])
@pytest.mark.parametrize(
    "mismatch", ["skipped", "other_attempt", "other_suite", "other_app", "other_check", "head"]
)
def test_return_requires_the_actual_product_and_infrastructure_jobs(path, mismatch):
    reader = Reader()
    a, b = run(PRODUCT, 1), run(INFRASTRUCTURE, 2)
    reader.native(a, "required")
    reader.native(b, "infrastructure")
    reader.store(a, "pr-ci-plan", "ci-transport-admission.json", plan(a))
    r = a if path == PRODUCT else b
    job = reader.listings[f"actions/runs/{r['id']}/attempts/1/jobs"][0]
    check = reader.checks[f"check-runs/{job['id']}"]
    if mismatch == "other_suite":
        check["check_suite"]["id"] += 1
    elif mismatch == "other_app":
        check["app"]["id"] += 1
    elif mismatch == "other_check":
        check["id"] += 1
    elif mismatch == "head":
        check["head_sha"] = BASE
    elif mismatch == "skipped":
        job["conclusion"] = "skipped"
    else:
        job["run_attempt"] += 1
    with pytest.raises(ValueError, match=r"did not execute|no matching"):
        check_return(reader, [a, b], PR)


def test_edit_away_from_main_leaves_room_for_a_later_valid_return_on_the_same_head():
    reader = Reader()
    away, a, b = run(INFRASTRUCTURE, 3), run(PRODUCT, 1), run(INFRASTRUCTURE, 2)
    reader.native(away, "edit", base="parent", previous_base="main")
    marker = reader.successful_job(away, "Classify infrastructure edit")
    checks = [reader.checks[f"check-runs/{marker['id']}"]]
    reader.listings["actions/runs/3/attempts/1/jobs"].append(
        {"id": 8, "name": "OpenTofu modules and template contracts", "conclusion": "skipped"}
    )
    reader.native(a, "required")
    reader.store(a, "pr-ci-plan", "ci-transport-admission.json", plan(a))
    retained, lightweight = classify_workflows(reader, [away, a, b], checks, PR)
    assert retained == [a, b]
    assert lightweight == [away["id"]]
    reader.native(b, "infrastructure", base="parent")
    with pytest.raises(ValueError, match="Missing successful"):
        check_return(reader, retained, PR)
    reader.native(b, "infrastructure")
    assert check_return(reader, retained, PR)["transition"] == "return"
