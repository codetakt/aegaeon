"""Verify the event data retained across same-head edits and workflow reruns."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RECORDER = ROOT / ".github/actions/record-pr-event/record.py"


def native_event(changes: dict) -> dict:
    repository = {"full_name": "codetakt/aegaeon"}
    return {
        "action": "edited",
        "number": 19,
        "changes": changes,
        "repository": repository,
        "sender": {"login": "maintainer"},
        "pull_request": {
            "number": 19,
            "title": "private-title-sentinel",
            "body": "private-body-sentinel",
            "merged": False,
            "updated_at": "2026-11-27T03:47:24Z",
            "base": {"repo": repository, "ref": "main", "sha": "b" * 40},
            "head": {"sha": "c" * 40},
        },
    }


def record(path: Path, event: dict, attempt: int = 1) -> dict:
    path.mkdir()
    event_path = path / "event.json"
    raw = json.dumps(event).encode()
    event_path.write_bytes(raw)
    subprocess.run(  # noqa: S603 -- fixed interpreter and repository script.
        [sys.executable, "-I", RECORDER],
        check=True,
        env={
            **os.environ,
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": "codetakt/aegaeon",
            "GITHUB_EVENT_PATH": str(event_path),
            "GITHUB_SHA": "d" * 40,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": str(attempt),
            "GITHUB_JOB": "required",
            "GITHUB_WORKFLOW_REF": "codetakt/aegaeon/.github/workflows/pr.yml@refs/pull/19/merge",
            "RUNNER_TEMP": str(path),
        },
    )
    output = (path / "native-pr-event.json").read_text()
    assert "sentinel" not in output
    receipt = json.loads(output)
    assert receipt["event_sha256"] == hashlib.sha256(raw).hexdigest()
    return receipt


def test_original_retarget_event_survives_a_rerun(tmp_path: Path) -> None:
    event = native_event({"base": {"ref": {"from": "stack"}}, "body": {"from": "old-sentinel"}})
    first = record(tmp_path / "original", event)
    assert first["previous_base"] == "stack"
    assert first["change_keys"] == ["base", "body"]
    assert first["head"] == "c" * 40
    assert first["base"] == "main"
    assert first["test_sha"] == "d" * 40
    assert first["sender"] == "maintainer"
    assert first["updated_at"] == event["pull_request"]["updated_at"]
    assert record(tmp_path / "rerun", event, 2) == {**first, "run_attempt": 2}


@pytest.mark.parametrize("keys", [[], ["body"], ["title", "body"], ["unknown"]])
def test_edit_preserves_only_changed_keys(tmp_path: Path, keys: list[str]) -> None:
    receipt = record(
        tmp_path / "edit", native_event({key: {"from": "old-sentinel"} for key in keys})
    )
    assert receipt["change_keys"] == sorted(keys)
    assert receipt["previous_base"] is None


def test_mismatched_pull_request_cannot_produce_a_receipt(tmp_path: Path) -> None:
    event = native_event({})
    event["number"] += 1
    with pytest.raises(subprocess.CalledProcessError):
        record(tmp_path / "invalid", event)
    assert not (tmp_path / "invalid/native-pr-event.json").exists()
