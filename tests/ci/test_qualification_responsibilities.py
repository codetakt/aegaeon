"""Inventory validation does not manufacture qualification evidence."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
from check_qualification_responsibilities import validate  # noqa: E402


def inventory():
    return json.loads((ROOT / "ci/qualification-responsibilities.json").read_text())


def test_complete_inventory_is_still_not_qualified():
    report = validate(ROOT, inventory())
    assert report["inventory_valid"]
    assert report["workflow_jobs"] == 73
    assert report["external_responsibilities"] == 7
    assert report["qualification_admitted"] is False
    assert all(report["open_items"].values())


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_job",
        "duplicate_job",
        "new_job",
        "unknown_kind",
        "missing_obligation",
        "duplicate_obligation",
    ],
)
def test_incomplete_inventory_is_rejected(mutation):
    data = copy.deepcopy(inventory())
    if mutation == "missing_job":
        data["jobs"].pop()
    elif mutation == "duplicate_job":
        data["jobs"].append(data["jobs"][0])
    elif mutation == "new_job":
        data["jobs"].append({"id": "unknown.yml/new", "kind": "functional"})
    elif mutation == "unknown_kind":
        data["jobs"][0]["kind"] = "qualified"
    elif mutation == "missing_obligation":
        data["external_obligations"].pop()
    elif mutation == "duplicate_obligation":
        data["external_obligations"].append(data["external_obligations"][0])
    with pytest.raises(ValueError, match=r"inventory|responsibility"):
        validate(ROOT, data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner", ""),
        ("required_evidence", []),
        ("open_items", []),
        ("entrypoints", ["does-not-exist"]),
        ("entrypoints", ["../AGENTS.md"]),
    ],
)
def test_invalid_responsibility_is_rejected(field, value):
    data = copy.deepcopy(inventory())
    data["external_obligations"][0][field] = value
    with pytest.raises(ValueError, match=r"owner|obligation|entrypoint"):
        validate(ROOT, data)


def test_commissioning_cannot_be_claimed_by_inventory():
    data = copy.deepcopy(inventory())
    data["status"] = "commissioned"
    with pytest.raises(ValueError, match="cannot commission"):
        validate(ROOT, data)


@pytest.mark.parametrize("suffix", ["yml", "yaml"])
def test_new_actual_workflow_requires_inventory_update(tmp_path, suffix):
    workflows = tmp_path / ".github/workflows"
    workflows.mkdir(parents=True)
    for original in (ROOT / ".github/workflows").iterdir():
        if original.suffix in {".yml", ".yaml"}:
            (workflows / original.name).write_bytes(original.read_bytes())
    (workflows / f"new-workflow.{suffix}").write_text(
        "jobs:\n  unreviewed:\n    runs-on: ubuntu-latest\n"
    )
    with pytest.raises(ValueError, match="Actual workflow jobs differ"):
        validate(tmp_path, inventory())
