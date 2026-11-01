"""Check responsibility coverage; this audit never admits an external qualification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

KINDS = {
    "functional",
    "monitoring",
    "publication",
    "notice",
    "aggregation",
    "reusable",
    "emulator",
    "external_conformance",
    "functional_load",
    "diagnostic",
}
OBLIGATIONS = {
    "dudect",
    "performance",
    "auth0",
    "kms",
    "conformance",
    "admission",
    "measurement-lifecycle",
}


def require(condition: bool, message: str) -> None:  # noqa: FBT001 -- assertion, not a mode
    if not condition:
        raise ValueError(message)


def strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(v, str) and bool(v.strip()) for v in value)
        and len(value) == len(set(value))
    )


def validate(root: Path, inventory: dict[str, Any]) -> dict[str, Any]:
    require(inventory["schema"] == "ci-responsibility-audit/1", "Unknown inventory schema")
    require(inventory["status"] == "commissioning_required", "This audit cannot commission a route")
    actual: set[str] = set()
    workflows = root / ".github/workflows"
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        workflow = yaml.safe_load(path.read_text())
        actual.update(path.name + "/" + job for job in workflow["jobs"])
    jobs = inventory["jobs"]
    ids = [row["id"] for row in jobs]
    require(bool(actual) and len(ids) == len(set(ids)), "Empty or duplicate job inventory")
    require(set(ids) == actual, "Actual workflow jobs differ from responsibility inventory")
    require(all(row["kind"] in KINDS for row in jobs), "Unknown responsibility kind")
    obligations = inventory["external_obligations"]
    ids = [row["id"] for row in obligations]
    require(
        len(ids) == len(set(ids)) and set(ids) == OBLIGATIONS, "Missing or duplicate responsibility"
    )
    for row in obligations:
        check_obligation(root, row)
    return {
        "inventory_valid": True,
        "workflow_jobs": len(jobs),
        "external_responsibilities": len(obligations),
        "qualification_admitted": False,
        "open_items": {row["id"]: row["open_items"] for row in obligations},
    }


def check_obligation(root: Path, row: dict[str, Any]) -> None:
    for field in ("owner", "subject"):
        require(isinstance(row[field], str) and bool(row[field].strip()), "Missing owner/subject")
    for field in ("required_evidence", "entrypoints", "open_items"):
        require(strings(row[field]), "Empty, invalid or duplicate obligation fields")
    for name in row["entrypoints"]:
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts, "Invalid entrypoint path")
        target = (root / path).resolve()
        require(target.is_relative_to(root.resolve()) and target.is_file(), "Missing entrypoint")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    root = args.root.resolve()
    result = validate(
        root, json.loads((root / "ci/qualification-responsibilities.json").read_text())
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
