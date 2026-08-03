#!/usr/bin/env python3
"""Validate Phase 5 pre-public server/client blocker-closure reports."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = pathlib.Path("spec/server-client-pre-public-blocker-closure.schema.json")
REQUIRED_CLOSURE_IDS = {
    "client-promotion-report-shape",
    "released-client-report-shape",
    "hosted-readiness-report-shape",
    "managed-provider-evidence-shape",
    "admin-sdk-evidence-shape",
    "release-publication-bundle-shape",
    "publication-org-rollout-ready",
    "publication-org-contract",
    "release-security-contract",
    "internal-review-signoff",
}
REQUIRED_ACTIVATION_BLOCKERS = {
    "released-client-claim-activation",
    "fresh-managed-provider-evidence",
    "release-security-archive",
    "release-custody-review",
    "external-security-review",
    "public-wording-release",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"Pre-public blocker report not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def item_ids(items: object, label: str) -> set[str]:
    if not isinstance(items, list):
        raise ValidationError(f"{label} must be a list")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValidationError(f"{label} item missing string id")
        item_id = cast("str", item["id"])
        if item_id in seen:
            raise ValidationError(f"{label}: duplicate id {item_id}")
        seen.add(item_id)
    return seen


def validate_semantics(report: dict[str, Any]) -> None:
    if report.get("public_claim_ready") is not False:
        raise ValidationError("pre-public report must keep public_claim_ready=false")
    if report.get("all_non_public_blockers_closed") is not True:
        raise ValidationError("all non-public blockers must be closed")

    closure_items = cast("list[dict[str, Any]]", report["closure_items"])
    closure_ids = item_ids(closure_items, "closure_items")
    missing_closure = REQUIRED_CLOSURE_IDS - closure_ids
    if missing_closure:
        joined = ", ".join(sorted(missing_closure))
        raise ValidationError(f"missing closure items: {joined}")

    for item in closure_items:
        if item.get("status") != "complete":
            raise ValidationError(f"{item['id']}: closure item is not complete")
        evidence_uri = item.get("evidence_uri")
        if isinstance(evidence_uri, str) and evidence_uri.startswith("http://"):
            raise ValidationError(f"{item['id']}: evidence_uri must not use http")

    activation_blockers = cast("list[dict[str, Any]]", report["activation_blockers"])
    blocker_ids = item_ids(activation_blockers, "activation_blockers")
    missing_blockers = REQUIRED_ACTIVATION_BLOCKERS - blocker_ids
    if missing_blockers:
        joined = ", ".join(sorted(missing_blockers))
        raise ValidationError(f"missing activation blockers: {joined}")

    review = report.get("review")
    if not isinstance(review, dict) or review.get("decision") != "approved":
        raise ValidationError("pre-public report requires approved internal review")


def validate_report(path: pathlib.Path) -> None:
    schema = load_json(SCHEMA_PATH)
    report = cast("dict[str, Any]", load_json(path))
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(report)
    validate_semantics(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", nargs="+", help="Pre-public blocker report JSON path(s)")
    args = parser.parse_args()

    failures = 0
    for raw_path in args.report:
        path = pathlib.Path(raw_path)
        try:
            validate_report(path)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
