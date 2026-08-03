#!/usr/bin/env python3
"""Validate future claim-gate policy documents against canonical schemas."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

DEFAULT_PAIRS = [
    (
        pathlib.Path("spec/enterprise-readiness-claim.schema.json"),
        pathlib.Path("spec/enterprise-readiness-claim.current.json"),
    ),
    (
        pathlib.Path("spec/certification-claim.schema.json"),
        pathlib.Path("spec/certification-claim.current.json"),
    ),
    (
        pathlib.Path("spec/admin-ui-assurance-claim.schema.json"),
        pathlib.Path("spec/admin-ui-assurance-claim.current.json"),
    ),
    (
        pathlib.Path("spec/server-client-formal-assurance-claim.schema.json"),
        pathlib.Path("spec/server-client-formal-assurance-claim.current.json"),
    ),
]


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"Claim gate file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def validate_pair(schema_path: pathlib.Path, policy_path: pathlib.Path) -> None:
    schema = load_json(schema_path)
    policy = cast("dict[str, Any]", load_json(policy_path))
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(policy)
    validate_unique_evidence_ids(policy)
    validate_evidence_uris(policy)
    validate_activation_semantics(policy)


def validate_unique_evidence_ids(policy: dict[str, Any]) -> None:
    evidence = policy.get("required_evidence")
    if not isinstance(evidence, list):
        return

    seen: set[str] = set()
    for item in evidence:
        if not isinstance(item, dict):
            continue
        item_id = item.get("id")
        if not isinstance(item_id, str):
            continue
        if item_id in seen:
            raise ValidationError(f"{item_id}: duplicate required_evidence id")
        seen.add(item_id)


def validate_evidence_uris(policy: dict[str, Any]) -> None:
    evidence = policy.get("required_evidence")
    if not isinstance(evidence, list):
        return

    for item in evidence:
        if not isinstance(item, dict):
            continue
        status = item.get("status")
        if status not in {"in_progress", "complete"}:
            continue

        evidence_uri = item.get("evidence_uri")
        item_id = item.get("id", "<unknown>")
        if not isinstance(evidence_uri, str) or not evidence_uri:
            raise ValidationError(
                f"{item_id}: {status} evidence requires a non-empty evidence_uri",
            )
        if is_external_evidence_uri(evidence_uri):
            validate_external_evidence_uri(item_id, evidence_uri)
            continue

        evidence_path_text = evidence_uri.split("#", maxsplit=1)[0]
        if not evidence_path_text:
            raise ValidationError(f"{item_id}: evidence_uri must include a path before '#'")
        evidence_path = pathlib.Path(evidence_path_text)
        if evidence_path.is_absolute():
            raise ValidationError(f"{item_id}: local evidence_uri must be relative")
        resolved = (pathlib.Path.cwd() / evidence_path).resolve()
        if not resolved.exists():
            raise ValidationError(
                f"{item_id}: {status} evidence_uri does not exist: {evidence_uri}",
            )


def is_external_evidence_uri(evidence_uri: str) -> bool:
    return evidence_uri.startswith(("http://", "https://", "s3://", "gs://"))


def validate_external_evidence_uri(item_id: object, evidence_uri: str) -> None:
    if evidence_uri.startswith("http://"):
        raise ValidationError(f"{item_id}: external evidence_uri must not use http")


def validate_activation_semantics(policy: dict[str, Any]) -> None:
    if policy.get("claim_active") is not True:
        return

    evidence = policy.get("required_evidence")
    if not isinstance(evidence, list):
        raise ValidationError("active claim gate requires required_evidence list")

    incomplete = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        if item.get("required_for_activation") is True and item.get("status") != "complete":
            incomplete.append(f"{item.get('id', '<unknown>')}={item.get('status')}")

    if incomplete:
        joined = ", ".join(incomplete)
        raise ValidationError(f"claim_active=true but required evidence is incomplete: {joined}")

    if policy.get("claim_target") == "certification":
        scope = policy.get("certification_scope")
        if not isinstance(scope, dict):
            raise ValidationError("active certification gate requires certification_scope")
        target = scope.get("target")
        if scope.get("selected") is not True or not isinstance(target, str) or not target:
            raise ValidationError(
                "active certification gate requires selected=true and non-empty target"
            )

    if policy.get("claim_target") == "admin-ui-assurance":
        excluded_surfaces = policy.get("excluded_surfaces")
        if not isinstance(excluded_surfaces, list) or not excluded_surfaces:
            raise ValidationError("active admin UI gate requires explicit excluded_surfaces")

    if policy.get("claim_target") == "server-client-formal-assurance":
        excluded_tcb_boundaries = policy.get("excluded_tcb_boundaries")
        if not isinstance(excluded_tcb_boundaries, list) or not excluded_tcb_boundaries:
            raise ValidationError(
                "active server/client gate requires explicit excluded_tcb_boundaries",
            )
        if policy.get("claim_stage") != "public-claim-active":
            raise ValidationError(
                "active server/client gate requires claim_stage=public-claim-active",
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Validate all source-managed claim gates",
    )
    parser.add_argument(
        "policy",
        nargs="*",
        help=(
            "Optional policy JSON path(s). When provided, each file is matched "
            "to the schema named by its $schema basename."
        ),
    )
    args = parser.parse_args()

    if args.all or not args.policy:
        pairs = DEFAULT_PAIRS
    else:
        pairs = []
        for raw_policy in args.policy:
            policy_path = pathlib.Path(raw_policy)
            policy = cast("dict[str, Any]", load_json(policy_path))
            if not isinstance(policy, dict) or not isinstance(policy.get("$schema"), str):
                print(f"[invalid] {policy_path}: missing string $schema", file=sys.stderr)
                return 1
            schema_name = pathlib.Path(policy["$schema"]).name
            schema_path = pathlib.Path("spec") / schema_name
            pairs.append((schema_path, policy_path))

    failures = 0
    for schema_path, policy_path in pairs:
        try:
            validate_pair(schema_path, policy_path)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {policy_path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {policy_path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
