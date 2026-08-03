#!/usr/bin/env python3
"""Validate Phase 4 claim activation preflight bundles."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

VALIDATION_DIR = pathlib.Path(__file__).resolve().parent
if str(VALIDATION_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATION_DIR))

import validate_admin_ui_assurance  # noqa: E402
import validate_certification_evidence_bundle  # noqa: E402
import validate_claim_gates  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "spec/phase4-claim-activation-preflight.schema.json"
CLAIM_SCHEMA_BY_TARGET = {
    "enterprise-readiness": REPO_ROOT / "spec/enterprise-readiness-claim.schema.json",
    "certification": REPO_ROOT / "spec/certification-claim.schema.json",
    "admin-ui-assurance": REPO_ROOT / "spec/admin-ui-assurance-claim.schema.json",
}
VALID_EXTERNAL_BLOCKER_CLASSES = {
    "external-hosted-evidence",
    "external-certification",
    "external-publication",
    "public-wording-release",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"Phase 4 preflight file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def repo_relative_path(repo_root: pathlib.Path, raw_path: str, label: str) -> pathlib.Path:
    if not raw_path:
        raise ValidationError(f"{label}: path must be non-empty")
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        raise ValidationError(f"{label}: local path must be repository-relative")
    if ".." in path.parts:
        raise ValidationError(f"{label}: local path must not contain '..'")
    resolved_root = repo_root.resolve()
    resolved = (resolved_root / path).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValidationError(f"{label}: local path escapes repository root") from exc
    return resolved


def require_existing_file(repo_root: pathlib.Path, raw_path: str, label: str) -> pathlib.Path:
    path = repo_relative_path(repo_root, raw_path, label)
    if not path.is_file():
        raise ValidationError(f"{label}: path does not exist or is not a file: {raw_path}")
    return path


def validate_phase_semantics(bundle: dict[str, Any]) -> None:
    phase4_status = bundle["phase4_status"]
    public_claim_ready = bundle["public_claim_ready"]
    external_blockers = cast("list[Any]", bundle["external_blockers"])
    review = cast("dict[str, Any]", bundle["review"])
    release_activation = cast("dict[str, Any]", bundle["release_activation"])

    if phase4_status == "internal-preflight-complete":
        if public_claim_ready is not False:
            raise ValidationError("internal Phase 4 preflight must keep public_claim_ready=false")
        if not external_blockers:
            raise ValidationError(
                "internal Phase 4 preflight must list remaining external blockers"
            )
        if review.get("decision") != "approved" or not review.get("reviewer"):
            raise ValidationError(
                "internal Phase 4 preflight requires approved review with reviewer"
            )
        if release_activation.get("product_wording_update_required") is not True:
            raise ValidationError("internal Phase 4 preflight must require product wording update")
        if release_activation.get("readme_update_required") is not True:
            raise ValidationError("internal Phase 4 preflight must require README update")
        if release_activation.get("release_tag_required") is not True:
            raise ValidationError("internal Phase 4 preflight must require release tag")
        return

    if phase4_status == "external-activation-complete":
        if public_claim_ready is not True:
            raise ValidationError("external Phase 4 activation requires public_claim_ready=true")
        if external_blockers:
            raise ValidationError("external Phase 4 activation cannot have remaining blockers")
        if review.get("decision") != "approved" or not review.get("reviewer"):
            raise ValidationError(
                "external Phase 4 activation requires approved review with reviewer"
            )


def validate_preflight_claim_gates(
    repo_root: pathlib.Path,
    bundle: dict[str, Any],
) -> tuple[set[tuple[str, str]], dict[str, dict[str, Any]]]:
    incomplete_required: set[tuple[str, str]] = set()
    policies_by_target: dict[str, dict[str, Any]] = {}
    seen_targets: set[str] = set()

    for raw_gate in cast("list[Any]", bundle["claim_gates"]):
        gate = cast("dict[str, Any]", raw_gate)
        target = cast("str", gate["claim_target"])
        if target in seen_targets:
            raise ValidationError(f"duplicate claim gate entry for {target}")
        seen_targets.add(target)
        gate_path = require_existing_file(
            repo_root,
            cast("str", gate["claim_gate_path"]),
            f"claim_gates[{target}].claim_gate_path",
        )
        schema_path = CLAIM_SCHEMA_BY_TARGET[target]
        validate_claim_gates_module(schema_path, gate_path)
        policy = cast("dict[str, Any]", load_json(gate_path))
        if policy.get("claim_target") != target:
            raise ValidationError(f"{target}: claim gate target mismatch")

        activation_status = gate["activation_status"]
        if bundle["phase4_status"] == "internal-preflight-complete":
            if policy.get("claim_active") is not False:
                raise ValidationError(f"{target}: internal preflight requires claim_active=false")
            if activation_status != "blocked-on-external":
                raise ValidationError(f"{target}: internal preflight requires blocked-on-external")
        else:
            if activation_status != "ready-for-public-activation":
                raise ValidationError(
                    f"{target}: external activation requires ready-for-public-activation"
                )

        evidence = policy.get("required_evidence")
        if not isinstance(evidence, list):
            raise ValidationError(f"{target}: required_evidence must be a list")
        for item in evidence:
            if not isinstance(item, dict) or item.get("required_for_activation") is not True:
                continue
            item_id = item.get("id")
            status = item.get("status")
            if not isinstance(item_id, str):
                raise ValidationError(f"{target}: evidence item missing id")
            if status == "missing":
                raise ValidationError(f"{target}: evidence item {item_id} is missing")
            if status != "complete":
                incomplete_required.add((target, item_id))
        policies_by_target[target] = policy

    expected_targets = set(CLAIM_SCHEMA_BY_TARGET)
    if seen_targets != expected_targets:
        missing = expected_targets - seen_targets
        extra = seen_targets - expected_targets
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("unexpected " + ", ".join(sorted(extra)))
        raise ValidationError(
            "claim_gates must cover exactly the managed claim targets: " + "; ".join(details)
        )

    return incomplete_required, policies_by_target


def validate_claim_gates_module(schema_path: pathlib.Path, gate_path: pathlib.Path) -> None:
    validate_claim_gates.validate_pair(schema_path, gate_path)


def validate_internal_evidence(repo_root: pathlib.Path, bundle: dict[str, Any]) -> None:
    seen_ids: set[str] = set()
    for raw_evidence in cast("list[Any]", bundle["internal_evidence"]):
        evidence = cast("dict[str, Any]", raw_evidence)
        evidence_id = cast("str", evidence["id"])
        if evidence_id in seen_ids:
            raise ValidationError(f"duplicate internal evidence id {evidence_id}")
        seen_ids.add(evidence_id)
        path = require_existing_file(
            repo_root,
            cast("str", evidence["path"]),
            f"internal_evidence[{evidence_id}].path",
        )
        if evidence_id == "certification-phase2-internal-bundle":
            validate_certification_evidence_bundle.validate_bundle(path, repo_root=repo_root)
        if evidence_id == "admin-ui-phase3-internal-bundle":
            validate_admin_ui_assurance.validate_bundle(path, repo_root=repo_root)


def validate_external_blockers(
    bundle: dict[str, Any],
    incomplete_required: set[tuple[str, str]],
) -> None:
    blocker_keys: set[tuple[str, str]] = set()
    release_blockers = 0

    for raw_blocker in cast("list[Any]", bundle["external_blockers"]):
        blocker = cast("dict[str, Any]", raw_blocker)
        target = cast("str", blocker["claim_target"])
        evidence_id = cast("str", blocker["evidence_id"])
        blocker_class = cast("str", blocker["blocker_class"])
        if blocker_class not in VALID_EXTERNAL_BLOCKER_CLASSES:
            raise ValidationError(f"{target}/{evidence_id}: invalid blocker class")
        key = (target, evidence_id)
        if key in blocker_keys:
            raise ValidationError(f"duplicate external blocker {target}/{evidence_id}")
        blocker_keys.add(key)
        if target == "release":
            release_blockers += 1

    claim_blockers = {key for key in blocker_keys if key[0] != "release"}
    missing_blockers = sorted(incomplete_required - claim_blockers)
    if missing_blockers:
        formatted = ", ".join(f"{target}/{item_id}" for target, item_id in missing_blockers)
        raise ValidationError(
            f"incomplete activation evidence missing external blocker: {formatted}"
        )

    stale_blockers = sorted(claim_blockers - incomplete_required)
    if stale_blockers:
        formatted = ", ".join(f"{target}/{item_id}" for target, item_id in stale_blockers)
        raise ValidationError(
            f"external blocker references complete or unknown evidence: {formatted}"
        )

    if bundle["phase4_status"] == "internal-preflight-complete" and release_blockers == 0:
        raise ValidationError("internal Phase 4 preflight requires at least one release blocker")


def validate_bundle(path: pathlib.Path, repo_root: pathlib.Path | None = None) -> None:
    resolved_repo_root = (repo_root or REPO_ROOT).resolve()
    schema = load_json(SCHEMA_PATH)
    bundle = cast("dict[str, Any]", load_json(path))
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(bundle)

    validate_phase_semantics(bundle)
    incomplete_required, _policies_by_target = validate_preflight_claim_gates(
        resolved_repo_root, bundle
    )
    validate_internal_evidence(resolved_repo_root, bundle)
    validate_external_blockers(bundle, incomplete_required)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="+", help="Phase 4 preflight bundle JSON path(s)")
    args = parser.parse_args()

    failures = 0
    for raw_path in args.bundle:
        path = pathlib.Path(raw_path)
        try:
            validate_bundle(path)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
