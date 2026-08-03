#!/usr/bin/env python3
"""Validate the server/client formal-assurance claim gate and evidence bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any, cast

import validate_claim_gates
import validate_server_client_pre_public_blockers
from jsonschema import Draft202012Validator, ValidationError

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CLAIM_SCHEMA_PATH = REPO_ROOT / "spec/server-client-formal-assurance-claim.schema.json"
BUNDLE_SCHEMA_PATH = REPO_ROOT / "spec/server-client-formal-assurance-evidence-bundle.schema.json"
CLIENT_BOUNDARY_SCHEMA_PATH = REPO_ROOT / "spec/client-claim-boundary.schema.json"
CLIENT_PROMOTION_SCHEMA_PATH = REPO_ROOT / "spec/client-claim-promotion.schema.json"
RELEASED_CLIENT_SCHEMA_PATH = REPO_ROOT / "spec/released-client-claim.schema.json"
PHASE4_PREFLIGHT_SCHEMA_PATH = REPO_ROOT / "spec/phase4-claim-activation-preflight.schema.json"

DEFAULT_CLAIM_PATH = REPO_ROOT / "spec/server-client-formal-assurance-claim.current.json"
PRE_PUBLIC_BLOCKER_REPORT_PATH = (
    REPO_ROOT / "docs/releases/evidence/phase5-pre-public-blockers.json"
)

REQUIRED_EVIDENCE_IDS = {
    "server-assurance-baseline",
    "client-rp-assurance-case",
    "client-boundary-policy",
    "released-client-claim-gate",
    "hosted-real-provider-evidence",
    "admin-sdk-evidence",
    "publication-custody",
    "release-security-evidence",
    "multi-review-signoff",
    "phase5-internal-evidence-bundle",
    "pre-public-blocker-closure",
    "positioning-scope-update",
}

REQUIRED_TCB_IDS = {
    "cryptographic-hardness-premises",
    "os-device-entropy",
    "third-party-dependencies",
    "runtime-adapter-signature-preverification",
    "external-idp-hosts-and-network",
    "client-storage-and-callback-hosting",
    "compat-algorithm-surfaces",
    "admin-ui-rendering",
}

REQUIRED_DEPENDENT_GATE_IDS = {
    "released-client-claim",
    "client-claim-boundary",
    "client-claim-promotion",
}

INTERNAL_COMPLETE_REVIEW_SCOPES = {
    "claim-wording",
    "formal-boundary",
    "server-implementation",
    "sdk-adapter",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"JSON file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def validate_schema(schema_path: pathlib.Path, value: object) -> None:
    schema = load_json(schema_path)
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(value)


def repo_path(path_text: str) -> pathlib.Path:
    path = pathlib.Path(path_text)
    if path.is_absolute():
        raise ValidationError(f"repo-relative path required: {path_text}")
    resolved = (REPO_ROOT / path).resolve()
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValidationError(f"repo-relative path escapes repository: {path_text}") from exc
    return resolved


def require_unique_ids(items: object, label: str) -> set[str]:
    if not isinstance(items, list):
        raise ValidationError(f"{label} must be a list")

    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValidationError(f"{label} item missing string id")
        item_id = item["id"]
        if item_id in seen:
            raise ValidationError(f"{label}: duplicate id {item_id}")
        seen.add(item_id)
    return seen


def require_local_evidence_uri_exists(item_id: str, evidence_uri: object) -> None:
    if not isinstance(evidence_uri, str) or not evidence_uri:
        raise ValidationError(f"{item_id}: evidence_uri must be a non-empty string")
    if evidence_uri.startswith(("https://", "s3://", "gs://")):
        return
    if evidence_uri.startswith("http://"):
        raise ValidationError(f"{item_id}: external evidence_uri must not use http")
    evidence_path = evidence_uri.split("#", maxsplit=1)[0]
    if not evidence_path:
        raise ValidationError(f"{item_id}: evidence_uri must include a path before '#'")
    if not repo_path(evidence_path).exists():
        raise ValidationError(f"{item_id}: evidence_uri does not exist: {evidence_uri}")


def validate_wording(claim: dict[str, Any]) -> None:
    joined = " ".join(
        [
            cast("str", claim["future_allowed_wording"]),
            cast("str", claim["minimum_qualified_wording"]),
        ],
    ).lower()
    if "assumption-qualified" not in joined:
        raise ValidationError("server/client claim wording must remain assumption-qualified")
    if "tcb" not in joined and "boundary" not in joined:
        raise ValidationError("server/client claim wording must disclose TCB or boundary scope")


def validate_dependent_gate(gate: dict[str, Any], claim_active: bool) -> None:
    gate_path = repo_path(cast("str", gate["path"]))
    gate_doc = cast("dict[str, Any]", load_json(gate_path))
    kind = gate["kind"]

    if kind == "released-client-claim":
        validate_schema(RELEASED_CLIENT_SCHEMA_PATH, gate_doc)
        current_state = cast("dict[str, Any]", gate_doc["current_state"])
        if claim_active and current_state.get("released_client_claim_active") is not True:
            raise ValidationError(
                "server/client claim activation requires released client claim active=true",
            )
        return

    if kind == "client-boundary":
        validate_schema(CLIENT_BOUNDARY_SCHEMA_PATH, gate_doc)
        if claim_active:
            if gate_doc.get("released_client_claim_active") is not True:
                raise ValidationError(
                    "server/client claim activation requires client boundary promotion",
                )
            if gate_doc.get("default_profile") == "compat-interop":
                raise ValidationError(
                    "server/client claim activation rejects compat-interop default profile",
                )
        return

    if kind == "client-promotion":
        validate_schema(CLIENT_PROMOTION_SCHEMA_PATH, gate_doc)
        return

    if kind == "evidence-preflight":
        validate_schema(PHASE4_PREFLIGHT_SCHEMA_PATH, gate_doc)
        return

    if kind == "claim-gate":
        if gate_doc.get("claim_active") is True and gate_doc.get("claim_target") is None:
            raise ValidationError(f"{gate['id']}: invalid claim-gate dependency")
        return

    raise ValidationError(f"{gate['id']}: unsupported dependent gate kind {kind}")


def validate_claim(claim_path: pathlib.Path) -> dict[str, Any]:
    claim = cast("dict[str, Any]", load_json(claim_path))
    validate_schema(CLAIM_SCHEMA_PATH, claim)
    validate_claim_gates.validate_pair(CLAIM_SCHEMA_PATH, claim_path)
    validate_wording(claim)

    evidence_ids = require_unique_ids(claim["required_evidence"], "required_evidence")
    missing_evidence = REQUIRED_EVIDENCE_IDS - evidence_ids
    if missing_evidence:
        joined = ", ".join(sorted(missing_evidence))
        raise ValidationError(f"missing required server/client evidence ids: {joined}")

    tcb_ids = require_unique_ids(claim["excluded_tcb_boundaries"], "excluded_tcb_boundaries")
    missing_tcb = REQUIRED_TCB_IDS - tcb_ids
    if missing_tcb:
        joined = ", ".join(sorted(missing_tcb))
        raise ValidationError(f"missing required server/client TCB boundaries: {joined}")

    boundary_ids = require_unique_ids(
        claim["included_claim_boundaries"],
        "included_claim_boundaries",
    )
    if "verified-client-core" not in boundary_ids:
        raise ValidationError("included_claim_boundaries must include verified-client-core")
    for boundary in cast("list[dict[str, Any]]", claim["included_claim_boundaries"]):
        require_local_evidence_uri_exists(boundary["id"], boundary["evidence_uri"])

    dependent_gate_ids = require_unique_ids(claim["dependent_gates"], "dependent_gates")
    missing_gate = REQUIRED_DEPENDENT_GATE_IDS - dependent_gate_ids
    if missing_gate:
        joined = ", ".join(sorted(missing_gate))
        raise ValidationError(f"missing required dependent gates: {joined}")

    claim_active = claim["claim_active"] is True
    if claim_active and claim.get("claim_stage") != "public-claim-active":
        raise ValidationError("claim_active=true requires claim_stage=public-claim-active")

    for gate in cast("list[dict[str, Any]]", claim["dependent_gates"]):
        validate_dependent_gate(gate, claim_active)

    return claim


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_bundle(bundle_path: pathlib.Path) -> None:
    bundle = cast("dict[str, Any]", load_json(bundle_path))
    validate_schema(BUNDLE_SCHEMA_PATH, bundle)

    claim_gate_path = repo_path(cast("str", bundle["claim_gate_path"]))
    actual_sha256 = sha256_file(claim_gate_path)
    if bundle["claim_gate_sha256"] != actual_sha256:
        raise ValidationError("claim_gate_sha256 does not match claim_gate_path")

    claim = validate_claim(claim_gate_path)
    require_unique_ids(bundle["dependent_gate_snapshots"], "dependent_gate_snapshots")
    evidence_ids = require_unique_ids(bundle["evidence_items"], "evidence_items")
    require_unique_ids(bundle["review_passes"], "review_passes")

    public_ready = bundle["public_claim_ready"] is True
    if public_ready and bundle["release_stage"] != "external-complete":
        raise ValidationError("public_claim_ready=true requires release_stage=external-complete")
    if public_ready and bundle["blockers"]:
        raise ValidationError("public_claim_ready=true requires an empty blockers list")

    if bundle["release_stage"] == "internal-complete":
        if public_ready:
            raise ValidationError("internal-complete bundle must keep public_claim_ready=false")
        if claim.get("claim_stage") != "phase5-internal-complete":
            raise ValidationError(
                "internal-complete bundle requires claim_stage=phase5-internal-complete",
            )
        missing_evidence = REQUIRED_EVIDENCE_IDS - evidence_ids
        if missing_evidence:
            joined = ", ".join(sorted(missing_evidence))
            raise ValidationError(f"internal-complete bundle missing evidence ids: {joined}")
        if not bundle["blockers"]:
            raise ValidationError("internal-complete bundle must list public-activation blockers")
        validate_server_client_pre_public_blockers.validate_report(PRE_PUBLIC_BLOCKER_REPORT_PATH)

        approved_scopes = {
            review["scope"]
            for review in cast("list[dict[str, Any]]", bundle["review_passes"])
            if review.get("status") == "approved"
        }
        missing_reviews = INTERNAL_COMPLETE_REVIEW_SCOPES - approved_scopes
        if missing_reviews:
            joined = ", ".join(sorted(missing_reviews))
            raise ValidationError(f"internal-complete bundle missing reviews: {joined}")

    if public_ready:
        for snapshot in cast("list[dict[str, Any]]", bundle["dependent_gate_snapshots"]):
            if snapshot.get("ready_for_activation") is not True:
                raise ValidationError(f"{snapshot['id']}: dependent gate is not ready")
        for item in cast("list[dict[str, Any]]", bundle["evidence_items"]):
            if item.get("status") != "complete" or item.get("fresh") is not True:
                raise ValidationError(f"{item['id']}: evidence item is not complete and fresh")
        for review in cast("list[dict[str, Any]]", bundle["review_passes"]):
            if review.get("status") != "approved":
                raise ValidationError(f"{review['id']}: review pass is not approved")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--claim",
        default=str(DEFAULT_CLAIM_PATH),
        help="Server/client formal-assurance claim gate JSON",
    )
    parser.add_argument(
        "bundles",
        nargs="*",
        help="Optional evidence bundle JSON file(s) to validate",
    )
    args = parser.parse_args()

    failures = 0
    claim_path = pathlib.Path(args.claim)
    if not claim_path.is_absolute():
        claim_path = (pathlib.Path.cwd() / claim_path).resolve()

    try:
        validate_claim(claim_path)
    except (ValidationError, SystemExit) as exc:
        print(f"[invalid] {claim_path}: {exc}", file=sys.stderr)
        failures += 1
    else:
        print(f"[ok] {claim_path}")

    for raw_bundle in args.bundles:
        bundle_path = pathlib.Path(raw_bundle)
        if not bundle_path.is_absolute():
            bundle_path = (pathlib.Path.cwd() / bundle_path).resolve()
        try:
            validate_bundle(bundle_path)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {bundle_path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {bundle_path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
