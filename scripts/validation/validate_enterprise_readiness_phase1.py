#!/usr/bin/env python3
"""Validate Phase 1 enterprise-readiness closure status."""

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

import validate_claim_gates  # noqa: E402
import validate_enterprise_readiness_evidence_bundle  # noqa: E402

CLAIM_SCHEMA = pathlib.Path("spec/enterprise-readiness-claim.schema.json")
CLAIM_GATE = pathlib.Path("spec/enterprise-readiness-claim.current.json")
PHASE1_REQUIRED_EVIDENCE_IDS = {
    "enterprise-slo-baselines",
    "hardened-reference-deployment",
    "kms-hsm-classification",
    "managed-provider-evidence",
    "publication-org-rollout",
    "regulated-runbooks",
    "release-security-evidence",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"Phase 1 validation input not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def validate_claim_gate(policy_path: pathlib.Path) -> dict[str, Any]:
    validate_claim_gates.validate_pair(CLAIM_SCHEMA, policy_path)
    schema = load_json(CLAIM_SCHEMA)
    policy = cast("dict[str, Any]", load_json(policy_path))
    Draft202012Validator(schema).validate(policy)
    if policy.get("claim_target") != "enterprise-readiness":
        raise ValidationError("Phase 1 requires the enterprise-readiness claim gate")
    if policy.get("claim_active") is not False:
        raise ValidationError("Phase 1 closure must precede enterprise claim activation")
    return policy


def activation_blockers(policy: dict[str, Any]) -> list[str]:
    evidence = policy.get("required_evidence")
    if not isinstance(evidence, list):
        return ["required_evidence list is missing"]

    seen_ids = {
        item.get("id")
        for item in evidence
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    missing_ids = sorted(PHASE1_REQUIRED_EVIDENCE_IDS - seen_ids)
    blockers: list[str] = []
    blockers.extend(f"{item_id}=missing" for item_id in missing_ids)
    for item in evidence:
        if not isinstance(item, dict) or item.get("required_for_activation") is not True:
            continue
        status = item.get("status")
        if status != "complete":
            blockers.append(f"{item.get('id', '<unknown>')}={status}")
    return blockers


def validate_phase1(
    bundle_path: pathlib.Path,
    claim_gate_path: pathlib.Path = CLAIM_GATE,
    require_approved: bool = True,
) -> None:
    policy = validate_claim_gate(claim_gate_path)
    blockers = activation_blockers(policy)
    if blockers:
        joined = ", ".join(blockers)
        raise ValidationError(f"Phase 1 required evidence is not complete: {joined}")

    require_bundle_claim_gate(bundle_path, claim_gate_path)
    validate_enterprise_readiness_evidence_bundle.validate_bundle(
        bundle_path,
        require_approved=require_approved,
    )


def require_bundle_claim_gate(
    bundle_path: pathlib.Path,
    claim_gate_path: pathlib.Path,
) -> None:
    bundle = load_json(bundle_path)
    if not isinstance(bundle, dict):
        raise ValidationError("Phase 1 bundle must be a JSON object")
    raw_claim_gate = bundle.get("claim_gate_path")
    if not isinstance(raw_claim_gate, str) or not raw_claim_gate:
        raise ValidationError("Phase 1 bundle requires claim_gate_path")
    bundle_claim_gate = pathlib.Path(raw_claim_gate)
    if not bundle_claim_gate.is_absolute():
        bundle_claim_gate = bundle_path.parent / bundle_claim_gate
    if bundle_claim_gate.resolve() != claim_gate_path.resolve():
        raise ValidationError("Phase 1 bundle claim_gate_path must match the validated claim gate")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--claim-gate",
        default=str(CLAIM_GATE),
        help="Enterprise-readiness claim gate JSON path",
    )
    parser.add_argument(
        "--no-require-approved",
        action="store_true",
        help="Validate the final bundle without requiring approved review records",
    )
    parser.add_argument(
        "bundle",
        help="Enterprise-readiness evidence bundle JSON path",
    )
    args = parser.parse_args()

    bundle_path = pathlib.Path(args.bundle)
    claim_gate_path = pathlib.Path(args.claim_gate)
    try:
        validate_phase1(
            bundle_path,
            claim_gate_path=claim_gate_path,
            require_approved=not args.no_require_approved,
        )
    except (ValidationError, SystemExit) as exc:
        print(f"[invalid] Phase 1 enterprise-readiness closure: {exc}", file=sys.stderr)
        return 1

    print(f"[ok] Phase 1 enterprise-readiness closure: {bundle_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
