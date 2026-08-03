#!/usr/bin/env python3
"""Self-test Phase 4 activation preflight validator with local fixtures."""

from __future__ import annotations

import json
import pathlib
import tempfile
from collections.abc import Callable  # noqa: TC003
from typing import Any

import validate_phase4_activation_preflight
from jsonschema import ValidationError


def write_json(path: pathlib.Path, value: object) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def touch(path: pathlib.Path, content: str = "fixture\n") -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def expect_invalid(label: str, action: Callable[[], object]) -> None:
    try:
        action()
    except (ValidationError, SystemExit):
        return
    raise AssertionError(f"{label}: expected validation failure")


def enterprise_claim() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/enterprise-readiness-claim.schema.json",
        "schema_version": 1,
        "claim_target": "enterprise-readiness",
        "claim_active": False,
        "current_public_wording": "fixture current",
        "future_allowed_wording": "fixture future",
        "required_evidence": [
            {
                "id": "runbook",
                "description": "Fixture runbook.",
                "status": "complete",
                "required_for_activation": True,
                "evidence_uri": "docs/product-positioning.md",
                "owner": "fixture",
            },
            {
                "id": "hosted-evidence",
                "description": "Fixture hosted evidence.",
                "status": "in_progress",
                "required_for_activation": True,
                "evidence_uri": "docs/product-positioning.md",
                "owner": "fixture",
            },
        ],
    }


def certification_claim() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/certification-claim.schema.json",
        "schema_version": 1,
        "claim_target": "certification",
        "claim_active": False,
        "current_public_wording": "fixture current",
        "future_allowed_wording": "fixture future",
        "certification_scope": {
            "selected": True,
            "target": "fixture target",
            "notes": "fixture",
        },
        "required_evidence": [
            {
                "id": "internal-bundle",
                "description": "Fixture internal bundle.",
                "status": "complete",
                "required_for_activation": True,
                "evidence_uri": "docs/product-positioning.md",
                "owner": "fixture",
            },
            {
                "id": "formal-submission",
                "description": "Fixture formal submission.",
                "status": "planned",
                "required_for_activation": True,
                "evidence_uri": None,
                "owner": "fixture",
            },
        ],
    }


def admin_claim() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/admin-ui-assurance-claim.schema.json",
        "schema_version": 1,
        "claim_target": "admin-ui-assurance",
        "claim_active": False,
        "current_public_wording": "fixture current",
        "future_allowed_wording": "fixture future",
        "excluded_surfaces": ["React runtime correctness"],
        "required_evidence": [
            {
                "id": "model",
                "description": "Fixture model.",
                "status": "complete",
                "required_for_activation": True,
                "evidence_uri": "docs/product-positioning.md",
                "owner": "fixture",
            },
            {
                "id": "hosted-runtime-evidence",
                "description": "Fixture hosted runtime evidence.",
                "status": "in_progress",
                "required_for_activation": True,
                "evidence_uri": "docs/product-positioning.md",
                "owner": "fixture",
            },
        ],
    }


def preflight_bundle() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/phase4-claim-activation-preflight.schema.json",
        "schema_version": 1,
        "bundle_id": "fixture-phase4-preflight",
        "generated_at": "2026-05-20T00:00:00Z",
        "phase4_status": "internal-preflight-complete",
        "public_claim_ready": False,
        "claim_gates": [
            {
                "claim_target": "enterprise-readiness",
                "claim_gate_path": "enterprise.json",
                "internal_status": "internal-preflight-complete",
                "activation_status": "blocked-on-external",
            },
            {
                "claim_target": "certification",
                "claim_gate_path": "certification.json",
                "internal_status": "internal-complete",
                "activation_status": "blocked-on-external",
            },
            {
                "claim_target": "admin-ui-assurance",
                "claim_gate_path": "admin.json",
                "internal_status": "internal-complete",
                "activation_status": "blocked-on-external",
            },
        ],
        "internal_evidence": [
            {
                "id": "claim-gate-validator",
                "kind": "validator",
                "path": "runbook.md",
                "status": "complete",
            }
        ],
        "external_blockers": [
            {
                "claim_target": "enterprise-readiness",
                "evidence_id": "hosted-evidence",
                "blocker_class": "external-hosted-evidence",
                "owner": "fixture",
                "required_next_evidence": "fixture hosted evidence",
            },
            {
                "claim_target": "certification",
                "evidence_id": "formal-submission",
                "blocker_class": "external-certification",
                "owner": "fixture",
                "required_next_evidence": "fixture formal submission",
            },
            {
                "claim_target": "admin-ui-assurance",
                "evidence_id": "hosted-runtime-evidence",
                "blocker_class": "external-hosted-evidence",
                "owner": "fixture",
                "required_next_evidence": "fixture hosted runtime evidence",
            },
            {
                "claim_target": "release",
                "evidence_id": "public-wording-change-set",
                "blocker_class": "public-wording-release",
                "owner": "fixture",
                "required_next_evidence": "fixture release wording",
            },
        ],
        "release_activation": {
            "product_wording_update_required": True,
            "readme_update_required": True,
            "release_tag_required": True,
            "notes": "fixture",
        },
        "review": {
            "reviewer": "fixture-reviewer",
            "decision": "approved",
            "notes": "fixture",
        },
    }


def write_fixture(root: pathlib.Path, raw_bundle: dict[str, Any]) -> pathlib.Path:
    touch(root / "runbook.md")
    write_json(root / "enterprise.json", enterprise_claim())
    write_json(root / "certification.json", certification_claim())
    write_json(root / "admin.json", admin_claim())
    return write_json(root / "preflight.json", raw_bundle)


def validate(path: pathlib.Path, root: pathlib.Path) -> None:
    validate_phase4_activation_preflight.validate_bundle(path, repo_root=root)


def main() -> int:
    with tempfile.TemporaryDirectory() as raw_tmp:
        root = pathlib.Path(raw_tmp)
        bundle_path = write_fixture(root, preflight_bundle())
        validate(bundle_path, root)

        missing_blocker = preflight_bundle()
        missing_blocker["external_blockers"] = missing_blocker["external_blockers"][:-2]
        bundle_path = write_fixture(root, missing_blocker)
        expect_invalid("preflight with missing blockers", lambda: validate(bundle_path, root))

        stale_blocker = preflight_bundle()
        stale_blocker["external_blockers"].append(
            {
                "claim_target": "enterprise-readiness",
                "evidence_id": "runbook",
                "blocker_class": "external-publication",
                "owner": "fixture",
                "required_next_evidence": "stale blocker",
            }
        )
        bundle_path = write_fixture(root, stale_blocker)
        expect_invalid("preflight with stale blocker", lambda: validate(bundle_path, root))

        public_ready_internal = preflight_bundle()
        public_ready_internal["public_claim_ready"] = True
        bundle_path = write_fixture(root, public_ready_internal)
        expect_invalid(
            "internal preflight with public_claim_ready=true", lambda: validate(bundle_path, root)
        )

        active_claim = enterprise_claim()
        active_claim["claim_active"] = True
        bundle_path = write_fixture(root, preflight_bundle())
        write_json(root / "enterprise.json", active_claim)
        expect_invalid("preflight with active claim gate", lambda: validate(bundle_path, root))

        missing_internal_evidence = preflight_bundle()
        missing_internal_evidence["internal_evidence"][0]["path"] = "missing.md"
        bundle_path = write_fixture(root, missing_internal_evidence)
        expect_invalid(
            "preflight with missing internal evidence", lambda: validate(bundle_path, root)
        )

        path_traversal = preflight_bundle()
        path_traversal["internal_evidence"][0]["path"] = "../runbook.md"
        bundle_path = write_fixture(root, path_traversal)
        expect_invalid("preflight with path traversal", lambda: validate(bundle_path, root))

    print("[ok] Phase 4 activation preflight validator self-tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
