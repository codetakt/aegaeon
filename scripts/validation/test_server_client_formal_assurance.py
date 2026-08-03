#!/usr/bin/env python3
"""Self-test server/client formal-assurance validators with local fixtures."""

from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
from collections.abc import Callable  # noqa: TC003
from typing import Any, cast

import validate_server_client_formal_assurance as validator
from jsonschema import ValidationError

SOURCE_CLAIM = pathlib.Path("spec/server-client-formal-assurance-claim.current.json")


def load_source_claim() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(SOURCE_CLAIM.read_text()))


def write_json(path: pathlib.Path, value: dict[str, Any]) -> pathlib.Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def expect_invalid(label: str, action: Callable[[], object]) -> None:
    try:
        action()
    except (ValidationError, SystemExit):
        return
    raise AssertionError(f"{label}: expected validation failure")


def activate_claim_fixture() -> dict[str, Any]:
    claim = load_source_claim()
    claim["claim_active"] = True
    claim["claim_stage"] = "public-claim-active"
    for item in claim["required_evidence"]:
        item["status"] = "complete"
        if item.get("evidence_uri") is None:
            item["evidence_uri"] = "docs/product-positioning.md"
    return claim


def repo_relative(path: pathlib.Path) -> str:
    if path.is_absolute():
        return str(path.relative_to(pathlib.Path.cwd()))
    return str(path)


def bundle_fixture(claim_path: pathlib.Path) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "bundle_id": "server-client-formal-assurance-test",
        "generated_at": "2026-05-20T00:00:00Z",
        "claim_target": "server-client-formal-assurance",
        "claim_gate_path": repo_relative(claim_path),
        "claim_gate_sha256": hashlib.sha256(claim_path.read_bytes()).hexdigest(),
        "release_stage": "internal-preflight",
        "public_claim_ready": False,
        "dependent_gate_snapshots": [
            {
                "id": "released-client-claim",
                "path": "spec/released-client-claim.current.json",
                "status": "in_progress",
                "ready_for_activation": False,
                "notes": "Fixture keeps public claim inactive.",
            }
        ],
        "evidence_items": [
            {
                "id": "server-assurance-baseline",
                "status": "complete",
                "path": "docs/verification/claims/assurance-case/claim-definition.md",
                "fresh": True,
                "sha256": hashlib.sha256(
                    pathlib.Path(
                        "docs/verification/claims/assurance-case/claim-definition.md",
                    ).read_bytes(),
                ).hexdigest(),
                "notes": None,
            }
        ],
        "review_passes": [
            {
                "id": "claim-wording-review",
                "scope": "claim-wording",
                "reviewer": "aegaeon",
                "status": "pending",
                "evidence_uri": None,
            }
        ],
        "blockers": [
            "released-client-claim is inactive",
            "external review is pending",
        ],
    }


def main() -> int:
    validator.validate_claim(SOURCE_CLAIM)

    with tempfile.TemporaryDirectory() as raw_tmp:
        root = pathlib.Path(raw_tmp)
        claim_path = write_json(root / "claim.json", load_source_claim())
        validator.validate_claim(claim_path)

        active_claim = activate_claim_fixture()
        active_claim_path = write_json(root / "active-claim.json", active_claim)
        expect_invalid(
            "active server/client claim with inactive released-client dependency",
            lambda: validator.validate_claim(active_claim_path),
        )

        weak_wording = load_source_claim()
        weak_wording["future_allowed_wording"] = "formally verified server and client"
        weak_wording["minimum_qualified_wording"] = "formally verified server and client"
        weak_wording_path = write_json(root / "weak-wording.json", weak_wording)
        expect_invalid(
            "server/client claim wording without assumptions or TCB boundary",
            lambda: validator.validate_claim(weak_wording_path),
        )

        missing_tcb = load_source_claim()
        missing_tcb["excluded_tcb_boundaries"] = missing_tcb["excluded_tcb_boundaries"][:-1]
        missing_tcb_path = write_json(root / "missing-tcb.json", missing_tcb)
        expect_invalid(
            "server/client claim missing required TCB boundary",
            lambda: validator.validate_claim(missing_tcb_path),
        )

        bundle_path = write_json(root / "bundle.json", bundle_fixture(SOURCE_CLAIM))
        validator.validate_bundle(bundle_path)

        public_bundle = bundle_fixture(SOURCE_CLAIM)
        public_bundle["public_claim_ready"] = True
        public_bundle["release_stage"] = "external-complete"
        public_bundle_path = write_json(root / "public-bundle.json", public_bundle)
        expect_invalid(
            "public-ready evidence bundle with blockers",
            lambda: validator.validate_bundle(public_bundle_path),
        )

    print("[ok] server/client formal-assurance validator self-tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
