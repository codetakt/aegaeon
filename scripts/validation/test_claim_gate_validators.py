#!/usr/bin/env python3
"""Self-test future claim-gate validators with local fixtures."""

from __future__ import annotations

import copy
import json
import pathlib
import tempfile
from collections.abc import Callable  # noqa: TC003
from typing import Any

import validate_claim_gates
from jsonschema import ValidationError

SCHEMA_PATH = pathlib.Path("spec/enterprise-readiness-claim.schema.json")


def write_json(path: pathlib.Path, value: dict[str, Any]) -> pathlib.Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def expect_invalid(label: str, action: Callable[[], object]) -> None:
    try:
        action()
    except (ValidationError, SystemExit):
        return
    raise AssertionError(f"{label}: expected validation failure")


def claim_gate() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/enterprise-readiness-claim.schema.json",
        "schema_version": 1,
        "claim_target": "enterprise-readiness",
        "claim_active": False,
        "current_public_wording": "fixture inactive claim",
        "future_allowed_wording": "fixture active claim",
        "required_evidence": [
            {
                "id": "release-evidence",
                "description": "Fixture release evidence.",
                "status": "in_progress",
                "required_for_activation": True,
                "evidence_uri": "docs/product-positioning.md",
                "owner": "aegaeon",
            }
        ],
    }


def validate(policy_path: pathlib.Path) -> None:
    validate_claim_gates.validate_pair(SCHEMA_PATH, policy_path)


def main() -> int:
    with tempfile.TemporaryDirectory() as raw_tmp:
        root = pathlib.Path(raw_tmp)
        policy_path = write_json(root / "claim.json", claim_gate())
        validate(policy_path)

        duplicate_id = claim_gate()
        duplicate_id["required_evidence"].append(
            {
                **copy.deepcopy(duplicate_id["required_evidence"][0]),
                "description": "Duplicate identifier with different content.",
            }
        )
        write_json(policy_path, duplicate_id)
        expect_invalid(
            "claim gate with duplicate evidence id",
            lambda: validate(policy_path),
        )

        insecure_external = claim_gate()
        insecure_external["required_evidence"][0]["evidence_uri"] = (
            "http://evidence.example.test/release.json"
        )
        write_json(policy_path, insecure_external)
        expect_invalid(
            "claim gate with insecure external evidence URI",
            lambda: validate(policy_path),
        )

        missing_evidence = claim_gate()
        missing_evidence["required_evidence"][0]["evidence_uri"] = None
        write_json(policy_path, missing_evidence)
        expect_invalid(
            "claim gate with in-progress evidence missing URI",
            lambda: validate(policy_path),
        )

        absolute_evidence = claim_gate()
        absolute_evidence["required_evidence"][0]["evidence_uri"] = str(
            (pathlib.Path.cwd() / "docs/product-positioning.md").resolve()
        )
        write_json(policy_path, absolute_evidence)
        expect_invalid(
            "claim gate with absolute local evidence URI",
            lambda: validate(policy_path),
        )

        active_incomplete = claim_gate()
        active_incomplete["claim_active"] = True
        write_json(policy_path, active_incomplete)
        expect_invalid("active claim gate with incomplete evidence", lambda: validate(policy_path))

        active_complete = claim_gate()
        active_complete["claim_active"] = True
        active_complete["required_evidence"][0]["status"] = "complete"
        write_json(policy_path, active_complete)
        validate(policy_path)

    print("[ok] claim-gate validator self-tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
