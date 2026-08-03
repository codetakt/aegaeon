#!/usr/bin/env python3
"""Self-test Phase 2 certification evidence validators with local fixtures."""

from __future__ import annotations

import json
import pathlib
import tempfile
from collections.abc import Callable  # noqa: TC003
from typing import Any

import validate_certification_evidence_bundle
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


def claim_gate() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/certification-claim.schema.json",
        "schema_version": 1,
        "claim_target": "certification",
        "claim_active": False,
        "current_public_wording": "fixture beta conformance evidence",
        "future_allowed_wording": "fixture named certification target",
        "certification_scope": {
            "selected": True,
            "target": "OIDF OP Basic internal evidence baseline",
            "notes": "Fixture internal scope.",
        },
        "required_evidence": [
            {
                "id": "scope-selection",
                "description": "Fixture scope selection.",
                "status": "complete",
                "required_for_activation": True,
                "evidence_uri": "docs/releases/evidence/certification-phase2-internal-bundle.json",
                "owner": "aegaeon",
            }
        ],
    }


def results() -> list[dict[str, str]]:
    return [
        {
            "test_module": "oidcc-server",
            "test_id": "passed-fixture",
            "status": "FINISHED",
            "result": "PASSED",
        },
        {
            "test_module": "oidcc-scope-profile",
            "test_id": "warning-fixture",
            "status": "FINISHED",
            "result": "WARNING",
        },
    ]


def bundle() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/certification-evidence-bundle.schema.json",
        "schema_version": 1,
        "bundle_id": "fixture-phase2-internal",
        "generated_at": "2026-05-20T00:00:00Z",
        "claim_target": "certification",
        "claim_gate_path": "claim.json",
        "phase2_status": "internal-complete",
        "public_claim_ready": False,
        "certification_scope": {
            "selected": True,
            "target": "OIDF OP Basic internal evidence baseline",
            "target_kind": "oidf-op",
            "included_profiles": ["oidcc-basic-certification-test-plan"],
            "excluded_profiles": ["formal OIDF public listing"],
            "notes": "Fixture internal completion only.",
        },
        "plans": [
            {
                "plan_name": "oidcc-basic-certification-test-plan",
                "claim_bearing": True,
                "scope_status": "included",
                "result_status": "partial-with-dispositions",
                "artifacts": {
                    "results_json": "artifacts/results.json",
                    "plan_json": "artifacts/plan.json",
                    "export_zip": "artifacts/export.zip",
                    "suite_commit_txt": "artifacts/suite_commit.txt",
                    "screenshots_dir": None,
                },
                "result_counts": {
                    "passed": 1,
                    "review": 0,
                    "warning": 1,
                    "skipped": 0,
                    "failed": 0,
                },
                "dispositions": [
                    {
                        "test_module": "oidcc-scope-profile",
                        "result": "WARNING",
                        "disposition": "accepted-for-internal-evidence",
                        "reason": "Fixture warning is accepted only for internal evidence.",
                        "public_claim_blocker": True,
                    }
                ],
            }
        ],
        "formal_submission": {
            "required_for_public_claim": True,
            "status": "deferred",
            "evidence_uri": None,
            "notes": "External submission is deferred.",
        },
        "review": {
            "reviewer": "fixture-reviewer",
            "decision": "approved",
            "notes": "Fixture internal approval.",
        },
    }


def write_fixture(root: pathlib.Path, raw_bundle: dict[str, Any]) -> pathlib.Path:
    write_json(root / "claim.json", claim_gate())
    write_json(root / "artifacts/results.json", results())
    write_json(root / "artifacts/plan.json", {"plan": "fixture"})
    touch(root / "artifacts/export.zip", "zip-fixture\n")
    touch(root / "artifacts/suite_commit.txt", "abcdef\n")
    return write_json(root / "bundle.json", raw_bundle)


def validate(path: pathlib.Path, root: pathlib.Path) -> None:
    validate_certification_evidence_bundle.validate_bundle(path, repo_root=root)


def main() -> int:
    with tempfile.TemporaryDirectory() as raw_tmp:
        root = pathlib.Path(raw_tmp)
        bundle_path = write_fixture(root, bundle())
        validate(bundle_path, root)

        missing_artifact = bundle()
        missing_artifact["plans"][0]["artifacts"]["export_zip"] = "artifacts/missing.zip"
        bundle_path = write_fixture(root, missing_artifact)
        expect_invalid("bundle with missing artifact", lambda: validate(bundle_path, root))

        failed_results = results()
        failed_results.append(
            {
                "test_module": "oidcc-failed",
                "test_id": "failed-fixture",
                "status": "FINISHED",
                "result": "FAILED",
            }
        )
        failed_module = bundle()
        failed_module["plans"][0]["result_counts"]["failed"] = 1
        failed_module["plans"][0]["result_counts"]["passed"] = 1
        bundle_path = write_fixture(root, failed_module)
        write_json(root / "artifacts/results.json", failed_results)
        expect_invalid("bundle with failed module", lambda: validate(bundle_path, root))

        missing_disposition = bundle()
        missing_disposition["plans"][0]["dispositions"] = []
        bundle_path = write_fixture(root, missing_disposition)
        expect_invalid("bundle missing non-PASS disposition", lambda: validate(bundle_path, root))

        internal_public_ready = bundle()
        internal_public_ready["public_claim_ready"] = True
        bundle_path = write_fixture(root, internal_public_ready)
        expect_invalid(
            "internal bundle with public_claim_ready=true",
            lambda: validate(bundle_path, root),
        )

        external_deferred = bundle()
        external_deferred["phase2_status"] = "external-complete"
        external_deferred["public_claim_ready"] = True
        bundle_path = write_fixture(root, external_deferred)
        expect_invalid(
            "external bundle with deferred formal submission",
            lambda: validate(bundle_path, root),
        )

        path_traversal = bundle()
        path_traversal["plans"][0]["artifacts"]["results_json"] = "../results.json"
        bundle_path = write_fixture(root, path_traversal)
        expect_invalid("bundle with path traversal", lambda: validate(bundle_path, root))

        active_claim = claim_gate()
        active_claim["claim_active"] = True
        bundle_path = write_fixture(root, bundle())
        write_json(root / "claim.json", active_claim)
        expect_invalid("bundle pointing at active claim gate", lambda: validate(bundle_path, root))

    print("[ok] certification evidence validator self-tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
