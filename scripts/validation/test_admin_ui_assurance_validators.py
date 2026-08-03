#!/usr/bin/env python3
"""Self-test Phase 3 admin UI assurance validators with local fixtures."""

from __future__ import annotations

import json
import pathlib
import tempfile
from collections.abc import Callable  # noqa: TC003
from typing import Any

import validate_admin_ui_assurance
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
        "$schema": "https://aegaeon.dev/spec/admin-ui-assurance-claim.schema.json",
        "schema_version": 1,
        "claim_target": "admin-ui-assurance",
        "claim_active": False,
        "current_public_wording": "fixture inactive admin UI claim",
        "future_allowed_wording": "fixture bounded admin UI claim",
        "excluded_surfaces": [
            "React runtime correctness",
            "browser rendering",
            "CSS/layout behaviour",
            "browser extensions",
            "OS UI behaviour",
            "all possible visual interactions",
            "end-user credential submission on the admin SPA",
        ],
        "required_evidence": [
            {
                "id": "admin-ui-assurance-case",
                "description": "Fixture assurance case.",
                "status": "complete",
                "required_for_activation": True,
                "evidence_uri": "docs/verification/claims/admin-ui-assurance-case.md",
                "owner": "fixture",
            }
        ],
    }


def openapi() -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "info": {"title": "fixture", "version": "v1"},
        "paths": {
            "/api/v1/system/health": {"get": {"operationId": "system_health"}},
            "/api/v1/teams": {
                "get": {"operationId": "list_teams"},
                "post": {"operationId": "create_team"},
            },
            "/api/v1/teams/{teamId}": {
                "delete": {"operationId": "delete_team"},
            },
            "/api/v1/teams/{teamId}/longOperations/{operationId}": {
                "get": {"operationId": "get_long_operation"},
            },
        },
    }


def management_client_reference(include_delete: bool = True, include_csrf: bool = True) -> str:
    delete_operation = (
        """
    deleteTeam: Object.freeze({
        operationId: "delete_team",
        method: "DELETE",
        path: "/teams/{teamId}",
    }),"""
        if include_delete
        else ""
    )
    csrf_snippets = (
        """
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
requestHeaders.set("origin", effectiveOrigin);
requestHeaders.set("x-csrf-token", csrfToken);
await primeCsrf();
const options = { credentials: "include" };
"""
        if include_csrf
        else "const WRITE_METHODS = new Set([]);\n"
    )
    return (
        csrf_snippets
        + """
const MANAGEMENT_OPERATIONS = Object.freeze({
    systemHealth: Object.freeze({
        operationId: "system_health",
        method: "GET",
        path: "/system/health",
    }),
    listTeams: Object.freeze({
        operationId: "list_teams",
        method: "GET",
        path: "/teams",
    }),
    createTeam: Object.freeze({
        operationId: "create_team",
        method: "POST",
        path: "/teams",
    }),
    getLongOperation: Object.freeze({
        operationId: "get_long_operation",
        method: "GET",
        path:
            "/teams/{teamId}/" +
            "longOperations/{operationId}",
    }),"""
        + delete_operation
        + """
});
"""
    )


def state_machine() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/admin-ui-security-state-machine.schema.json",
        "schema_version": 1,
        "model_id": "fixture-admin-ui",
        "claim_boundary": {
            "boundary_type": "admin-control-plane-security-boundary",
            "included_surfaces": ["management-session"],
            "excluded_surfaces": ["React runtime correctness"],
            "trusted_boundaries": ["management-client"],
        },
        "initial_state": "anonymous",
        "states": [
            {
                "id": "anonymous",
                "management_session": "absent",
                "csrf_state": "absent",
                "privileged": False,
            },
            {
                "id": "authenticated",
                "management_session": "present",
                "csrf_state": "server-owned",
                "privileged": True,
            },
        ],
        "transitions": [
            {
                "id": "read-public",
                "from": "anonymous",
                "to": "anonymous",
                "event": "read",
                "operation_class": "public-read",
            },
            {
                "id": "write-privileged",
                "from": "authenticated",
                "to": "authenticated",
                "event": "write",
                "operation_class": "privileged-write",
            },
            {
                "id": "delete-dangerous",
                "from": "authenticated",
                "to": "authenticated",
                "event": "delete",
                "operation_class": "dangerous-write",
            },
        ],
        "operation_classes": [
            {
                "id": "public-read",
                "writes_management_api": False,
                "requires_management_session": False,
                "transport_boundary": "management-client",
                "csrf_origin_guard": "not-required",
                "admin_confirmation_required": False,
                "audit_event_required": False,
            },
            {
                "id": "public-management-session-write",
                "writes_management_api": True,
                "requires_management_session": False,
                "transport_boundary": "management-client",
                "csrf_origin_guard": "server-enforced",
                "admin_confirmation_required": False,
                "audit_event_required": False,
            },
            {
                "id": "session-logout-write",
                "writes_management_api": True,
                "requires_management_session": True,
                "transport_boundary": "management-client",
                "csrf_origin_guard": "server-enforced",
                "admin_confirmation_required": False,
                "audit_event_required": False,
            },
            {
                "id": "privileged-read",
                "writes_management_api": False,
                "requires_management_session": True,
                "transport_boundary": "management-client",
                "csrf_origin_guard": "not-required",
                "admin_confirmation_required": False,
                "audit_event_required": False,
            },
            {
                "id": "privileged-write",
                "writes_management_api": True,
                "requires_management_session": True,
                "transport_boundary": "management-client",
                "csrf_origin_guard": "server-enforced",
                "admin_confirmation_required": False,
                "audit_event_required": False,
            },
            {
                "id": "dangerous-write",
                "writes_management_api": True,
                "requires_management_session": True,
                "transport_boundary": "management-client",
                "csrf_origin_guard": "server-enforced",
                "admin_confirmation_required": True,
                "audit_event_required": True,
            },
        ],
        "route_groups": [
            {
                "id": "public-auth",
                "paths": ["/login"],
                "requires_management_session": False,
                "allowed_operation_classes": ["public-read"],
            },
            {
                "id": "team-control",
                "paths": ["/teams"],
                "requires_management_session": True,
                "allowed_operation_classes": [
                    "privileged-read",
                    "privileged-write",
                    "dangerous-write",
                ],
            },
        ],
        "forbidden_client_surfaces": ["direct fetch"],
        "drift_policy": {
            "management_openapi_path": "openapi.json",
            "management_client_reference_path": "management-client.ts",
            "require_all_openapi_operations_in_management_client": True,
            "require_write_csrf_origin_implementation": True,
            "dangerous_write_fragments": ["/revoke"],
        },
        "invariants": ["fixture invariant"],
    }


def bundle() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/admin-ui-assurance-evidence-bundle.schema.json",
        "schema_version": 1,
        "bundle_id": "fixture-admin-ui-phase3",
        "generated_at": "2026-05-20T00:00:00Z",
        "claim_target": "admin-ui-assurance",
        "claim_gate_path": "claim.json",
        "phase3_status": "internal-complete",
        "public_claim_ready": False,
        "artifacts": {
            "assurance_case": "assurance.md",
            "state_machine": "state-machine.json",
            "state_machine_schema": "schema.json",
            "validator": "validator.py",
            "validator_self_test": "validator-test.py",
            "product_positioning": "positioning.md",
        },
        "hosted_runtime_evidence": {
            "status": "deferred",
            "evidence_uri": None,
            "public_claim_blocker": True,
            "notes": "Fixture hosted evidence is deferred.",
        },
        "review": {
            "reviewer": "fixture-reviewer",
            "decision": "approved",
            "notes": "Fixture internal approval.",
        },
    }


def write_fixture(root: pathlib.Path, raw_bundle: dict[str, Any]) -> pathlib.Path:
    write_json(root / "claim.json", claim_gate())
    write_json(root / "openapi.json", openapi())
    touch(root / "management-client.ts", management_client_reference())
    write_json(root / "state-machine.json", state_machine())
    write_json(root / "schema.json", {})
    touch(root / "assurance.md")
    touch(root / "validator.py")
    touch(root / "validator-test.py")
    touch(root / "positioning.md")
    return write_json(root / "bundle.json", raw_bundle)


def validate(path: pathlib.Path, root: pathlib.Path) -> None:
    validate_admin_ui_assurance.validate_bundle(path, repo_root=root)


def main() -> int:
    with tempfile.TemporaryDirectory() as raw_tmp:
        root = pathlib.Path(raw_tmp)
        bundle_path = write_fixture(root, bundle())
        validate(bundle_path, root)

        active_claim = claim_gate()
        active_claim["claim_active"] = True
        bundle_path = write_fixture(root, bundle())
        write_json(root / "claim.json", active_claim)
        expect_invalid("bundle pointing at active claim gate", lambda: validate(bundle_path, root))

        internal_public_ready = bundle()
        internal_public_ready["public_claim_ready"] = True
        bundle_path = write_fixture(root, internal_public_ready)
        expect_invalid(
            "internal bundle with public_claim_ready=true",
            lambda: validate(bundle_path, root),
        )

        missing_sdk_operation = bundle()
        bundle_path = write_fixture(root, missing_sdk_operation)
        touch(root / "management-client.ts", management_client_reference(include_delete=False))
        expect_invalid("bundle with missing SDK operation", lambda: validate(bundle_path, root))

        missing_csrf = bundle()
        bundle_path = write_fixture(root, missing_csrf)
        touch(root / "management-client.ts", management_client_reference(include_csrf=False))
        expect_invalid(
            "bundle with missing CSRF/Origin snippets", lambda: validate(bundle_path, root)
        )

        dangerous_without_confirmation = bundle()
        bad_model = state_machine()
        for operation_class in bad_model["operation_classes"]:
            if operation_class["id"] == "dangerous-write":
                operation_class["admin_confirmation_required"] = False
        bundle_path = write_fixture(root, dangerous_without_confirmation)
        write_json(root / "state-machine.json", bad_model)
        expect_invalid(
            "bundle with dangerous writes lacking confirmation",
            lambda: validate(bundle_path, root),
        )

        missing_excluded_surface = bundle()
        bundle_path = write_fixture(root, missing_excluded_surface)
        bad_claim = claim_gate()
        bad_claim["excluded_surfaces"] = bad_claim["excluded_surfaces"][:-1]
        write_json(root / "claim.json", bad_claim)
        expect_invalid(
            "bundle with incomplete excluded surfaces",
            lambda: validate(bundle_path, root),
        )

        path_traversal = bundle()
        path_traversal["artifacts"]["assurance_case"] = "../assurance.md"
        bundle_path = write_fixture(root, path_traversal)
        expect_invalid("bundle with path traversal", lambda: validate(bundle_path, root))

    print("[ok] admin UI assurance validator self-tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
