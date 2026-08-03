#!/usr/bin/env python3
"""Validate Phase 3 admin UI assurance evidence bundles."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BUNDLE_SCHEMA_PATH = REPO_ROOT / "spec/admin-ui-assurance-evidence-bundle.schema.json"
MODEL_SCHEMA_PATH = REPO_ROOT / "spec/admin-ui-security-state-machine.schema.json"
CLAIM_SCHEMA_PATH = REPO_ROOT / "spec/admin-ui-assurance-claim.schema.json"
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
REQUIRED_EXCLUDED_SURFACES = {
    "React runtime correctness",
    "browser rendering",
    "CSS/layout behaviour",
    "browser extensions",
    "OS UI behaviour",
    "all possible visual interactions",
    "end-user credential submission on the admin SPA",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"Admin UI assurance evidence file not found: {path}") from exc
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


def is_external_uri(raw_uri: str) -> bool:
    return raw_uri.startswith(("http://", "https://", "s3://", "gs://"))


def validate_evidence_uri(repo_root: pathlib.Path, raw_uri: str | None, label: str) -> None:
    if raw_uri is None:
        return
    if is_external_uri(raw_uri):
        if raw_uri.startswith("http://"):
            raise ValidationError(f"{label}: external evidence_uri must not use http")
        return
    require_existing_file(repo_root, raw_uri, label)


def validate_claim_gate(repo_root: pathlib.Path, bundle: dict[str, Any]) -> dict[str, Any]:
    claim_gate_path = require_existing_file(
        repo_root,
        cast("str", bundle["claim_gate_path"]),
        "claim_gate_path",
    )
    claim_schema = load_json(CLAIM_SCHEMA_PATH)
    claim_gate = cast("dict[str, Any]", load_json(claim_gate_path))
    Draft202012Validator(
        claim_schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(claim_gate)

    if claim_gate.get("claim_target") != "admin-ui-assurance":
        raise ValidationError("claim_gate_path must point at the admin UI assurance claim gate")
    if claim_gate.get("claim_active") is not False:
        raise ValidationError("admin UI assurance evidence bundles must keep claim_active=false")
    excluded = claim_gate.get("excluded_surfaces")
    if not isinstance(excluded, list):
        raise ValidationError("admin UI assurance claim gate requires excluded_surfaces")
    missing = REQUIRED_EXCLUDED_SURFACES - set(map(str, excluded))
    if missing:
        raise ValidationError(
            "admin UI assurance claim gate missing excluded surfaces: "
            + ", ".join(sorted(missing)),
        )
    return claim_gate


def validate_phase_semantics(bundle: dict[str, Any]) -> None:
    phase3_status = bundle["phase3_status"]
    public_claim_ready = bundle["public_claim_ready"]
    hosted = cast("dict[str, Any]", bundle["hosted_runtime_evidence"])
    review = cast("dict[str, Any]", bundle["review"])

    if phase3_status == "internal-complete" and public_claim_ready is not False:
        raise ValidationError(
            "internal-complete admin UI evidence must keep public_claim_ready=false"
        )
    if phase3_status == "external-complete" and public_claim_ready is not True:
        raise ValidationError(
            "external-complete admin UI evidence requires public_claim_ready=true"
        )
    if phase3_status == "external-complete":
        if hosted.get("status") != "approved":
            raise ValidationError(
                "external-complete admin UI evidence requires approved hosted evidence"
            )
        if hosted.get("public_claim_blocker") is True:
            raise ValidationError("external-complete admin UI evidence cannot have hosted blocker")
        evidence_uri = hosted.get("evidence_uri")
        if not isinstance(evidence_uri, str) or not evidence_uri:
            raise ValidationError(
                "external-complete admin UI evidence requires hosted evidence_uri"
            )
    if phase3_status in {"internal-complete", "external-complete"}:
        if review.get("decision") != "approved":
            raise ValidationError(f"{phase3_status} admin UI evidence requires approved review")
        if not review.get("reviewer"):
            raise ValidationError(f"{phase3_status} admin UI evidence requires reviewer")


def unique_by_id(entries: list[Any], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            raise ValidationError(f"{label} entry {index} must be an object")
        entry = cast("dict[str, Any]", raw_entry)
        entry_id = entry.get("id")
        if not isinstance(entry_id, str):
            raise ValidationError(f"{label} entry {index} missing id")
        if entry_id in result:
            raise ValidationError(f"{label} contains duplicate id {entry_id}")
        result[entry_id] = entry
    return result


def validate_state_machine_structure(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    states = unique_by_id(cast("list[Any]", model["states"]), "states")
    operation_classes = unique_by_id(
        cast("list[Any]", model["operation_classes"]), "operation_classes"
    )
    route_groups = unique_by_id(cast("list[Any]", model["route_groups"]), "route_groups")
    transitions = unique_by_id(cast("list[Any]", model["transitions"]), "transitions")

    initial_state = model["initial_state"]
    if initial_state not in states:
        raise ValidationError("initial_state must reference a declared state")

    for transition_id, transition in transitions.items():
        from_state = transition["from"]
        to_state = transition["to"]
        operation_class = transition["operation_class"]
        if from_state not in states:
            raise ValidationError(f"{transition_id}: from state is not declared")
        if to_state not in states:
            raise ValidationError(f"{transition_id}: to state is not declared")
        if operation_class not in operation_classes:
            raise ValidationError(f"{transition_id}: operation_class is not declared")
        class_entry = operation_classes[cast("str", operation_class)]
        target_state = states[cast("str", to_state)]
        if (
            operation_class != "session-logout-write"
            and class_entry["requires_management_session"] is True
            and target_state["privileged"] is False
        ):
            raise ValidationError(
                f"{transition_id}: session-required transition cannot target non-privileged state",
            )

    for group_id, group in route_groups.items():
        allowed = cast("list[str]", group["allowed_operation_classes"])
        for operation_class in allowed:
            if operation_class not in operation_classes:
                raise ValidationError(
                    f"{group_id}: unknown allowed operation class {operation_class}"
                )
        if group["requires_management_session"] is True:
            for operation_class in allowed:
                class_entry = operation_classes[operation_class]
                if (
                    operation_class != "session-logout-write"
                    and class_entry["requires_management_session"] is not True
                ):
                    raise ValidationError(
                        f"{group_id}: privileged route allows non-session "
                        f"operation {operation_class}",
                    )

    return operation_classes


def validate_operation_class_invariants(operation_classes: dict[str, dict[str, Any]]) -> None:
    required = {
        "public-read",
        "public-management-session-write",
        "session-logout-write",
        "privileged-read",
        "privileged-write",
        "dangerous-write",
    }
    missing = required - set(operation_classes)
    if missing:
        raise ValidationError(
            "operation_classes missing required classes: " + ", ".join(sorted(missing))
        )

    for class_id, class_entry in operation_classes.items():
        if class_entry["writes_management_api"] is True:
            if class_entry["transport_boundary"] != "management-client":
                raise ValidationError(
                    f"{class_id}: management API writes must use management-client"
                )
            if class_entry["csrf_origin_guard"] != "server-enforced":
                raise ValidationError(
                    f"{class_id}: management API writes require CSRF/Origin guard"
                )

    privileged_write = operation_classes["privileged-write"]
    if privileged_write["requires_management_session"] is not True:
        raise ValidationError("privileged-write requires management session")
    dangerous_write = operation_classes["dangerous-write"]
    if dangerous_write["requires_management_session"] is not True:
        raise ValidationError("dangerous-write requires management session")
    if dangerous_write["admin_confirmation_required"] is not True:
        raise ValidationError("dangerous-write requires administrator confirmation")
    if dangerous_write["audit_event_required"] is not True:
        raise ValidationError("dangerous-write requires audit evidence")


def normalize_openapi_path(path: str) -> str:
    return path if path.startswith("/api/v1/") else f"/api/v1{path}"


def parse_management_client_path_expr(expr: str) -> str:
    fragments = re.findall(r'"([^"]*)"', expr)
    if not fragments:
        raise ValidationError("management-client operation path has no string literal fragments")
    remainder = re.sub(r'"[^"]*"', "", expr)
    if re.sub(r"[\s+]", "", remainder):
        raise ValidationError(
            "management-client operation path must be a string literal "
            "or string-literal concatenation"
        )
    return "".join(fragments)


def management_operations_block(text: str) -> str:
    start = text.find("MANAGEMENT_OPERATIONS")
    if start == -1:
        raise ValidationError("management-client reference lacks MANAGEMENT_OPERATIONS")
    open_brace = text.find("Object.freeze({", start)
    if open_brace == -1:
        raise ValidationError("management-client reference lacks operation metadata block")
    body_start = open_brace + len("Object.freeze({")
    close_match = re.search(r"^\}\);", text[body_start:], re.MULTILINE)
    if close_match is None:
        raise ValidationError("management-client operation metadata block is unterminated")
    return text[body_start : body_start + close_match.start()]


def load_openapi_operations(path: pathlib.Path) -> set[tuple[str, str]]:
    raw_openapi = load_json(path)
    if not isinstance(raw_openapi, dict):
        raise ValidationError("management OpenAPI must be a JSON object")
    paths = raw_openapi.get("paths")
    if not isinstance(paths, dict):
        raise ValidationError("management OpenAPI requires paths")
    operations: set[tuple[str, str]] = set()
    for raw_path, raw_methods in paths.items():
        if not isinstance(raw_path, str) or not isinstance(raw_methods, dict):
            continue
        for raw_method in raw_methods:
            method = raw_method.upper()
            if method in HTTP_METHODS:
                operations.add((method, normalize_openapi_path(raw_path)))
    if not operations:
        raise ValidationError("management OpenAPI contains no operations")
    return operations


def load_management_client_operations(path: pathlib.Path) -> set[tuple[str, str]]:
    text = management_operations_block(path.read_text())
    operation_re = re.compile(
        r"\n\s+([A-Za-z][A-Za-z0-9]*): Object\.freeze\(\{(?P<body>.*?)\n\s+\}\),",
        re.DOTALL,
    )
    operations: set[tuple[str, str]] = set()
    for name, body in operation_re.findall(text):
        method_match = re.search(r'\n\s+method: "([A-Z]+)",', body)
        path_match = re.search(
            r'\n\s+path:\s*(?P<expr>"[^"]+"|(?:\n\s+"[^"]+"\s*\+?)+)\s*,',
            body,
            re.MULTILINE,
        )
        if not method_match or not path_match:
            raise ValidationError(f"management-client operation metadata incomplete: {name}")
        operation_path = parse_management_client_path_expr(path_match.group("expr"))
        operations.add((method_match.group(1), normalize_openapi_path(operation_path)))
    if not operations:
        raise ValidationError("management-client reference contains no operation metadata")
    return operations


def validate_management_client_write_guards(path: pathlib.Path) -> None:
    text = path.read_text()
    required_snippets = (
        "const WRITE_METHODS",
        'requestHeaders.set("origin"',
        'requestHeaders.set("x-csrf-token"',
        "await primeCsrf()",
        "credentials:",
    )
    missing = [snippet for snippet in required_snippets if snippet not in text]
    if missing:
        raise ValidationError(
            "management-client reference is missing write guard snippets: " + ", ".join(missing),
        )


def validate_openapi_client_drift(
    model: dict[str, Any],
    repo_root: pathlib.Path,
    operation_classes: dict[str, dict[str, Any]],
) -> None:
    drift_policy = cast("dict[str, Any]", model["drift_policy"])
    openapi_path = require_existing_file(
        repo_root,
        cast("str", drift_policy["management_openapi_path"]),
        "drift_policy.management_openapi_path",
    )
    client_path = require_existing_file(
        repo_root,
        cast("str", drift_policy["management_client_reference_path"]),
        "drift_policy.management_client_reference_path",
    )
    openapi_operations = load_openapi_operations(openapi_path)
    client_operations = load_management_client_operations(client_path)

    if drift_policy["require_all_openapi_operations_in_management_client"] is True:
        missing = sorted(openapi_operations - client_operations)
        if missing:
            formatted = ", ".join(f"{method} {path}" for method, path in missing)
            raise ValidationError(
                f"management-client reference missing OpenAPI operations: {formatted}"
            )

    if drift_policy["require_write_csrf_origin_implementation"] is True:
        validate_management_client_write_guards(client_path)

    dangerous_fragments = cast("list[str]", drift_policy["dangerous_write_fragments"])
    if not dangerous_fragments:
        raise ValidationError("drift policy requires dangerous_write_fragments")
    dangerous_class = operation_classes["dangerous-write"]
    if dangerous_class["admin_confirmation_required"] is not True:
        raise ValidationError("dangerous OpenAPI writes require confirmation in the model")
    if dangerous_class["audit_event_required"] is not True:
        raise ValidationError("dangerous OpenAPI writes require audit evidence in the model")

    write_operations = [
        (method, path) for method, path in openapi_operations if method in WRITE_METHODS
    ]
    if not write_operations:
        raise ValidationError("management OpenAPI contains no write operations")
    for method, path in write_operations:
        is_dangerous = method == "DELETE" or any(
            fragment in path for fragment in dangerous_fragments
        )
        class_id = "dangerous-write" if is_dangerous else "privileged-write"
        class_entry = operation_classes[class_id]
        if class_entry["transport_boundary"] != "management-client":
            raise ValidationError(
                f"{method} {path}: classified write lacks management-client boundary"
            )
        if class_entry["csrf_origin_guard"] != "server-enforced":
            raise ValidationError(f"{method} {path}: classified write lacks CSRF/Origin guard")
        if class_id == "dangerous-write" and class_entry["admin_confirmation_required"] is not True:
            raise ValidationError(f"{method} {path}: dangerous write lacks confirmation")


def validate_state_machine(path: pathlib.Path, repo_root: pathlib.Path) -> None:
    model_schema = load_json(MODEL_SCHEMA_PATH)
    model = cast("dict[str, Any]", load_json(path))
    Draft202012Validator(
        model_schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(model)
    operation_classes = validate_state_machine_structure(model)
    validate_operation_class_invariants(operation_classes)
    validate_openapi_client_drift(model, repo_root, operation_classes)


def validate_bundle(path: pathlib.Path, repo_root: pathlib.Path | None = None) -> None:
    resolved_repo_root = (repo_root or REPO_ROOT).resolve()
    schema = load_json(BUNDLE_SCHEMA_PATH)
    bundle = cast("dict[str, Any]", load_json(path))
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(bundle)

    validate_phase_semantics(bundle)
    validate_claim_gate(resolved_repo_root, bundle)

    artifacts = cast("dict[str, Any]", bundle["artifacts"])
    for key, raw_path in artifacts.items():
        require_existing_file(resolved_repo_root, cast("str", raw_path), f"artifacts.{key}")

    model_path = require_existing_file(
        resolved_repo_root,
        cast("str", artifacts["state_machine"]),
        "artifacts.state_machine",
    )
    validate_state_machine(model_path, resolved_repo_root)

    hosted = cast("dict[str, Any]", bundle["hosted_runtime_evidence"])
    validate_evidence_uri(
        resolved_repo_root,
        cast("str | None", hosted.get("evidence_uri")),
        "hosted_runtime_evidence.evidence_uri",
    )
    if (
        bundle["phase3_status"] == "internal-complete"
        and hosted["public_claim_blocker"] is not True
    ):
        raise ValidationError(
            "internal Phase 3 bundle must keep hosted runtime evidence as a blocker"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="+", help="Admin UI assurance evidence bundle JSON path(s)")
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
