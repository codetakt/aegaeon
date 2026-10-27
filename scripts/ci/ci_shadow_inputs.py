"""Validate diagnostic input mappings without authorizing omitted CI work."""

from __future__ import annotations

import ast
import hashlib
from typing import TYPE_CHECKING, Any, cast

from verify_ci_plan import ambiguous_path

if TYPE_CHECKING:
    from collections.abc import Callable

MODEL_PATH = "ci/ci-shadow-inputs.json"
INVENTORY_PATH = "ci/ci-expected-inventory.json"
AUTHORITY_PATH = "ci/ci-input-authority.json"
KINDS = {"file", "tree", "absent-file", "absent-tree"}


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def fields(value: object, expected: set[str]) -> None:
    require(isinstance(value, dict) and set(value) == expected, "unknown or missing model field")


def text(value: object) -> str:
    require(isinstance(value, str) and bool(value.strip()), "empty or invalid model text")
    result = cast("str", value)
    require(not any(0xD800 <= ord(char) <= 0xDFFF for char in result), "invalid model Unicode")
    return result


def path_text(value: object) -> None:
    value = text(value)
    require(not ambiguous_path(value), "noncanonical model path")


def test_id(value: dict[str, Any]) -> tuple[str, str, str]:
    """Lines and historical snapshot labels are not stable test identities."""
    return value["path"], value.get("class", ""), value.get("method", value.get("function", ""))


def validate_test_id(value: dict[str, Any]) -> None:
    fields(value, {"path", "class", "method"})
    path_text(value["path"])
    require(value["path"].endswith(".py"), "test identity must name Python source")
    require(isinstance(value["class"], str), "invalid test class")
    text(value["method"])
    require(value["method"].startswith("test_"), "invalid test method")


def validate_correspondence(
    rows: list[dict[str, Any]], baseline: set[tuple[str, str, str]]
) -> None:
    require(isinstance(rows, list), "invalid correspondence list")
    seen = set()
    for row in rows:
        fields(row, {"old", "disposition", "related_current_tests", "reason"})
        validate_test_id(row["old"])
        old = test_id(row["old"])
        require(old in baseline and old not in seen, "unknown or duplicate historical test")
        seen.add(old)
        require(
            row["disposition"] in {"contract-changed", "execution-path-changed"},
            "invalid disposition",
        )
        text(row["reason"])
        current = row["related_current_tests"]
        require(isinstance(current, list) and bool(current), "missing related current tests")
        for item in current:
            validate_test_id(item)
        require(len({test_id(item) for item in current}) == len(current), "duplicate current test")


def validate_consumers(rows: list[dict[str, Any]], authority: dict[str, Any]) -> None:
    require(isinstance(rows, list) and bool(rows), "empty consumer inventory")
    seen = set()
    for row in rows:
        fields(row, {"id", "producer", "coverage", "holds", "inputs"})
        text(row["id"])
        require(row["id"] not in seen, "duplicate consumer")
        seen.add(row["id"])
        require(row["producer"] in authority["producers"], "unregistered producer")
        require(row["coverage"] == "partial", "shadow model cannot certify complete coverage")
        holds = row["holds"]
        require(isinstance(holds, list) and bool(holds), "consumer holds are required")
        require(all(isinstance(item, str) for item in holds), "invalid consumer hold")
        require(
            holds == sorted(set(holds)) and set(holds) <= set(authority["holds"]),
            "invalid consumer holds",
        )
        validate_rules(row["inputs"])


def validate_rules(rules: list[dict[str, str]]) -> None:
    require(isinstance(rules, list) and bool(rules), "empty input rules")
    seen = set()
    for rule in rules:
        fields(rule, {"kind", "path"})
        require(isinstance(rule["kind"], str) and rule["kind"] in KINDS, "unsupported input kind")
        path_text(rule["path"])
        key = rule["kind"], rule["path"]
        require(key not in seen, "duplicate input rule")
        seen.add(key)


def validate_model(
    model: dict[str, Any],
    inventory_bytes: bytes,
    inventory: dict[str, Any],
    authority: dict[str, Any],
) -> None:
    validate_envelope(inventory, authority)
    fields(
        model,
        {
            "version",
            "mode",
            "inventory_sha256",
            "coverage_equivalence_claimed",
            "correspondence",
            "additional_checks",
            "consumers",
        },
    )
    require(type(model["version"]) is int and model["version"] == 1, "unsupported shadow version")
    require(model["mode"] == "diagnostic-only", "model cannot authorize selection")
    require(
        model["coverage_equivalence_claimed"] is False, "lexical mapping cannot attest equivalence"
    )
    require(
        model["inventory_sha256"] == hashlib.sha256(inventory_bytes).hexdigest(),
        "historical inventory binding differs",
    )
    require(authority.get("narrowing_adopted") is False, "expected full-selection authority")
    baseline = {test_id(row) for row in inventory["source_candidates"]["python_test_methods"]}
    validate_correspondence(model["correspondence"], baseline)
    validate_consumers(model["consumers"], authority)
    validate_additional_checks(model["additional_checks"], inventory, authority)


def validate_envelope(inventory: dict[str, Any], authority: dict[str, Any]) -> None:
    require(authority.get("narrowing_adopted") is False, "expected full-selection authority")
    for name in ("producers", "holds"):
        values = authority.get(name)
        require(isinstance(values, list) and bool(values), "empty protected authority")
        values = cast("list[str]", values)
        require(
            all(isinstance(value, str) and value for value in values), "invalid authority value"
        )
        require(values == sorted(set(values)), "duplicate or unsorted authority values")
    rows = inventory["source_candidates"]["python_test_methods"]
    require(isinstance(rows, list) and bool(rows), "empty historical inventory")
    require(len({test_id(row) for row in rows}) == len(rows), "duplicate historical identity")


def validate_additional_checks(
    rows: list[dict[str, Any]], inventory: dict[str, Any], authority: dict[str, Any]
) -> None:
    require(isinstance(rows, list), "invalid additional checks")
    seen = set(inventory["nix_static_checks"])
    for row in rows:
        fields(row, {"name", "producer", "definition"})
        text(row["name"])
        require(row["name"] not in seen, "duplicate or historical additional check")
        seen.add(row["name"])
        require(row["producer"] in authority["producers"], "unregistered additional check owner")
        path_text(row["definition"])


def python_definitions(source: bytes) -> set[tuple[str, str]]:
    """Inspect lexical definitions without importing or executing candidate code."""
    module = ast.parse(source)
    result = {
        (node.name, method.name)
        for node in ast.walk(module)
        if isinstance(node, ast.ClassDef)
        for method in node.body
        if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    result.update(
        ("", node.name)
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    return result


def inventory_report(
    model: dict[str, Any], inventory: dict[str, Any], read: Callable[[str], bytes]
) -> dict[str, Any]:
    definitions = {}
    errors = {}
    historical = inventory["source_candidates"]["python_test_methods"]
    mappings = {test_id(row["old"]): row for row in model["correspondence"]}
    identities = [test_id(row) for row in historical]
    identities.extend(
        test_id(item) for row in mappings.values() for item in row["related_current_tests"]
    )
    for name in sorted({item[0] for item in identities}):
        try:
            definitions[name] = python_definitions(read(name))
        except (OSError, ValueError, SyntaxError) as error:
            definitions[name] = set()
            errors[name] = str(error)
    results = [describe_test(test_id(row), mappings, definitions) for row in historical]
    return {
        "kind": "lexical-correspondence-not-execution",
        "coverage_equivalence_claimed": False,
        "historical_records": len(results),
        "counts": {
            state: sum(row["status"] == state for row in results)
            for state in ("present", "related-definitions-present", "unresolved")
        },
        "tests": results,
        "source_errors": errors,
        "historical_nix_checks": inventory["nix_static_checks"],
        "additional_declared_checks": model["additional_checks"],
    }


def describe_test(
    identity: tuple[str, str, str],
    mappings: dict[tuple[str, str, str], dict[str, Any]],
    definitions: dict[str, set[tuple[str, str]]],
) -> dict[str, Any]:
    name, cls, method = identity
    row: dict[str, Any] = {"path": name, "class": cls, "method": method, "status": "unresolved"}
    if (cls, method) in definitions[name]:
        row["status"] = "present"
    elif identity in mappings:
        mapping = mappings[identity]
        related = [test_id(item) for item in mapping["related_current_tests"]]
        row.update(mapping)
        row["status"] = (
            "related-definitions-present"
            if all((c, m) in definitions[p] for p, c, m in related)
            else "unresolved"
        )
    return row


def matches(path: str, rule: dict[str, str]) -> bool:
    # A directory at a forbidden file path also makes Path.exists() true.
    if rule["kind"] in {"tree", "absent-tree", "absent-file"}:
        return path == rule["path"] or path.startswith(rule["path"] + "/")
    return path == rule["path"]


def selection_report(
    changes: list[dict[str, Any]], model: dict[str, Any], authority: dict[str, Any]
) -> dict[str, Any]:
    """Partial positive dependencies are observations, never omission permissions."""
    rows = []
    for change in changes:
        path = change["decoded_path"]
        known = []
        if not ambiguous_path(path):
            known = [
                {
                    "consumer": consumer["id"],
                    "producer": consumer["producer"],
                    "rules": [rule for rule in consumer["inputs"] if matches(path, rule)],
                }
                for consumer in model["consumers"]
            ]
            known = [item for item in known if item["rules"]]
        rows.append({**change, "known_matches": known})
    return {
        "mode": "shadow-only",
        "adoption_eligible": False,
        "omissions_enabled": False,
        "authoritative_scope": "full",
        "conservative_producers": authority["producers"],
        "unresolved_holds": authority["holds"],
        "directly_affected_producers": sorted(
            {item["producer"] for row in rows for item in row["known_matches"]}
        ),
        "unclassified_change_count": sum(not row["known_matches"] for row in rows),
        "changes": rows,
    }
