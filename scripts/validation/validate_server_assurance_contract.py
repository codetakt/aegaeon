#!/usr/bin/env python3
"""Check contract/source/matrix integrity; never attest proof or release success."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any
from urllib.parse import urlparse

import yaml
from assurance_document_integrity import read_assurance_documents
from jsonschema import Draft202012Validator, ValidationError

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "spec/server-assurance-contract.v1.json"
SCHEMA = ROOT / "spec/server-assurance-contract.schema.json"
MATRIX = ROOT / "spec/compliance-matrix.yaml"


def unique_ids(items: list[dict[str, Any]], field: str) -> set[str]:
    values = [item[field] for item in items]
    if len(values) != len(set(values)):
        raise ValidationError(f"duplicate {field}")
    return set(values)


def validate_contract(
    contract: dict[str, Any],
    matrix: dict[str, Any],
    source_dir: pathlib.Path | None = None,
) -> None:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
        contract
    )

    documents = read_assurance_documents(ROOT, contract)
    headings = re.findall(r"^### (G-\d{2}) —", documents["normative_document"], re.MULTILINE)
    guarantees = set(contract["guarantee_ids"])
    if len(headings) != len(set(headings)) or guarantees != set(headings):
        raise ValidationError("guarantee IDs must match unique normative headings")

    sources = unique_ids(contract["sources"], "id")
    unique_ids(contract["sources"], "uri")
    groups = unique_ids(contract["matrix_groups"], "matrix_key")
    unique_ids(contract["additional_role_bindings"], "id")
    matrix_groups = {key for key, value in matrix.items() if isinstance(value, list)}
    if groups != matrix_groups:
        raise ValidationError(
            f"matrix group dispositions differ: missing={sorted(matrix_groups - groups)}, "
            f"unknown={sorted(groups - matrix_groups)}"
        )
    if matrix.get("metadata", {}).get("assurance_contract") != str(CONTRACT.relative_to(ROOT)):
        raise ValidationError("matrix must reference the normative contract register")

    referenced_sources = set(contract["supporting_source_ids"])
    referenced_guarantees: set[str] = set()
    for binding in contract["matrix_groups"] + contract["additional_role_bindings"]:
        if not binding["source_ids"] and binding.get("applicability") != "project":
            raise ValidationError("non-project bindings require a pinned source")
        if not binding["role"].strip() or not binding["trigger"].strip():
            raise ValidationError("bindings require an explicit role and trigger")
        referenced_sources.update(binding["source_ids"])
        referenced_guarantees.update(binding["guarantee_ids"])
    if referenced_sources != sources:
        raise ValidationError("source references must resolve and every pin must be used")
    if referenced_guarantees != guarantees:
        raise ValidationError("guarantee references must resolve and cover the contract")

    for migration in contract["identifier_migrations"]:
        if migration["old_group"] in matrix_groups:
            raise ValidationError("retired matrix group is still present")
        rows = matrix.get(migration["new_group"], [])
        if not any(row.get("id") == migration["new_id"] for row in rows):
            raise ValidationError("identifier migration target does not exist")

    for source in contract["sources"]:
        parsed = urlparse(source["uri"])
        if parsed.netloc not in {"www.rfc-editor.org", "www.ietf.org", "openid.net"}:
            raise ValidationError(f"non-canonical source host: {source['uri']}")
        if parsed.query or parsed.fragment or not source["edition"].strip():
            raise ValidationError("source must identify an edition and complete document")
        if source_dir is not None:
            path = source_dir / pathlib.PurePosixPath(parsed.path).name
            if (
                not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]
            ):
                raise ValidationError(f"missing or changed source bytes: {source['id']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-dir",
        type=pathlib.Path,
        help="Also verify archived source bytes, stored under each URI's basename",
    )
    args = parser.parse_args()
    try:
        contract = json.loads(CONTRACT.read_text())
        matrix = yaml.safe_load(MATRIX.read_text())
        validate_contract(contract, matrix, args.source_dir)
    except (ValidationError, OSError, ValueError, yaml.YAMLError) as error:
        print(f"[invalid] {error}", file=sys.stderr)
        return 1
    print(
        f"Contract integrity OK: {len(contract['guarantee_ids'])} guarantees, "
        f"{len(contract['matrix_groups'])} matrix groups, "
        f"{len(contract['sources'])} source pins; no release attestation."
    )
    print(
        f"External source bytes checked: {len(contract['sources'])}."
        if args.source_dir is not None
        else "External source bytes not checked (no --source-dir)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
