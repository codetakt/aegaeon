#!/usr/bin/env python3
"""Check SDK obligation-register integrity; never attest release/proof success."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any
from urllib.parse import urlparse

from assurance_document_integrity import read_assurance_documents
from jsonschema import Draft202012Validator, ValidationError

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "spec/sdk-assurance-contract.v1.json"
SCHEMA = ROOT / "spec/sdk-assurance-contract.schema.json"
BOUNDARY = ROOT / "spec/client-claim-boundary.current.json"
SERVER_CONTRACT = ROOT / "spec/server-assurance-contract.v1.json"


def unique_ids(items: list[dict[str, Any]], field: str = "id") -> set[str]:
    values = [item[field] for item in items]
    if len(values) != len(set(values)):
        raise ValidationError(f"duplicate {field}")
    return set(values)


def local_file(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    resolved = (ROOT / path).resolve()
    if path.is_absolute() or ".." in path.parts or not resolved.is_relative_to(ROOT):
        raise ValidationError(f"repository-relative file required: {value}")
    if not resolved.is_file():
        raise ValidationError(f"missing local file: {value}")
    return resolved


def validate_contract(
    contract: dict[str, Any],
    boundary: dict[str, Any],
    *,
    source_dir: pathlib.Path | None = None,
    sdk_workspace: pathlib.Path | None = None,
) -> None:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
        contract
    )
    documents = read_assurance_documents(ROOT, contract)
    headings = re.findall(r"^### (C-\d{2}) —", documents["normative_document"], re.MULTILINE)
    guarantees = set(contract["guarantee_ids"])
    if len(headings) != len(set(headings)) or set(headings) != guarantees:
        raise ValidationError("guarantee IDs must match unique normative headings")

    sources = unique_ids(contract["sources"] + contract["project_sources"])
    unique_ids(contract["sources"], "uri")
    unique_ids(contract["specification_groups"])
    packages = unique_ids(contract["packages"])
    unique_ids(contract["packages"], "npm_name")
    unique_ids(contract["profiles"])
    selectors = unique_ids(contract["crypto_selectors"])

    used_sources = set(contract["supporting_source_ids"])
    used_guarantees: set[str] = set()
    for group in contract["specification_groups"]:
        if not group["source_ids"] and group["applicability"] != "project":
            raise ValidationError("non-project groups require pinned sources")
        if not group["role"].strip() or not group["trigger"].strip():
            raise ValidationError("specification groups require role and trigger")
        used_sources.update(group["source_ids"])
        used_guarantees.update(group["guarantee_ids"])
    if used_sources != sources:
        raise ValidationError("source references must resolve and every pin must be used")
    if used_guarantees != guarantees:
        raise ValidationError("specification guarantee references must cover the contract")

    package_guarantees = {
        package["id"]: set(package["guarantee_ids"]) for package in contract["packages"]
    }
    for package in contract["packages"]:
        if package["npm_name"] != "@aegaeon/" + package["id"]:
            raise ValidationError("package ID and npm name disagree")
        if not set(package["guarantee_ids"]) <= guarantees:
            raise ValidationError("unknown package guarantee")
        for path in package["reference_source_paths"]:
            local_file(path)
    used_packages: set[str] = set()
    for profile in contract["profiles"]:
        ids = set(profile["package_ids"])
        if not ids <= packages:
            raise ValidationError("profile refers to unknown package")
        used_packages.update(ids)
        required = set().union(*(package_guarantees[identifier] for identifier in ids))
        if not required <= set(profile["guarantee_ids"]) <= guarantees:
            raise ValidationError("profile must retain its packages' guarantee obligations")
    if used_packages != packages:
        raise ValidationError("every package requires an output profile")

    if selectors != set(boundary["profiles"]):
        raise ValidationError("crypto selector inventory differs from client boundary")
    for selector in contract["crypto_selectors"]:
        current = boundary["profiles"][selector["id"]]
        for field in ("jwt_algorithms", "dpop_algorithms", "signature_models"):
            if selector[field] != current[field]:
                raise ValidationError(f"crypto selector drift: {selector['id']} {field}")
    for path in contract["legacy_policy_documents"]:
        local_file(path)

    shared = {source["id"]: source for source in json.loads(SERVER_CONTRACT.read_text())["sources"]}
    for source in contract["sources"]:
        parsed = urlparse(source["uri"])
        if parsed.netloc not in {"www.rfc-editor.org", "www.ietf.org", "openid.net"}:
            raise ValidationError(f"non-canonical source host: {source['uri']}")
        if parsed.query or parsed.fragment or not source["edition"].strip():
            raise ValidationError("source must identify an edition and complete document")
        if source["id"] in shared and source != shared[source["id"]]:
            raise ValidationError(f"shared source pin differs: {source['id']}")
        if source_dir is not None:
            path = source_dir / pathlib.PurePosixPath(parsed.path).name
            if (
                not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]
            ):
                raise ValidationError(f"missing or changed source bytes: {source['id']}")
    for source in contract["project_sources"]:
        path = local_file(source["path"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
            raise ValidationError(f"project specification changed: {source['id']}")

    if sdk_workspace is not None:
        paths = sorted((sdk_workspace / "packages").glob("*/package.json"))
        names = [json.loads(path.read_text())["name"] for path in paths]
        expected = {package["npm_name"] for package in contract["packages"]}
        if len(names) != len(set(names)) or set(names) != expected:
            raise ValidationError("SDK workspace package inventory differs from contract")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=pathlib.Path, help="Check archived source bytes")
    parser.add_argument(
        "--sdk-workspace", type=pathlib.Path, help="Compare actual packages/*/package.json names"
    )
    args = parser.parse_args()
    try:
        contract = json.loads(CONTRACT.read_text())
        validate_contract(
            contract,
            json.loads(BOUNDARY.read_text()),
            source_dir=args.source_dir,
            sdk_workspace=args.sdk_workspace,
        )
    except (ValidationError, OSError, ValueError, KeyError) as error:
        print(f"[invalid] {error}", file=sys.stderr)
        return 1
    print(
        f"SDK contract integrity OK: {len(contract['guarantee_ids'])} guarantees, "
        f"{len(contract['profiles'])} profiles, {len(contract['packages'])} packages, "
        f"{len(contract['sources'])} external pins; no release attestation."
    )
    print(
        f"External source bytes checked: {len(contract['sources'])}."
        if args.source_dir is not None
        else "External source bytes not checked (no --source-dir)."
    )
    print(f"Project source bytes checked: {len(contract['project_sources'])}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
