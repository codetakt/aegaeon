#!/usr/bin/env python3
"""Validate release security evidence manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

VALIDATION_DIR = pathlib.Path(__file__).resolve().parent
if str(VALIDATION_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATION_DIR))

import validate_sdk_release_publication_bundle  # noqa: E402

SCHEMA_PATH = pathlib.Path("spec/release-security-evidence.schema.json")
REQUIRED_NON_EMPTY_GROUPS = {
    "build",
    "verification",
    "security",
    "sbom",
    "support",
}
ENTERPRISE_READINESS_REQUIRED_GROUPS = {
    "kms",
    "managed_provider",
    "performance",
    "publication",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"Release evidence file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def is_external_uri(uri: str) -> bool:
    return uri.startswith(("http://", "https://", "s3://", "gs://"))


def is_insecure_external_uri(uri: str) -> bool:
    return uri.startswith("http://")


def resolve_local_evidence_path(
    root: pathlib.Path,
    group: str,
    item_id: object,
    uri: str,
) -> pathlib.Path:
    if pathlib.Path(uri).is_absolute():
        raise ValidationError(
            f"{group}.{item_id}: required local evidence uri must be relative: {uri}",
        )
    evidence_path = (root / uri).resolve()
    try:
        evidence_path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValidationError(
            f"{group}.{item_id}: required evidence uri escapes release archive: {uri}",
        ) from exc
    return evidence_path


def validate_manifest(path: pathlib.Path) -> None:
    schema = load_json(SCHEMA_PATH)
    manifest = cast("dict[str, Any]", load_json(path))
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(manifest)
    validate_semantics(path, manifest)


def validate_enterprise_readiness_manifest(path: pathlib.Path) -> None:
    schema = load_json(SCHEMA_PATH)
    manifest = cast("dict[str, Any]", load_json(path))
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(manifest)
    validate_semantics(path, manifest)
    validate_enterprise_readiness_semantics(path, manifest)


def validate_semantics(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    evidence = manifest.get("evidence")
    if not isinstance(evidence, dict):
        raise ValidationError("release evidence manifest requires evidence object")

    missing_groups = []
    for group in sorted(REQUIRED_NON_EMPTY_GROUPS):
        items = evidence.get(group)
        if not isinstance(items, list) or not items:
            missing_groups.append(group)
    if missing_groups:
        joined = ", ".join(missing_groups)
        raise ValidationError(f"required evidence groups must be non-empty: {joined}")

    validate_unique_evidence_item_ids(evidence)

    root = path.parent
    for group, items in evidence.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("required") is not True:
                continue
            uri = item.get("uri")
            item_id = item.get("id", "<unknown>")
            if not isinstance(uri, str) or not uri:
                raise ValidationError(f"{group}.{item_id}: required item needs a uri")
            if is_external_uri(uri):
                validate_external_evidence_item(group, item_id, uri, item)
                continue
            evidence_path = resolve_local_evidence_path(root, group, item_id, uri)
            if not evidence_path.exists():
                raise ValidationError(
                    f"{group}.{item_id}: required evidence uri does not exist: {uri}",
                )

    review = manifest.get("review")
    if not isinstance(review, dict):
        raise ValidationError("release evidence manifest requires review object")
    if review.get("decision") == "approved" and not review.get("reviewer"):
        raise ValidationError("approved release evidence requires a reviewer")


def validate_unique_evidence_item_ids(evidence: dict[str, Any]) -> None:
    for group, items in evidence.items():
        if not isinstance(items, list):
            continue
        seen: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            item_id = item.get("id")
            if not isinstance(item_id, str):
                continue
            if item_id in seen:
                raise ValidationError(f"{group}.{item_id}: duplicate evidence item id")
            seen.add(item_id)


def validate_enterprise_readiness_semantics(
    path: pathlib.Path,
    manifest: dict[str, Any],
) -> None:
    claim_context = manifest.get("claim_context")
    if not isinstance(claim_context, dict):
        raise ValidationError("enterprise release evidence requires claim_context object")
    if claim_context.get("enterprise_readiness_claim_active") is not False:
        raise ValidationError(
            "enterprise release evidence must be collected before claim activation",
        )

    evidence = manifest.get("evidence")
    if not isinstance(evidence, dict):
        raise ValidationError("enterprise release evidence requires evidence object")

    for group in sorted(ENTERPRISE_READINESS_REQUIRED_GROUPS):
        items = evidence.get(group)
        if not isinstance(items, list) or not items:
            raise ValidationError(f"enterprise release evidence requires non-empty {group} group")
        if not any(isinstance(item, dict) and item.get("required") is True for item in items):
            raise ValidationError(
                f"enterprise release evidence requires at least one required {group} item",
            )

    validate_required_evidence_hashes(path, evidence)
    validate_sdk_publication_evidence(path, evidence)


def validate_required_evidence_hashes(path: pathlib.Path, evidence: dict[str, Any]) -> None:
    root = path.parent
    for group, items in evidence.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or item.get("required") is not True:
                continue
            item_id = item.get("id", "<unknown>")
            uri = item.get("uri")
            expected_sha256 = item.get("sha256")
            if not isinstance(expected_sha256, str) or not expected_sha256:
                raise ValidationError(
                    f"{group}.{item_id}: enterprise required item needs sha256",
                )
            if not isinstance(uri, str) or is_external_uri(uri):
                if isinstance(uri, str):
                    validate_external_evidence_item(group, item_id, uri, item)
                continue
            evidence_path = resolve_local_evidence_path(root, group, item_id, uri)
            actual_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            if actual_sha256 != expected_sha256:
                raise ValidationError(
                    f"{group}.{item_id}: sha256 mismatch for required evidence uri: {uri}",
                )


def validate_sdk_publication_evidence(path: pathlib.Path, evidence: dict[str, Any]) -> None:
    publication = evidence.get("publication")
    if not isinstance(publication, list):
        raise ValidationError("enterprise release evidence requires publication group")

    candidates = [
        item
        for item in publication
        if isinstance(item, dict)
        and item.get("id") == "sdk-release-publication-bundle"
        and item.get("required") is True
    ]
    if not candidates:
        raise ValidationError(
            "enterprise release evidence requires required "
            "publication.sdk-release-publication-bundle",
        )
    item = candidates[0]
    uri = item.get("uri")
    if not isinstance(uri, str) or is_external_uri(uri):
        raise ValidationError(
            "enterprise release evidence requires local sdk-release-publication-bundle evidence",
        )
    bundle_path = resolve_local_evidence_path(
        path.parent,
        "publication",
        "sdk-release-publication-bundle",
        uri,
    )
    schema = validate_sdk_release_publication_bundle.load_json(
        validate_sdk_release_publication_bundle.SCHEMA_FILE,
    )
    bundle = cast(
        "dict[str, Any]",
        validate_sdk_release_publication_bundle.load_json(bundle_path),
    )
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(bundle)
    validate_sdk_release_publication_bundle.validate_enterprise_readiness(bundle)


def validate_external_evidence_item(
    group: str,
    item_id: object,
    uri: str,
    item: dict[str, Any],
) -> None:
    if is_insecure_external_uri(uri):
        raise ValidationError(f"{group}.{item_id}: external evidence URI must not use http")
    if item.get("kind") != "external":
        raise ValidationError(f"{group}.{item_id}: external evidence URI requires kind=external")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-enterprise-ready",
        action="store_true",
        help=(
            "Require publication, managed-provider, performance, and KMS evidence suitable for an "
            "enterprise-readiness evidence bundle"
        ),
    )
    parser.add_argument("manifest", nargs="+", help="Release evidence manifest JSON path(s)")
    args = parser.parse_args()

    failures = 0
    for raw_path in args.manifest:
        path = pathlib.Path(raw_path)
        try:
            if args.require_enterprise_ready:
                validate_enterprise_readiness_manifest(path)
            else:
                validate_manifest(path)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
