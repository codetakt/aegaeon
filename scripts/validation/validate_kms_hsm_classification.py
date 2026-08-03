#!/usr/bin/env python3
"""Validate KMS/HSM deployment classification manifests."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = pathlib.Path("spec/kms-hsm-deployment-classification.schema.json")
CLAIM_PRESERVING_PROVIDER_ALGORITHMS = {
    "RSASSA_PKCS1_V1_5_SHA_256",
    "RsassaPkcs1V15Sha256",
    "RSASSA-PKCS1-v1_5-SHA-256",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"KMS/HSM classification file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def is_external_uri(uri: str) -> bool:
    return uri.startswith(("http://", "https://", "s3://", "gs://"))


def validate_evidence_uri(path: pathlib.Path, label: str, uri: str) -> None:
    if uri.startswith("http://"):
        raise ValidationError(f"{label}: evidence URI must not use http")
    if is_external_uri(uri):
        return
    if pathlib.Path(uri).is_absolute():
        raise ValidationError(f"{label}: local evidence URI must be relative")
    evidence_path = (path.parent / uri).resolve()
    try:
        evidence_path.relative_to(path.parent.resolve())
    except ValueError as exc:
        raise ValidationError(
            f"{label}: local evidence URI escapes classification directory"
        ) from exc
    if not evidence_path.exists():
        raise ValidationError(f"{label}: evidence URI does not exist: {uri}")


def validate_manifest(path: pathlib.Path) -> None:
    schema = load_json(SCHEMA_PATH)
    manifest = cast("dict[str, Any]", load_json(path))
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(manifest)
    validate_semantics(path, manifest)


def validate_semantics(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    validate_optional_parity_evidence_uri(path, manifest)
    validate_review_semantics(manifest)

    classification = manifest.get("classification")
    if classification == "claim-preserving":
        validate_claim_preserving(path, manifest)
        return
    if classification == "compat-only":
        reason = manifest.get("compat_reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("compat-only classification requires compat_reason")
        return
    raise ValidationError(f"unknown classification: {classification}")


def validate_optional_parity_evidence_uri(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    parity = manifest.get("parity_evidence")
    if not isinstance(parity, dict):
        raise ValidationError("KMS/HSM classification requires parity_evidence object")
    uri = parity.get("uri")
    if uri is None:
        return
    if not isinstance(uri, str) or not uri:
        raise ValidationError("parity_evidence.uri must be null or non-empty string")
    validate_evidence_uri(path, "parity_evidence.uri", uri)


def validate_review_semantics(manifest: dict[str, Any]) -> None:
    review = manifest.get("review")
    if not isinstance(review, dict):
        raise ValidationError("KMS/HSM classification requires review object")
    if review.get("decision") == "approved" and not review.get("reviewer"):
        raise ValidationError("approved KMS/HSM classification requires reviewer")


def validate_claim_preserving(_path: pathlib.Path, manifest: dict[str, Any]) -> None:
    algorithm = cast("dict[str, Any]", manifest.get("algorithm"))
    if algorithm.get("jose_alg") != "RS256":
        raise ValidationError("claim-preserving classification requires jose_alg=RS256")
    if algorithm.get("provider_algorithm") not in CLAIM_PRESERVING_PROVIDER_ALGORITHMS:
        raise ValidationError(
            "claim-preserving classification requires exact RSASSA_PKCS1_V1_5_SHA_256",
        )

    signing = cast("dict[str, Any]", manifest.get("signing_input_ownership"))
    if signing.get("aegaeon_constructs_jws_signing_input") is not True:
        raise ValidationError("claim-preserving classification requires Aegaeon-owned JWS input")
    if signing.get("provider_returns_finished_jwt") is not False:
        raise ValidationError("claim-preserving classification rejects provider-finished JWTs")

    jwk = cast("dict[str, Any]", manifest.get("public_jwk_derivation"))
    if jwk.get("method") not in {"provider-api", "checked-import"}:
        raise ValidationError(
            "claim-preserving classification requires provider-api or "
            "checked-import JWK derivation",
        )
    if jwk.get("key_match_checked") is not True:
        raise ValidationError("claim-preserving classification requires key-match check")

    rotation = cast("dict[str, Any]", manifest.get("jwks_rotation"))
    for key in (
        "overlap_matches_local_path",
        "rollback_matches_local_path",
        "kid_reuse_prevented",
    ):
        if rotation.get(key) is not True:
            raise ValidationError(f"claim-preserving classification requires {key}=true")

    boundary = cast("dict[str, Any]", manifest.get("claim_boundary"))
    for key in (
        "rs256_required_slice_unchanged",
        "external_signer_recorded_as_tcb",
        "broad_rsa_not_promoted",
    ):
        if boundary.get(key) is not True:
            raise ValidationError(f"claim-preserving classification requires {key}=true")

    parity = cast("dict[str, Any]", manifest.get("parity_evidence"))
    if parity.get("status") != "pass":
        raise ValidationError("claim-preserving classification requires passing parity evidence")
    uri = parity.get("uri")
    if not isinstance(uri, str) or not uri:
        raise ValidationError("claim-preserving classification requires parity evidence uri")

    review = cast("dict[str, Any]", manifest.get("review"))
    if review.get("decision") != "approved" or not review.get("reviewer"):
        raise ValidationError("claim-preserving classification requires approved reviewer")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="+", help="KMS/HSM classification manifest JSON path(s)")
    args = parser.parse_args()

    failures = 0
    for raw_path in args.manifest:
        path = pathlib.Path(raw_path)
        try:
            validate_manifest(path)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
