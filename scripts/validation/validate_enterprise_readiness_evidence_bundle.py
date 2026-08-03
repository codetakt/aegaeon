#!/usr/bin/env python3
"""Validate enterprise-readiness evidence bundles."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

VALIDATION_DIR = pathlib.Path(__file__).resolve().parent
if str(VALIDATION_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATION_DIR))

import validate_enterprise_slo_baseline  # noqa: E402
import validate_kms_hsm_classification  # noqa: E402
import validate_managed_provider_evidence  # noqa: E402
import validate_publication_org_rollout  # noqa: E402
import validate_release_security_evidence  # noqa: E402

SCHEMA_PATH = pathlib.Path("spec/enterprise-readiness-evidence-bundle.schema.json")


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"Enterprise-readiness evidence bundle not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def resolve_bundle_path(bundle_path: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path
    return (bundle_path.parent / path).resolve()


def validate_claim_gate(path: pathlib.Path) -> None:
    policy = load_json(path)
    if not isinstance(policy, dict):
        raise ValidationError("enterprise claim gate must be a JSON object")
    if policy.get("claim_target") != "enterprise-readiness":
        raise ValidationError("claim_gate_path must point at enterprise-readiness claim gate")
    if policy.get("claim_active") is not False:
        raise ValidationError(
            "enterprise-readiness evidence bundle must be reviewed before claim_active changes",
        )


def validate_managed_provider(
    path: pathlib.Path,
    *,
    reference_time: dt.datetime,
) -> dict[str, Any]:
    schema = validate_managed_provider_evidence.load_json(
        validate_managed_provider_evidence.SCHEMA_FILE,
    )
    evidence = cast("dict[str, Any]", validate_managed_provider_evidence.load_json(path))
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(evidence)
    validate_managed_provider_evidence.validate_enterprise_readiness(
        evidence,
        now=reference_time,
    )
    return evidence


def required_release_evidence_paths(
    manifest_path: pathlib.Path,
    groups: set[str],
) -> dict[str, set[pathlib.Path]]:
    manifest = cast(
        "dict[str, Any]",
        validate_release_security_evidence.load_json(manifest_path),
    )
    evidence = manifest.get("evidence")
    if not isinstance(evidence, dict):
        raise ValidationError("release manifest requires evidence object")

    paths: dict[str, set[pathlib.Path]] = {group: set() for group in groups}
    root = manifest_path.parent
    for group in groups:
        items = evidence.get(group)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or item.get("required") is not True:
                continue
            uri = item.get("uri")
            if not isinstance(uri, str) or not uri:
                continue
            if validate_release_security_evidence.is_external_uri(uri):
                continue
            paths[group].add((root / uri).resolve())
    return paths


def require_matching_source_revision(
    bundle_revision: str,
    evidence: dict[str, Any],
    label: str,
) -> None:
    evidence_revision = evidence.get("source_revision")
    if evidence_revision != bundle_revision:
        raise ValidationError(
            f"{label} source_revision must match enterprise bundle source_revision",
        )


def parse_generated_at(evidence: dict[str, Any], label: str) -> dt.datetime:
    raw_value = evidence.get("generated_at")
    if not isinstance(raw_value, str):
        raise ValidationError(f"{label} requires generated_at")
    normalized = raw_value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError(f"{label} generated_at must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{label} generated_at must include a timezone")
    return parsed.astimezone(dt.UTC)


def require_not_after_bundle(
    bundle_generated_at: dt.datetime,
    evidence: dict[str, Any],
    label: str,
) -> None:
    generated_at = parse_generated_at(evidence, label)
    if generated_at > bundle_generated_at:
        raise ValidationError(f"{label} generated_at must not be after bundle generated_at")


def require_approved_review(evidence: dict[str, Any], label: str) -> None:
    review = evidence.get("review")
    if not isinstance(review, dict):
        raise ValidationError(f"{label} requires review object for activation review")
    if review.get("decision") != "approved":
        raise ValidationError(f"{label} review must be approved for activation review")
    reviewer = review.get("reviewer")
    if not isinstance(reviewer, str) or not reviewer.strip():
        raise ValidationError(f"{label} approved review requires reviewer")


def validate_bundle(path: pathlib.Path, require_approved: bool = False) -> None:
    schema = load_json(SCHEMA_PATH)
    bundle = cast("dict[str, Any]", load_json(path))
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    validator.validate(bundle)
    bundle_revision = cast("str", bundle["source_revision"])
    bundle_generated_at = parse_generated_at(bundle, "enterprise-readiness evidence bundle")

    claim_gate_path = resolve_bundle_path(path, cast("str", bundle["claim_gate_path"]))
    validate_claim_gate(claim_gate_path)

    evidence = cast("dict[str, Any]", bundle["evidence"])
    publication_report = resolve_bundle_path(
        path,
        cast("str", evidence["publication_org_rollout_report"]),
    )
    validate_publication_org_rollout.validate_report(publication_report, require_ready=True)
    publication_evidence = cast(
        "dict[str, Any]",
        validate_publication_org_rollout.load_json(publication_report),
    )
    require_not_after_bundle(
        bundle_generated_at,
        publication_evidence,
        "publication organization rollout report",
    )

    managed_provider = resolve_bundle_path(
        path,
        cast("str", evidence["managed_provider_evidence"]),
    )
    managed_provider_evidence = validate_managed_provider(
        managed_provider,
        reference_time=bundle_generated_at,
    )
    require_not_after_bundle(
        bundle_generated_at, managed_provider_evidence, "managed-provider evidence"
    )

    kms_classifications = []
    seen_kms_classifications: set[pathlib.Path] = set()
    for raw_classification in cast("list[str]", evidence["kms_hsm_classifications"]):
        classification = resolve_bundle_path(path, raw_classification)
        resolved_classification = classification.resolve()
        if resolved_classification in seen_kms_classifications:
            raise ValidationError(
                "enterprise bundle KMS/HSM classifications must resolve to unique paths",
            )
        seen_kms_classifications.add(resolved_classification)
        kms_classifications.append(classification)
        validate_kms_hsm_classification.validate_manifest(classification)
        classification_manifest = cast(
            "dict[str, Any]",
            validate_kms_hsm_classification.load_json(classification),
        )
        require_matching_source_revision(
            bundle_revision, classification_manifest, "KMS/HSM classification"
        )
        require_not_after_bundle(
            bundle_generated_at, classification_manifest, "KMS/HSM classification"
        )
        if require_approved:
            require_approved_review(classification_manifest, "KMS/HSM classification")

    release_manifest = resolve_bundle_path(
        path,
        cast("str", evidence["release_security_evidence_manifest"]),
    )
    validate_release_security_evidence.validate_enterprise_readiness_manifest(release_manifest)
    release_evidence = cast(
        "dict[str, Any]",
        validate_release_security_evidence.load_json(release_manifest),
    )
    if release_evidence.get("release_id") != bundle["release_id"]:
        raise ValidationError("release manifest release_id must match enterprise bundle release_id")
    require_matching_source_revision(bundle_revision, release_evidence, "release security evidence")
    require_not_after_bundle(bundle_generated_at, release_evidence, "release security evidence")
    if require_approved:
        require_approved_review(release_evidence, "release security evidence")
    release_paths = required_release_evidence_paths(
        release_manifest,
        {"kms", "managed_provider", "performance", "publication"},
    )
    if publication_report.resolve() not in release_paths["publication"]:
        raise ValidationError(
            "enterprise bundle publication report must be a required release-manifest item",
        )
    if managed_provider.resolve() not in release_paths["managed_provider"]:
        raise ValidationError(
            "enterprise bundle managed-provider evidence must be a required release-manifest item",
        )
    for classification in kms_classifications:
        if classification.resolve() not in release_paths["kms"]:
            raise ValidationError(
                "enterprise bundle KMS/HSM classification must be a required release-manifest item",
            )

    slo_manifest = resolve_bundle_path(
        path,
        cast("str", evidence["enterprise_slo_baseline_manifest"]),
    )
    if slo_manifest.resolve() not in release_paths["performance"]:
        raise ValidationError(
            "enterprise bundle SLO baseline must be a required release-manifest item",
        )
    validate_enterprise_slo_baseline.validate_manifest(slo_manifest)
    slo_evidence = cast(
        "dict[str, Any]",
        validate_enterprise_slo_baseline.load_json(slo_manifest),
    )
    require_matching_source_revision(bundle_revision, slo_evidence, "enterprise SLO baseline")
    require_not_after_bundle(bundle_generated_at, slo_evidence, "enterprise SLO baseline")
    if require_approved:
        require_approved_review(slo_evidence, "enterprise SLO baseline")

    review = cast("dict[str, Any]", bundle["review"])
    if review.get("decision") == "approved" and not review.get("reviewer"):
        raise ValidationError("approved enterprise-readiness evidence bundle requires reviewer")
    if require_approved:
        require_approved_review(bundle, "enterprise-readiness evidence bundle")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-approved",
        action="store_true",
        help="Require activation-review approval on the bundle and reviewable evidence manifests",
    )
    parser.add_argument(
        "bundle", nargs="+", help="Enterprise-readiness evidence bundle JSON path(s)"
    )
    args = parser.parse_args()

    failures = 0
    for raw_path in args.bundle:
        path = pathlib.Path(raw_path)
        try:
            validate_bundle(path, require_approved=args.require_approved)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        print(f"[ok] {path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
