"""Validate SDK release-publication bundles against the canonical schema."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_FILE = pathlib.Path("spec/sdk-release-publication-bundle.schema.json")
GITHUB_RUN_ID_RE = re.compile(r"^[0-9]+$")
GITHUB_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"Bundle file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def validate_enterprise_readiness(bundle: dict[str, Any]) -> None:
    if bundle.get("release_phase") != "released-client-claim":
        raise ValidationError(
            "enterprise SDK release-publication bundle requires "
            "release_phase=released-client-claim",
        )

    source = bundle.get("source")
    if not isinstance(source, dict):
        raise ValidationError("enterprise SDK release-publication bundle requires source object")
    for field in (
        "github_ref",
        "github_sha",
        "github_run_id",
        "github_workflow",
        "npm_dist_tag",
    ):
        value = source.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(
                f"enterprise SDK release-publication bundle requires source.{field}"
            )
    validate_github_source_metadata(source)

    release_attestation = bundle.get("release_attestation")
    if not isinstance(release_attestation, dict):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires release_attestation"
        )
    for field in (
        "npm_provenance_enabled",
        "signed_release_attestation_present",
        "sbom_publication_present",
    ):
        if release_attestation.get(field) is not True:
            raise ValidationError(
                "enterprise SDK release-publication bundle requires "
                f"release_attestation.{field}=true",
            )
    deferred_attestation = release_attestation.get("deferred_requirements")
    if isinstance(deferred_attestation, list) and deferred_attestation:
        raise ValidationError(
            "enterprise SDK release-publication bundle rejects deferred attestation requirements"
        )

    if not isinstance(bundle.get("release_attestation_signature"), dict):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires signed attestation descriptor"
        )

    managed_provider = bundle.get("managed_provider_evidence")
    if not isinstance(managed_provider, dict):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires managed-provider evidence"
        )
    if managed_provider.get("hosted") is not True or managed_provider.get("status") != "passed":
        raise ValidationError(
            "enterprise SDK release-publication bundle requires hosted "
            "passed managed-provider evidence"
        )
    if managed_provider.get("provider_class") not in {"commercial", "enterprise"}:
        raise ValidationError(
            "enterprise SDK release-publication bundle requires commercial/enterprise provider"
        )

    client_claim_promotion = bundle.get("client_claim_promotion")
    if not isinstance(client_claim_promotion, dict):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires client-claim promotion report"
        )
    if (
        client_claim_promotion.get("ready") is not True
        or client_claim_promotion.get("failure_count") != 0
    ):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires ready client-claim promotion"
        )

    released_client = bundle.get("released_client_claim_report")
    if not isinstance(released_client, dict):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires released-client claim report"
        )
    if released_client.get("ready") is not True or released_client.get("blocker_count") != 0:
        raise ValidationError(
            "enterprise SDK release-publication bundle requires ready released-client claim report"
        )

    publication_org = bundle.get("publication_org_rollout_report")
    if not isinstance(publication_org, dict):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires publication-org rollout report"
        )
    if publication_org.get("ready") is not True or publication_org.get("blocker_count") != 0:
        raise ValidationError(
            "enterprise SDK release-publication bundle requires ready publication-org rollout"
        )

    deferred = bundle.get("deferred_publication_requirements")
    if isinstance(deferred, list) and deferred:
        raise ValidationError(
            "enterprise SDK release-publication bundle rejects deferred publication requirements"
        )


def validate_github_source_metadata(source: dict[str, Any]) -> None:
    run_id = cast("str", source["github_run_id"])
    if not GITHUB_RUN_ID_RE.fullmatch(run_id):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires numeric source.github_run_id"
        )

    ref = cast("str", source["github_ref"])
    if not ref.startswith("refs/"):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires full refs/* source.github_ref"
        )

    sha = cast("str", source["github_sha"])
    if not GITHUB_SHA_RE.fullmatch(sha):
        raise ValidationError(
            "enterprise SDK release-publication bundle requires 40-hex source.github_sha"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-enterprise-ready",
        action="store_true",
        help=(
            "Require released-client publication evidence suitable for Phase 1 enterprise readiness"
        ),
    )
    parser.add_argument(
        "bundle",
        nargs="+",
        help="Path(s) to SDK release-publication-bundle JSON files",
    )
    args = parser.parse_args()

    schema = json.loads(SCHEMA_FILE.read_text())
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )

    failures = 0
    for raw_path in args.bundle:
        bundle_path = pathlib.Path(raw_path)
        try:
            bundle = cast("dict[str, Any]", load_json(bundle_path))
            validator.validate(bundle)
            if args.require_enterprise_ready:
                validate_enterprise_readiness(bundle)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {bundle_path}: {exc}", file=sys.stderr)
            failures += 1
            continue

        print(f"[ok] {bundle_path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
