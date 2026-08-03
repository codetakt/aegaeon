"""Validate managed-provider evidence documents against the canonical schema."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_FILE = pathlib.Path("spec/managed-provider-evidence.schema.json")
GITHUB_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_RUN_ID_RE = re.compile(r"^[0-9]+$")
DEFAULT_MAX_AGE_HOURS = 168.0
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except OSError as exc:
        raise SystemExit(f"Managed-provider evidence file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def validate_enterprise_readiness(
    evidence: dict[str, Any],
    *,
    now: dt.datetime | None = None,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
) -> None:
    validate_generated_at_freshness(evidence, now=now, max_age_hours=max_age_hours)

    provider = evidence.get("provider")
    if not isinstance(provider, dict):
        raise ValidationError("enterprise managed-provider evidence requires provider object")
    provider_class = provider.get("class")
    if provider_class not in {"commercial", "enterprise"}:
        raise ValidationError(
            "enterprise managed-provider evidence requires provider.class commercial or enterprise",
        )
    issuer = provider.get("issuer")
    if not isinstance(issuer, str) or not issuer.startswith("https://"):
        raise ValidationError("enterprise managed-provider evidence requires https provider.issuer")

    lane = evidence.get("lane")
    if not isinstance(lane, dict):
        raise ValidationError("enterprise managed-provider evidence requires lane object")
    if lane.get("hosted") is not True:
        raise ValidationError("enterprise managed-provider evidence requires hosted=true")
    if lane.get("status") != "passed":
        raise ValidationError("enterprise managed-provider evidence requires lane.status=passed")

    source = evidence.get("source")
    if not isinstance(source, dict):
        raise ValidationError("enterprise managed-provider evidence requires source object")
    for field in (
        "github_run_id",
        "github_workflow",
        "github_repository",
        "github_ref",
        "github_sha",
    ):
        value = source.get(field)
        if not isinstance(value, str) or not value:
            raise ValidationError(f"enterprise managed-provider evidence requires source.{field}")
    validate_github_source_metadata(source)

    runtime = evidence.get("runtime")
    if not isinstance(runtime, dict):
        raise ValidationError("enterprise managed-provider evidence requires runtime object")
    if runtime.get("claim_phase") != "released-client-claim":
        raise ValidationError(
            "enterprise managed-provider evidence requires "
            "runtime.claim_phase=released-client-claim",
        )
    if runtime.get("default_profile") == "compat-interop":
        raise ValidationError(
            "enterprise managed-provider evidence rejects compat-interop default profile"
        )
    promoted = runtime.get("promoted_client_slices")
    if not isinstance(promoted, list) or not promoted:
        raise ValidationError(
            "enterprise managed-provider evidence requires promoted client slices"
        )
    compat_only = runtime.get("compat_only_surfaces")
    if not isinstance(compat_only, list):
        raise ValidationError(
            "enterprise managed-provider evidence requires compat_only_surfaces list"
        )


def parse_generated_at(evidence: dict[str, Any]) -> dt.datetime:
    raw_value = evidence.get("generated_at")
    if not isinstance(raw_value, str) or not raw_value:
        raise ValidationError("enterprise managed-provider evidence requires generated_at")
    normalized = raw_value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError(
            "enterprise managed-provider evidence generated_at must be RFC3339"
        ) from exc
    if parsed.tzinfo is None:
        raise ValidationError(
            "enterprise managed-provider evidence generated_at must include timezone"
        )
    return parsed.astimezone(dt.UTC)


def validate_generated_at_freshness(
    evidence: dict[str, Any],
    *,
    now: dt.datetime | None,
    max_age_hours: float,
) -> None:
    reference_time = (now or dt.datetime.now(dt.UTC)).astimezone(dt.UTC)
    generated_at = parse_generated_at(evidence)
    if generated_at > reference_time + MAX_FUTURE_SKEW:
        raise ValidationError(
            "enterprise managed-provider evidence generated_at must not be in the future"
        )
    max_age = dt.timedelta(hours=max_age_hours)
    if reference_time - generated_at > max_age:
        raise ValidationError(
            f"enterprise managed-provider evidence must be no older than {max_age_hours:g} hours"
        )


def validate_github_source_metadata(source: dict[str, Any]) -> None:
    run_id = cast("str", source["github_run_id"])
    if not GITHUB_RUN_ID_RE.fullmatch(run_id):
        raise ValidationError("enterprise managed-provider evidence requires numeric github_run_id")

    repository = cast("str", source["github_repository"])
    if repository.count("/") != 1 or any(not part for part in repository.split("/")):
        raise ValidationError(
            "enterprise managed-provider evidence requires owner/repo github_repository"
        )

    ref = cast("str", source["github_ref"])
    if not ref.startswith("refs/"):
        raise ValidationError(
            "enterprise managed-provider evidence requires full refs/* github_ref"
        )

    sha = cast("str", source["github_sha"])
    if not GITHUB_SHA_RE.fullmatch(sha):
        raise ValidationError("enterprise managed-provider evidence requires 40-hex github_sha")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-enterprise-ready",
        action="store_true",
        help=(
            "Require hosted commercial/enterprise provider evidence suitable "
            "for enterprise-readiness activation"
        ),
    )
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=DEFAULT_MAX_AGE_HOURS,
        help=(
            "Maximum generated_at age allowed with --require-enterprise-ready "
            f"(default: {DEFAULT_MAX_AGE_HOURS:g})"
        ),
    )
    parser.add_argument(
        "evidence",
        nargs="+",
        help="Path(s) to managed-provider evidence JSON files",
    )
    args = parser.parse_args()

    schema = json.loads(SCHEMA_FILE.read_text())
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )

    failures = 0
    for raw_path in args.evidence:
        evidence_path = pathlib.Path(raw_path)
        try:
            evidence = cast("dict[str, Any]", load_json(evidence_path))
            validator.validate(evidence)
            if args.require_enterprise_ready:
                validate_enterprise_readiness(evidence, max_age_hours=args.max_age_hours)
        except (ValidationError, SystemExit) as exc:
            print(f"[invalid] {evidence_path}: {exc}", file=sys.stderr)
            failures += 1
            continue

        print(f"[ok] {evidence_path}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
