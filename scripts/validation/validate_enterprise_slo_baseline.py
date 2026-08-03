#!/usr/bin/env python3
"""Validate enterprise SLO baseline manifests."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = pathlib.Path("spec/enterprise-slo-baseline.schema.json")
REQUIRED_SCENARIOS = {
    "smoke",
    "auth-code",
    "dpop",
    "introspection",
    "revocation",
    "par",
    "discovery",
    "jwks",
    "policy-mixed",
    "management-api",
}


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"SLO baseline file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc


def is_external_uri(uri: str) -> bool:
    return uri.startswith(("http://", "https://", "s3://", "gs://"))


def validate_evidence_uri(root: pathlib.Path, label: str, uri: str) -> None:
    if uri.startswith("http://"):
        raise ValidationError(f"{label}: evidence URI must not use http")
    if is_external_uri(uri):
        return
    if pathlib.Path(uri).is_absolute():
        raise ValidationError(f"{label}: local evidence URI must be relative")
    evidence_path = (root / uri).resolve()
    try:
        evidence_path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValidationError(f"{label}: local evidence URI escapes baseline directory") from exc
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
    deployment = manifest.get("deployment")
    if not isinstance(deployment, dict):
        raise ValidationError("enterprise SLO baseline requires deployment object")
    target_url = deployment.get("target_url")
    if not isinstance(target_url, str) or not target_url.startswith("https://"):
        raise ValidationError("enterprise SLO baseline requires https deployment target_url")

    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValidationError("enterprise SLO baseline requires scenarios list")

    seen = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            continue
        name = scenario.get("name")
        if not isinstance(name, str):
            continue
        if name in seen:
            raise ValidationError(f"duplicate scenario entry: {name}")
        seen[name] = scenario

    missing = sorted(REQUIRED_SCENARIOS - set(seen))
    if missing:
        joined = ", ".join(missing)
        raise ValidationError(f"missing required SLO scenarios: {joined}")

    root = path.parent
    for name in sorted(REQUIRED_SCENARIOS):
        scenario = seen[name]
        status = scenario.get("status")
        report_uri = scenario.get("report_uri")
        notes = scenario.get("notes")
        if status == "not_applicable":
            if not isinstance(notes, str) or not notes.strip():
                raise ValidationError(f"{name}: not_applicable requires notes")
            continue
        if status != "pass":
            raise ValidationError(
                f"{name}: required scenario must pass or be scoped not_applicable"
            )
        if not isinstance(report_uri, str) or not report_uri:
            raise ValidationError(f"{name}: passing scenario requires report_uri")
        validate_evidence_uri(root, f"{name}.report_uri", report_uri)

    observability = manifest.get("observability")
    if not isinstance(observability, dict):
        raise ValidationError("enterprise SLO baseline requires observability object")
    if not any(observability.get(key) for key in ("metrics_uri", "dashboard_uri", "alerts_uri")):
        raise ValidationError("observability requires at least one metrics/dashboard/alerts URI")
    for key in ("metrics_uri", "dashboard_uri", "alerts_uri"):
        uri = observability.get(key)
        if uri is None:
            continue
        if not isinstance(uri, str) or not uri:
            raise ValidationError(f"observability.{key}: URI must be null or non-empty string")
        validate_evidence_uri(root, f"observability.{key}", uri)

    review = manifest.get("review")
    if not isinstance(review, dict):
        raise ValidationError("enterprise SLO baseline requires review object")
    if review.get("decision") == "approved" and not review.get("reviewer"):
        raise ValidationError("approved enterprise SLO baseline requires a reviewer")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="+", help="Enterprise SLO baseline manifest JSON path(s)")
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
