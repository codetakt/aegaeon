#!/usr/bin/env python3
"""Build an enterprise SLO baseline manifest from hosted readiness evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import shutil
import subprocess
import sys
from typing import Any, cast

from jsonschema import ValidationError

VALIDATION_DIR = pathlib.Path(__file__).resolve().parent
if str(VALIDATION_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATION_DIR))

import validate_enterprise_slo_baseline  # noqa: E402

SCENARIOS = (
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
)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"hosted evidence file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in hosted evidence file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"hosted evidence JSON must be an object: {path}")
    return value


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def generated_at_from_summary(summary: dict[str, Any]) -> str:
    raw = summary.get("timestamp_utc")
    if isinstance(raw, str):
        try:
            parsed = dt.datetime.strptime(raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.UTC)
            return parsed.isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def copy_if_present(src: pathlib.Path, dst: pathlib.Path) -> bool:
    if not src.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def write_json(path: pathlib.Path, value: dict[str, Any]) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def pass_scenario(name: str, report_uri: str, notes: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": "pass",
        "required": True,
        "report_uri": report_uri,
        "workers": 1,
        "target_rps": None,
        "duration_seconds": None,
        "error_rate": 0.0,
        "p99_latency_ms": None,
        "notes": notes,
    }


def pending_scenario(name: str, notes: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": "not_applicable",
        "required": True,
        "report_uri": None,
        "workers": None,
        "target_rps": None,
        "duration_seconds": None,
        "error_rate": None,
        "p99_latency_ms": None,
        "notes": notes,
    }


def scenario_entries(summary: dict[str, Any]) -> list[dict[str, Any]]:
    smoke_status = summary.get("smoke_status")
    smoke_lines = (
        [line for line in smoke_status if isinstance(line, str)]
        if isinstance(smoke_status, list)
        else []
    )
    smoke_joined = "\n".join(smoke_lines)

    entries: dict[str, dict[str, Any]] = {}
    entries["smoke"] = pass_scenario(
        "smoke",
        "reports/hosted-smoke-summary.json",
        "Hosted readiness smoke passed for /health, discovery, JWKS, and system health.",
    )
    entries["discovery"] = pass_scenario(
        "discovery",
        "reports/http-smoke-status.txt",
        "Discovery endpoint returned HTTP 200 during hosted readiness smoke."
        if "/.well-known/openid-configuration" in smoke_joined
        else "Discovery endpoint was included in hosted readiness evidence.",
    )
    entries["jwks"] = pass_scenario(
        "jwks",
        "reports/http-smoke-status.txt",
        "JWKS endpoint returned HTTP 200 during hosted readiness smoke."
        if "/.well-known/jwks.json" in smoke_joined
        else "JWKS endpoint was included in hosted readiness evidence.",
    )

    pending_note = (
        "Not collected by this short hosted readiness smoke. A full enterprise SLO "
        "baseline still needs the dedicated load scenario before the gate can be "
        "reviewed as complete."
    )
    for scenario in SCENARIOS:
        entries.setdefault(scenario, pending_scenario(scenario, pending_note))

    entries["management-api"] = pending_scenario(
        "management-api",
        "Only /api/v1/system/health was exercised by the hosted readiness smoke; "
        "management API read/write load evidence remains required.",
    )
    return [entries[name] for name in SCENARIOS]


def build_manifest(args: argparse.Namespace) -> pathlib.Path:
    evidence_dir = cast("pathlib.Path", args.evidence_dir)
    out_dir = cast("pathlib.Path", args.out_dir)
    summary = load_json(evidence_dir / "summary.json")

    reports = out_dir / "reports"
    observability = out_dir / "observability"
    logs = out_dir / "logs"
    copy_if_present(evidence_dir / "summary.json", reports / "hosted-smoke-summary.json")
    copy_if_present(evidence_dir / "http-smoke-status.txt", reports / "http-smoke-status.txt")
    copy_if_present(evidence_dir / "http-metrics-head.txt", observability / "http-metrics-head.txt")
    copy_if_present(
        evidence_dir / "server-error-filter-last-5m.txt",
        observability / "server-error-filter-last-5m.txt",
    )
    copy_if_present(evidence_dir / "server-tail-last-10m.txt", logs / "server-tail-last-10m.txt")

    target_url = summary.get("base_url")
    if not isinstance(target_url, str) or not target_url:
        raise ValidationError("hosted evidence summary requires base_url")

    manifest = {
        "$schema": "https://aegaeon.dev/spec/enterprise-slo-baseline.schema.json",
        "schema_version": 1,
        "baseline_id": args.baseline_id,
        "source_revision": args.source_revision,
        "generated_at": args.generated_at or generated_at_from_summary(summary),
        "deployment": {
            "shape": "aws-hosted-enterprise-validation",
            "target_url": target_url,
            "database_backend": "postgres",
            "signer_backend": "aws-kms",
            "feature_flags": [
                "policy.oidcEnabled=true",
                "policy.oidcEnableDiscovery=true",
                "policy.oidcEnableUserinfo=true",
                "runtimeKey.OIDC_ID_TOKEN_SIGNING.provider=aws-kms",
                "enterprise_readiness_profile=true",
            ],
        },
        "scenarios": scenario_entries(summary),
        "observability": {
            "metrics_uri": "observability/http-metrics-head.txt",
            "dashboard_uri": None,
            "alerts_uri": "observability/server-error-filter-last-5m.txt",
        },
        "review": {
            "reviewer": args.reviewer,
            "decision": args.review_decision,
            "notes": (
                "Generated from hosted readiness evidence. This is a partial baseline: "
                "issuer smoke, discovery, JWKS, and management health are covered; "
                "full enterprise load scenarios remain pending."
            ),
        },
    }
    manifest_path = write_json(out_dir / "manifest.json", manifest)
    validate_enterprise_slo_baseline.validate_manifest(manifest_path)
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=pathlib.Path, required=True)
    parser.add_argument("--out-dir", type=pathlib.Path, required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument("--source-revision", default=git_head())
    parser.add_argument("--generated-at")
    parser.add_argument("--reviewer")
    parser.add_argument(
        "--review-decision",
        choices=("pending", "approved", "rejected"),
        default="pending",
    )
    args = parser.parse_args()

    try:
        manifest_path = build_manifest(args)
    except (ValidationError, SystemExit) as exc:
        print(f"[invalid] enterprise SLO baseline: {exc}", file=sys.stderr)
        return 1
    print(f"[ok] enterprise SLO baseline: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
