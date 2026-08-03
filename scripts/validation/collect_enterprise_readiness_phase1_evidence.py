#!/usr/bin/env python3
"""Collect Phase 1 enterprise-readiness evidence into a release archive."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from collections.abc import Callable  # noqa: TC003
from dataclasses import dataclass
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError

VALIDATION_DIR = pathlib.Path(__file__).resolve().parent
if str(VALIDATION_DIR) not in sys.path:
    sys.path.insert(0, str(VALIDATION_DIR))

import validate_enterprise_readiness_evidence_bundle  # noqa: E402
import validate_enterprise_readiness_phase1  # noqa: E402
import validate_enterprise_slo_baseline  # noqa: E402
import validate_kms_hsm_classification  # noqa: E402
import validate_managed_provider_evidence  # noqa: E402
import validate_publication_org_rollout  # noqa: E402
import validate_release_security_evidence  # noqa: E402
import validate_sdk_release_publication_bundle  # noqa: E402


@dataclass(frozen=True)
class Phase1EvidenceInputs:
    release_id: str
    out_dir: pathlib.Path
    source_revision: str
    flake_lock_revision: str
    generated_at: str
    claim_gate: pathlib.Path
    publication_org_rollout: pathlib.Path
    sdk_release_publication_bundle: pathlib.Path
    managed_provider_evidence: pathlib.Path
    kms_classifications: tuple[pathlib.Path, ...]
    enterprise_slo_baseline: pathlib.Path
    build_log: pathlib.Path
    verification_log: pathlib.Path
    security_log: pathlib.Path
    sbom: pathlib.Path
    support_response: pathlib.Path
    reviewer: str | None
    force: bool
    phase1_check: bool
    preflight_only: bool


@dataclass(frozen=True)
class CollectedArchive:
    release_manifest: pathlib.Path
    enterprise_bundle: pathlib.Path


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise SystemExit(f"Evidence file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"Evidence JSON must be an object: {path}")
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def flake_lock_hash() -> str:
    path = pathlib.Path("flake.lock")
    if not path.exists():
        return "missing-flake-lock"
    return f"sha256:{sha256_file(path)}"


def ensure_file(path: pathlib.Path, label: str) -> pathlib.Path:
    if not path.is_file():
        raise SystemExit(f"{label} file not found: {path}")
    return path


def copy_file(src: pathlib.Path, dst: pathlib.Path) -> pathlib.Path:
    ensure_file(src, "Evidence")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return dst


def is_external_uri(uri: str) -> bool:
    return uri.startswith(("http://", "https://", "s3://", "gs://"))


def copy_local_uri_evidence(
    source_manifest: pathlib.Path,
    destination_dir: pathlib.Path,
    uri: object,
) -> None:
    if uri is None:
        return
    if not isinstance(uri, str) or not uri:
        raise ValidationError(f"local evidence URI must be null or non-empty string: {uri!r}")
    if is_external_uri(uri):
        return
    if pathlib.Path(uri).is_absolute():
        raise ValidationError(f"local evidence URI must be relative: {uri}")
    source_root = source_manifest.parent.resolve()
    source_path = (source_root / uri).resolve()
    try:
        source_path.relative_to(source_root)
    except ValueError as exc:
        raise ValidationError(
            f"local evidence URI escapes source manifest directory: {uri}"
        ) from exc
    copy_file(source_path, destination_dir / uri)


def copy_kms_classification(
    source: pathlib.Path,
    destination_dir: pathlib.Path,
    index: int,
) -> pathlib.Path:
    validate_kms_hsm_classification.validate_manifest(source)
    manifest = load_json(source)
    deployment = manifest.get("deployment_id")
    suffix = slugify(deployment) if isinstance(deployment, str) and deployment else str(index + 1)
    destination = unique_destination(destination_dir, f"{suffix}-classification.json")
    parity = manifest.get("parity_evidence")
    if isinstance(parity, dict):
        copy_local_uri_evidence(source, destination.parent, parity.get("uri"))
    copy_file(source, destination)
    validate_kms_hsm_classification.validate_manifest(destination)
    return destination


def copy_slo_baseline(source: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    validate_enterprise_slo_baseline.validate_manifest(source)
    manifest = load_json(source)
    scenarios = manifest.get("scenarios")
    if isinstance(scenarios, list):
        for scenario in scenarios:
            if isinstance(scenario, dict):
                copy_local_uri_evidence(source, destination.parent, scenario.get("report_uri"))
    observability = manifest.get("observability")
    if isinstance(observability, dict):
        for key in ("metrics_uri", "dashboard_uri", "alerts_uri"):
            copy_local_uri_evidence(source, destination.parent, observability.get(key))
    copy_file(source, destination)
    validate_enterprise_slo_baseline.validate_manifest(destination)
    return destination


def slugify(value: object) -> str:
    raw = str(value).strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return slug or "evidence"


def unique_destination(directory: pathlib.Path, filename: str) -> pathlib.Path:
    stem = pathlib.Path(filename).stem
    suffix = pathlib.Path(filename).suffix
    candidate = directory / filename
    counter = 2
    while candidate.exists():
        candidate = directory / f"{stem}-{counter}{suffix}"
        counter += 1
    return candidate


def relative_uri(root: pathlib.Path, path: pathlib.Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def relative_path(from_dir: pathlib.Path, path: pathlib.Path) -> str:
    return pathlib.Path(os.path.relpath(path.resolve(), from_dir.resolve())).as_posix()


def evidence_item(
    root: pathlib.Path,
    item_id: str,
    path: pathlib.Path,
    kind: str,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "uri": relative_uri(root, path),
        "kind": kind,
        "required": True,
        "sha256": sha256_file(path),
    }


def format_preflight_exception(exc: BaseException) -> str:
    if isinstance(exc, ValidationError):
        return str(exc.message)
    return str(exc)


def capture_preflight(label: str, action: Callable[[], object], errors: list[str]) -> None:
    try:
        action()
    except (ValidationError, SystemExit, OSError) as exc:
        errors.append(f"{label}: {format_preflight_exception(exc)}")


def validate_sdk_publication_source(path: pathlib.Path) -> None:
    sdk_schema = validate_sdk_release_publication_bundle.load_json(
        validate_sdk_release_publication_bundle.SCHEMA_FILE,
    )
    sdk_bundle = cast(
        "dict[str, Any]",
        validate_sdk_release_publication_bundle.load_json(path),
    )
    Draft202012Validator(
        sdk_schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(sdk_bundle)
    validate_sdk_release_publication_bundle.validate_enterprise_readiness(sdk_bundle)


def parse_reference_time(value: str) -> dt.datetime:
    normalized = value.replace("Z", "+00:00")
    return dt.datetime.fromisoformat(normalized).astimezone(dt.UTC)


def validate_managed_provider_source(
    path: pathlib.Path,
    *,
    reference_time: dt.datetime,
) -> None:
    managed_schema = validate_managed_provider_evidence.load_json(
        validate_managed_provider_evidence.SCHEMA_FILE,
    )
    managed_evidence = cast(
        "dict[str, Any]",
        validate_managed_provider_evidence.load_json(path),
    )
    Draft202012Validator(
        managed_schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(managed_evidence)
    validate_managed_provider_evidence.validate_enterprise_readiness(
        managed_evidence,
        now=reference_time,
    )


def preflight_source_evidence(inputs: Phase1EvidenceInputs) -> list[str]:
    errors: list[str] = []

    def validate_publication_rollout() -> None:
        validate_publication_org_rollout.validate_report(
            inputs.publication_org_rollout,
            require_ready=True,
        )

    def validate_sdk_bundle() -> None:
        validate_sdk_publication_source(inputs.sdk_release_publication_bundle)

    def validate_managed_provider() -> None:
        validate_managed_provider_source(
            inputs.managed_provider_evidence,
            reference_time=parse_reference_time(inputs.generated_at),
        )

    def validate_slo_baseline() -> None:
        validate_enterprise_slo_baseline.validate_manifest(inputs.enterprise_slo_baseline)

    def ensure_named_file(
        path: pathlib.Path,
        label: str,
    ) -> Callable[[], pathlib.Path]:
        return lambda: ensure_file(path, label)

    capture_preflight(
        "publication-org rollout",
        validate_publication_rollout,
        errors,
    )
    capture_preflight(
        "SDK release-publication bundle",
        validate_sdk_bundle,
        errors,
    )
    capture_preflight(
        "managed-provider evidence",
        validate_managed_provider,
        errors,
    )
    for classification in inputs.kms_classifications:

        def validate_classification(path: pathlib.Path = classification) -> None:
            validate_kms_hsm_classification.validate_manifest(path)

        capture_preflight(
            f"KMS/HSM classification {classification}",
            validate_classification,
            errors,
        )
    capture_preflight(
        "enterprise SLO baseline",
        validate_slo_baseline,
        errors,
    )
    for label, path in (
        ("build log", inputs.build_log),
        ("verification log", inputs.verification_log),
        ("security log", inputs.security_log),
        ("SBOM", inputs.sbom),
        ("support response", inputs.support_response),
    ):
        capture_preflight(label, ensure_named_file(path, label), errors)
    return errors


def validate_source_evidence(inputs: Phase1EvidenceInputs) -> None:
    errors = preflight_source_evidence(inputs)
    if errors:
        formatted = "\n  - ".join(errors)
        raise ValidationError(f"Phase 1 source evidence is incomplete:\n  - {formatted}")


def collect_archive(inputs: Phase1EvidenceInputs) -> CollectedArchive:
    validate_source_evidence(inputs)

    out_dir = inputs.out_dir
    manifest_path = out_dir / "manifest.json"
    bundle_path = out_dir / "enterprise-readiness-bundle.json"
    if not inputs.force and (manifest_path.exists() or bundle_path.exists()):
        raise SystemExit(
            f"Refusing to overwrite existing Phase 1 archive outputs under {out_dir}; pass --force",
        )

    build_log = copy_file(inputs.build_log, out_dir / "build/nix-flake-check.log")
    verification_log = copy_file(
        inputs.verification_log, out_dir / "verification/verified-reqs.log"
    )
    security_log = copy_file(inputs.security_log, out_dir / "security/security-suite.log")
    sbom = copy_file(inputs.sbom, out_dir / "sbom/aegaeon-sbom.json")
    support_response = copy_file(inputs.support_response, out_dir / "support/response.md")

    publication_report = copy_file(
        inputs.publication_org_rollout,
        out_dir / "publication/publication-org-rollout-report.json",
    )
    sdk_publication = copy_file(
        inputs.sdk_release_publication_bundle,
        out_dir / "publication/sdk-release-publication-bundle.json",
    )
    managed_provider = copy_file(
        inputs.managed_provider_evidence,
        out_dir / "managed-provider/evidence.json",
    )
    kms_classifications = tuple(
        copy_kms_classification(classification, out_dir / "kms", index)
        for index, classification in enumerate(inputs.kms_classifications)
    )
    slo_baseline = copy_slo_baseline(
        inputs.enterprise_slo_baseline,
        out_dir / "performance/enterprise-slo-baseline.json",
    )

    review = {
        "reviewer": inputs.reviewer,
        "decision": "approved" if inputs.reviewer else "pending",
    }
    evidence = {
        "build": [evidence_item(out_dir, "nix-flake-check", build_log, "log")],
        "verification": [evidence_item(out_dir, "verified-reqs", verification_log, "log")],
        "security": [evidence_item(out_dir, "security-suite", security_log, "log")],
        "sbom": [evidence_item(out_dir, "cyclonedx-sbom", sbom, "json")],
        "conformance": [],
        "kms": [
            evidence_item(
                out_dir,
                f"kms-hsm-classification-{slugify(load_json(classification).get('deployment_id'))}",
                classification,
                "json",
            )
            for classification in kms_classifications
        ],
        "managed_provider": [
            evidence_item(out_dir, "managed-provider-evidence", managed_provider, "json"),
        ],
        "performance": [
            evidence_item(out_dir, "enterprise-slo-baseline", slo_baseline, "json"),
        ],
        "publication": [
            evidence_item(out_dir, "publication-org-rollout", publication_report, "json"),
            evidence_item(out_dir, "sdk-release-publication-bundle", sdk_publication, "json"),
        ],
        "support": [evidence_item(out_dir, "support-response", support_response, "markdown")],
    }
    release_manifest = {
        "$schema": "https://aegaeon.dev/spec/release-security-evidence.schema.json",
        "schema_version": 1,
        "release_id": inputs.release_id,
        "source_revision": inputs.source_revision,
        "flake_lock_revision": inputs.flake_lock_revision,
        "generated_at": inputs.generated_at,
        "claim_context": {
            "enterprise_readiness_claim_active": False,
            "certification_claim_active": False,
            "admin_ui_assurance_claim_active": False,
        },
        "evidence": evidence,
        "review": review,
    }
    write_json(manifest_path, release_manifest)

    enterprise_bundle = {
        "$schema": "https://aegaeon.dev/spec/enterprise-readiness-evidence-bundle.schema.json",
        "schema_version": 1,
        "bundle_id": f"{inputs.release_id}-enterprise-readiness",
        "release_id": inputs.release_id,
        "generated_at": inputs.generated_at,
        "source_revision": inputs.source_revision,
        "claim_target": "enterprise-readiness",
        "claim_gate_path": relative_path(out_dir, inputs.claim_gate),
        "evidence": {
            "publication_org_rollout_report": relative_uri(out_dir, publication_report),
            "managed_provider_evidence": relative_uri(out_dir, managed_provider),
            "kms_hsm_classifications": [
                relative_uri(out_dir, classification) for classification in kms_classifications
            ],
            "release_security_evidence_manifest": relative_uri(out_dir, manifest_path),
            "enterprise_slo_baseline_manifest": relative_uri(out_dir, slo_baseline),
        },
        "review": review,
    }
    write_json(bundle_path, enterprise_bundle)

    validate_release_security_evidence.validate_enterprise_readiness_manifest(manifest_path)
    validate_enterprise_readiness_evidence_bundle.validate_bundle(
        bundle_path,
        require_approved=inputs.reviewer is not None,
    )
    if inputs.phase1_check:
        validate_enterprise_readiness_phase1.validate_phase1(
            bundle_path,
            claim_gate_path=inputs.claim_gate,
        )
    return CollectedArchive(release_manifest=manifest_path, enterprise_bundle=bundle_path)


def parse_args() -> Phase1EvidenceInputs:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--out-dir", type=pathlib.Path)
    parser.add_argument("--source-revision", default=git_head())
    parser.add_argument("--flake-lock-revision", default=flake_lock_hash())
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument(
        "--claim-gate",
        type=pathlib.Path,
        default=pathlib.Path("spec/enterprise-readiness-claim.current.json"),
    )
    parser.add_argument("--publication-org-rollout", type=pathlib.Path, required=True)
    parser.add_argument("--sdk-release-publication-bundle", type=pathlib.Path, required=True)
    parser.add_argument("--managed-provider-evidence", type=pathlib.Path, required=True)
    parser.add_argument(
        "--kms-classification",
        type=pathlib.Path,
        action="append",
        required=True,
    )
    parser.add_argument("--enterprise-slo-baseline", type=pathlib.Path, required=True)
    parser.add_argument("--build-log", type=pathlib.Path, required=True)
    parser.add_argument("--verification-log", type=pathlib.Path, required=True)
    parser.add_argument("--security-log", type=pathlib.Path, required=True)
    parser.add_argument("--sbom", type=pathlib.Path, required=True)
    parser.add_argument("--support-response", type=pathlib.Path, required=True)
    parser.add_argument(
        "--reviewer",
        help="Mark the generated release manifest and enterprise bundle approved by this reviewer",
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--phase1-check",
        action="store_true",
        help="Also run the final Phase 1 closure validator after collecting the archive",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help=(
            "Validate all source evidence inputs and report every blocker "
            "without writing an archive"
        ),
    )
    args = parser.parse_args()

    out_dir = args.out_dir or pathlib.Path("artifacts/releases") / args.release_id
    return Phase1EvidenceInputs(
        release_id=args.release_id,
        out_dir=out_dir,
        source_revision=args.source_revision,
        flake_lock_revision=args.flake_lock_revision,
        generated_at=args.generated_at,
        claim_gate=args.claim_gate,
        publication_org_rollout=args.publication_org_rollout,
        sdk_release_publication_bundle=args.sdk_release_publication_bundle,
        managed_provider_evidence=args.managed_provider_evidence,
        kms_classifications=tuple(args.kms_classification),
        enterprise_slo_baseline=args.enterprise_slo_baseline,
        build_log=args.build_log,
        verification_log=args.verification_log,
        security_log=args.security_log,
        sbom=args.sbom,
        support_response=args.support_response,
        reviewer=args.reviewer,
        force=args.force,
        phase1_check=args.phase1_check,
        preflight_only=args.preflight_only,
    )


def main() -> int:
    inputs = parse_args()
    if inputs.preflight_only:
        errors = preflight_source_evidence(inputs)
        if errors:
            for error in errors:
                print(f"[invalid] {error}", file=sys.stderr)
            return 1
        print("[ok] Phase 1 source evidence preflight passed")
        return 0
    try:
        archive = collect_archive(inputs)
    except (ValidationError, SystemExit) as exc:
        print(f"[invalid] {exc}", file=sys.stderr)
        return 1
    print(f"[ok] release manifest: {archive.release_manifest}")
    print(f"[ok] enterprise bundle: {archive.enterprise_bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
