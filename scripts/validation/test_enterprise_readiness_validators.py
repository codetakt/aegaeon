#!/usr/bin/env python3
"""Self-test enterprise-readiness evidence validators with local fixtures."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import pathlib
import tempfile
from collections.abc import Callable  # noqa: TC003
from typing import Any

import build_publication_org_rollout_report
import collect_enterprise_readiness_phase1_evidence
import validate_enterprise_readiness_evidence_bundle
import validate_enterprise_readiness_phase1
import validate_enterprise_slo_baseline
import validate_kms_hsm_classification
import validate_managed_provider_evidence
import validate_publication_org_rollout
import validate_release_security_evidence
from jsonschema import ValidationError

SHA256 = "a" * 64
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
FIXTURE_SHA256 = hashlib.sha256(b"fixture\n").hexdigest()
EMPTY_JSON_SHA256 = hashlib.sha256(b"{}\n").hexdigest()
FIXTURE_TIME = dt.datetime(2026, 5, 19, tzinfo=dt.UTC)


def write_json(path: pathlib.Path, value: dict[str, Any]) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def json_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    return hashlib.sha256(payload.encode()).hexdigest()


def touch(path: pathlib.Path, content: str = "fixture\n") -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def expect_invalid(label: str, action: Callable[[], object]) -> None:
    try:
        action()
    except (ValidationError, SystemExit):
        return
    raise AssertionError(f"{label}: expected validation failure")


def publication_report() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/publication-org-rollout.schema.json",
        "schema_version": 1,
        "generated_at": "2026-05-19T00:00:00Z",
        "rollout_target": "released-client-claim",
        "target_repository": {
            "owner": "aegaeon-test",
            "repo": "aegaeon-sdk",
            "branch": "main",
        },
        "tasks": [
            {
                "name": "publication_org_branch_protection",
                "status": "done",
                "detail": "fixture",
            },
            {
                "name": "publication_org_secret_rollout",
                "status": "done",
                "detail": "fixture",
            },
        ],
        "ready": True,
        "blockers": [],
    }


def sdk_release_publication_bundle() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": "2026-05-19T00:00:00Z",
        "release_phase": "released-client-claim",
        "source": {
            "github_ref": "refs/heads/main",
            "github_sha": "b" * 40,
            "github_run_id": "123456",
            "github_workflow": "release-publication.yml",
            "npm_dist_tag": "latest",
        },
        "publish_manifest": {
            "path": "artifacts/npm/publish-manifest.json",
            "sha256": SHA256,
            "tarball_count": 1,
        },
        "release_attestation": {
            "path": "artifacts/release/release-attestation.json",
            "sha256": SHA256,
            "npm_provenance_enabled": True,
            "signed_release_attestation_present": True,
            "sbom_publication_present": True,
            "deferred_requirements": [],
        },
        "release_attestation_signature": {
            "path": "artifacts/release/release-attestation.json",
            "sha256": SHA256,
            "signature_path": "artifacts/release/release-attestation.sig",
            "signature_sha256": SHA256,
            "public_key_path": "artifacts/release/release-attestation.pub",
            "public_key_sha256": SHA256,
            "signature_algorithm": "ed25519",
            "key_type": "ed25519",
            "signer_source": "cosign_key_env",
        },
        "workspace_sbom": {
            "path": "artifacts/sbom/workspace.cdx.json",
            "sha256": SHA256,
            "bom_format": "CycloneDX",
            "spec_version": "1.6",
            "component_count": 1,
            "serial_number": "urn:uuid:00000000-0000-4000-8000-000000000000",
        },
        "verified_core": {
            "manifest_path": "artifacts/verified-core/manifest.json",
            "manifest_sha256": SHA256,
            "handoff_manifest_path": "artifacts/verified-core/handoff.json",
            "handoff_manifest_sha256": SHA256,
        },
        "managed_provider_evidence": {
            "path": "artifacts/managed-provider/evidence.json",
            "sha256": SHA256,
            "lane_name": "hosted-managed-provider",
            "provider_slug": "commercial-fixture",
            "provider_class": "commercial",
            "hosted": True,
            "status": "passed",
        },
        "admin_sdk_evidence": {
            "path": "artifacts/admin-sdk/evidence.json",
            "sha256": SHA256,
            "lane_name": "admin-sdk",
            "stack_mode": "hosted",
            "management_sdk_package": "@aegaeon/admin-sdk",
            "capability_count": 1,
        },
        "client_claim_promotion": {
            "path": "artifacts/client-claim/promotion-report.json",
            "sha256": SHA256,
            "ready": True,
            "failure_count": 0,
            "failures": [],
        },
        "released_client_claim_report": {
            "path": "artifacts/client-claim/released-client-claim-report.json",
            "sha256": SHA256,
            "ready": True,
            "blocker_count": 0,
            "current_claim_active": False,
            "target_statement": "released client claim ready",
        },
        "publication_org_rollout_report": {
            "path": "artifacts/release/publication-org-rollout-report.json",
            "sha256": SHA256,
            "ready": True,
            "blocker_count": 0,
            "target_repository": "aegaeon-test/aegaeon-sdk",
        },
        "deferred_publication_requirements": [],
    }


def managed_provider_evidence() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": "2026-05-19T00:00:00Z",
        "source": {
            "config_path": "providers/commercial.json",
            "config_sha256": SHA256,
            "claim_boundary_path": "spec/client-claim-boundary.current.json",
            "claim_boundary_sha256": SHA256,
            "github_run_id": "123456",
            "github_workflow": "managed-provider-evidence.yml",
            "github_repository": "aegaeon/aegaeon-sdk",
            "github_ref": "refs/heads/main",
            "github_sha": "b" * 40,
            "github_job": "managed-provider-evidence",
        },
        "provider": {
            "name": "commercial-fixture",
            "class": "commercial",
            "issuer": "https://idp.example.test",
            "client_id": "aegaeon-fixture",
            "auth_method": "client_secret_post",
        },
        "lane": {
            "name": "hosted-managed-provider",
            "hosted": True,
            "status": "passed",
            "browser": "chromium",
        },
        "runtime": {
            "default_profile": "verified-core",
            "claim_phase": "released-client-claim",
            "promoted_client_slices": ["discovery", "authorization-code"],
            "compat_only_surfaces": ["es256-interop-surface"],
        },
    }


def kms_classification() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/kms-hsm-deployment-classification.schema.json",
        "schema_version": 1,
        "deployment_id": "production-us-east-1",
        "generated_at": "2026-05-19T00:00:00Z",
        "source_revision": "b" * 40,
        "signer_backend": "aws-kms",
        "classification": "claim-preserving",
        "algorithm": {
            "jose_alg": "RS256",
            "provider_algorithm": "RSASSA_PKCS1_V1_5_SHA_256",
        },
        "signing_input_ownership": {
            "aegaeon_constructs_jws_signing_input": True,
            "provider_returns_finished_jwt": False,
        },
        "public_jwk_derivation": {
            "method": "provider-api",
            "key_match_checked": True,
        },
        "jwks_rotation": {
            "overlap_matches_local_path": True,
            "rollback_matches_local_path": True,
            "kid_reuse_prevented": True,
        },
        "parity_evidence": {
            "status": "pass",
            "uri": "summary.json",
            "generated_at": "2026-05-19T00:00:00Z",
        },
        "claim_boundary": {
            "rs256_required_slice_unchanged": True,
            "external_signer_recorded_as_tcb": True,
            "broad_rsa_not_promoted": True,
        },
        "compat_reason": None,
        "review": {
            "reviewer": "security-reviewer",
            "decision": "approved",
        },
    }


def release_manifest() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/release-security-evidence.schema.json",
        "schema_version": 1,
        "release_id": "v0.0.0-rc.0",
        "source_revision": "b" * 40,
        "flake_lock_revision": "c" * 40,
        "generated_at": "2026-05-19T00:00:00Z",
        "claim_context": {
            "enterprise_readiness_claim_active": False,
            "certification_claim_active": False,
            "admin_ui_assurance_claim_active": False,
        },
        "evidence": {
            "build": [
                {
                    "id": "nix-flake-check",
                    "uri": "build/nix-flake-check.log",
                    "kind": "log",
                    "required": True,
                    "sha256": FIXTURE_SHA256,
                }
            ],
            "verification": [
                {
                    "id": "verified-reqs",
                    "uri": "verification/verified-reqs.log",
                    "kind": "log",
                    "required": True,
                    "sha256": FIXTURE_SHA256,
                }
            ],
            "security": [
                {
                    "id": "security-suite",
                    "uri": "security/security-suite.log",
                    "kind": "log",
                    "required": True,
                    "sha256": FIXTURE_SHA256,
                }
            ],
            "sbom": [
                {
                    "id": "cyclonedx-sbom",
                    "uri": "sbom/aegaeon-sbom.json",
                    "kind": "json",
                    "required": True,
                    "sha256": EMPTY_JSON_SHA256,
                }
            ],
            "conformance": [],
            "kms": [
                {
                    "id": "kms-classification",
                    "uri": "kms/production-us-east-1-classification.json",
                    "kind": "json",
                    "required": True,
                    "sha256": json_sha256(kms_classification()),
                }
            ],
            "managed_provider": [
                {
                    "id": "managed-provider-evidence",
                    "uri": "managed-provider/evidence.json",
                    "kind": "json",
                    "required": True,
                    "sha256": json_sha256(managed_provider_evidence()),
                }
            ],
            "performance": [
                {
                    "id": "enterprise-slo-baseline",
                    "uri": "performance/enterprise-slo-baseline.json",
                    "kind": "json",
                    "required": True,
                    "sha256": json_sha256(slo_baseline()),
                }
            ],
            "publication": [
                {
                    "id": "publication-org-rollout",
                    "uri": "publication/publication-org-rollout-report.json",
                    "kind": "json",
                    "required": True,
                    "sha256": json_sha256(publication_report()),
                },
                {
                    "id": "sdk-release-publication-bundle",
                    "uri": "publication/sdk-release-publication-bundle.json",
                    "kind": "json",
                    "required": True,
                    "sha256": json_sha256(sdk_release_publication_bundle()),
                },
            ],
            "support": [
                {
                    "id": "support-response",
                    "uri": "support/response.md",
                    "kind": "markdown",
                    "required": True,
                    "sha256": FIXTURE_SHA256,
                }
            ],
        },
        "review": {
            "reviewer": None,
            "decision": "pending",
        },
    }


def slo_baseline() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/enterprise-slo-baseline.schema.json",
        "schema_version": 1,
        "baseline_id": "v0.0.0-rc.0-enterprise",
        "source_revision": "b" * 40,
        "generated_at": "2026-05-19T00:00:00Z",
        "deployment": {
            "shape": "fixture",
            "target_url": "https://issuer.example.test",
            "database_backend": "postgres",
            "signer_backend": "aws-kms",
            "feature_flags": ["policy.oidcEnabled=true"],
        },
        "scenarios": [
            {
                "name": scenario,
                "status": "pass",
                "required": True,
                "report_uri": "reports/load.json",
                "workers": 1,
                "target_rps": 1.0,
                "duration_seconds": 1,
                "error_rate": 0.0,
                "p99_latency_ms": 1.0,
            }
            for scenario in SCENARIOS
        ],
        "observability": {
            "metrics_uri": "observability/prometheus.json",
            "dashboard_uri": None,
            "alerts_uri": None,
        },
        "review": {
            "reviewer": None,
            "decision": "pending",
        },
    }


def bundle(path: pathlib.Path) -> dict[str, Any]:
    repo_root = pathlib.Path.cwd()
    return {
        "$schema": "https://aegaeon.dev/spec/enterprise-readiness-evidence-bundle.schema.json",
        "schema_version": 1,
        "bundle_id": "v0.0.0-rc.0-enterprise-readiness",
        "release_id": "v0.0.0-rc.0",
        "generated_at": "2026-05-19T00:00:00Z",
        "source_revision": "b" * 40,
        "claim_target": "enterprise-readiness",
        "claim_gate_path": str(repo_root / "spec/enterprise-readiness-claim.current.json"),
        "evidence": {
            "publication_org_rollout_report": str(
                path / "release/publication/publication-org-rollout-report.json"
            ),
            "managed_provider_evidence": str(path / "release/managed-provider/evidence.json"),
            "kms_hsm_classifications": [
                str(path / "release/kms/production-us-east-1-classification.json")
            ],
            "release_security_evidence_manifest": str(path / "release/manifest.json"),
            "enterprise_slo_baseline_manifest": str(
                path / "release/performance/enterprise-slo-baseline.json"
            ),
        },
        "review": {
            "reviewer": None,
            "decision": "pending",
        },
    }


def complete_claim_gate() -> dict[str, Any]:
    return {
        "$schema": "https://aegaeon.dev/spec/enterprise-readiness-claim.schema.json",
        "schema_version": 1,
        "claim_target": "enterprise-readiness",
        "claim_active": False,
        "current_public_wording": "fixture inactive enterprise claim",
        "future_allowed_wording": "fixture active enterprise claim",
        "required_evidence": [
            {
                "id": item_id,
                "description": f"Fixture complete evidence for {item_id}.",
                "status": "complete",
                "required_for_activation": True,
                "evidence_uri": evidence_uri,
                "owner": "fixture",
            }
            for item_id, evidence_uri in (
                ("publication-org-rollout", "docs/releases/evidence/publication-org-rollout.md"),
                (
                    "managed-provider-evidence",
                    "docs/releases/evidence/managed-provider-evidence.md",
                ),
                ("kms-hsm-classification", "docs/operations/kms-hsm-deployment-classification.md"),
                (
                    "regulated-runbooks",
                    "docs/operations/management-platform-regulated-environment.md",
                ),
                (
                    "hardened-reference-deployment",
                    "docs/operations/hardened-reference-deployment.md",
                ),
                (
                    "release-security-evidence",
                    "docs/releases/evidence/release-security-evidence.md",
                ),
                ("enterprise-slo-baselines", "docs/performance/enterprise-slo-baselines.md"),
            )
        ],
    }


def prepare_fixture(root: pathlib.Path) -> pathlib.Path:
    release = root / "release"
    touch(release / "build/nix-flake-check.log")
    touch(release / "verification/verified-reqs.log")
    touch(release / "security/security-suite.log")
    touch(release / "sbom/aegaeon-sbom.json", "{}\n")
    touch(release / "support/response.md")
    touch(release / "kms/summary.json", "{}\n")
    write_json(release / "publication/publication-org-rollout-report.json", publication_report())
    write_json(
        release / "publication/sdk-release-publication-bundle.json",
        sdk_release_publication_bundle(),
    )
    write_json(release / "kms/production-us-east-1-classification.json", kms_classification())
    write_json(release / "manifest.json", release_manifest())

    write_json(release / "managed-provider/evidence.json", managed_provider_evidence())

    touch(release / "performance/reports/load.json", "{}\n")
    touch(release / "performance/observability/prometheus.json", "{}\n")
    write_json(release / "performance/enterprise-slo-baseline.json", slo_baseline())

    return write_json(root / "enterprise-bundle.json", bundle(root))


def set_review(
    value: dict[str, Any],
    reviewer: str = "enterprise-reviewer",
    decision: str = "approved",
) -> dict[str, Any]:
    reviewed = copy.deepcopy(value)
    reviewed["review"] = {
        "reviewer": reviewer,
        "decision": decision,
    }
    return reviewed


def approve_bundle_fixture(root: pathlib.Path) -> pathlib.Path:
    write_json(root / "release/manifest.json", set_review(release_manifest()))
    write_json(
        root / "release/performance/enterprise-slo-baseline.json",
        set_review(slo_baseline()),
    )
    reviewed_release = release_manifest()
    reviewed_release["evidence"]["performance"][0]["sha256"] = json_sha256(
        set_review(slo_baseline())
    )
    write_json(root / "release/manifest.json", set_review(reviewed_release))
    reviewed_bundle = set_review(bundle(root))
    return write_json(root / "enterprise-bundle-approved.json", reviewed_bundle)


def approve_phase1_fixture(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    claim_gate_path = write_json(
        root / "complete-enterprise-claim.json",
        complete_claim_gate(),
    )
    approved_bundle = set_review(bundle(root))
    approved_bundle["claim_gate_path"] = str(claim_gate_path)
    bundle_path = write_json(root / "enterprise-phase1-approved.json", approved_bundle)
    return claim_gate_path, bundle_path


def main() -> int:
    with tempfile.TemporaryDirectory() as raw_tmp:
        root = pathlib.Path(raw_tmp)
        bundle_path = prepare_fixture(root)

        validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path)
        expect_invalid(
            "pending bundle in activation-review mode",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(
                bundle_path,
                require_approved=True,
            ),
        )
        validate_release_security_evidence.validate_enterprise_readiness_manifest(
            root / "release/manifest.json",
        )
        validate_kms_hsm_classification.validate_manifest(
            root / "release/kms/production-us-east-1-classification.json",
        )
        validate_enterprise_slo_baseline.validate_manifest(
            root / "release/performance/enterprise-slo-baseline.json",
        )
        validate_managed_provider_evidence.validate_enterprise_readiness(
            managed_provider_evidence(),
            now=FIXTURE_TIME,
        )
        stale_managed_provider = managed_provider_evidence()
        stale_managed_provider["generated_at"] = "2026-05-11T23:59:59Z"
        expect_invalid(
            "stale managed-provider evidence",
            lambda: validate_managed_provider_evidence.validate_enterprise_readiness(
                stale_managed_provider,
                now=FIXTURE_TIME,
            ),
        )
        validate_publication_org_rollout.validate_report(
            root / "release/publication/publication-org-rollout-report.json",
            require_ready=True,
        )
        generated_publication_report_path = root / "generated-publication-report.json"
        generated_publication_report = build_publication_org_rollout_report.build_report(
            type(
                "Args",
                (),
                {
                    "owner": "aegaeon-test",
                    "repo": "aegaeon-sdk",
                    "branch": "main",
                    "task": [
                        (
                            "publication_org_branch_protection",
                            "done",
                            "ruleset=123 required_checks=release reviewer=security",
                        ),
                        (
                            "publication_org_secret_rollout",
                            "done",
                            "environment=production rotated_at=2026-05-19 reviewer=security",
                        ),
                    ],
                    "generated_at": "2026-05-19T00:00:00Z",
                },
            )(),
        )
        write_json(generated_publication_report_path, generated_publication_report)
        validate_publication_org_rollout.validate_report(
            generated_publication_report_path,
            require_ready=True,
        )

        collector_claim_gate = write_json(
            root / "collector-enterprise-claim.json", complete_claim_gate()
        )
        collected = collect_enterprise_readiness_phase1_evidence.collect_archive(
            collect_enterprise_readiness_phase1_evidence.Phase1EvidenceInputs(
                release_id="v0.0.0-rc.0",
                out_dir=root / "collected-release",
                source_revision="b" * 40,
                flake_lock_revision="c" * 40,
                generated_at="2026-05-19T00:00:00Z",
                claim_gate=collector_claim_gate,
                publication_org_rollout=(
                    root / "release/publication/publication-org-rollout-report.json"
                ),
                sdk_release_publication_bundle=(
                    root / "release/publication/sdk-release-publication-bundle.json"
                ),
                managed_provider_evidence=root / "release/managed-provider/evidence.json",
                kms_classifications=(
                    root / "release/kms/production-us-east-1-classification.json",
                ),
                enterprise_slo_baseline=(root / "release/performance/enterprise-slo-baseline.json"),
                build_log=root / "release/build/nix-flake-check.log",
                verification_log=root / "release/verification/verified-reqs.log",
                security_log=root / "release/security/security-suite.log",
                sbom=root / "release/sbom/aegaeon-sbom.json",
                support_response=root / "release/support/response.md",
                reviewer=None,
                force=False,
                phase1_check=False,
                preflight_only=False,
            ),
        )
        validate_release_security_evidence.validate_enterprise_readiness_manifest(
            collected.release_manifest,
        )
        validate_enterprise_readiness_evidence_bundle.validate_bundle(
            collected.enterprise_bundle,
        )

        missing_sdk_publication_release = release_manifest()
        missing_sdk_publication_release["evidence"]["publication"] = [
            missing_sdk_publication_release["evidence"]["publication"][0]
        ]
        missing_sdk_publication_path = write_json(
            root / "release/missing-sdk-publication.json",
            missing_sdk_publication_release,
        )
        expect_invalid(
            "enterprise release manifest missing SDK publication bundle",
            lambda: validate_release_security_evidence.validate_enterprise_readiness_manifest(
                missing_sdk_publication_path,
            ),
        )

        pre_release_sdk_publication = sdk_release_publication_bundle()
        pre_release_sdk_publication["release_phase"] = "pre-release-client-baseline"
        write_json(
            root / "release/publication/sdk-release-publication-bundle.json",
            pre_release_sdk_publication,
        )
        pre_release_manifest = release_manifest()
        pre_release_manifest["evidence"]["publication"][1]["sha256"] = json_sha256(
            pre_release_sdk_publication,
        )
        write_json(root / "release/manifest.json", pre_release_manifest)
        expect_invalid(
            "enterprise release manifest with pre-release SDK publication bundle",
            lambda: validate_release_security_evidence.validate_enterprise_readiness_manifest(
                root / "release/manifest.json",
            ),
        )
        write_json(
            root / "release/publication/sdk-release-publication-bundle.json",
            sdk_release_publication_bundle(),
        )
        write_json(root / "release/manifest.json", release_manifest())

        weak_source_sdk_publication = sdk_release_publication_bundle()
        weak_source_sdk_publication["source"]["github_ref"] = "main"
        write_json(
            root / "release/publication/sdk-release-publication-bundle.json",
            weak_source_sdk_publication,
        )
        weak_source_manifest = release_manifest()
        weak_source_manifest["evidence"]["publication"][1]["sha256"] = json_sha256(
            weak_source_sdk_publication,
        )
        write_json(root / "release/manifest.json", weak_source_manifest)
        expect_invalid(
            "enterprise release manifest with weak SDK publication source metadata",
            lambda: validate_release_security_evidence.validate_enterprise_readiness_manifest(
                root / "release/manifest.json",
            ),
        )
        write_json(
            root / "release/publication/sdk-release-publication-bundle.json",
            sdk_release_publication_bundle(),
        )
        write_json(root / "release/manifest.json", release_manifest())

        deferred_sdk_publication = sdk_release_publication_bundle()
        deferred_sdk_publication["deferred_publication_requirements"] = [
            "publish signed released-client report",
        ]
        write_json(
            root / "release/publication/sdk-release-publication-bundle.json",
            deferred_sdk_publication,
        )
        deferred_manifest = release_manifest()
        deferred_manifest["evidence"]["publication"][1]["sha256"] = json_sha256(
            deferred_sdk_publication,
        )
        write_json(root / "release/manifest.json", deferred_manifest)
        expect_invalid(
            "enterprise release manifest with deferred SDK publication requirements",
            lambda: validate_release_security_evidence.validate_enterprise_readiness_manifest(
                root / "release/manifest.json",
            ),
        )
        write_json(
            root / "release/publication/sdk-release-publication-bundle.json",
            sdk_release_publication_bundle(),
        )
        write_json(root / "release/manifest.json", release_manifest())

        approved_bundle_path = approve_bundle_fixture(root)
        validate_enterprise_readiness_evidence_bundle.validate_bundle(
            approved_bundle_path,
            require_approved=True,
        )
        phase1_claim_gate_path, phase1_bundle_path = approve_phase1_fixture(root)
        validate_enterprise_readiness_phase1.validate_phase1(
            phase1_bundle_path,
            claim_gate_path=phase1_claim_gate_path,
        )
        expect_invalid(
            "Phase 1 closure with incomplete source-managed claim gate",
            lambda: validate_enterprise_readiness_phase1.validate_phase1(
                approved_bundle_path,
                claim_gate_path=pathlib.Path("spec/enterprise-readiness-claim.current.json"),
            ),
        )
        mismatched_claim_bundle = copy.deepcopy(set_review(bundle(root)))
        mismatched_claim_bundle["claim_gate_path"] = str(phase1_claim_gate_path)
        mismatched_claim_bundle_path = write_json(
            root / "enterprise-phase1-mismatched-claim.json",
            mismatched_claim_bundle,
        )
        other_complete_claim_gate_path = write_json(
            root / "other-complete-enterprise-claim.json",
            complete_claim_gate(),
        )
        expect_invalid(
            "Phase 1 closure with bundle pointing at a different claim gate",
            lambda: validate_enterprise_readiness_phase1.validate_phase1(
                mismatched_claim_bundle_path,
                claim_gate_path=other_complete_claim_gate_path,
            ),
        )
        prepare_fixture(root)

        non_enterprise_release = copy.deepcopy(release_manifest())
        non_enterprise_release["evidence"]["kms"] = []
        non_enterprise_release["evidence"]["managed_provider"] = []
        non_enterprise_release["evidence"]["performance"] = []
        non_enterprise_release["evidence"]["publication"] = []
        non_enterprise_path = write_json(
            root / "release/non-enterprise.json", non_enterprise_release
        )
        validate_release_security_evidence.validate_manifest(non_enterprise_path)
        expect_invalid(
            "enterprise release manifest without KMS/managed-provider/publication",
            lambda: validate_release_security_evidence.validate_enterprise_readiness_manifest(
                non_enterprise_path,
            ),
        )

        external_release = release_manifest()
        external_release["evidence"]["build"][0]["uri"] = (
            "https://evidence.example.test/v0.0.0-rc.0/nix-flake-check.log"
        )
        external_release["evidence"]["build"][0]["kind"] = "external"
        external_release_path = write_json(root / "release/external.json", external_release)
        validate_release_security_evidence.validate_manifest(external_release_path)

        insecure_external_release_manifest = release_manifest()
        insecure_external_release_manifest["evidence"]["build"][0]["uri"] = (
            "http://evidence.example.test/v0.0.0-rc.0/nix-flake-check.log"
        )
        insecure_external_release_manifest["evidence"]["build"][0]["kind"] = "external"
        insecure_external_release_path = write_json(
            root / "release/insecure-external.json",
            insecure_external_release_manifest,
        )
        expect_invalid(
            "release manifest with insecure external evidence URI",
            lambda: validate_release_security_evidence.validate_manifest(
                insecure_external_release_path,
            ),
        )

        missing_hash_release = release_manifest()
        del missing_hash_release["evidence"]["build"][0]["sha256"]
        write_json(root / "release/manifest.json", missing_hash_release)
        expect_invalid(
            "bundle with release manifest missing required evidence hash",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        duplicate_id_release = release_manifest()
        duplicate_id_release["evidence"]["build"].append(
            copy.deepcopy(duplicate_id_release["evidence"]["build"][0])
        )
        write_json(root / "release/manifest.json", duplicate_id_release)
        expect_invalid(
            "bundle with duplicate release manifest evidence item id",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        mismatched_hash_release = release_manifest()
        mismatched_hash_release["evidence"]["build"][0]["sha256"] = "0" * 64
        write_json(root / "release/manifest.json", mismatched_hash_release)
        expect_invalid(
            "bundle with release manifest required evidence hash mismatch",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        publication_missing_detail = publication_report()
        publication_missing_detail["tasks"][0]["detail"] = None
        write_json(
            root / "release/publication/publication-org-rollout-report.json",
            publication_missing_detail,
        )
        expect_invalid(
            "publication rollout ready report with missing done task detail",
            lambda: validate_publication_org_rollout.validate_report(
                root / "release/publication/publication-org-rollout-report.json",
                require_ready=True,
            ),
        )
        write_json(
            root / "release/publication/publication-org-rollout-report.json",
            publication_report(),
        )

        insecure_kms_parity = kms_classification()
        insecure_kms_parity["parity_evidence"]["uri"] = (
            "http://evidence.example.test/v0.0.0-rc.0/kms-summary.json"
        )
        write_json(
            root / "release/kms/production-us-east-1-classification.json",
            insecure_kms_parity,
        )
        expect_invalid(
            "KMS classification with insecure parity evidence URI",
            lambda: validate_kms_hsm_classification.validate_manifest(
                root / "release/kms/production-us-east-1-classification.json",
            ),
        )
        write_json(
            root / "release/kms/production-us-east-1-classification.json",
            kms_classification(),
        )

        escaping_kms_parity = kms_classification()
        escaping_kms_parity["parity_evidence"]["uri"] = "../summary.json"
        touch(root / "release/summary.json", "{}\n")
        write_json(
            root / "release/kms/production-us-east-1-classification.json",
            escaping_kms_parity,
        )
        expect_invalid(
            "KMS classification with escaping local parity evidence URI",
            lambda: validate_kms_hsm_classification.validate_manifest(
                root / "release/kms/production-us-east-1-classification.json",
            ),
        )
        write_json(
            root / "release/kms/production-us-east-1-classification.json",
            kms_classification(),
        )

        approved_compat_without_reviewer = kms_classification()
        approved_compat_without_reviewer["classification"] = "compat-only"
        approved_compat_without_reviewer["compat_reason"] = "fixture compat-only posture"
        approved_compat_without_reviewer["review"]["reviewer"] = None
        write_json(
            root / "release/kms/production-us-east-1-classification.json",
            approved_compat_without_reviewer,
        )
        expect_invalid(
            "approved KMS classification without reviewer",
            lambda: validate_kms_hsm_classification.validate_manifest(
                root / "release/kms/production-us-east-1-classification.json",
            ),
        )
        write_json(
            root / "release/kms/production-us-east-1-classification.json", kms_classification()
        )

        insecure_slo_observability = slo_baseline()
        insecure_slo_observability["observability"]["metrics_uri"] = (
            "http://evidence.example.test/v0.0.0-rc.0/prometheus.json"
        )
        write_json(
            root / "release/performance/enterprise-slo-baseline.json", insecure_slo_observability
        )
        expect_invalid(
            "SLO baseline with insecure observability URI",
            lambda: validate_enterprise_slo_baseline.validate_manifest(
                root / "release/performance/enterprise-slo-baseline.json",
            ),
        )
        write_json(root / "release/performance/enterprise-slo-baseline.json", slo_baseline())

        insecure_slo_target = slo_baseline()
        insecure_slo_target["deployment"]["target_url"] = "http://issuer.example.test"
        write_json(root / "release/performance/enterprise-slo-baseline.json", insecure_slo_target)
        expect_invalid(
            "SLO baseline with insecure deployment target URL",
            lambda: validate_enterprise_slo_baseline.validate_manifest(
                root / "release/performance/enterprise-slo-baseline.json",
            ),
        )
        write_json(root / "release/performance/enterprise-slo-baseline.json", slo_baseline())

        escaping_slo_report = slo_baseline()
        escaping_slo_report["scenarios"][0]["report_uri"] = "../load.json"
        touch(root / "release/load.json", "{}\n")
        write_json(root / "release/performance/enterprise-slo-baseline.json", escaping_slo_report)
        expect_invalid(
            "SLO baseline with escaping local report URI",
            lambda: validate_enterprise_slo_baseline.validate_manifest(
                root / "release/performance/enterprise-slo-baseline.json",
            ),
        )
        write_json(root / "release/performance/enterprise-slo-baseline.json", slo_baseline())

        insecure_managed_provider = managed_provider_evidence()
        insecure_managed_provider["provider"]["issuer"] = "http://idp.example.test"
        write_json(root / "release/managed-provider/evidence.json", insecure_managed_provider)
        expect_invalid(
            "managed-provider evidence with insecure issuer",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/managed-provider/evidence.json", managed_provider_evidence())

        compat_managed_provider = managed_provider_evidence()
        compat_managed_provider["runtime"]["default_profile"] = "compat-interop"
        write_json(root / "release/managed-provider/evidence.json", compat_managed_provider)
        expect_invalid(
            "managed-provider evidence with compat-interop default profile",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/managed-provider/evidence.json", managed_provider_evidence())

        weak_github_source = managed_provider_evidence()
        weak_github_source["source"]["github_sha"] = "not-a-commit"
        write_json(root / "release/managed-provider/evidence.json", weak_github_source)
        expect_invalid(
            "managed-provider evidence with weak GitHub source metadata",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/managed-provider/evidence.json", managed_provider_evidence())

        escaping_path_release = release_manifest()
        escaping_path_release["evidence"]["build"][0]["uri"] = "../outside.log"
        touch(root / "outside.log")
        escaping_path_release["evidence"]["build"][0]["sha256"] = FIXTURE_SHA256
        write_json(root / "release/manifest.json", escaping_path_release)
        expect_invalid(
            "bundle with release manifest escaping archive root",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        absolute_path_release = release_manifest()
        absolute_path_release["evidence"]["build"][0]["uri"] = str(
            (root / "release/build/nix-flake-check.log").resolve()
        )
        write_json(root / "release/manifest.json", absolute_path_release)
        expect_invalid(
            "bundle with release manifest absolute local evidence path",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        external_build_release = release_manifest()
        external_build_release["evidence"]["build"][0]["uri"] = (
            "https://evidence.example.test/v0.0.0-rc.0/nix-flake-check.log"
        )
        external_build_release["evidence"]["build"][0]["kind"] = "external"
        write_json(root / "release/manifest.json", external_build_release)
        validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path)
        write_json(root / "release/manifest.json", release_manifest())

        insecure_external_release = release_manifest()
        insecure_external_release["evidence"]["build"][0]["uri"] = (
            "http://evidence.example.test/v0.0.0-rc.0/nix-flake-check.log"
        )
        insecure_external_release["evidence"]["build"][0]["kind"] = "external"
        write_json(root / "release/manifest.json", insecure_external_release)
        expect_invalid(
            "bundle with insecure external evidence URI",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        external_kind_mismatch = release_manifest()
        external_kind_mismatch["evidence"]["build"][0]["uri"] = (
            "https://evidence.example.test/v0.0.0-rc.0/nix-flake-check.log"
        )
        write_json(root / "release/manifest.json", external_kind_mismatch)
        expect_invalid(
            "bundle with external evidence URI not marked external",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        missing_managed_provider = release_manifest()
        missing_managed_provider["evidence"]["managed_provider"] = []
        write_json(root / "release/manifest.json", missing_managed_provider)
        expect_invalid(
            "bundle with release manifest missing managed-provider evidence",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        mismatched_managed_provider = release_manifest()
        mismatched_managed_provider["evidence"]["managed_provider"][0]["uri"] = (
            "managed-provider/different-evidence.json"
        )
        touch(root / "release/managed-provider/different-evidence.json", "{}\n")
        write_json(root / "release/manifest.json", mismatched_managed_provider)
        expect_invalid(
            "bundle with release manifest pointing at different managed-provider evidence",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        duplicate_kms_bundle = copy.deepcopy(bundle(root))
        duplicate_kms_bundle["evidence"]["kms_hsm_classifications"].append(
            "release/kms/production-us-east-1-classification.json"
        )
        duplicate_kms_bundle_path = write_json(
            root / "duplicate-kms-bundle.json", duplicate_kms_bundle
        )
        expect_invalid(
            "bundle with duplicate resolved KMS classification path",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(
                duplicate_kms_bundle_path,
            ),
        )

        missing_performance = release_manifest()
        missing_performance["evidence"]["performance"] = []
        write_json(root / "release/manifest.json", missing_performance)
        expect_invalid(
            "bundle with release manifest missing performance evidence",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        mismatched_performance = release_manifest()
        mismatched_performance["evidence"]["performance"][0]["uri"] = (
            "performance/different-slo-baseline.json"
        )
        write_json(root / "release/performance/different-slo-baseline.json", slo_baseline())
        mismatched_performance["evidence"]["performance"][0]["sha256"] = json_sha256(slo_baseline())
        write_json(root / "release/manifest.json", mismatched_performance)
        expect_invalid(
            "bundle with release manifest pointing at different performance evidence",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        mismatched_release = release_manifest()
        mismatched_release["evidence"]["publication"][0]["uri"] = (
            "publication/different-rollout-report.json"
        )
        touch(root / "release/publication/different-rollout-report.json", "{}\n")
        write_json(root / "release/manifest.json", mismatched_release)
        expect_invalid(
            "bundle with release manifest pointing at different publication evidence",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        release_id_mismatch = release_manifest()
        release_id_mismatch["release_id"] = "v0.0.0-rc.1"
        write_json(root / "release/manifest.json", release_id_mismatch)
        expect_invalid(
            "bundle with release_id mismatch",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        revision_mismatch_release = release_manifest()
        revision_mismatch_release["source_revision"] = "d" * 40
        write_json(root / "release/manifest.json", revision_mismatch_release)
        expect_invalid(
            "bundle with release source_revision mismatch",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        revision_mismatch_kms = kms_classification()
        revision_mismatch_kms["source_revision"] = "d" * 40
        write_json(
            root / "release/kms/production-us-east-1-classification.json",
            revision_mismatch_kms,
        )
        expect_invalid(
            "bundle with KMS source_revision mismatch",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(
            root / "release/kms/production-us-east-1-classification.json",
            kms_classification(),
        )

        revision_mismatch_slo = slo_baseline()
        revision_mismatch_slo["source_revision"] = "d" * 40
        write_json(
            root / "release/performance/enterprise-slo-baseline.json",
            revision_mismatch_slo,
        )
        expect_invalid(
            "bundle with SLO source_revision mismatch",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/performance/enterprise-slo-baseline.json", slo_baseline())

        future_release = release_manifest()
        future_release["generated_at"] = "2026-05-19T00:00:01Z"
        write_json(root / "release/manifest.json", future_release)
        expect_invalid(
            "bundle with evidence generated after bundle",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(bundle_path),
        )
        write_json(root / "release/manifest.json", release_manifest())

        active_claim = {
            "claim_target": "enterprise-readiness",
            "claim_active": True,
        }
        active_claim_path = write_json(root / "active-claim.json", active_claim)
        active_bundle = copy.deepcopy(bundle(root))
        active_bundle["claim_gate_path"] = str(active_claim_path)
        active_bundle_path = write_json(root / "active-bundle.json", active_bundle)
        expect_invalid(
            "bundle with active claim gate",
            lambda: validate_enterprise_readiness_evidence_bundle.validate_bundle(
                active_bundle_path
            ),
        )

    print("[ok] enterprise-readiness validator self-tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
