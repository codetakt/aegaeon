#!/usr/bin/env bash
# Nix-wrapped VerifiedReqs integrity checks.
# Runs: schema validation, future claim-gate validation, evidence-manifest
# validator checks, proof-reference check, claim-index freshness, runtime-link
# drift detection (warning mode).
set -euo pipefail

LOG="${OUT_DIR:+${OUT_DIR}/verify.log}"

{
	echo "=== VerifiedReqs Integrity (nix) ==="
	echo ""

	echo "--- Schema validation ---"
	python3 scripts/validation/validate_compliance_matrix.py --check

	echo ""
	echo "--- Future claim-gate validation ---"
	python3 -m py_compile \
		scripts/validation/validate_claim_gates.py \
		scripts/validation/test_claim_gate_validators.py
	python3 scripts/validation/test_claim_gate_validators.py
	python3 scripts/validation/validate_claim_gates.py --all

	echo ""
	echo "--- Evidence manifest validator checks ---"
	python3 -m py_compile \
		scripts/validation/build_publication_org_rollout_report.py \
		scripts/validation/collect_enterprise_readiness_phase1_evidence.py \
		scripts/validation/validate_admin_ui_assurance.py \
		scripts/validation/validate_certification_evidence_bundle.py \
		scripts/validation/validate_enterprise_readiness_evidence_bundle.py \
		scripts/validation/validate_enterprise_readiness_phase1.py \
		scripts/validation/build_enterprise_slo_baseline_from_hosted_evidence.py \
		scripts/validation/validate_enterprise_slo_baseline.py \
		scripts/validation/validate_kms_hsm_classification.py \
		scripts/validation/validate_managed_provider_evidence.py \
		scripts/validation/validate_phase4_activation_preflight.py \
		scripts/validation/validate_publication_org_rollout.py \
		scripts/validation/validate_release_security_evidence.py \
		scripts/validation/collect_server_client_formal_assurance_phase5_evidence.py \
		scripts/validation/validate_server_client_formal_assurance.py \
		scripts/validation/validate_server_client_pre_public_blockers.py \
		scripts/validation/validate_sdk_release_publication_bundle.py \
		scripts/validation/test_admin_ui_assurance_validators.py \
		scripts/validation/test_certification_evidence_validators.py \
		scripts/validation/test_enterprise_readiness_validators.py \
		scripts/validation/test_phase4_activation_preflight.py \
		scripts/validation/test_server_client_formal_assurance.py
	python3 - <<'PY'
import json
from pathlib import Path

from jsonschema import Draft202012Validator

for schema_path in (
Path("spec/admin-ui-assurance-evidence-bundle.schema.json"),
Path("spec/admin-ui-security-state-machine.schema.json"),
Path("spec/certification-evidence-bundle.schema.json"),
Path("spec/enterprise-readiness-evidence-bundle.schema.json"),
Path("spec/enterprise-slo-baseline.schema.json"),
Path("spec/kms-hsm-deployment-classification.schema.json"),
Path("spec/managed-provider-evidence.schema.json"),
Path("spec/phase4-claim-activation-preflight.schema.json"),
Path("spec/publication-org-rollout.schema.json"),
Path("spec/release-security-evidence.schema.json"),
Path("spec/server-client-formal-assurance-evidence-bundle.schema.json"),
Path("spec/server-client-pre-public-blocker-closure.schema.json"),
Path("spec/sdk-release-publication-bundle.schema.json"),
):
	Draft202012Validator.check_schema(json.loads(schema_path.read_text()))
	print(f"OK: {schema_path}")
PY
	python3 scripts/validation/test_admin_ui_assurance_validators.py
	python3 scripts/validation/validate_admin_ui_assurance.py \
		docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json
	python3 scripts/validation/test_certification_evidence_validators.py
	python3 scripts/validation/test_phase4_activation_preflight.py
	python3 scripts/validation/validate_phase4_activation_preflight.py \
		docs/releases/evidence/phase4-claim-activation-preflight.json
	python3 scripts/validation/test_server_client_formal_assurance.py
	python3 scripts/validation/validate_server_client_pre_public_blockers.py \
		docs/releases/evidence/phase5-pre-public-blockers.json
	python3 scripts/validation/validate_server_client_formal_assurance.py
	python3 scripts/validation/collect_server_client_formal_assurance_phase5_evidence.py --check
	python3 scripts/validation/validate_server_client_formal_assurance.py \
		docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json
	python3 scripts/validation/test_enterprise_readiness_validators.py

	echo ""
	echo "--- Proof-reference check (refinement traces required for MUST-level) ---"
	python3 scripts/validation/verify_verified_reqs.py --strict --require-trace-must

	echo ""
	echo "--- Claim index freshness ---"
	python3 scripts/validation/generate_claim_index.py --check

	echo ""
	echo "--- Runtime-link drift check (warning mode; crypto fail-close) ---"
	DRIFT_WARNINGS=0
	DRIFT_RC=0
	python3 scripts/validation/check_runtime_drift.py --check 2>&1 || DRIFT_RC=$?
	if [ "$DRIFT_RC" -eq 0 ]; then
		echo "  No drift detected."
	elif [ "$DRIFT_RC" -eq 2 ]; then
		echo "  CRITICAL: Crypto trust-boundary file drift detected (fail-close)."
		exit 1
	else
		echo "  WARNING: Runtime-link drift detected (non-blocking)."
		DRIFT_WARNINGS=1
	fi

	echo ""
	echo "--- Direct crypto call detection (fail-close) ---"
	if python3 scripts/validation/check_crypto_calls.py --check 2>&1; then
		echo "  No direct crypto calls in production code."
	else
		echo "  CRITICAL: Direct crypto calls detected outside crates/crypto (fail-close)."
		exit 1
	fi

	echo ""
	echo "--- dudect constant-time evidence (fail-close) ---"
	if python3 scripts/validation/check_dudect.py 2>&1; then
		echo "  dudect constant-time evidence passed."
	else
		echo "  FAIL: dudect constant-time evidence failed (fail-close)."
		exit 1
	fi

	echo ""
	if [ "$DRIFT_WARNINGS" -eq 1 ]; then
		echo "=== VerifiedReqs checks completed (with warnings) ==="
	else
		echo "=== All VerifiedReqs checks passed ==="
	fi
} 2>&1 | tee "${LOG:-/dev/fd/1}"
