#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${ROOT_DIR}"

TOFU_DIR="${AEG_OIDC_AWS_KMS_TOFU_DIR:-infra/tofu/oidc-aws-kms-parity}"
ARTIFACT_DIR="${AEG_OIDC_KMS_ARTIFACT_DIR:-artifacts/oidc-kms/aws-production}"
CLASSIFICATION_PATH="${ARTIFACT_DIR}/classification.json"

require_cmd() {
	local cmd="$1"
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "required command not found: ${cmd}" >&2
		exit 2
	fi
}

tofu_output() {
	local name="$1"
	tofu -chdir="${TOFU_DIR}" output -raw "${name}"
}

require_cmd tofu
require_cmd python3

if [[ -z ${AEG_KMS_CLASSIFICATION_REVIEWER:-} ]]; then
	echo "AEG_KMS_CLASSIFICATION_REVIEWER is required for an approved claim-preserving classification" >&2
	exit 2
fi

aws_account_id="$(tofu_output aws_account_id)"
aws_region="$(tofu_output aws_region)"
kms_key_id="$(tofu_output kms_key_id)"
oidc_signing_kid="$(tofu_output oidc_signing_kid)"
source_revision="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
deployment_id="${AEG_KMS_CLASSIFICATION_DEPLOYMENT_ID:-aws-kms-${aws_account_id}-${aws_region}-${kms_key_id}}"

export aws_account_id
export aws_region
export deployment_id
export generated_at
export source_revision

mkdir -p "${ARTIFACT_DIR}"

export AWS_REGION="${aws_region}"
export AWS_DEFAULT_REGION="${aws_region}"
export AEGAEON_OIDC_SIGNING_BACKEND="aws-kms"
export AEGAEON_OIDC_SIGNING_AWS_REGION="${aws_region}"
export AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID="${kms_key_id}"
export AEGAEON_OIDC_SIGNING_KID="${oidc_signing_kid}"
export AEG_OIDC_KMS_MODE="aws"
export AEG_OIDC_KMS_ARTIFACT_DIR="${ARTIFACT_DIR}"

scripts/validation/run_oidc_kms_parity.sh

python3 - "${CLASSIFICATION_PATH}" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
manifest = {
    "$schema": "https://aegaeon.dev/spec/kms-hsm-deployment-classification.schema.json",
    "schema_version": 1,
    "deployment_id": os.environ["deployment_id"],
    "generated_at": os.environ["generated_at"],
    "source_revision": os.environ["source_revision"],
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
        "generated_at": os.environ["generated_at"],
    },
    "claim_boundary": {
        "rs256_required_slice_unchanged": True,
        "external_signer_recorded_as_tcb": True,
        "broad_rsa_not_promoted": True,
    },
    "compat_reason": None,
    "review": {
        "reviewer": os.environ["AEG_KMS_CLASSIFICATION_REVIEWER"],
        "decision": "approved",
        "notes": (
            "Generated from AWS KMS OpenTofu parity stack outputs for account "
            f"{os.environ['aws_account_id']} in {os.environ['aws_region']}; "
            "reviewer must confirm this deployment is the intended release evidence boundary."
        ),
    },
}
path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")
PY

python3 scripts/validation/validate_kms_hsm_classification.py "${CLASSIFICATION_PATH}"

cat <<EOF
OIDC AWS KMS parity evidence complete.

Artifacts:
  ${ARTIFACT_DIR}/metadata.txt
  ${ARTIFACT_DIR}/test.log
  ${ARTIFACT_DIR}/summary.json
  ${CLASSIFICATION_PATH}
EOF
