#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="${AEG_OIDC_KMS_ARTIFACT_DIR:-artifacts/oidc-kms}"
MODE="${AEG_OIDC_KMS_MODE:-localstack}"
DEFAULT_LOCALSTACK_HEALTH_URL="http://127.0.0.1:4566/_localstack/health"
DEFAULT_LOCALSTACK_FALLBACK_HEALTH_URL="http://127.0.0.1:4566/health"
LOCALSTACK_HEALTH_URL="${AEG_OIDC_KMS_LOCALSTACK_HEALTH_URL:-${DEFAULT_LOCALSTACK_HEALTH_URL}}"
if [[ -n ${AEG_OIDC_KMS_LOCALSTACK_FALLBACK_HEALTH_URL:-} ]]; then
	LOCALSTACK_FALLBACK_HEALTH_URL="${AEG_OIDC_KMS_LOCALSTACK_FALLBACK_HEALTH_URL}"
else
	LOCALSTACK_FALLBACK_HEALTH_URL="${DEFAULT_LOCALSTACK_FALLBACK_HEALTH_URL}"
fi
LOCALSTACK_WAIT_SECONDS="${AEG_OIDC_KMS_LOCALSTACK_WAIT_SECONDS:-60}"
REQUIRE_LOCALSTACK="${AEG_KMS_REQUIRE_LOCALSTACK:-1}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEST_NAME="oidc::config::tests::kms_parity::test_oidc_aws_kms_runtime_key_material_issues_verifiable_rs256_jwt"
TEST_COMMAND_STRING="cargo test -p aegaeon-server --features kms-aws"
TEST_COMMAND_STRING="${TEST_COMMAND_STRING} --lib ${TEST_NAME} -- --exact --nocapture --color never"
TEST_COMMAND=(
	cargo test -p aegaeon-server --features kms-aws --lib "${TEST_NAME}"
	-- --exact --nocapture --color never
)
EXECUTION_BACKEND="cargo"
BUILD_RECEIPT_JSON=null
TEST_WORKING_DIRECTORY="${PWD}"

mkdir -p "${ARTIFACT_DIR}"

status="failed"

git_value() {
	local value

	if value=$(git "$@" 2>/dev/null); then
		printf '%s' "${value}"
	else
		printf 'unknown'
	fi
}

write_summary() {
	local localstack_health_json=null
	local require_localstack_json=false

	if [[ ${MODE} == "localstack" ]]; then
		localstack_health_json='"localstack-health.json"'
	fi
	if [[ ${REQUIRE_LOCALSTACK} == "1" ]]; then
		require_localstack_json=true
	fi

	cat >"${ARTIFACT_DIR}/summary.json" <<EOF
{
	"artifacts": {
		"build": ${BUILD_RECEIPT_JSON},
		"execution": "execution.json",
		"localstack_health": ${localstack_health_json},
		"log": "test.log",
		"metadata": "metadata.txt"
	},
	"aws_endpoint_url": "${AWS_ENDPOINT_URL:-}",
	"aws_region": "${AWS_REGION:-}",
	"aws_kms_key_id": "${AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID:-}",
	"execution_backend": "${EXECUTION_BACKEND}",
	"git_branch": "$(git_value branch --show-current)",
	"git_commit": "$(git_value rev-parse HEAD)",
	"localstack_fallback_health_url": "${LOCALSTACK_FALLBACK_HEALTH_URL}",
	"localstack_health_url": "${LOCALSTACK_HEALTH_URL}",
	"mode": "${MODE}",
	"oidc_signing_kid": "${AEGAEON_OIDC_SIGNING_KID:-}",
	"require_localstack": ${require_localstack_json},
	"scope": "oidc-aws-kms-rs256-parity",
	"signing_backend": "aws-kms",
	"status": "${status}",
	"test_command": "${TEST_COMMAND_STRING}",
	"timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

trap write_summary EXIT

# Never let an earlier run supply execution evidence for this attempt.
rm -f "${ARTIFACT_DIR}/test.log" "${ARTIFACT_DIR}/execution.json" "${ARTIFACT_DIR}/build.json"

if (($# > 1)) || { (($# == 1)) && [[ $1 != "--nix" ]]; }; then
	echo "usage: run_oidc_kms_parity.sh [--nix]" >&2
	exit 2
fi

if [[ ${MODE} != "aws" && ${MODE} != "localstack" ]]; then
	echo "AEG_OIDC_KMS_MODE must be localstack or aws (got ${MODE})" >&2
	exit 2
fi

if [[ ${MODE} == "localstack" ]]; then
	export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
	export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
	export AWS_REGION="${AWS_REGION:-us-east-1}"
	export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://127.0.0.1:4566}"
	export AEG_KMS_REQUIRE_LOCALSTACK="${REQUIRE_LOCALSTACK}"
else
	REQUIRE_LOCALSTACK="0"
	export AEG_KMS_REQUIRE_LOCALSTACK="0"
	export AWS_REGION="${AWS_REGION:-${AEGAEON_OIDC_SIGNING_AWS_REGION:-}}"
	if [[ -z ${AWS_REGION} ]]; then
		echo "AWS mode requires AWS_REGION or AEGAEON_OIDC_SIGNING_AWS_REGION" >&2
		exit 2
	fi
	export AEGAEON_OIDC_SIGNING_AWS_REGION="${AEGAEON_OIDC_SIGNING_AWS_REGION:-${AWS_REGION}}"
	kms_key_id="${AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID:-${AEG_OIDC_KMS_AWS_KEY_ID:-}}"
	export AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID="${kms_key_id}"
	if [[ -z ${AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID} ]]; then
		echo "AWS mode requires AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID" >&2
		exit 2
	fi
	if [[ -z ${AEGAEON_OIDC_SIGNING_KID:-} ]]; then
		echo "AWS mode requires AEGAEON_OIDC_SIGNING_KID to prevent kid reuse" >&2
		exit 2
	fi
	if [[ -n ${AWS_ENDPOINT_URL:-} && ${AEG_OIDC_KMS_ALLOW_ENDPOINT_URL:-0} != "1" ]]; then
		echo "AWS mode refuses AWS_ENDPOINT_URL; unset it or set AEG_OIDC_KMS_ALLOW_ENDPOINT_URL=1" >&2
		exit 2
	fi
	export AEGAEON_OIDC_SIGNING_BACKEND="aws-kms"
fi

if (($# == 1)); then
	# Resolve the current checkout's fixed package, not a caller-supplied binary.
	# Only compilation is cached. The health check and exact test below stay live.
	EXECUTION_BACKEND="nix"
	repository_root="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
	package="$(nix build --no-link --print-out-paths "${repository_root}#oidc-kms-test")"
	if [[ ${package} != /* || ${package} == *$'\n'* ]]; then
		echo "expected one absolute Nix output for the KMS test package" >&2
		exit 1
	fi
	python3 "${SCRIPT_DIR}/oidc_kms_test_package.py" validate "${package}" \
		>"${ARTIFACT_DIR}/build.json"
	BUILD_RECEIPT_JSON='"build.json"'
	TEST_COMMAND=("${package}/libexec/oidc-kms-test" "${TEST_NAME}" --exact --nocapture --color never)
	TEST_COMMAND_STRING="${TEST_COMMAND[*]}"
	# Cargo runs a library's tests in that package's directory.
	TEST_WORKING_DIRECTORY="${repository_root}/crates/server"
fi

{
	echo "=== OIDC AWS KMS Parity Evidence ==="
	echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
	echo "Git commit: $(git_value rev-parse HEAD)"
	echo "Git branch: $(git_value branch --show-current)"
	echo "Mode: ${MODE}"
	echo "Require LocalStack: ${REQUIRE_LOCALSTACK}"
	echo "AWS_REGION: ${AWS_REGION}"
	echo "AWS_ENDPOINT_URL: ${AWS_ENDPOINT_URL:-}"
	echo "AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID: ${AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID:-}"
	echo "AEGAEON_OIDC_SIGNING_KID: ${AEGAEON_OIDC_SIGNING_KID:-}"
	echo "Health URL: ${LOCALSTACK_HEALTH_URL}"
	echo "Fallback health URL: ${LOCALSTACK_FALLBACK_HEALTH_URL}"
	echo "Command: ${TEST_COMMAND[*]}"
	echo "Working directory: ${TEST_WORKING_DIRECTORY}"
} | tee "${ARTIFACT_DIR}/metadata.txt"

if [[ ${MODE} == "localstack" && ${REQUIRE_LOCALSTACK} == "1" ]]; then
	deadline=$((SECONDS + LOCALSTACK_WAIT_SECONDS))
	health_artifact="${ARTIFACT_DIR}/localstack-health.json"
	until curl -fsS "${LOCALSTACK_HEALTH_URL}" >"${health_artifact}" 2>/dev/null ||
		curl -fsS "${LOCALSTACK_FALLBACK_HEALTH_URL}" >"${health_artifact}" 2>/dev/null; do
		if ((SECONDS >= deadline)); then
			echo "::error::LocalStack KMS endpoint did not become ready within" \
				"${LOCALSTACK_WAIT_SECONDS}s" | tee -a "${ARTIFACT_DIR}/metadata.txt"
			exit 1
		fi
		sleep 2
	done
fi

(
	cd -- "${TEST_WORKING_DIRECTORY}"
	"${TEST_COMMAND[@]}"
) 2>&1 | tee "${ARTIFACT_DIR}/test.log"
python3 "${SCRIPT_DIR}/validate_oidc_kms_execution.py" "${ARTIFACT_DIR}/test.log" \
	>"${ARTIFACT_DIR}/execution.json"
status="passed"
