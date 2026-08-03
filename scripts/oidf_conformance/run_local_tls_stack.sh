#!/usr/bin/env bash

set -euo pipefail

die() {
	echo "error: $*" >&2
	exit 1
}

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		die "missing required command: $1"
	fi
}

need_cmd docker
need_cmd gzip

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"
source "${REPO_ROOT}/scripts/oidf_conformance/common_tls.sh"

ENV_FILE="${OIDF_ENV_FILE:-scripts/oidf_conformance/.env.local}"
ENV_PATH="${REPO_ROOT}/${ENV_FILE}"
[ -f "${ENV_PATH}" ] || die "env file not found: ${ENV_PATH}"

OIDF_ENV_FILE="${ENV_FILE}" bash "${REPO_ROOT}/scripts/oidf_conformance/prepare_local_tls.sh"

# shellcheck disable=SC1090
set -a
source "${ENV_PATH}"
set +a
oidf_init_curl "${REPO_ROOT}"

AEGAEON_IMAGE_RAW="${AEGAEON_IMAGE:-}"
AEGAEON_IMAGE="${AEGAEON_IMAGE_RAW:-aegaeon:latest}"
export AEGAEON_IMAGE

ensure_aegaeon_image() {
	if docker image inspect "${AEGAEON_IMAGE}" >/dev/null 2>&1; then
		return 0
	fi

	if [ -n "${AEGAEON_IMAGE_RAW}" ]; then
		echo "== Pull Aegaeon image (${AEGAEON_IMAGE})"
		docker pull "${AEGAEON_IMAGE}" >/dev/null || die "failed to pull ${AEGAEON_IMAGE}"
		return 0
	fi

	need_cmd nix
	echo "== Build/load local Aegaeon image (Nix)"
	nix build .#docker-image --print-build-logs
	gzip -dc result | docker load >/dev/null
}

compose() {
	docker compose \
		-f scripts/oidf_conformance/docker-compose.oidf.yml \
		-f scripts/oidf_conformance/docker-compose.localcert.yml \
		--env-file "${ENV_PATH}" \
		"$@"
}

ensure_aegaeon_image

echo "== Start local TLS OIDF stack"
compose up -d --build

SUITE_HTTPS_BASE="${SUITE_PUBLIC_BASE_URL}"
AEGAEON_HTTPS_BASE="${AEGAEON_PUBLIC_BASE_URL}"

echo "== Wait for readiness"
for i in $(seq 1 120); do
	if oidf_curl -fsS "${SUITE_HTTPS_BASE}/actuator/health" >/dev/null 2>&1 &&
		oidf_curl -fsS "${AEGAEON_HTTPS_BASE}/health" >/dev/null 2>&1; then
		break
	fi
	sleep 2
	if [ "${i}" = "120" ]; then
		die "timed out waiting for local TLS stack readiness"
	fi
done

echo "suite: ${SUITE_HTTPS_BASE}"
echo "aegaeon: ${AEGAEON_HTTPS_BASE}"
if [ -n "${OIDF_CA_CERT_RESOLVED:-}" ]; then
	echo "curl example: curl --cacert ${OIDF_CA_CERT_RESOLVED} ${AEGAEON_HTTPS_BASE}/health"
fi
