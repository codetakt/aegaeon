#!/usr/bin/env bash
set -euo pipefail

# Query OIDF conformance suite for available test plans.
# Usage: ./discover_plans.sh [SUITE_BASE_URL]
# Output: one plan name per line to stdout (machine-readable, sorted).
# Exit non-zero if the suite is unreachable.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO_ROOT}/scripts/oidf_conformance/common_tls.sh"

ENV_FILE="${OIDF_ENV_FILE:-scripts/oidf_conformance/.env}"
if [ -f "${REPO_ROOT}/${ENV_FILE}" ]; then
	# shellcheck disable=SC1090
	set -a
	source "${REPO_ROOT}/${ENV_FILE}"
	set +a
fi
oidf_init_curl "${REPO_ROOT}"

SUITE_BASE="${1:-${SUITE_HTTPS_BASE:-https://localhost:9999}}"

response="$(oidf_curl -fsS "${SUITE_BASE}/api/plan/available" 2>/dev/null)"
echo "${response}" | jq -r '.[].planName' | sort
