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

need_cmd curl
need_cmd cargo
need_cmd docker
need_cmd git
need_cmd jq
need_cmd mvn
need_cmd python

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/oidf_conformance/common_tls.sh
source "${REPO_ROOT}/scripts/oidf_conformance/common_tls.sh"

ART_DIR="${CONFORMANCE_ARTIFACT_DIR:-artifacts/conformance}"
CACHE_HOME="${XDG_CACHE_HOME:-${HOME:-${TMPDIR:-/tmp}}/.cache}"
SUITE_DIR="${OIDF_SUITE_DIR:-${CACHE_HOME}/aegaeon/oidf/conformance-suite}"
MODE="${OIDF_MODE:-bootstrap}"

MONGO_PORT="${OIDF_MONGO_PORT:-27017}"
SUITE_PORT="${OIDF_SUITE_PORT:-9999}"

SERVER_HOST="${OIDF_SERVER_HOST:-127.0.0.1}"
SERVER_PORT="${OIDF_SERVER_PORT:-18081}"
SERVER_BIN="${OIDF_SERVER_BIN:-}"
RUNTIME_ISSUER_HOST="${AEGAEON_RUNTIME_ISSUER_HOST:-${OIDF_RUNTIME_ISSUER_HOST:-}}"
APPLY_DATABASE_MIGRATIONS="${OIDF_APPLY_DATABASE_MIGRATIONS:-0}"

MONGO_USER="${OIDF_MONGO_USER:-admin}"
MONGO_PASSWORD="${OIDF_MONGO_PASSWORD:-password}"
MONGO_DB="${OIDF_MONGO_DB:-conformance}"

MONGO_CONTAINER="${OIDF_MONGO_CONTAINER:-aegaeon-oidf-mongodb}"

SERVER_URL="http://${SERVER_HOST}:${SERVER_PORT}"
DISCOVERY_URL="${SERVER_URL}/.well-known/oauth-authorization-server"
MONGO_URI="mongodb://${MONGO_USER}:${MONGO_PASSWORD}@localhost:${MONGO_PORT}/${MONGO_DB}?authSource=${MONGO_USER}"
SUITE_URL="http://localhost:${SUITE_PORT}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BOOTSTRAP_DIR="${ART_DIR}/bootstrap"
RUN_LOG="${BOOTSTRAP_DIR}/run-${RUN_ID}.log"

mkdir -p "${BOOTSTRAP_DIR}"
exec > >(tee -a "${RUN_LOG}") 2>&1

suite_curl() {
	oidf_curl -fsS -H "X-Forwarded-Proto: https" "$@"
}

suite_curl_optional() {
	oidf_curl -s -H "X-Forwarded-Proto: https" "$@"
}

oidf_init_curl "${REPO_ROOT}"

echo "OIDF OAuth 2.x conformance run: ${RUN_ID}"
echo "artifacts: ${ART_DIR}"
echo "suite dir: ${SUITE_DIR}"
echo "server: ${SERVER_URL}"
echo "suite: ${SUITE_URL}"
echo "mongo: ${MONGO_URI}"
echo

if [ -z "${AEGAEON_DATABASE_URL:-}" ]; then
	die "AEGAEON_DATABASE_URL is required; OIDF local server runs only from PostgreSQL-backed runtime configuration"
fi
if [ -z "${RUNTIME_ISSUER_HOST}" ]; then
	die "AEGAEON_RUNTIME_ISSUER_HOST or OIDF_RUNTIME_ISSUER_HOST is required"
fi
export DATABASE_URL="${AEGAEON_DATABASE_URL}"

cleanup() {
	set +e
	if [ -n "${SUITE_PID:-}" ]; then
		kill "${SUITE_PID}" >/dev/null 2>&1 || true
		wait "${SUITE_PID}" >/dev/null 2>&1 || true
	fi
	if [ -n "${SERVER_PID:-}" ]; then
		kill "${SERVER_PID}" >/dev/null 2>&1 || true
		wait "${SERVER_PID}" >/dev/null 2>&1 || true
	fi
	docker stop "${MONGO_CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== Start MongoDB (${MONGO_CONTAINER})"
docker stop "${MONGO_CONTAINER}" >/dev/null 2>&1 || true
docker run -d --rm \
	--name "${MONGO_CONTAINER}" \
	-p "${MONGO_PORT}:27017" \
	-e "MONGO_INITDB_ROOT_USERNAME=${MONGO_USER}" \
	-e "MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}" \
	mongo:6 >/dev/null

if [ "${APPLY_DATABASE_MIGRATIONS}" = "1" ]; then
	need_cmd atlas
	echo "== Apply PostgreSQL migrations"
	atlas migrate apply --env local
fi

echo "== Start aegaeon-server"
if [ -z "${SERVER_BIN}" ]; then
	if [ -x "result/bin/aegaeon-server" ]; then
		SERVER_BIN="result/bin/aegaeon-server"
	elif [ -x "./target/release/aegaeon-server" ]; then
		SERVER_BIN="./target/release/aegaeon-server"
	else
		echo "building aegaeon-server (release)..."
		cargo build --release --bin aegaeon-server
		SERVER_BIN="./target/release/aegaeon-server"
	fi
fi
[ -x "${SERVER_BIN}" ] || die "server binary not executable: ${SERVER_BIN}"

env -u BASE_URL \
	AEGAEON_RUNTIME_ISSUER_HOST="${RUNTIME_ISSUER_HOST}" \
	CONFORMANCE_MODE=true LOG_LEVEL=debug \
	"${SERVER_BIN}" --host "${SERVER_HOST}" --port "${SERVER_PORT}" &
SERVER_PID="$!"

for _ in {1..30}; do
	if oidf_curl -fsS "${SERVER_URL}/health" >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
oidf_curl -fsS "${DISCOVERY_URL}" >/dev/null
echo "server ready: ${DISCOVERY_URL}"

echo "== Prepare conformance suite checkout"
mkdir -p "$(dirname "${SUITE_DIR}")"
if [ ! -d "${SUITE_DIR}/.git" ]; then
	rm -rf "${SUITE_DIR}"
	git clone https://github.com/openid-certification/conformance-suite.git "${SUITE_DIR}"
fi
SUITE_COMMIT="$(git -C "${SUITE_DIR}" rev-parse HEAD)"
echo "${SUITE_COMMIT}" >"${BOOTSTRAP_DIR}/suite_commit_${RUN_ID}.txt"
echo "suite commit: ${SUITE_COMMIT}"

echo "== Build conformance suite (mvn)"
(cd "${SUITE_DIR}" && mvn clean package -DskipTests)

SUITE_JAR=""
if [ -f "${SUITE_DIR}/target/conformance-suite.jar" ]; then
	SUITE_JAR="target/conformance-suite.jar"
elif [ -f "${SUITE_DIR}/target/fapi-test-suite.jar" ]; then
	SUITE_JAR="target/fapi-test-suite.jar"
else
	die "could not find suite jar under ${SUITE_DIR}/target (expected conformance-suite.jar or fapi-test-suite.jar)"
fi

echo "== Start conformance suite"
SUITE_STDOUT_LOG="${BOOTSTRAP_DIR}/suite_stdout_${RUN_ID}.log"
(cd "${SUITE_DIR}" && java -jar "${SUITE_JAR}" \
	--server.port="${SUITE_PORT}" \
	--server.forward-headers-strategy=native \
	--spring.profiles.active=dev \
	--spring.data.mongodb.uri="${MONGO_URI}" \
	--fintechlabs.base_url="${SUITE_URL}" \
	--fintechlabs.devmode=true) >"${SUITE_STDOUT_LOG}" 2>&1 &
SUITE_PID="$!"

for _ in {1..60}; do
	if suite_curl "${SUITE_URL}/actuator/health" >/dev/null 2>&1; then
		break
	fi
	sleep 2
done
if ! suite_curl "${SUITE_URL}/actuator/health" >"${BOOTSTRAP_DIR}/suite_info_${RUN_ID}.json"; then
	echo "suite failed to start; tailing ${SUITE_STDOUT_LOG}:" >&2
	tail -n 200 "${SUITE_STDOUT_LOG}" >&2 || true
	die "conformance suite not ready at ${SUITE_URL}"
fi
echo "suite ready: ${SUITE_URL} (jar: ${SUITE_JAR})"

declare -A PLAN_IDS

echo "== Fetch available plans"
suite_curl "${SUITE_URL}/api/plan/available" >"${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.json"
jq -r '.[].planName' "${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.json" >"${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.txt"

echo "available plans saved: ${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.txt"

urlencode() {
	printf '%s' "$1" | jq -sRr @uri
}

sanitize_filename() {
	# Keep filenames stable and portable.
	printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '_' | sed 's/^_\\+//;s/_\\+$//'
}

register_plan() {
	local plan_name="$1"
	local variant_json="${2:-}"
	local config_json="$3"
	local safe_name
	safe_name="$(sanitize_filename "${plan_name}")"

	local create_url
	create_url="${SUITE_URL}/api/plan?planName=$(urlencode "${plan_name}")"
	if [ -n "${variant_json}" ]; then
		create_url="${create_url}&variant=$(urlencode "${variant_json}")"
	fi

	local response_with_status
	response_with_status="$(suite_curl_optional -w '\n__HTTP_STATUS__:%{http_code}\n' -X POST "${create_url}" -H "Content-Type: application/json" -d "${config_json}")"
	local http_status
	http_status="$(printf '%s' "${response_with_status}" | tail -n 1 | sed 's/^__HTTP_STATUS__://')"
	local response
	response="$(printf '%s' "${response_with_status}" | sed '$d')"

	echo "${response}" >"${BOOTSTRAP_DIR}/plan_create_${safe_name}_${RUN_ID}.json"
	if [ "${http_status}" != "200" ] && [ "${http_status}" != "201" ]; then
		echo "plan registration failed (${plan_name}) http_status=${http_status}" >&2
		echo "${response}" >&2
		die "plan registration failed for ${plan_name}"
	fi

	local plan_id
	plan_id="$(echo "${response}" | jq -r '.id')"
	if [ -z "${plan_id}" ] || [ "${plan_id}" = "null" ]; then
		die "plan registration failed for ${plan_name}: ${response}"
	fi
	PLAN_IDS["${plan_name}"]="${plan_id}"
	echo "registered ${plan_name}: ${plan_id}"
}

case "${MODE}" in
bootstrap)
	echo "== Bootstrap done"
	echo "next:"
	echo "  - inspect ${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.txt"
	echo "  - decide which planName(s) match Aegaeon’s supported profile"
	echo "  - then extend this script / CI to create & execute a concrete plan"
	echo "run log: ${RUN_LOG}"
	;;
create-plan)
	PLAN_NAME="${OIDF_PLAN_NAME:-}"
	PLAN_VARIANT_JSON="${OIDF_PLAN_VARIANT_JSON:-}"
	PLAN_CONFIG_JSON="${OIDF_PLAN_CONFIG_JSON:-}"

	[ -n "${PLAN_NAME}" ] || die "OIDF_MODE=create-plan requires OIDF_PLAN_NAME"
	[ -n "${PLAN_CONFIG_JSON}" ] || die "OIDF_MODE=create-plan requires OIDF_PLAN_CONFIG_JSON"

	echo "== Create plan: ${PLAN_NAME}"
	register_plan "${PLAN_NAME}" "${PLAN_VARIANT_JSON}" "${PLAN_CONFIG_JSON}"
	PLAN_ID="${PLAN_IDS[${PLAN_NAME}]}"
	echo "${PLAN_ID}" >"${BOOTSTRAP_DIR}/plan_id_${RUN_ID}.txt"
	suite_curl "${SUITE_URL}/api/plan/${PLAN_ID}" >"${BOOTSTRAP_DIR}/plan_${RUN_ID}.json"
	echo "created plan: ${PLAN_ID}"

	EXPORT_PATH="${BOOTSTRAP_DIR}/plan_export_${RUN_ID}.zip"
	export_status="$(oidf_curl -s -o "${EXPORT_PATH}" -w "%{http_code}" -H "X-Forwarded-Proto: https" "${SUITE_URL}/api/plan/export/${PLAN_ID}")"
	if [ "${export_status}" != "200" ]; then
		rm -f "${EXPORT_PATH}" || true
		echo "plan export unavailable http_status=${export_status}" >&2
	fi

	echo "run log: ${RUN_LOG}"
	;;
*)
	die "unknown OIDF_MODE=${MODE} (expected: bootstrap|create-plan)"
	;;
esac

echo "== Done"
