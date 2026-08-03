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
need_cmd docker
need_cmd jq
need_cmd python3
need_cmd unzip

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"
source "${REPO_ROOT}/scripts/oidf_conformance/common_tls.sh"

ENV_FILE="${OIDF_ENV_FILE:-scripts/oidf_conformance/.env}"
PLAN_NAME="${OIDF_PLAN_NAME:-oidcc-config-certification-test-plan}"
PLAN_ALIAS="${OIDF_PLAN_ALIAS:-aegaeon-oidcc-basic}"

# If set, only run these test modules (space-separated). Otherwise run all modules in the plan.
ONLY_MODULES="${OIDF_ONLY_MODULES:-}"

ART_DIR="${CONFORMANCE_ARTIFACT_DIR:-artifacts/conformance}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
TEST_POLL_MAX_SECS="${OIDF_TEST_POLL_MAX_SECS:-600}"
AUTO_UPLOAD_EVIDENCE="${OIDF_AUTO_UPLOAD_EVIDENCE:-0}"
EVIDENCE_IMAGE_DATA_URI="${OIDF_EVIDENCE_IMAGE_DATA_URI:-}"
SCREENSHOT_BROWSER="${OIDF_SCREENSHOT_BROWSER:-}"

if [ -z "${SCREENSHOT_BROWSER}" ]; then
	for candidate in google-chrome-stable chromium google-chrome; do
		if command -v "${candidate}" >/dev/null 2>&1; then
			SCREENSHOT_BROWSER="$(command -v "${candidate}")"
			break
		fi
	done
fi

if [ ! -f "${ENV_FILE}" ]; then
	die "env file not found: ${ENV_FILE} (copy from scripts/oidf_conformance/.env.example)"
fi

# shellcheck disable=SC1090
set -a
source "${ENV_FILE}"
set +a
oidf_init_curl "${REPO_ROOT}"

: "${AEGAEON_DOMAIN:?missing AEGAEON_DOMAIN in ${ENV_FILE}}"
: "${SUITE_DOMAIN:?missing SUITE_DOMAIN in ${ENV_FILE}}"

AEGAEON_IMAGE_RAW="${AEGAEON_IMAGE:-}"
AEGAEON_IMAGE="${AEGAEON_IMAGE_RAW:-aegaeon:latest}"
export AEGAEON_IMAGE

NGINX_HTTPS_PORT="${NGINX_HTTPS_PORT:-443}"

https_base() {
	local host="$1"
	local port="$2"
	if [ "${port}" = "443" ]; then
		printf 'https://%s' "${host}"
	else
		printf 'https://%s:%s' "${host}" "${port}"
	fi
}

SUITE_HTTPS_BASE="$(https_base "${SUITE_DOMAIN}" "${NGINX_HTTPS_PORT}")"
AEGAEON_HTTPS_BASE="$(https_base "${AEGAEON_DOMAIN}" "${NGINX_HTTPS_PORT}")"

CALLBACK_URL="${OIDF_CALLBACK_URL:-${SUITE_HTTPS_BASE}/test/a/${PLAN_ALIAS}/callback}"

OUT_DIR="${ART_DIR}/${PLAN_NAME}"
BOOTSTRAP_DIR="${ART_DIR}/bootstrap"
mkdir -p "${OUT_DIR}/plan-export" "${BOOTSTRAP_DIR}"

exec > >(tee -a "${OUT_DIR}/run.log" "${OUT_DIR}/run-${RUN_ID}.log") 2>&1

echo "OIDF conformance run: ${RUN_ID}"
echo "planName: ${PLAN_NAME}"
echo "alias: ${PLAN_ALIAS}"
echo "callback: ${CALLBACK_URL}"
echo "suite: ${SUITE_HTTPS_BASE}"
echo "aegaeon: ${AEGAEON_HTTPS_BASE}"
echo "aegaeon image: ${AEGAEON_IMAGE}"
echo "artifacts: ${OUT_DIR}"
if [ -n "${OIDF_CA_CERT_RESOLVED:-}" ]; then
	echo "ca cert: ${OIDF_CA_CERT_RESOLVED}"
fi
echo

COMPOSE_FILES=(-f scripts/oidf_conformance/docker-compose.oidf.yml)
if [ "${OIDF_LOCAL_CERTS:-1}" = "1" ]; then
	COMPOSE_FILES+=(-f scripts/oidf_conformance/docker-compose.localcert.yml)
fi

ensure_aegaeon_image() {
	if docker image inspect "${AEGAEON_IMAGE}" >/dev/null 2>&1; then
		return 0
	fi

	if [ -n "${AEGAEON_IMAGE_RAW}" ]; then
		echo "== Pull Aegaeon image (${AEGAEON_IMAGE})"
		docker pull "${AEGAEON_IMAGE}" >/dev/null || die "failed to pull ${AEGAEON_IMAGE}"
		return 0
	fi

	echo "== Build/load local Aegaeon image (Nix)"
	need_cmd nix
	need_cmd gzip
	nix build .#docker-image --print-build-logs
	gzip -dc result | docker load >/dev/null
}

compose() {
	AEGAEON_TEST_CLIENT_REDIRECT_URIS="${CALLBACK_URL}" docker compose \
		"${COMPOSE_FILES[@]}" \
		--env-file "${ENV_FILE}" \
		"$@"
}

cleanup() {
	set +e
	compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

ensure_aegaeon_image

echo "== Start stack"
compose down -v --remove-orphans || true
compose up -d --build

echo "== Wait for readiness"
for i in $(seq 1 120); do
	if oidf_curl -fsS "${SUITE_HTTPS_BASE}/actuator/health" >/dev/null 2>&1 &&
		oidf_curl -fsS "${AEGAEON_HTTPS_BASE}/health" >/dev/null 2>&1; then
		break
	fi
	sleep 2
	if [ "${i}" = "120" ]; then
		die "timed out waiting for suite/aegaeon health endpoints"
	fi
done

echo "== Record suite ref/commit"
if compose exec -T suite sh -lc 'test -f /opt/suite/SUITE_COMMIT.txt'; then
	suite_commit="$(compose exec -T suite sh -lc 'cat /opt/suite/SUITE_COMMIT.txt' | tr -d '\r\n')"
	echo "${suite_commit}" >"${BOOTSTRAP_DIR}/suite_commit_${RUN_ID}.txt"
	echo "${suite_commit}" >"${OUT_DIR}/suite_commit_${RUN_ID}.txt"
	echo "${suite_commit}" >"${OUT_DIR}/plan-export/suite_commit.txt"
	echo "suite commit: ${suite_commit}"
else
	echo "suite commit: unavailable (missing /opt/suite/SUITE_COMMIT.txt)"
fi

echo "== Export available plans (bootstrap)"
oidf_curl -fsS "${SUITE_HTTPS_BASE}/api/plan/available" >"${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.json"
jq -r '.[].planName' "${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.json" >"${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.txt"

echo "== Create test plan"
plan_variants_len="$(
	jq -r \
		--arg plan "${PLAN_NAME}" \
		'.[] | select(.planName == $plan) | (.variants | length)' \
		"${BOOTSTRAP_DIR}/plan_available_${RUN_ID}.json"
)"
if [ -z "${plan_variants_len}" ] || [ "${plan_variants_len}" = "null" ]; then
	die "planName not found in /api/plan/available: ${PLAN_NAME}"
fi

variant_param=""
if [ "${plan_variants_len}" != "0" ]; then
	VARIANT_JSON="${OIDF_PLAN_VARIANT_JSON:-{\"client_registration\":\"static_client\",\"server_metadata\":\"discovery\"}}"
	VARIANT_URI="$(printf '%s' "${VARIANT_JSON}" | jq -sRr @uri)"
	variant_param="&variant=${VARIANT_URI}"
fi

CONFIG_JSON="$(
	jq -n \
		--arg alias "${PLAN_ALIAS}" \
		--arg discovery "${AEGAEON_HTTPS_BASE}/.well-known/openid-configuration" \
		--arg cb "${CALLBACK_URL}" \
		'{
      alias: $alias,
      publish: "summary",
      server: { discoveryUrl: $discovery },
      client: { client_id: "test-client", client_secret: "test-secret", redirect_uri: $cb },
      client2: { client_id: "test-client2", client_secret: "test-secret2", redirect_uri: $cb },
      client_secret_post: { client_id: "test-client-post", client_secret: "test-secret-post", redirect_uri: $cb }
    }'
)"

plan_create_path="${OUT_DIR}/plan_create_${RUN_ID}.json"
plan_create_url="${SUITE_HTTPS_BASE}/api/plan?planName=${PLAN_NAME}${variant_param}"
http_status="$(
	oidf_curl -sS -o "${plan_create_path}" -w '%{http_code}' -X POST \
		"${plan_create_url}" \
		-H 'Content-Type: application/json' \
		-d "${CONFIG_JSON}"
)"
if [ "${http_status}" != "200" ] && [ "${http_status}" != "201" ]; then
	echo "plan creation failed http_status=${http_status} url=${plan_create_url}" >&2
	cat "${plan_create_path}" >&2 || true
	die "plan creation failed"
fi
PLAN_ID="$(jq -r '.id' "${plan_create_path}")"
if [ -z "${PLAN_ID}" ] || [ "${PLAN_ID}" = "null" ]; then
	die "plan creation did not return an id"
fi
echo "${PLAN_ID}" >"${OUT_DIR}/plan_id_${RUN_ID}.txt"
echo "plan_id=${PLAN_ID}"

echo "== Discover plan modules"
MODULES="$(
	jq -r '.modules[].testModule' "${plan_create_path}"
)"
if [ -n "${ONLY_MODULES}" ]; then
	echo "Using OIDF_ONLY_MODULES override: ${ONLY_MODULES}"
	MODULES="${ONLY_MODULES}"
fi

echo "== Run modules"
RESULTS_JSON="${OUT_DIR}/plan-export/results_${RUN_ID}.json"
echo '[]' >"${RESULTS_JSON}"
SCREENSHOT_DIR="${OUT_DIR}/plan-export/screenshots_${RUN_ID}"
mkdir -p "${SCREENSHOT_DIR}"

declare -A UPLOADED_EVIDENCE_PLACEHOLDERS=()
declare -A CAPTURED_EVIDENCE_IMAGE_DATA_URIS=()

rewrite_url_for_host_port() {
	# If the suite prints URLs without an explicit port, we may still be running the proxy on a non-443 host port.
	# Rewrite https://{host}/... -> https://{host}:{NGINX_HTTPS_PORT}/...
	local url="$1"
	local host_port="$2"
	if [ "${NGINX_HTTPS_PORT}" = "443" ]; then
		printf '%s' "${url}"
		return 0
	fi
	printf '%s' "${url}" | sed -E "s#^https://${host_port}/#https://${host_port}:${NGINX_HTTPS_PORT}/#"
}

render_screenshot_html() {
	local source_path="$1"
	local final_url="$2"
	local output_path="$3"

	python3 - "${source_path}" "${final_url}" "${output_path}" <<'PY'
from pathlib import Path
import html
import re
import sys

source_path = Path(sys.argv[1])
final_url = sys.argv[2]
output_path = Path(sys.argv[3])
raw = source_path.read_text(encoding="utf-8", errors="replace")
looks_html = bool(re.search(r"<!doctype html|<html|<body", raw, re.IGNORECASE))

if looks_html:
    if re.search(r"<head[^>]*>", raw, re.IGNORECASE):
        rendered = re.sub(
            r"(<head[^>]*>)",
            r'\1<meta charset="utf-8"><base href="%s">' % final_url,
            raw,
            count=1,
            flags=re.IGNORECASE,
        )
    else:
        rendered = (
            '<!doctype html><html><head><meta charset="utf-8">'
            f'<base href="{html.escape(final_url, quote=True)}"></head>'
            f'<body>{raw}</body></html>'
        )
else:
    escaped = html.escape(raw)
    title = html.escape(final_url)
    rendered = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    body {{
      margin: 0;
      padding: 24px;
      background: #ffffff;
      color: #111827;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }}
    h1 {{
      margin: 0 0 12px 0;
      font-size: 20px;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
    }}
    p {{
      margin: 0 0 16px 0;
      color: #4b5563;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
    }}
    pre {{
      margin: 0;
      padding: 16px;
      white-space: pre-wrap;
      word-break: break-word;
      background: #f3f4f6;
      border: 1px solid #d1d5db;
      border-radius: 8px;
    }}
  </style>
</head>
<body>
  <h1>OIDF evidence capture</h1>
  <p>{title}</p>
  <pre>{escaped}</pre>
</body>
</html>
"""

output_path.write_text(rendered, encoding="utf-8")
PY
}

capture_evidence_screenshot() {
	local test_name="$1"
	local test_id="$2"
	local final_url="$3"
	local source_path="$4"

	if [ "${AUTO_UPLOAD_EVIDENCE}" != "1" ]; then
		return 0
	fi

	if [ -z "${SCREENSHOT_BROWSER}" ]; then
		echo "warn: no headless browser found for evidence capture; falling back to configured placeholder"
		return 0
	fi

	local html_path="${SCREENSHOT_DIR}/${test_id}.html"
	local png_path="${SCREENSHOT_DIR}/${test_id}.png"
	local browser_profile
	browser_profile="$(mktemp -d)"

	render_screenshot_html "${source_path}" "${final_url}" "${html_path}"

	if ! "${SCREENSHOT_BROWSER}" \
		--headless=new \
		--disable-gpu \
		--hide-scrollbars \
		--ignore-certificate-errors \
		--allow-file-access-from-files \
		--user-data-dir="${browser_profile}" \
		--window-size=1440,1400 \
		--virtual-time-budget=5000 \
		--screenshot="${png_path}" \
		"file://${html_path}" >/dev/null 2>&1; then
		echo "warn: screenshot capture failed test=${test_name} id=${test_id} browser=${SCREENSHOT_BROWSER}"
		rm -rf "${browser_profile}"
		return 0
	fi

	rm -rf "${browser_profile}"

	if [ ! -s "${png_path}" ]; then
		echo "warn: screenshot capture produced empty file test=${test_name} id=${test_id}"
		return 0
	fi

	CAPTURED_EVIDENCE_IMAGE_DATA_URIS["${test_id}"]="data:image/png;base64,$(base64 <"${png_path}" | tr -d '\n')"
	echo "-- evidence screenshot captured: ${test_name} (${test_id})"
}

upload_evidence_placeholders() {
	local test_name="$1"
	local test_id="$2"
	local evidence_image_data_uri=""

	if [ "${AUTO_UPLOAD_EVIDENCE}" != "1" ]; then
		return 0
	fi

	if [ -n "${CAPTURED_EVIDENCE_IMAGE_DATA_URIS[${test_id}]+x}" ]; then
		evidence_image_data_uri="${CAPTURED_EVIDENCE_IMAGE_DATA_URIS[${test_id}]}"
	else
		evidence_image_data_uri="${EVIDENCE_IMAGE_DATA_URI}"
	fi

	if [ -z "${evidence_image_data_uri}" ]; then
		die "OIDF_AUTO_UPLOAD_EVIDENCE=1 requires OIDF_EVIDENCE_IMAGE_DATA_URI (data:image/png;base64,...)"
	fi

	local log_path="${OUT_DIR}/plan-export/log_${test_id}_${RUN_ID}.json"
	local log_status
	log_status="$(
		oidf_curl -sS -o "${log_path}" -w '%{http_code}' "${SUITE_HTTPS_BASE}/api/log/${test_id}" || true
	)"
	if [ "${log_status}" != "200" ]; then
		return 0
	fi

	local placeholders
	placeholders="$(jq -r '.[] | .upload? // empty' "${log_path}" | sort -u | tr '\n' ' ' | xargs || true)"
	if [ -z "${placeholders}" ]; then
		return 0
	fi

	for placeholder in ${placeholders}; do
		local key="${test_id}:${placeholder}"
		if [ -n "${UPLOADED_EVIDENCE_PLACEHOLDERS[${key}]+x}" ]; then
			continue
		fi

		echo "-- upload evidence: ${test_name} (${test_id}) placeholder=${placeholder}"
		upload_status="$(
			oidf_curl -sS -o /dev/null -w '%{http_code}' -X POST \
				-H 'Content-Type: text/plain' \
				--data "${evidence_image_data_uri}" \
				"${SUITE_HTTPS_BASE}/api/log/${test_id}/images/${placeholder}" || true
		)"

		if [ "${upload_status}" = "200" ]; then
			UPLOADED_EVIDENCE_PLACEHOLDERS["${key}"]=1
			echo "-- evidence uploaded: ${test_name} (${test_id}) placeholder=${placeholder}"
		else
			echo "warn: evidence upload failed http=${upload_status} test=${test_name} id=${test_id} placeholder=${placeholder}"
		fi
	done
}

for test_name in ${MODULES}; do
	echo "-- create: ${test_name}"
	create_json="$(oidf_curl -fsS -X POST "${SUITE_HTTPS_BASE}/api/runner?test=${test_name}&plan=${PLAN_ID}" -H 'Content-Type: application/json')"
	test_id="$(echo "${create_json}" | jq -r '.id')"
	test_url="$(echo "${create_json}" | jq -r '.url // empty')"
	if [ -z "${test_id}" ] || [ "${test_id}" = "null" ]; then
		die "failed to create test instance for ${test_name}: ${create_json}"
	fi
	if [ -n "${test_url}" ]; then
		echo "${test_url}" >"${OUT_DIR}/plan-export/test_url_${test_id}_${RUN_ID}.txt"
	fi

	# Wait until the async configure step completes enough that start is legal.
	for i in $(seq 1 120); do
		info="$(oidf_curl -fsS "${SUITE_HTTPS_BASE}/api/info/${test_id}")"
		status="$(echo "${info}" | jq -r '.status')"
		if [ "${status}" != "CREATED" ]; then
			break
		fi
		sleep 1
		if [ "${i}" = "120" ]; then
			die "timeout waiting for test to leave CREATED: ${test_name} (${test_id})"
		fi
	done

	# Start (if it didn't auto-start already)
	info="$(oidf_curl -fsS "${SUITE_HTTPS_BASE}/api/info/${test_id}")"
	status="$(echo "${info}" | jq -r '.status')"
	if [ "${status}" = "CONFIGURED" ]; then
		echo "-- start: ${test_name} (${test_id})"
		oidf_curl -fsS -X POST "${SUITE_HTTPS_BASE}/api/runner/${test_id}" >/dev/null
	fi

	# Poll until completion; auto-visit browser URLs when the suite is waiting for front-channel steps.
	final_info=""
	for i in $(seq 1 "${TEST_POLL_MAX_SECS}"); do
		info="$(oidf_curl -fsS "${SUITE_HTTPS_BASE}/api/info/${test_id}")"
		status="$(echo "${info}" | jq -r '.status')"
		if [ "${status}" = "FINISHED" ] || [ "${status}" = "INTERRUPTED" ]; then
			upload_evidence_placeholders "${test_name}" "${test_id}"
			final_info="${info}"
			break
		fi

		if [ "${status}" = "WAITING" ]; then
			browser_path="${OUT_DIR}/plan-export/browser_${test_id}_${RUN_ID}.json"
			browser_status="$(
				oidf_curl -sS -o "${browser_path}" -w '%{http_code}' \
					"${SUITE_HTTPS_BASE}/api/runner/browser/${test_id}" || true
			)"
			if [ "${browser_status}" != "200" ]; then
				echo "warn: browser control unavailable http=${browser_status} test=${test_name} id=${test_id}"
			fi
			urls="$(jq -r '.urls[]?' "${browser_path}" 2>/dev/null || true)"
			cookie_jar="${OUT_DIR}/plan-export/cookies_${test_id}_${RUN_ID}.txt"
			for url in ${urls}; do
				# Visit and then mark as visited in the suite.
				visit_url="$(rewrite_url_for_host_port "${url}" "${SUITE_DOMAIN}")"
				visit_url="$(rewrite_url_for_host_port "${visit_url}" "${AEGAEON_DOMAIN}")"
				visit_tmp="$(mktemp)"
				visit_meta="$(
					oidf_curl -sS -L -c "${cookie_jar}" -b "${cookie_jar}" \
						-o "${visit_tmp}" -w '%{http_code} %{url_effective}' "${visit_url}" || true
				)"
				visit_status="$(printf '%s' "${visit_meta}" | awk '{print $1}')"
				visit_final_url="$(printf '%s' "${visit_meta}" | awk '{print $2}')"
				if [ "${visit_status}" -ge 400 ] 2>/dev/null; then
					echo "warn: visit failed http=${visit_status} url=${visit_url}"
					head -c 512 "${visit_tmp}" || true
					echo
				fi

				capture_evidence_screenshot "${test_name}" "${test_id}" "${visit_final_url:-${visit_url}}" "${visit_tmp}"

				# If the suite's callback page expects the fragment to be submitted via XHR, emulate it:
				# - extract the XHR target URL from the callback HTML
				# - post the effective URL's fragment (or query-as-fragment) as text/plain
				implicit_url_raw="$(
					sed -nE "s/.*xhr\\.open\\('POST', \"([^\"]+)\".*/\\1/p" "${visit_tmp}" | head -n 1
				)"
				if [ -n "${implicit_url_raw}" ]; then
					implicit_url="$(
						printf '%s' "\"${implicit_url_raw}\"" | jq -r . 2>/dev/null || true
					)"
					if [ -n "${implicit_url}" ] && [ -n "${visit_final_url}" ]; then
						if [[ ${visit_final_url} == *#* ]]; then
							hash="#${visit_final_url#*#}"
						else
							qs="${visit_final_url#*\\?}"
							if [[ ${qs} == "${visit_final_url}" ]]; then
								qs=""
							fi
							hash="#${qs}"
						fi
						implicit_post_status="$(
							oidf_curl -sS -o /dev/null -w '%{http_code}' -X POST \
								-H 'Content-Type: text/plain' \
								--data "${hash}" \
								-c "${cookie_jar}" -b "${cookie_jar}" \
								"${implicit_url}" || true
						)"
						if [ "${implicit_post_status}" != "204" ]; then
							echo "warn: suite implicit-submit failed http=${implicit_post_status} test=${test_name} id=${test_id}"
						fi
					fi
				fi
				rm -f "${visit_tmp}"

				visit_mark_status="$(
					oidf_curl -sS -o /dev/null -w '%{http_code}' -X POST \
						"${SUITE_HTTPS_BASE}/api/runner/browser/${test_id}/visit?url=$(printf '%s' "${url}" | jq -sRr @uri)" || true
				)"
				if [ "${visit_mark_status}" != "204" ]; then
					echo "warn: suite visit-mark failed http=${visit_mark_status} test=${test_name} id=${test_id}"
				fi
			done

			upload_evidence_placeholders "${test_name}" "${test_id}"
		fi

		sleep 1
		if [ "${i}" = "${TEST_POLL_MAX_SECS}" ]; then
			die "timeout waiting for ${test_name} (${test_id}) status=${status} test_url=${test_url}"
		fi
	done

	# Record the final status/result from /api/info (even if timed out).
	if [ -z "${final_info}" ]; then
		final_info="$(oidf_curl -fsS "${SUITE_HTTPS_BASE}/api/info/${test_id}")"
	fi
	echo "${final_info}" >"${OUT_DIR}/plan-export/info_${test_id}_${RUN_ID}.json"

	status="$(echo "${final_info}" | jq -r '.status')"
	result="$(echo "${final_info}" | jq -r '.result // empty')"
	echo "-- done: ${test_name} (${test_id}) status=${status} result=${result}"

	tmp="$(mktemp)"
	jq \
		--arg test_name "${test_name}" \
		--arg test_id "${test_id}" \
		--arg status "${status}" \
		--arg result "${result}" \
		'. + [{test_module: $test_name, test_id: $test_id, status: $status, result: $result}]' \
		"${RESULTS_JSON}" >"${tmp}"
	mv "${tmp}" "${RESULTS_JSON}"
done

echo "== Export plan logs"
export_zip="${OUT_DIR}/plan-export/export_${RUN_ID}.zip"
http_status="$(oidf_curl -s -o "${export_zip}" -w '%{http_code}' "${SUITE_HTTPS_BASE}/api/plan/export/${PLAN_ID}")"
if [ "${http_status}" != "200" ]; then
	rm -f "${export_zip}" || true
	die "plan export failed http_status=${http_status}"
fi

cp "${export_zip}" "${OUT_DIR}/plan-export/export.zip"
cp "${RESULTS_JSON}" "${OUT_DIR}/plan-export/results.json"
echo "${RUN_ID}" >"${OUT_DIR}/plan-export/latest_run_id.txt"
echo "${PLAN_ID}" >"${OUT_DIR}/plan-export/plan_id.txt"

rm -rf "${OUT_DIR}/plan-export/files_${RUN_ID}"
mkdir -p "${OUT_DIR}/plan-export/files_${RUN_ID}"
unzip -q "${export_zip}" -d "${OUT_DIR}/plan-export/files_${RUN_ID}"

echo "== Save plan JSON"
oidf_curl -fsS "${SUITE_HTTPS_BASE}/api/plan/${PLAN_ID}" >"${OUT_DIR}/plan-export/plan_${RUN_ID}.json"
cp "${OUT_DIR}/plan-export/plan_${RUN_ID}.json" "${OUT_DIR}/plan-export/plan.json"

echo "== Done"
echo "run log: ${OUT_DIR}/run-${RUN_ID}.log"
echo "results: ${OUT_DIR}/plan-export/results.json"
echo "plan export: ${export_zip}"
echo "plan: ${OUT_DIR}/plan-export/plan.json"
