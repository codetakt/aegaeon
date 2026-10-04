#!/usr/bin/env bash

# Run the Aegaeon performance smoke (server + load test) and collect artifacts.
# This helper is shared by nix apps and CI workflows so we keep all orchestration
# in one place.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
cd "$REPO_ROOT"

ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts/perf/load-test}"
SERVER_LOG="${SERVER_LOG:-$ARTIFACT_DIR/server.log}"
LOADTEST_LOG="${LOADTEST_LOG:-$ARTIFACT_DIR/loadtest.log}"
REPORT_PATH="${REPORT_PATH:-$ARTIFACT_DIR/report.json}"
LEGACY_REPORT="${LEGACY_REPORT:-artifacts/load-test-report.json}"
SERVER_PID=""
SOURCE_STATUS="pending"
ARTIFACT_DIR_VALIDATED=0
SOURCE_PRODUCER="$REPO_ROOT/scripts/perf/source_manifest.py"
SOURCE_EVIDENCE="$ARTIFACT_DIR/source"

# Load-test tunables (env overrides keep CI configurable).
SERVER_HOST="${PERF_SERVER_HOST:-127.0.0.1}"
SERVER_PORT="${PERF_SERVER_PORT:-}"
BASE_URL="${PERF_BASE_URL:-}"
RUNTIME_ISSUER_HOST="${AEGAEON_RUNTIME_ISSUER_HOST:-${PERF_RUNTIME_ISSUER_HOST:-}}"
APPLY_DATABASE_MIGRATIONS="${PERF_APPLY_DATABASE_MIGRATIONS:-0}"
WORKERS="${PERF_WORKERS:-50}"
RUN_TIME="${PERF_RUN_TIME:-60s}"
WARMUP="${PERF_WARMUP:-10}"
RPS="${PERF_RPS:-${PERF_SPAWN_RATE:-100}}"
SCENARIO="${PERF_SCENARIO:-smoke}"
MANAGE_SERVER="${PERF_MANAGE_SERVER:-1}"
EXTRA_ARGS=()

while [ $# -gt 0 ]; do
	case "$1" in
	--url)
		BASE_URL="$2"
		MANAGE_SERVER=0
		shift 2
		;;
	--workers | --users)
		WORKERS="$2"
		shift 2
		;;
	--run-time | --run_time | --duration)
		RUN_TIME="$2"
		shift 2
		;;
	--warmup)
		WARMUP="$2"
		shift 2
		;;
	--rps | --spawn-rate | --spawn_rate)
		RPS="$2"
		shift 2
		;;
	--report-file | --report_file)
		REPORT_PATH="$2"
		shift 2
		;;
	--scenario)
		SCENARIO="$2"
		shift 2
		;;
	--server-host)
		SERVER_HOST="$2"
		shift 2
		;;
	--server-port)
		SERVER_PORT="$2"
		shift 2
		;;
	--manage-server)
		MANAGE_SERVER=1
		shift
		;;
	--no-manage-server)
		MANAGE_SERVER=0
		shift
		;;
	--)
		shift
		break
		;;
	*)
		echo "[perf] unknown argument" >&2
		exit 2
		;;
	esac
done

if [ $# -gt 0 ]; then
	EXTRA_ARGS+=("$@")
fi

cleanup() {
	local original_status=$?
	local status_write_exit=0
	set +e
	if [ "$ARTIFACT_DIR_VALIDATED" = 1 ]; then
		python3 "$SOURCE_PRODUCER" status --root "$REPO_ROOT" --evidence "$SOURCE_EVIDENCE" \
			--artifact-directory "$ARTIFACT_DIR" --stage "$SOURCE_STATUS" \
			--exit-status "$original_status" || status_write_exit=$?
	fi
	if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID"
	fi
	if [ "$original_status" -eq 0 ] && [ "$status_write_exit" -ne 0 ]; then
		exit "$status_write_exit"
	fi
}
trap cleanup EXIT

if [ "$(realpath "${BASH_SOURCE[0]}")" != "$REPO_ROOT/scripts/perf/run_load_tests.sh" ] ||
	[ -L "$SOURCE_PRODUCER" ] || [ "$(realpath "$SOURCE_PRODUCER")" != "$SOURCE_PRODUCER" ]; then
	echo "[perf] runner must be the tracked repository entrypoint" >&2
	exit 2
fi
SOURCE_STATUS="paths"
OUTPUT_ARGS=(--output-directory "$ARTIFACT_DIR" --artifact-directory "$ARTIFACT_DIR"
	--report-file "$REPORT_PATH" --legacy-report-file "$LEGACY_REPORT")
OUTPUT_ARGS+=(--fresh-output-file "$REPORT_PATH")
for destination in "$SERVER_LOG" "$LOADTEST_LOG" \
	"$ARTIFACT_DIR/server-build.jsonl" "$ARTIFACT_DIR/build.log" \
	"$ARTIFACT_DIR/loadtest-build.jsonl" "$ARTIFACT_DIR/loadtest-build.log" \
	"$ARTIFACT_DIR/db-migrate.log"; do
	OUTPUT_ARGS+=(--output-file "$destination" --fresh-output-file "$destination")
done
python3 "$SOURCE_PRODUCER" paths --root "$REPO_ROOT" --evidence "$SOURCE_EVIDENCE" \
	"${OUTPUT_ARGS[@]}"
ARTIFACT_DIR_VALIDATED=1
if [ "${AEG_LOADTEST_SOURCE_SHA256+x}" = x ]; then
	echo "[perf] caller source digest is not accepted" >&2
	exit 2
fi
mkdir -p "$ARTIFACT_DIR"
SOURCE_STATUS="freeze"
AEG_LOADTEST_SOURCE_SHA256="$(python3 "$SOURCE_PRODUCER" freeze \
	--root "$REPO_ROOT" --evidence "$SOURCE_EVIDENCE" \
	"${OUTPUT_ARGS[@]}")"
export AEG_LOADTEST_SOURCE_SHA256
verify_source() {
	python3 "$SOURCE_PRODUCER" verify --root "$REPO_ROOT" \
		--evidence "$SOURCE_EVIDENCE" --sha256 "$AEG_LOADTEST_SOURCE_SHA256"
}
SOURCE_STATUS="setup"

pick_server_port() {
	if [ -n "$SERVER_PORT" ]; then
		echo "$SERVER_PORT"
		return 0
	fi

	python3 - <<'PY'
import socket
import os

host = os.environ.get("PERF_SERVER_HOST", "127.0.0.1")
preferred = 8080

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
	s.bind((host, preferred))
	port = s.getsockname()[1]
	s.close()
	print(port)
except OSError:
	s.close()
	s = socket.socket()
	s.bind((host, 0))
	port = s.getsockname()[1]
	s.close()
	print(port)
PY
}

if [ "$MANAGE_SERVER" = "1" ]; then
	SERVER_PORT="$(pick_server_port)"
	BASE_URL="${BASE_URL:-http://${SERVER_HOST}:${SERVER_PORT}}"
else
	if [ -z "$BASE_URL" ]; then
		echo "[perf] PERF_BASE_URL or --url is required when PERF_MANAGE_SERVER=0" >&2
		exit 2
	fi
fi

if [ "$MANAGE_SERVER" = "1" ]; then
	if [ -z "${AEGAEON_DATABASE_URL:-}" ]; then
		echo "[perf] AEGAEON_DATABASE_URL is required when PERF_MANAGE_SERVER=1" >&2
		echo "[perf] the database must contain an active management runtime configuration for the selected issuer host" >&2
		exit 2
	fi
	if [ -z "$RUNTIME_ISSUER_HOST" ]; then
		echo "[perf] AEGAEON_RUNTIME_ISSUER_HOST or PERF_RUNTIME_ISSUER_HOST is required when PERF_MANAGE_SERVER=1" >&2
		exit 2
	fi
	export DATABASE_URL="${AEGAEON_DATABASE_URL}"

	if [ "$APPLY_DATABASE_MIGRATIONS" = "1" ]; then
		echo "[perf] applying database migrations..."
		atlas migrate apply --env local >"$ARTIFACT_DIR/db-migrate.log" 2>&1
	fi

	SOURCE_STATUS="server-build"
	verify_source
	echo "[perf] building release server binary..."
	cargo build --release --locked --bin aegaeon-server --message-format=json-render-diagnostics \
		>"$ARTIFACT_DIR/server-build.jsonl" 2>"$ARTIFACT_DIR/build.log"
	SERVER_BIN="$(python3 "$SOURCE_PRODUCER" bind --root "$REPO_ROOT" \
		--evidence "$SOURCE_EVIDENCE" --sha256 "$AEG_LOADTEST_SOURCE_SHA256" \
		--build-log "$ARTIFACT_DIR/server-build.jsonl" --name aegaeon-server)"
	SOURCE_STATUS="server-launch"
	python3 "$SOURCE_PRODUCER" binary --root "$REPO_ROOT" \
		--evidence "$SOURCE_EVIDENCE" --sha256 "$AEG_LOADTEST_SOURCE_SHA256" \
		--name aegaeon-server >/dev/null

	echo "[perf] launching server..."
	env -u BASE_URL AEGAEON_RUNTIME_ISSUER_HOST="$RUNTIME_ISSUER_HOST" \
		"$SERVER_BIN" --host "$SERVER_HOST" --port "$SERVER_PORT" >"$SERVER_LOG" 2>&1 &
	SERVER_PID=$!
fi

SOURCE_STATUS="readiness"
READINESS_CURL_ARGS=(-fsS)
if [ -n "${AEG_LOADTEST_CA_CERT:-}" ]; then
	READINESS_CURL_ARGS+=(--cacert "$AEG_LOADTEST_CA_CERT")
fi
echo "[perf] waiting for health endpoint at ${BASE_URL}/health..."
for attempt in $(seq 1 30); do
	if curl "${READINESS_CURL_ARGS[@]}" "${BASE_URL%/}/health" >/dev/null 2>&1; then
		break
	fi
	if [ "$attempt" -eq 30 ]; then
		echo "[perf] server failed to report healthy after 30s" >&2
		exit 1
	fi
	sleep 1
done

echo "[perf] running load test (workers=${WORKERS}, rps=${RPS}, scenario=${SCENARIO})..."
SOURCE_STATUS="loadtest-build"
verify_source
cargo build --release -p aegaeon-loadtest --bin aegaeon-loadtest \
	--message-format=json-render-diagnostics >"$ARTIFACT_DIR/loadtest-build.jsonl" \
	2>"$ARTIFACT_DIR/loadtest-build.log"
LOADTEST_BIN="$(python3 "$SOURCE_PRODUCER" bind --root "$REPO_ROOT" \
	--evidence "$SOURCE_EVIDENCE" --sha256 "$AEG_LOADTEST_SOURCE_SHA256" \
	--build-log "$ARTIFACT_DIR/loadtest-build.jsonl" --name aegaeon-loadtest)"
SOURCE_STATUS="loadtest-launch"
python3 "$SOURCE_PRODUCER" binary --root "$REPO_ROOT" \
	--evidence "$SOURCE_EVIDENCE" --sha256 "$AEG_LOADTEST_SOURCE_SHA256" \
	--name aegaeon-loadtest >/dev/null
LOADTEST_STATUS=0
"$LOADTEST_BIN" \
	--url "$BASE_URL" \
	--workers "$WORKERS" \
	--run-time "$RUN_TIME" \
	--warmup "$WARMUP" \
	--rps "$RPS" \
	--scenario "$SCENARIO" \
	--report-file "$REPORT_PATH" \
	"${EXTRA_ARGS[@]}" >"$LOADTEST_LOG" 2>&1 || LOADTEST_STATUS=$?

if [ ! -f "$REPORT_PATH" ]; then
	echo "[perf] load test failed before writing a report; see $LOADTEST_LOG" >&2
	if [ "$LOADTEST_STATUS" -eq 0 ]; then
		exit 1
	fi
	exit "$LOADTEST_STATUS"
fi

SOURCE_STATUS="report-binding"
BINDING_STATUS=0
python3 "$SOURCE_PRODUCER" report --root "$REPO_ROOT" \
	--evidence "$SOURCE_EVIDENCE" --sha256 "$AEG_LOADTEST_SOURCE_SHA256" \
	--report "$REPORT_PATH" || BINDING_STATUS=$?
if [ "$BINDING_STATUS" -ne 0 ] && [ "$LOADTEST_STATUS" -eq 0 ]; then
	exit "$BINDING_STATUS"
fi
mkdir -p "$(dirname "$LEGACY_REPORT")"
if [ "$(realpath -m -- "$REPORT_PATH")" = "$(realpath -m -- "$LEGACY_REPORT")" ]; then
	LEGACY_NOTE="same as report path"
else
	cp "$REPORT_PATH" "$LEGACY_REPORT"
	LEGACY_NOTE="$LEGACY_REPORT"
fi

echo "[perf] load test complete; results at $REPORT_PATH (legacy copy: $LEGACY_NOTE)"
if command -v jq >/dev/null 2>&1 && [ -f "$REPORT_PATH" ]; then
	jq '
		. | {
			duration,
			throughput,
			attempted_throughput,
			p99_latency_ms,
			failed_requests,
			error_rate
		}
	' "$REPORT_PATH" || true
fi

if [ "$LOADTEST_STATUS" -ne 0 ]; then
	echo "[perf] load test exited with status $LOADTEST_STATUS" \
		"after writing its report" >&2
	exit "$LOADTEST_STATUS"
fi

SOURCE_STATUS="complete"
