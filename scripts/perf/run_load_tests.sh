#!/usr/bin/env bash

# Run the Aegaeon performance smoke (server + load test) and collect artifacts.
# This helper is shared by nix apps and CI workflows so we keep all orchestration
# in one place.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts/perf/load-test}"
SERVER_LOG="${SERVER_LOG:-$ARTIFACT_DIR/server.log}"
LOADTEST_LOG="${LOADTEST_LOG:-$ARTIFACT_DIR/loadtest.log}"
REPORT_PATH="${REPORT_PATH:-$ARTIFACT_DIR/report.json}"
LEGACY_REPORT="${LEGACY_REPORT:-artifacts/load-test-report.json}"
SERVER_PID=""

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
		echo "[perf] unknown argument: $1" >&2
		exit 2
		;;
	esac
done

if [ $# -gt 0 ]; then
	EXTRA_ARGS+=("$@")
fi

mkdir -p "$ARTIFACT_DIR"

cleanup() {
	set +e
	if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID"
	fi
}
trap cleanup EXIT

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

	echo "[perf] building release server binary..."
	cargo build --release --locked --bin aegaeon-server >"$ARTIFACT_DIR/build.log" 2>&1

	SERVER_BIN="target/release/aegaeon-server"
	if [ ! -x "$SERVER_BIN" ]; then
		echo "[perf] server binary missing at $SERVER_BIN" >&2
		exit 1
	fi

	echo "[perf] launching server..."
	env -u BASE_URL AEGAEON_RUNTIME_ISSUER_HOST="$RUNTIME_ISSUER_HOST" \
		"$SERVER_BIN" --host "$SERVER_HOST" --port "$SERVER_PORT" >"$SERVER_LOG" 2>&1 &
	SERVER_PID=$!
fi

echo "[perf] waiting for health endpoint at ${BASE_URL}/health..."
for attempt in $(seq 1 30); do
	if curl -fsS "${BASE_URL%/}/health" >/dev/null 2>&1; then
		break
	fi
	if [ "$attempt" -eq 30 ]; then
		echo "[perf] server failed to report healthy after 30s" >&2
		exit 1
	fi
	sleep 1
done

echo "[perf] running load test (workers=${WORKERS}, rps=${RPS}, scenario=${SCENARIO})..."
LOADTEST_STATUS=0
cargo run --release -p aegaeon-loadtest -- \
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
	exit "${LOADTEST_STATUS:-1}"
fi

mkdir -p "$(dirname "$LEGACY_REPORT")"
if [ "$REPORT_PATH" = "$LEGACY_REPORT" ]; then
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
