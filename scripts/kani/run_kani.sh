#!/usr/bin/env bash
# Wrapper script for running Kani with proper configuration
# Works around the panic_unwind issue

set -euo pipefail

# Resolve repository root to place sandbox-friendly state/cache directories
REPO_ROOT="$(
	git rev-parse --show-toplevel 2>/dev/null || {
		cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
	}
)"

# Load Kani runner configuration from kani.toml.
#
# NOTE: Kani does not auto-load this file; the wrapper script translates it into
# `cargo kani` flags. Environment variables override the file.
KANI_CONFIG_FILE="${AEG_KANI_CONFIG:-$REPO_ROOT/kani.toml}"
if [ ! -f "$KANI_CONFIG_FILE" ]; then
	echo "[KANI] ERROR: missing config file: $KANI_CONFIG_FILE" >&2
	exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "[KANI] ERROR: python3 is required to parse $KANI_CONFIG_FILE" >&2
	exit 1
fi

KANI_CONFIG_SH="$(mktemp -t kani-config-XXXXXX.sh)"
python3 - "$KANI_CONFIG_FILE" >"$KANI_CONFIG_SH" <<'PY'
import sys

try:
    import tomllib  # Python 3.11+
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"tomllib unavailable: {exc}")


def bash_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def bash_bool(value: object, *, key: str) -> str:
    if not isinstance(value, bool):
        raise SystemExit(f"expected bool for {key}, got {type(value).__name__}")
    return "1" if value else "0"


def bash_int(value: object, *, key: str) -> str:
    if not isinstance(value, int):
        raise SystemExit(f"expected int for {key}, got {type(value).__name__}")
    return str(value)


def require(table: dict, key: str, *, where: str) -> object:
    if key not in table:
        raise SystemExit(f"missing required key: {where}.{key}")
    return table[key]


path = sys.argv[1]
with open(path, "rb") as f:
    cfg = tomllib.load(f)

kani = cfg.get("kani")
if not isinstance(kani, dict):
    raise SystemExit("missing or invalid [kani] table")

timeouts = cfg.get("timeouts")
if not isinstance(timeouts, dict):
    raise SystemExit("missing or invalid [timeouts] table")

suites = cfg.get("suites")
if not isinstance(suites, dict):
    raise SystemExit("missing or invalid [suites] table")

server = cfg.get("server")
if not isinstance(server, dict):
    raise SystemExit("missing or invalid [server] table")

suite_default = require(suites, "default", where="suites")
if not isinstance(suite_default, str):
    raise SystemExit("suites.default must be a string")

smoke = suites.get("smoke")
regression = suites.get("regression")
if not isinstance(smoke, dict) or not isinstance(regression, dict):
    raise SystemExit("missing [suites.smoke] and/or [suites.regression] tables")

smoke_h = require(smoke, "harnesses", where="suites.smoke")
regression_h = require(regression, "harnesses", where="suites.regression")
server_h = require(server, "harnesses", where="server")

for name, harnesses in [
    ("suites.smoke.harnesses", smoke_h),
    ("suites.regression.harnesses", regression_h),
    ("server.harnesses", server_h),
]:
    if not isinstance(harnesses, list) or not all(isinstance(x, str) for x in harnesses):
        raise SystemExit(f"{name} must be an array of strings")

print(f"KANI_CFG_SOLVER={bash_quote(str(require(kani,'solver',where='kani')))}")
print(f"KANI_CFG_JOBS={bash_int(require(kani,'jobs',where='kani'), key='kani.jobs')}")
print(
    f"KANI_CFG_DEFAULT_UNWIND={bash_int(require(kani,'default_unwind',where='kani'), key='kani.default_unwind')}"
)
print(f"KANI_CFG_EXTRA_FLAGS={bash_quote(str(require(kani,'extra_flags',where='kani')))}")
print(f"KANI_CFG_PANIC={bash_quote(str(require(kani,'panic',where='kani')))}")
print(f"KANI_CFG_VMEM_LIMIT_MB={bash_int(require(kani,'vmem_limit_mb',where='kani'), key='kani.vmem_limit_mb')}")

print(
    f"KANI_CFG_TIMEOUT_HARNESS_SECS={bash_int(require(timeouts,'harness_secs',where='timeouts'), key='timeouts.harness_secs')}"
)
print(
    f"KANI_CFG_TIMEOUT_SERVER_SECS={bash_int(require(timeouts,'server_harness_secs',where='timeouts'), key='timeouts.server_harness_secs')}"
)

print(f"KANI_CFG_SUITE_DEFAULT={bash_quote(suite_default)}")
print(f"KANI_CFG_SERVER_ENABLED_DEFAULT={bash_bool(require(server,'enabled_default',where='server'), key='server.enabled_default')}")

print(
    "KANI_CFG_SUITE_SMOKE_HARNS=("
    + " ".join(bash_quote(x) for x in smoke_h)
    + ")"
)
print(
    "KANI_CFG_SUITE_REGRESSION_HARNS=("
    + " ".join(bash_quote(x) for x in regression_h)
    + ")"
)
print(
    "KANI_CFG_SERVER_HARNS=(" + " ".join(bash_quote(x) for x in server_h) + ")"
)
PY

# shellcheck source=/dev/null
source "$KANI_CONFIG_SH"
rm -f "$KANI_CONFIG_SH"

# Avoid WASI toolchains leaking into native builds (FFI C code needs a native compiler).
if [[ ${CC:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CC
fi
if [[ ${CXX:-} == *"wasm32-unknown-wasi"* ]]; then
	unset CXX
fi
if [[ -z ${CC:-} ]] && command -v cc >/dev/null 2>&1; then
	CC="$(command -v cc)"
	export CC
fi
if [[ -z ${CXX:-} ]] && command -v c++ >/dev/null 2>&1; then
	CXX="$(command -v c++)"
	export CXX
fi

# Prepare artifact/log destinations
LOG_DIR="$REPO_ROOT/artifacts/kani"
mkdir -p "$LOG_DIR"
RUN_ID="$(date +%Y%m%dT%H%M%S)"
LOG_FILE="$LOG_DIR/run_${RUN_ID}.log"
SUMMARY_FILE="$LOG_DIR/report.json"
HISTORY_FILE="$LOG_DIR/report.log"
LOG_FILE_REL="${LOG_FILE#"$REPO_ROOT"/}"

# Mirror stdout/stderr to a timestamped log file for reproducibility
exec > >(tee "$LOG_FILE") 2>&1

echo "[KANI] Writing detailed log to $LOG_FILE_REL"

# Track harness results for machine-readable summaries.
# Note: Under `set -u`, associative arrays must be initialised (e.g. `=()`)
# before `${#arr[@]}` / `${!arr[@]}` expansions are safe.
declare -A HARNESS_RESULTS=()
declare -A SERVER_HARNESS_RESULTS=()
GLOBAL_STATUS="success"
SERVER_RUN_MODE="skipped"

# Ensure XDG state/cache dirs stay inside the repository when not provided
if [ -z "${XDG_STATE_HOME:-}" ]; then
	export XDG_STATE_HOME="$REPO_ROOT/artifacts/kani/xdg-state"
fi
if [ -z "${XDG_CACHE_HOME:-}" ]; then
	export XDG_CACHE_HOME="$REPO_ROOT/artifacts/kani/xdg-cache"
fi
mkdir -p "$XDG_STATE_HOME" "$XDG_CACHE_HOME"

echo "Running Kani verification (toolchain-aware)…"

# Place a soft virtual-memory ceiling on the CBMC processes spawned by cargo-kani.
# Prevents runaway SAT solving from exhausting physical RAM; override or disable
# by exporting AEG_KANI_VMEM_LIMIT_MB=0 before invoking this script.
AEG_KANI_VMEM_LIMIT_MB="${AEG_KANI_VMEM_LIMIT_MB:-${KANI_CFG_VMEM_LIMIT_MB}}"
if [ "$AEG_KANI_VMEM_LIMIT_MB" -gt 0 ] 2>/dev/null; then
	AEG_KANI_VMEM_LIMIT_KB=$((AEG_KANI_VMEM_LIMIT_MB * 1024))
	if ulimit -Sv "$AEG_KANI_VMEM_LIMIT_KB" 2>/dev/null; then
		echo "Applying virtual memory cap: ${AEG_KANI_VMEM_LIMIT_MB} MiB"
	else
		echo "[KANI] WARN: ulimit -Sv not supported; continuing without memory cap" >&2
	fi
fi

# Limit default loop unwinding so that symbolic loops remain tractable.
export KANI_DEFAULT_UNWIND=${KANI_DEFAULT_UNWIND:-${KANI_CFG_DEFAULT_UNWIND}}

# Prefer Kani-bundled cargo to avoid toolchain mismatch
if [ -n "${KANI_HOME:-}" ] && [ -x "$KANI_HOME/toolchain/bin/cargo" ]; then
	CARGO_KANI="$KANI_HOME/toolchain/bin/cargo"
	# Ensure Kani selects its bundled rustc, not the shell's RUSTC override
	export PATH="$KANI_HOME/toolchain/bin:$PATH"
	unset RUSTC
	unset CARGO
else
	CARGO_KANI="cargo"
fi

# Ensure a stable cargo binary is always available to cargo-kani's metadata calls
if ! command -v cargo >/dev/null 2>&1; then
	echo "Error: cargo not found in PATH" >&2
	exit 1
fi
KANI_TMP_WRAPPER=$(mktemp -d -t kani-cargo-XXXXXX)
trap 'rm -rf "$KANI_TMP_WRAPPER"' EXIT
ln -sf "$(command -v cargo)" "$KANI_TMP_WRAPPER/cargo"
export PATH="$KANI_TMP_WRAPPER:$PATH"
CARGO="$(command -v cargo)"
export CARGO

# Capture toolchain versions for reporting
KANI_VERSION="$("$CARGO_KANI" kani --version 2>/dev/null | head -n1 || echo "cargo-kani unknown")"
CBMC_VERSION="$(cbmc --version 2>/dev/null | head -n1 || echo "cbmc unknown")"
echo "[KANI] Tool versions -> ${KANI_VERSION}; ${CBMC_VERSION}"

# Select panic strategy; default to abort for Kani 0.65.0 sysroot
# Note: Avoid '-Z build-std' since the bundled rustc may not support it.
# Also, ignore any pre-existing RUSTFLAGS to prevent duplicate/empty args.
unset RUSTFLAGS
AEG_KANI_PANIC="${AEG_KANI_PANIC:-${KANI_CFG_PANIC}}"
if [ "$AEG_KANI_PANIC" = "unwind" ]; then
	export RUSTFLAGS="-C panic=unwind"
	echo "Using panic=unwind"
else
	export RUSTFLAGS="-C panic=abort -Z panic-abort-tests"
	echo "Using panic=abort"
fi
export RUSTFLAGS="$RUSTFLAGS --cfg kani"

export KANI_LOG=${KANI_LOG:-info}
export KANI_CONCURRENCY=${KANI_CONCURRENCY:-1}

# When running inside a Nix build sandbox, network access is unavailable.
# Force cargo to operate offline instead of skipping verification.
if [ -n "${NIX_BUILD_TOP:-}" ]; then
	echo "[KANI] Detected Nix build sandbox; forcing cargo offline mode"
	export CARGO_NET_OFFLINE=true
fi

# Run Kani with timeout
# Run Kani on the minimal harness crate to avoid heavy deps
KANIDIR="${REPO_ROOT}/crates/kani-harness"
if [ ! -d "$KANIDIR" ]; then
	if [ -d "crates/kani-harness" ]; then
		KANIDIR="$(pwd)/crates/kani-harness"
	elif [ -d "$PWD/crates/kani-harness" ]; then
		KANIDIR="$PWD/crates/kani-harness"
	fi
fi
if ! pushd "$KANIDIR" >/dev/null 2>&1; then
	echo "[KANI] WARN: crates/kani-harness missing; skipping Kani harnesses" >&2
	exit 0
fi

# Offline shim mode (enabled via env var)
if [ "${AEG_KANI_OFFLINE_SHIM:-}" = "1" ]; then
	echo "[KANI] OFFLINE SHIM mode: compile-only (no verification)."
	"$CARGO_KANI" kani --only-compile
	popd >/dev/null
	echo "Kani shim compile-only path completed"
	exit 0
fi
# Try running individual harness functions by name to avoid relying on macros.
# Use a suite selector so CI can run a thicker regression set without forcing
# heavy runs in every environment.
AEG_KANI_SUITE="${AEG_KANI_SUITE:-${KANI_CFG_SUITE_DEFAULT}}"
case "$AEG_KANI_SUITE" in
smoke)
	HARNS=("${KANI_CFG_SUITE_SMOKE_HARNS[@]}")
	;;
regression)
	HARNS=("${KANI_CFG_SUITE_REGRESSION_HARNS[@]}")
	;;
*)
	echo "[KANI] ERROR: unknown AEG_KANI_SUITE=$AEG_KANI_SUITE (expected: smoke|regression)" >&2
	exit 1
	;;
esac

echo "[KANI] Harness suite: $AEG_KANI_SUITE (${#HARNS[@]} harnesses)"

# Per-harness timeout (seconds). Protects CI from hanging on accidental heavy harnesses.
AEG_KANI_HARNESS_TIMEOUT_SECS="${AEG_KANI_HARNESS_TIMEOUT_SECS:-${KANI_CFG_TIMEOUT_HARNESS_SECS}}"
# Server harnesses are compiled from the full `crates/server` crate (plus deps),
# which can exceed the per-harness timeout on CI runners when the first harness
# triggers a cold build. Use a separate (larger) timeout for those invocations.
AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS="${AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS:-${KANI_CFG_TIMEOUT_SERVER_SECS}}"
if [ -n "${NIX_BUILD_TOP:-}" ]; then
	if [[ ! $AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS =~ ^[0-9]+$ ]]; then
		echo "[KANI] WARN: non-numeric AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS=$AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS; using 600" >&2
		AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS=600
	elif [ "$AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS" -lt 600 ]; then
		AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS=600
	fi
fi
KANI_EXTRA_FLAGS=${KANI_EXTRA_FLAGS:-${KANI_CFG_EXTRA_FLAGS}}
AEG_KANI_SOLVER="${AEG_KANI_SOLVER:-${KANI_CFG_SOLVER}}"
AEG_KANI_JOBS="${AEG_KANI_JOBS:-${KANI_CFG_JOBS}}"

# shellcheck disable=SC2206
EXTRA_ARR=($KANI_EXTRA_FLAGS)
if [ -n "${AEG_KANI_SOLVER:-}" ]; then
	EXTRA_ARR+=(--solver "$AEG_KANI_SOLVER")
fi
if [[ ${AEG_KANI_JOBS:-} =~ ^[0-9]+$ ]] && [ "${AEG_KANI_JOBS:-0}" -gt 0 ]; then
	EXTRA_ARR+=(-j "$AEG_KANI_JOBS")
fi
ANY_HARNESS_SUCCESS=0
for H in "${HARNS[@]}"; do
	echo "[KANI] Running harness: $H"
	if timeout "$AEG_KANI_HARNESS_TIMEOUT_SECS" "$CARGO_KANI" kani "${EXTRA_ARR[@]}" --harness "$H"; then
		HARNESS_RESULTS["$H"]="passed"
		ANY_HARNESS_SUCCESS=1
	else
		exit_code=$?
		HARNESS_RESULTS["$H"]="failed"
		GLOBAL_STATUS="failure"
		if [ "$exit_code" -eq 124 ]; then
			HARNESS_RESULTS["$H"]="timeout"
			echo "[KANI] Harness $H timed out after ${AEG_KANI_HARNESS_TIMEOUT_SECS}s; continuing" >&2
		else
			echo "[KANI] Harness $H failed or unsupported; continuing"
		fi
	fi
done
if [ $ANY_HARNESS_SUCCESS -eq 0 ]; then
	echo "[KANI] Falling back to crate-wide cargo-kani run"
	if timeout 300 "$CARGO_KANI" kani "${EXTRA_ARR[@]}"; then
		HARNESS_RESULTS["crate_default"]="passed"
		ANY_HARNESS_SUCCESS=1
	else
		exit_code=$?
		HARNESS_RESULTS["crate_default"]="failed"
		GLOBAL_STATUS="failure"
		if [ $exit_code -eq 124 ]; then
			echo "[KANI] WARN: Kani verification timed out after 5 minutes"
		else
			echo "[KANI] ERROR: cargo kani exited with status $exit_code"
			popd >/dev/null
			exit $exit_code
		fi
	fi
fi
echo "Kani models in aegaeon-kani-harness completed"
popd >/dev/null

# Run server-side Kani harnesses (HashMap-free shims).
SERVER_DIR="${REPO_ROOT}/crates/server"
AEG_KANI_RUN_SERVER="${AEG_KANI_RUN_SERVER:-$KANI_CFG_SERVER_ENABLED_DEFAULT}"
if [ "${AEG_KANI_RUN_SERVER:-0}" != "0" ] && pushd "$SERVER_DIR" >/dev/null 2>&1; then
	SERVER_RUN_MODE="enabled"
	for H in "${KANI_CFG_SERVER_HARNS[@]}"; do
		echo "[KANI][server] Running harness: $H"
		if timeout "$AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS" "$CARGO_KANI" kani "${EXTRA_ARR[@]}" --harness "$H"; then
			echo "[KANI][server] Harness $H completed"
			SERVER_HARNESS_RESULTS["$H"]="passed"
		else
			exit_code=$?
			echo "[KANI][server] Harness $H failed or unsupported" >&2
			if [ "$exit_code" -eq 124 ]; then
				echo "[KANI][server] Harness $H timed out after ${AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS}s" >&2
				SERVER_HARNESS_RESULTS["$H"]="timeout"
			else
				SERVER_HARNESS_RESULTS["$H"]="failed"
			fi
			GLOBAL_STATUS="failure"
		fi
	done
	popd >/dev/null
elif [ "${AEG_KANI_RUN_SERVER:-0}" != "0" ]; then
	echo "[KANI] WARN: crates/server missing; skipping server harnesses" >&2
	SERVER_RUN_MODE="missing"
else
	echo "[KANI] Server harnesses skipped (set AEG_KANI_RUN_SERVER=1 to enable)"
fi

# Record results into JSON/LOG artifacts
RUN_DATE="$(date -Iseconds)"
json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	printf '%s' "$s"
}

write_json_kv_map() {
	local -n _map="$1"
	local indent="$2"
	local first=1
	printf '{'
	for name in $(printf '%s\n' "${!_map[@]}" | sort); do
		if [ $first -eq 1 ]; then
			first=0
		else
			printf ','
		fi
		printf '\n%s"%s": "%s"' \
			"$indent" \
			"$(json_escape "$name")" \
			"$(json_escape "${_map[$name]}")"
	done
	if [ $first -eq 0 ]; then
		printf '\n'
	fi
	printf '}'
}

{
	printf '{\n'
	printf '  "status": "%s",\n' "$(json_escape "$GLOBAL_STATUS")"
	printf '  "run_id": "%s",\n' "$(json_escape "$RUN_ID")"
	printf '  "run_date": "%s",\n' "$(json_escape "$RUN_DATE")"
	printf '  "log": "%s",\n' "$(json_escape "$LOG_FILE_REL")"
	printf '  "server_run_mode": "%s",\n' "$(json_escape "$SERVER_RUN_MODE")"
	printf '  "harnesses": %s,\n' "$(write_json_kv_map HARNESS_RESULTS '    ')"
	printf '  "server_harnesses": %s,\n' "$(write_json_kv_map SERVER_HARNESS_RESULTS '    ')"
	printf '  "toolchain": {\n'
	printf '    "kani": "%s",\n' "$(json_escape "${KANI_VERSION:-unknown}")"
	printf '    "cbmc": "%s"\n' "$(json_escape "${CBMC_VERSION:-unknown}")"
	printf '  }\n'
	printf '}\n'
} >"$SUMMARY_FILE"

{
	printf '%s status=%s log=%s\n' "$RUN_DATE" "$GLOBAL_STATUS" "$LOG_FILE_REL"
	if [ ${#HARNESS_RESULTS[@]} -gt 0 ]; then
		printf '  harnesses:\n'
		for name in $(printf '%s\n' "${!HARNESS_RESULTS[@]}" | sort); do
			printf '    - %s: %s\n' "$name" "${HARNESS_RESULTS[$name]}"
		done
	fi
	if [ ${#SERVER_HARNESS_RESULTS[@]} -gt 0 ]; then
		printf '  server_harnesses:\n'
		for name in $(printf '%s\n' "${!SERVER_HARNESS_RESULTS[@]}" | sort); do
			printf '    - %s: %s\n' "$name" "${SERVER_HARNESS_RESULTS[$name]}"
		done
	fi
	printf '\n'
} >>"$HISTORY_FILE"

if [ "$GLOBAL_STATUS" != "success" ]; then
	echo "Kani verification completed with failures" >&2
	exit 1
fi

echo "Kani verification completed successfully"
