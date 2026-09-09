#!/usr/bin/env bash
# Thin wrapper over the Kani evidence runner for local use.
#
#   scripts/kani/run_kani.sh                      # full scope (required + diagnostic), writes gate.json
#   scripts/kani/run_kani.sh --scope diagnostic   # diagnostic groups only, never writes gate.json
#   scripts/kani/run_kani.sh --scope partial --groups ffi-evidence
#   scripts/kani/run_kani.sh --baseline <earlier evaluation.json>   # report-only property-set comparison
#
# The selection lives in spec/kani-evidence.json. The former kani.toml suites and the
# AEG_KANI_* / KANI_* environment knobs are retired: they selected harnesses and accepted
# results by exit status, which the admission contract no longer allows.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || {
	cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
})"
cd "$REPO_ROOT"

retired=(AEG_KANI_SUITE AEG_KANI_RUN_SERVER AEG_KANI_OFFLINE_SHIM AEG_KANI_SOLVER AEG_KANI_JOBS
	AEG_KANI_PANIC AEG_KANI_HARNESS_TIMEOUT_SECS AEG_KANI_SERVER_HARNESS_TIMEOUT_SECS
	AEG_KANI_VMEM_LIMIT_MB AEG_KANI_VMEM_LIMIT_KB AEG_KANI_CONFIG KANI_EXTRA_FLAGS)
for name in "${retired[@]}"; do
	if [ -n "${!name:-}" ]; then
		echo "[KANI] ERROR: $name is retired; edit spec/kani-evidence.json and use --scope/--groups instead" >&2
		exit 2
	fi
done

if ! command -v cargo-kani >/dev/null 2>&1; then
	echo "[KANI] ERROR: cargo-kani not found in PATH; use nix develop .#verification" >&2
	exit 1
fi

exec python3 scripts/validation/run_kani_evidence.py "$@"
