#!/usr/bin/env bash
# Run Kani checks and capture logs for CI

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

LOG_DIR="artifacts/kani/ci"
LOG_FILE="$LOG_DIR/kani_ci.log"
REPORT_FILE="$LOG_DIR/status.txt"

mkdir -p "$LOG_DIR"

if bash scripts/kani/run_kani.sh >"$LOG_FILE" 2>&1; then
	echo "Kani verification succeeded (see $LOG_FILE)" >"$REPORT_FILE"
else
	echo "Kani verification failed (see $LOG_FILE)" >"$REPORT_FILE"
	exit 1
fi
