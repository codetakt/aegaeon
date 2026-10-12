#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"
: "${EVERCRYPT_DIST:?EVERCRYPT_DIST not set}"

source scripts/flake/dudect_output_permissions.sh

# Build-time observations are retained here; CI still collects afresh.
status=0
python3 tests/constant_time/run_contract.py --suite nix --profile pr \
	--output "$OUT_DIR/evidence" >"$OUT_DIR/dudect.log" 2>&1 || status=$?
cat "$OUT_DIR/dudect.log"
exit "$status"
