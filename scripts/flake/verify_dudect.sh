#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"
: "${EVERCRYPT_DIST:?EVERCRYPT_DIST not set}"

source scripts/flake/dudect_output_permissions.sh

# Hosted/Nix checks exercise callbacks and evidence validators, never a timing gate.
python3 scripts/validation/test_dudect.py
python3 scripts/ci/check_dudect_functional.py --output "$OUT_DIR/functional"
