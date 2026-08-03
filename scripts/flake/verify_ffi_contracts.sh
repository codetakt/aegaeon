#!/usr/bin/env bash
# Nix-wrapped FFI contract drift detection.
set -euo pipefail

LOG="${OUT_DIR:+${OUT_DIR}/verify.log}"
bash scripts/validation/verify_ffi_contracts.sh 2>&1 | tee "${LOG:-/dev/fd/1}"
