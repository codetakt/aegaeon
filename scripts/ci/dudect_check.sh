#!/usr/bin/env bash
set -euo pipefail

# dudect CI gate — compile and run the constant-time verification harness.
# Exit 0 = ct_eq is constant-time (PASS), non-zero = leakage detected (FAIL).

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v nix >/dev/null 2>&1; then
	echo "[dudect] ERROR: nix is required for HACL*/EverCrypt-backed dudect" >&2
	exit 1
fi

echo "[dudect] Running HACL*/EverCrypt dudect via Nix ..."
cd "$REPO_ROOT"
nix build .#dudect-check -L
echo "[dudect] PASS -- no timing leakage detected"
