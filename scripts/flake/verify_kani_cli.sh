#!/usr/bin/env bash
# `nix run .#verify-kani`: the same gate as the derivation, from a checkout with the pinned
# Kani toolchain on PATH.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

if ! command -v cargo-kani >/dev/null 2>&1; then
	echo "cargo-kani not found in PATH" >&2
	exit 1
fi
exec bash scripts/flake/verify_kani_check.sh
