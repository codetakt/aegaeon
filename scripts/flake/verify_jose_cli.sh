#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/verify-jose.XXXXXX")
trap 'rm -rf "$OUT_DIR"' EXIT

export OUT_DIR

exec bash scripts/flake/verify_jose_check.sh
