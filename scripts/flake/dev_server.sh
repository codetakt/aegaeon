#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

if [ -z "${AEGAEON_DATABASE_URL:-}" ]; then
	echo "[dev] AEGAEON_DATABASE_URL is required" >&2
	exit 2
fi
if [ -z "${AEGAEON_RUNTIME_ISSUER_HOST:-}" ]; then
	echo "[dev] AEGAEON_RUNTIME_ISSUER_HOST is required" >&2
	exit 2
fi

echo "[dev] starting aegaeon-server..."
exec env -u BASE_URL cargo run --bin aegaeon-server "$@"
