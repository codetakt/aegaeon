#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"
exec "$ROOT/scripts/security/run_geiger.sh" "$@"
