#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

WATCH_CMD="${DEV_WATCH_CMD:-run}"
exec cargo watch -x "$WATCH_CMD" "$@"
