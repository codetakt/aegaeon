#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
exec nix run "$ROOT#perf-load" -- "$@"
