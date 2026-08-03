#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

echo "[verify] running nix flake check..."
nix flake check --print-build-logs

echo "[verify] running security suite..."
nix run .#security-suite -- "$@"
