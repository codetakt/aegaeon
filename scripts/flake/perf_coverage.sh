#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

OUTPUT_DIR="${COVERAGE_HTML_DIR:-artifacts/perf/coverage}"
mkdir -p "$OUTPUT_DIR"

cargo llvm-cov --workspace --html --output-dir "$OUTPUT_DIR" "$@"

LEGACY_DIR="target/llvm-cov/html"
mkdir -p "$(dirname "$LEGACY_DIR")"
rm -rf "$LEGACY_DIR"
ln -sfn "$(realpath "$OUTPUT_DIR")" "$LEGACY_DIR"

echo "[perf] coverage report available at $OUTPUT_DIR/index.html"
