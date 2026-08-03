#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

mkdir -p artifacts/lowstar
LOG="${LOWSTAR_LOG:-artifacts/lowstar/run.log}"
: >"$LOG"

{
	echo "=== Low* extraction ($(date -u +"%Y-%m-%dT%H:%M:%SZ")) ==="
	./scripts/extraction/run_jose_lowstar.sh "$@"
	echo
	echo "=== Verifying committed artefacts ==="

	status=$(
		git status --short --untracked-files=all \
			generated/everparse \
			generated/lowstar \
			artifacts/karamel 2>/dev/null || true
	)
	if [ -n "$status" ]; then
		echo "Detected changes in generated extraction artefacts:" >&2
		printf "%s\n" "$status" >&2
		git diff -- generated/everparse generated/lowstar artifacts/karamel \
			>artifacts/lowstar/diff.patch || true
		exit 1
	fi

	git diff --stat generated/everparse generated/lowstar artifacts/karamel >/dev/null || {
		git diff -- generated/everparse generated/lowstar artifacts/karamel \
			>artifacts/lowstar/diff.patch || true
		exit 1
	}

	legacy=$(
		rg -n 'EverParseErrorFrame|EverParseInputBuffer|EverParseDefaultErrorHandler_Impl' \
			generated/everparse/*Wrapper.c || true
	)
	if [ -n "$legacy" ]; then
		echo "Found EverParse wrapper using legacy compatibility aliases" >&2
		printf "%s\n" "$legacy" >&2
		exit 1
	fi

	missing=$(
		rg --files-without-match -- 'uint64_t error_code' generated/everparse/*Wrapper.c || true
	)
	if [ -n "$missing" ]; then
		echo "Found EverParse wrapper missing error_code parameter" >&2
		printf "%s\n" "$missing" >&2
		exit 1
	fi

	echo "[OK] Extraction artefacts match the repository"
} | tee -a "$LOG"
