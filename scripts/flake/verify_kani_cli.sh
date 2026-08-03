#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

if [ ! -f scripts/kani/run_kani.sh ]; then
	echo "scripts/kani/run_kani.sh not found in $ROOT" >&2
	exit 1
fi

export AEG_KANI_SUITE="${AEG_KANI_SUITE:-regression}"
export AEG_KANI_RUN_SERVER="${AEG_KANI_RUN_SERVER:-1}"

if command -v cargo-kani >/dev/null 2>&1; then
	kani_bin="$(dirname "$(command -v cargo-kani)")"
	kani_root="$(cd "$kani_bin/.." && pwd)"
	export PATH="$kani_root/bin:$kani_root/toolchain/bin:$PATH"
else
	echo "cargo-kani not found in PATH" >&2
	exit 1
fi

exec bash scripts/kani/run_kani.sh
