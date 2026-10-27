#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"
if [[ $# -gt 1 || (${1:-pr} != pr && ${1:-pr} != periodic) ]]; then
	echo "usage: dudect_check.sh [pr|periodic]" >&2
	exit 2
fi
binary_package="$(nix build .#dudect-check --no-link --print-out-paths -L)"
if [[ ! -f "$binary_package/package.json" ]]; then
	echo "Missing native dudect package" >&2
	exit 1
fi
# A cached build can supply the executable, never the runtime decision.
exec nix develop .#verification --command python3 tests/constant_time/run_contract.py \
	--suite nix --native-package "$binary_package" --profile "${1:-pr}"
