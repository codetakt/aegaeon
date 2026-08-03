#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"

if command -v act >/dev/null 2>&1; then
	act "$@"
	exit $?
fi

if command -v nix >/dev/null 2>&1; then
	nix develop .#default --command act "$@"
	exit $?
fi

echo "act is not available. Install it or run: nix develop .#default --command act ..." >&2
exit 1
