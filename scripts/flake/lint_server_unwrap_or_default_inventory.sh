#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
inventory="$script_dir/server_unwrap_or_default_inventory.allowlist"

actual="$(mktemp)"
expected="$(mktemp)"
trap 'rm -f "$actual" "$expected"' EXIT

cd "$repo_root"

{
	rg -N "unwrap_or_default" crates/server/src || true
} | LC_ALL=C sort >"$actual"

{
	grep -vE '^[[:space:]]*(#|$)' "$inventory" || true
} | LC_ALL=C sort >"$expected"

if ! diff -u "$expected" "$actual"; then
	cat >&2 <<'MSG'
Unexpected aegaeon-server unwrap_or_default inventory drift.

Review each new/defaulted call site for fail-closed behavior. If it is intentional,
document it in scripts/flake/server_unwrap_or_default_inventory.allowlist.
MSG
	exit 1
fi
