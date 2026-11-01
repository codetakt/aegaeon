#!/usr/bin/env bash
# Run all Verified Core WASM smoke tests.
#
# Usage:
#   ./tests/verified_core_wasm/run_all.sh [path/to/verified_core.wasm]
#
# If wabt/xxd/openssl are not in PATH, attempts to use nix-shell.

set -euo pipefail

# Prefer git root; fall back to script-relative path for non-git environments
# (tarball, Nix build, CI source copy).
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z $ROOT ]]; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
fi
WASM="${1:-$ROOT/tests/fixtures/verified-core/verified_core.wasm}"
TEST_DIR="$ROOT/tests/verified_core_wasm"

echo "============================================"
echo "  Verified Core WASM — Full Test Suite"
echo "============================================"
echo ""

rc=0

# Ambient Node must meet the same major/security floor as the pinned shell.
have_supported_node() {
	command -v node >/dev/null 2>&1 || return 1
	node -e 'const match = /^26\.(\d+)\.(\d+)$/.exec(process.versions.node); process.exit(match && (Number(match[1]) >= 13) ? 0 : 1)'
}

# Select one environment for the entire suite, including the equivalence child.
# A missing/unsupported runtime must never silently remove required Node stages.
if ! have_supported_node || ! command -v npm >/dev/null 2>&1; then
	if [[ ${AEGAEON_WASM_NIX_REENTRY:-0} != 1 ]] && command -v nix >/dev/null 2>&1; then
		export AEGAEON_WASM_NIX_REENTRY=1
		exec nix develop "$ROOT#typescript" --command bash "$TEST_DIR/run_all.sh" "$@"
	fi
	echo "[error] Node >=26.13.0 <27 and npm are required; pinned fallback unavailable" >&2
	exit 1
fi

echo "[1/13] Structural smoke tests (wasm-objdump)"
echo "--------------------------------------------"
if command -v wasm-objdump >/dev/null 2>&1 && command -v xxd >/dev/null 2>&1; then
	bash "$TEST_DIR/smoke_test.sh" "$WASM" || rc=1
elif command -v nix-shell >/dev/null 2>&1; then
	if nix-shell -p wabt openssl xxd --run "command -v wasm-objdump >/dev/null 2>&1 && command -v xxd >/dev/null 2>&1" >/dev/null 2>&1; then
		nix-shell -p wabt openssl xxd --run "bash $TEST_DIR/smoke_test.sh $WASM" || rc=1
	else
		echo "  [skip] wabt/xxd unavailable via nix-shell in this environment"
	fi
else
	echo "  [skip] wabt/xxd not available and nix-shell not found"
fi

echo ""
echo "[2/13] Functional instantiation tests (Node.js)"
echo "-----------------------------------------------"
node --experimental-strip-types "$TEST_DIR/test_instantiate.ts" "$WASM" || rc=1

echo ""
echo "[3/13] Native ↔ WASM equivalence tests"
echo "--------------------------------------"
bash "$TEST_DIR/test_equivalence.sh" "$WASM" || rc=1

echo ""
echo "[4/13] Reference runtime adapter tests (Node)"
echo "--------------------------------------"
node --experimental-strip-types "$TEST_DIR/runtime_node_reference_test.ts" || rc=1

echo ""
echo "[5/13] Web reference adapter API tests"
echo "----------------------------------"
node --experimental-strip-types "$TEST_DIR/runtime_web_reference_test.ts" || rc=1

echo ""
echo "[6/13] Browser runtime-web smoke tests"
echo "--------------------------------------"
node --experimental-strip-types "$TEST_DIR/runtime_web_browser_smoke_test.ts" || rc=1

echo ""
echo "[7/13] Packaging / signature tests"
echo "---------------------------------"
node --experimental-strip-types "$TEST_DIR/package_dist_test.ts" || rc=1

echo ""
echo "[8/13] Staged SDK workspace tests"
echo "--------------------------------"
node --experimental-strip-types "$TEST_DIR/staged_sdk_workspace_test.ts" || rc=1

echo ""
echo "[9/13] Publishable SDK package tests"
echo "-----------------------------------"
node --experimental-strip-types "$TEST_DIR/publishable_sdk_package_test.ts" || rc=1

echo ""
echo "[10/13] Verified Core public-key helper tests"
echo "---------------------------------------------"
node --experimental-strip-types "$TEST_DIR/verified_core_public_key_materialization_test.ts" || rc=1

echo ""
echo "[11/13] SDK repo scaffold tests"
echo "------------------------------"
node --experimental-strip-types "$TEST_DIR/scaffold_sdk_repo_test.ts" || rc=1

echo ""
echo "[12/13] SDK repository dispatch payload tests"
echo "---------------------------------------------"
node --experimental-strip-types "$TEST_DIR/sdk_repository_dispatch_payload_test.ts" || rc=1

echo ""
echo "[13/13] Verified Core handoff manifest tests"
echo "---------------------------------------------"
node --experimental-strip-types "$TEST_DIR/verified_core_handoff_manifest_test.ts" || rc=1

echo ""
if [[ $rc -eq 0 ]]; then
	echo "============================================"
	echo "  ALL TESTS PASSED"
	echo "============================================"
else
	echo "============================================"
	echo "  SOME TESTS FAILED"
	echo "============================================"
fi

exit $rc
