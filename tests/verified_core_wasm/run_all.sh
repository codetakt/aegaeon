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

have_nix_node24() {
	if ! command -v nix >/dev/null 2>&1; then
		return 1
	fi
	nix shell nixpkgs#nodejs_24 -c node --version >/dev/null 2>&1
}

run_with_node24() {
	nix shell nixpkgs#nodejs_24 -c node --experimental-strip-types "$@"
}

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
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/test_instantiate.ts" "$WASM" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/test_instantiate.ts" "$WASM" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[3/13] Native ↔ WASM equivalence tests"
echo "--------------------------------------"
bash "$TEST_DIR/test_equivalence.sh" "$WASM" || rc=1

echo ""
echo "[4/13] Reference runtime adapter tests (Node)"
echo "--------------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/runtime_node_reference_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/runtime_node_reference_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[5/13] Web reference adapter API tests"
echo "----------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/runtime_web_reference_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/runtime_web_reference_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[6/13] Browser runtime-web smoke tests"
echo "--------------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/runtime_web_browser_smoke_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/runtime_web_browser_smoke_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[7/13] Packaging / signature tests"
echo "---------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/package_dist_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/package_dist_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[8/13] Staged SDK workspace tests"
echo "--------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/staged_sdk_workspace_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/staged_sdk_workspace_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[9/13] Publishable SDK package tests"
echo "-----------------------------------"
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/publishable_sdk_package_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/publishable_sdk_package_test.ts" || rc=1
	else
		echo "  [skip] node/npm unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node/npm not available and nix not found"
fi

echo ""
echo "[10/13] Verified Core public-key helper tests"
echo "---------------------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/verified_core_public_key_materialization_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/verified_core_public_key_materialization_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[11/13] SDK repo scaffold tests"
echo "------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/scaffold_sdk_repo_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/scaffold_sdk_repo_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[12/13] SDK repository dispatch payload tests"
echo "---------------------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/sdk_repository_dispatch_payload_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/sdk_repository_dispatch_payload_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

echo ""
echo "[13/13] Verified Core handoff manifest tests"
echo "---------------------------------------------"
if command -v node >/dev/null 2>&1; then
	node --experimental-strip-types "$TEST_DIR/verified_core_handoff_manifest_test.ts" || rc=1
elif have_nix_node24; then
	if have_nix_node24; then
		run_with_node24 "$TEST_DIR/verified_core_handoff_manifest_test.ts" || rc=1
	else
		echo "  [skip] node unavailable via nix shell in this environment"
	fi
else
	echo "  [skip] node not available and nix not found"
fi

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
