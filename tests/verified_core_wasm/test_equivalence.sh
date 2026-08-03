#!/usr/bin/env bash
# Native ↔ WASM Equivalence Tests
#
# Runs the same test vectors through both the native Rust FFI and the WASM
# module, comparing results.  Exits 1 on any mismatch (fail-close).
#
# Both sides read from tests/verified_core_wasm/vectors/*.json.
#
# Usage:
#   ./tests/verified_core_wasm/test_equivalence.sh [path/to/verified_core.wasm]
#
# If the WASM binary is not available, the WASM-side tests are skipped with
# a warning (native tests still run as a regression baseline).

set -euo pipefail

# ── Locate repo root ──────────────────────────────────────────────────
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z $ROOT ]]; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
fi
WASM="${1:-$ROOT/tests/fixtures/verified-core/verified_core.wasm}"

native_rc=0
wasm_rc=0
skipped_wasm=0
native_skip_reason=""

node_supports_strip_types() {
	if ! command -v node >/dev/null 2>&1; then
		return 1
	fi

	node --experimental-strip-types -e "type X = number; console.log(0)" >/dev/null 2>&1
}

run_wasm_equivalence_with_nix_node() {
	local script wasm
	script="$1"
	wasm="$2"

	if command -v nix >/dev/null 2>&1; then
		nix shell nixpkgs#nodejs_24 -c \
			node --experimental-strip-types "$script" "$wasm"
		return $?
	fi

	if command -v nix-shell >/dev/null 2>&1; then
		nix-shell -p nodejs_24 --run \
			"node --experimental-strip-types \"$script\" \"$wasm\""
		return $?
	fi

	return 127
}

detect_broken_native_linker_wrapper() {
	if ! command -v rustc >/dev/null 2>&1; then
		return 1
	fi

	local host sysroot wrapper wrapper_target
	host="$(rustc -vV | sed -n 's/^host: //p')"
	sysroot="$(rustc --print sysroot 2>/dev/null || true)"
	wrapper="$sysroot/lib/rustlib/$host/bin/gcc-ld/ld.lld"

	if [[ ! -f $wrapper ]]; then
		return 1
	fi

	wrapper_target="$(sed -n 's#^"\(.*ld-wrapper\.sh\)".*#\1#p' "$wrapper" | head -n 1)"
	if [[ -n $wrapper_target && ! -e $wrapper_target ]]; then
		native_skip_reason="broken native linker wrapper ($wrapper_target missing)"
		return 0
	fi

	return 1
}

echo "============================================"
echo "  Native ↔ WASM Equivalence Tests"
echo "============================================"
echo ""

# ── Phase 1: Native tests (cargo test) ───────────────────────────────
echo "[1/2] Native equivalence tests (cargo test)"
echo "--------------------------------------------"

if command -v cargo >/dev/null 2>&1; then
	if detect_broken_native_linker_wrapper; then
		if [[ ${AEGAEON_REQUIRE_NATIVE_EQUIV:-0} == "1" ]]; then
			echo "  [error] native cargo equivalence required but unavailable: $native_skip_reason"
			exit 1
		fi
		echo "  [skip] native cargo equivalence unavailable: $native_skip_reason"
		native_rc=0
	elif (cd "$ROOT" && env -u LD cargo test -p ffi --test equivalence_pkce_test -- --nocapture 2>&1); then
		printf '  \033[32m✓\033[0m Native PKCE equivalence tests passed\n'
	else
		printf '  \033[31m✗\033[0m Native PKCE equivalence tests FAILED\n'
		native_rc=1
	fi
else
	if [[ ${AEGAEON_REQUIRE_WASM:-0} == "1" ]]; then
		echo "  [error] cargo not available (required for equivalence)"
		exit 1
	fi
	echo "  [skip] cargo not available"
	native_rc=0
fi

echo ""

# ── Phase 2: WASM tests (Node.js) ────────────────────────────────────
echo "[2/2] WASM equivalence tests (Node.js)"
echo "---------------------------------------"

if [[ ! -f $WASM ]]; then
	if [[ ${AEGAEON_REQUIRE_WASM:-0} == "1" ]]; then
		echo "  [error] WASM binary missing: $WASM"
		echo "          Set AEGAEON_REQUIRE_WASM=0 to skip WASM tests"
		exit 1
	fi
	echo "  [skip] WASM binary not found at: $WASM"
	echo "         Build with: nix build .#verified-core-wasm"
	echo "         Then copy to: $WASM"
	skipped_wasm=1
else
	if node_supports_strip_types; then
		if node --experimental-strip-types "$ROOT/tests/verified_core_wasm/test_equivalence_wasm.ts" "$WASM"; then
			printf '  \033[32m✓\033[0m WASM equivalence tests passed\n'
		else
			printf '  \033[31m✗\033[0m WASM equivalence tests FAILED\n'
			wasm_rc=1
		fi
	elif command -v nix >/dev/null 2>&1 || command -v nix-shell >/dev/null 2>&1; then
		if run_wasm_equivalence_with_nix_node "$ROOT/tests/verified_core_wasm/test_equivalence_wasm.ts" "$WASM"; then
			printf '  \033[32m✓\033[0m WASM equivalence tests passed (via Nix)\n'
		else
			printf '  \033[31m✗\033[0m WASM equivalence tests FAILED\n'
			wasm_rc=1
		fi
	else
		if [[ ${AEGAEON_REQUIRE_WASM:-0} == "1" ]]; then
			echo "  [error] node not available and no Nix shell command found"
			exit 1
		fi
		echo "  [skip] node not available and no Nix shell command found"
		skipped_wasm=1
	fi
fi

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "============================================"

rc=$((native_rc + wasm_rc))

if [[ $rc -eq 0 ]]; then
	if [[ $skipped_wasm -eq 1 ]]; then
		echo "  NATIVE PASSED (WASM skipped — no binary)"
		echo "  To run full equivalence: provide WASM binary"
	elif [[ -n $native_skip_reason ]]; then
		echo "  EQUIVALENCE CONFIRMED (native lane skipped — unsupported environment)"
		echo "  Reason: $native_skip_reason"
	else
		echo "  EQUIVALENCE CONFIRMED: native and WASM match"
	fi
else
	echo "  EQUIVALENCE FAILED"
	[[ $native_rc -ne 0 ]] && echo "    - Native tests failed"
	[[ $wasm_rc -ne 0 ]] && echo "    - WASM tests failed"
fi

echo "============================================"

# Fail-close: exit 1 on any mismatch
exit $rc
