#!/usr/bin/env bash
# Verified Core WASM smoke tests
#
# Validates that the WASM binary:
#   1. Is a valid WebAssembly module
#   2. Exports the required function symbols
#   3. Imports only expected host callbacks
#   4. Has a memory export
#   5. Matches the manifest hash (if manifest is present)
#
# Usage:
#   ./tests/verified_core_wasm/smoke_test.sh [path/to/verified_core.wasm]
#
# If no path is provided, uses tests/fixtures/verified-core/verified_core.wasm.

set -euo pipefail

# Prefer git root; fall back to script-relative path for non-git environments
# (tarball, Nix build, CI source copy).
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z $ROOT ]]; then
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
fi
WASM="${1:-$ROOT/tests/fixtures/verified-core/verified_core.wasm}"
MANIFEST_DIR="$(dirname "$WASM")"

passed=0
failed=0
total=0

pass() {
	total=$((total + 1))
	passed=$((passed + 1))
	printf '  \033[32m✓\033[0m %s\n' "$1"
}

fail() {
	total=$((total + 1))
	failed=$((failed + 1))
	printf '  \033[31m✗\033[0m %s\n' "$1"
}

echo "=== Verified Core WASM Smoke Tests ==="
echo "  artifact: $WASM"
echo ""

# --- Test 1: File exists and is non-empty ---
if [[ -f $WASM && -s $WASM ]]; then
	pass "WASM file exists and is non-empty ($(wc -c <"$WASM") bytes)"
else
	fail "WASM file does not exist or is empty: $WASM"
	echo ""
	echo "RESULT: $passed/$total passed ($failed failed)"
	exit 1
fi

# --- Test 2: Valid WebAssembly magic header ---
magic=$(xxd -l 4 -p "$WASM")
if [[ $magic == "0061736d" ]]; then
	pass 'Valid WebAssembly magic header (\00asm)'
else
	fail "Invalid magic header: $magic (expected 0061736d)"
fi

# --- Test 3: WebAssembly version 1 ---
version=$(xxd -s 4 -l 4 -p "$WASM")
if [[ $version == "01000000" ]]; then
	pass "WebAssembly version 1"
else
	fail "Unexpected WASM version: $version (expected 01000000)"
fi

# --- Structural tests using wasm-objdump (if available) ---
OBJDUMP=""
if command -v wasm-objdump >/dev/null 2>&1; then
	OBJDUMP="wasm-objdump"
elif [[ -n ${WABT_PREFIX:-} ]] && [[ -x "$WABT_PREFIX/bin/wasm-objdump" ]]; then
	OBJDUMP="$WABT_PREFIX/bin/wasm-objdump"
fi

if [[ -n $OBJDUMP ]]; then
	exports=$("$OBJDUMP" -x "$WASM" 2>/dev/null | sed -n '/^Export\[/,/^[A-Z]/p' || true)

	# --- Test 4: Memory export ---
	if echo "$exports" | grep -q 'memory\[0\] -> "memory"'; then
		pass "Memory export present"
	else
		fail "Missing memory export"
	fi

	# --- Test 5: Required internal API exports ---
	required_exports=(
		"VerifiedCore_dpop_verify_v1"
		"VerifiedCore_jwt_verify_v1"
		"VerifiedCore_dpop_verify_claims_v1"
		"VerifiedCore_jwt_verify_claims_v1"
	)
	for sym in "${required_exports[@]}"; do
		if echo "$exports" | grep -q "\"$sym\""; then
			pass "Export: $sym"
		else
			fail "Missing export: $sym"
		fi
	done

	# --- Test 6: PKCE function exports ---
	pkce_exports=(
		"Pkce_verifier_ok"
		"Pkce_verify_pkce"
		"Pkce_verify_pkce_s256"
	)
	for sym in "${pkce_exports[@]}"; do
		if echo "$exports" | grep -q "\"$sym\""; then
			pass "Export: $sym"
		else
			fail "Missing export: $sym"
		fi
	done

	# --- Test 7: DPoP function exports ---
	dpop_exports=(
		"Dpop_Validation_verify_dpop"
		"Dpop_Iat_validation_validate_iat"
		"Dpop_Htm_validation_validate_htm"
		"Dpop_Htu_validation_validate_htu"
		"Dpop_Ath_validation_validate_ath"
	)
	for sym in "${dpop_exports[@]}"; do
		if echo "$exports" | grep -q "\"$sym\""; then
			pass "Export: $sym"
		else
			fail "Missing export: $sym"
		fi
	done

	# --- Test 8: Claims runtime exports ---
	claims_exports=(
		"VerifiedCore_Api_Claims_Runtime_dpop_verify_claims_impl"
		"VerifiedCore_Api_Claims_Runtime_jwt_verify_claims_impl"
		"VerifiedCore_Api_Claims_Runtime_status_to_u32"
		"VerifiedCore_Api_Claims_Runtime_iat_in_window"
		"VerifiedCore_Api_Claims_Runtime_not_expired"
		"VerifiedCore_Api_Claims_Runtime_is_active"
		"VerifiedCore_Api_Claims_Runtime_try_verify_signature"
	)
	for sym in "${claims_exports[@]}"; do
		if echo "$exports" | grep -q "\"$sym\""; then
			pass "Export: $sym"
		else
			fail "Missing export: $sym"
		fi
	done

	# --- Test 9: ConstTime exports ---
	if echo "$exports" | grep -q '"ConstTime_ct_bytes_eq"'; then
		pass "Export: ConstTime_ct_bytes_eq"
	else
		fail "Missing export: ConstTime_ct_bytes_eq"
	fi

	# --- Test 10: Import validation (no unexpected imports) ---
	imports=$("$OBJDUMP" -x "$WASM" 2>/dev/null | sed -n '/^Import\[/,/^[A-Z]/p' || true)

	allowed_import_prefixes=(
		"env.FStar_"
		"env.Prims_"
		"env.Dpop_"
		"env.Pkce_"
		"env.VerifiedCore_Api_Claims_Runtime_host_"
		"env.Host_"
		"env.Hacl_"
		"env.fprintf"
		"env.exit"
		"env.vc_host_"
		"env.__eq__"
		"env.__multi3"
		"env.malloc"
		"env.calloc"
		"env.free"
		"env.strlen"
		"env.memcmp"
	)

	unexpected_imports=()
	while IFS= read -r line; do
		import_name=$(echo "$line" | grep -oP '<- \K\S+' || true)
		if [[ -z $import_name ]]; then
			continue
		fi
		is_allowed=0
		for prefix in "${allowed_import_prefixes[@]}"; do
			if [[ $import_name == "$prefix"* ]]; then
				is_allowed=1
				break
			fi
		done
		if [[ $is_allowed -eq 0 ]]; then
			unexpected_imports+=("$import_name")
		fi
	done <<<"$(echo "$imports" | grep '<-')"

	if [[ ${#unexpected_imports[@]} -eq 0 ]]; then
		pass "No unexpected imports"
	else
		fail "Unexpected imports: ${unexpected_imports[*]}"
	fi

	# --- Test 11: Export count sanity ---
	export_count=$(echo "$exports" | grep -c -- '-> "' || true)
	if [[ $export_count -ge 20 ]]; then
		pass "Sufficient exports present ($export_count total)"
	else
		fail "Too few exports: $export_count (expected >= 20)"
	fi

else
	echo "  [skip] wasm-objdump not available — structural tests skipped"
	echo "         Install wabt or run inside 'nix develop'"
fi

# --- Test 12: Manifest hash verification ---
manifest="$MANIFEST_DIR/manifest.json"
if [[ -f $manifest ]]; then
	expected_sha256=$(grep -oP '"sha256":\s*"\K[0-9a-f]+' "$manifest" || true)
	if [[ -n $expected_sha256 ]]; then
		actual_sha256=$(sha256sum "$WASM" | awk '{print $1}')
		if [[ $actual_sha256 == "$expected_sha256" ]]; then
			pass "SHA-256 matches manifest ($actual_sha256)"
		else
			fail "SHA-256 mismatch: actual=$actual_sha256 expected=$expected_sha256"
		fi
	else
		echo "  [skip] No sha256 field in manifest"
	fi

	# Check manifest has required fields
	for field in artifact size_bytes sha256 sri; do
		if grep -q "\"$field\"" "$manifest"; then
			pass "Manifest field: $field"
		else
			fail "Missing manifest field: $field"
		fi
	done
else
	echo "  [skip] No manifest.json found in $(dirname "$WASM")"
fi

# --- Test 13: SRI hash verification ---
sri_file="$MANIFEST_DIR/verified_core.wasm.sri"
if [[ -f $sri_file ]]; then
	expected_sri=$(cat "$sri_file" | tr -d '\n\r')
	actual_sri_payload=$(openssl dgst -sha256 -binary "$WASM" | openssl base64 -A 2>/dev/null || true)
	actual_sri="sha256-${actual_sri_payload}"
	if [[ $actual_sri == "$expected_sri" ]]; then
		pass "SRI hash matches ($expected_sri)"
	else
		fail "SRI mismatch: actual=$actual_sri expected=$expected_sri"
	fi
else
	echo "  [skip] No .sri file found"
fi

# --- Summary ---
echo ""
echo "=== Results: $passed/$total passed ($failed failed) ==="

if [[ $failed -gt 0 ]]; then
	exit 1
fi
