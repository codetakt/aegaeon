#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/verify-jose}"

script="tests/conformance/jose_vector_test.py"
if [ ! -f "$script" ]; then
	echo "JOSE vector test script not found: $script" >&2
	exit 1
fi

log="$OUT_DIR/verify-jose.log"
rm -f "$log"

ffi_tlv_features="ffi_jose_header_tlv"
entry_validator_features="everparse_jose_header_entry"
strict_features="verified-claim"
strict_ffi_tlv_features="ffi_jose_header_tlv,verified-claim"
strict_idtoken_runtime_features="verified-claim,idtoken_runtime"

run_logged() {
	local label="$1"
	shift

	echo "=> ${label}" | tee -a "$log"
	if "$@" 2>&1 | tee -a "$log"; then
		echo "[OK] ${label}" | tee -a "$log"
	else
		echo "[FAIL] ${label}" | tee -a "$log"
		exit 1
	fi
}

run_logged "Running JOSE conformance tests" python3 "$script"

run_logged \
	"RFC 7520 vectors (default profile)" \
	cargo test -p aegaeon-jose --test rfc7520_vectors -- --test-threads=1
run_logged \
	"TLV parity (default profile)" \
	cargo test -p aegaeon-jose --test tlv_parity -- --test-threads=1
run_logged \
	"JOSE header runtime bridge (native profile)" \
	cargo test -p ffi --test jose_header_runtime_test -- --test-threads=1
run_logged \
	"Raw JSON structural backend selection (jose-header Phase 1)" \
	env AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER=verified-structural-v1 \
	cargo test -p aegaeon-jose structural_backend_override_ -- --test-threads=1

run_logged \
	"RFC 7520 vectors (everparse_jose_header_entry profile)" \
	cargo test -p aegaeon-jose --test rfc7520_vectors \
	--features "$entry_validator_features" -- --test-threads=1
run_logged \
	"TLV parity (everparse_jose_header_entry profile)" \
	cargo test -p aegaeon-jose --test tlv_parity \
	--features "$entry_validator_features" -- --test-threads=1

run_logged \
	"RFC 7520 vectors (verified-claim profile)" \
	cargo test -p aegaeon-jose --test rfc7520_vectors --features "$strict_features" -- --test-threads=1
run_logged \
	"TLV parity (verified-claim profile)" \
	cargo test -p aegaeon-jose --test tlv_parity --features "$strict_features" -- --test-threads=1

run_logged \
	"FFI TLV header path unit tests (compat profile)" \
	cargo test -p aegaeon-jose ffi_tlv_feature \
	--features "$ffi_tlv_features" -- --test-threads=1
run_logged \
	"FFI TLV normalization unit tests (compat profile)" \
	cargo test -p aegaeon-jose json_header_pairs_via_ffi_tlv \
	--features "$ffi_tlv_features" -- --test-threads=1
run_logged \
	"RFC 7520 vectors (ffi_jose_header_tlv profile)" \
	cargo test -p aegaeon-jose --test rfc7520_vectors \
	--features "$ffi_tlv_features" -- --test-threads=1
run_logged \
	"TLV parity (ffi_jose_header_tlv profile)" \
	cargo test -p aegaeon-jose --test tlv_parity \
	--features "$ffi_tlv_features" -- --test-threads=1

run_logged \
	"FFI TLV header path unit tests (strict profile)" \
	cargo test -p aegaeon-jose ffi_tlv_feature \
	--features "$strict_ffi_tlv_features" -- --test-threads=1
run_logged \
	"FFI TLV parser-unavailable mapping (strict profile)" \
	cargo test -p aegaeon-jose \
	tlv_abi_parser_unavailable_maps_to_json_parser_unavailable \
	--features "$strict_ffi_tlv_features" -- --test-threads=1
run_logged \
	"RFC 7520 vectors (ffi_jose_header_tlv + verified-claim profile)" \
	cargo test -p aegaeon-jose --test rfc7520_vectors \
	--features "$strict_ffi_tlv_features" -- --test-threads=1
run_logged \
	"TLV parity (ffi_jose_header_tlv + verified-claim profile)" \
	cargo test -p aegaeon-jose --test tlv_parity \
	--features "$strict_ffi_tlv_features" -- --test-threads=1

run_logged \
	"OIDC ID Token structure precheck tolerance (compat profile)" \
	cargo test -p aegaeon-server --lib \
	id_token_structure_precheck_tolerates_unavailable_parser \
	-- --test-threads=1
run_logged \
	"OIDC hash runtime unavailable fallback (compat profile)" \
	cargo test -p aegaeon-server --lib \
	compat_profile_falls_back_when_hash_runtime_is_unavailable \
	-- --test-threads=1
run_logged \
	"OIDC hash runtime failure fallback (compat profile)" \
	cargo test -p aegaeon-server --lib \
	compat_profile_falls_back_when_hash_runtime_fails \
	-- --test-threads=1
run_logged \
	"OIDC hash runtime null-digest fallback (compat profile)" \
	cargo test -p aegaeon-server --lib \
	compat_profile_falls_back_when_hash_runtime_returns_null_digest \
	-- --test-threads=1
run_logged \
	"OIDC hash oversized input maps to invalid request" \
	cargo test -p aegaeon-server --lib \
	finalize_hash_result_maps_input_too_large_to_invalid_request \
	-- --test-threads=1
run_logged \
	"JOSE header runtime bridge (verified-claim profile)" \
	cargo test -p ffi --test jose_header_runtime_test \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC hash runtime shim (verified-claim profile)" \
	cargo test -p ffi --test oidc_hash_runtime_test \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC ID Token structure parser unavailable fails closed (verified-claim profile)" \
	cargo test -p aegaeon-server --lib \
	verified_claim_profile_rejects_unavailable_id_token_structure_parser \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC hash vectors (verified-claim profile)" \
	cargo test -p aegaeon-server --test oidc_hash_vectors \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC hash runtime unavailable fails closed (verified-claim profile)" \
	cargo test -p aegaeon-server --lib \
	verified_claim_profile_rejects_unavailable_hash_runtime \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC hash runtime failure fails closed (verified-claim profile)" \
	cargo test -p aegaeon-server --lib \
	verified_claim_profile_rejects_failed_hash_runtime \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC hash runtime null-digest fails closed (verified-claim profile)" \
	cargo test -p aegaeon-server --lib \
	verified_claim_profile_rejects_null_digest_hash_runtime \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC hash oversized input maps to invalid request (verified-claim profile)" \
	cargo test -p aegaeon-server --lib \
	finalize_hash_result_maps_input_too_large_to_invalid_request \
	--features "$strict_features" -- --test-threads=1
run_logged \
	"OIDC IdToken Low* runtime opt-in compiles (verified-claim + idtoken_runtime)" \
	cargo test -p ffi --features "$strict_idtoken_runtime_features" --no-run
