#!/usr/bin/env bash
# verify_ffi_contracts.sh — CI drift detection for F* ↔ C FFI contracts
#
# Checks source-symbol presence, generated-file presence, and the exact lexical
# inventory of registered first-party assume vals. This is drift detection, not
# a proof of functional contracts, compiled linkage, or premise acceptance.
#
# Exit codes:
#   0 — all contracts are consistent
#   1 — mismatch detected
#
# Usage:
#   ./scripts/validation/verify_ffi_contracts.sh [--verbose]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERBOSE="${1:-}"
ERRORS=0

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
	RED=$'\033[0;31m'
	GREEN=$'\033[0;32m'
	NC=$'\033[0m'
else
	RED=''
	GREEN=''
	NC=''
fi

log_ok() { echo "${GREEN}[OK]${NC} $1"; }
log_err() {
	echo "${RED}[ERR]${NC} $1"
	ERRORS=$((ERRORS + 1))
}
log_verbose() { [ "$VERBOSE" = "--verbose" ] && echo "     $1" || true; }

echo "=== F* ↔ C FFI Contract Drift Detection ==="
echo ""

# ---------------------------------------------------------------
# Step 1: Extract Category B assume vals from F* source
# ---------------------------------------------------------------
echo "--- Step 1: Extracting Category B assume vals from F* ---"

# F* files still containing Category B (FFI) assume vals.
# Originally 8 assume vals across 4 files + 1 bridge (free_bytes_ffi) = 9 total.
# All 9 eliminated via concrete Low* implementations; 0 remaining.
# json_parse_entries_to_c: replaced with concrete noextract implementation
# composing validate_members_utf8 + collect_raw_members_stack + parse_json_entries.
# Map: F* module path → expected KaRaMeL C function name prefix
declare -A FSTAR_FFI_FILES=(
)

# Expected assume val → C function mappings (Category B only)
# All 9 eliminated entries:
#   Jose.BytesBlock:malloc_bytes → concrete Buffer.malloc
#   Jose.BytesBlock:free_bytes → concrete Buffer.free
#   Jose.LowStar.Json.Stack:malloc_bytes → concrete Buffer.malloc
#   Jose.LowStar.Json.Stack:collect_members_u32_stack_aux → concrete with frame lemmas
#   Jose.LowStar.Json.Runtime:malloc_entry_array → concrete Buffer.malloc
#   Jose.LowStar.Json.Runtime:free_entry_array → concrete Buffer.free (ST, callers reordered)
#   Jose.LowStar.Json.Runtime:free_entry_array_contents
#     → concrete recursive with disjointness frame lemmas
#   Jose.LowStar.Json:free_bytes_ffi → concrete Buffer.free (freeable_disjoint' + frame lemmas)
#   Jose.LowStar.Json:json_parse_entries_to_c
#     → concrete noextract (validate_members_utf8 + spec pipeline)
# Remaining 0:
declare -A ASSUME_VAL_TO_C=(
)

FSTAR_ASSUME_COUNT=0
for fstar_file in "${!FSTAR_FFI_FILES[@]}"; do
	full_path="${REPO_ROOT}/${fstar_file}"
	if [ ! -f "$full_path" ]; then
		log_err "F* file not found: ${fstar_file}"
		continue
	fi
	count=$(grep -c '^\s*assume val' "$full_path" || true)
	FSTAR_ASSUME_COUNT=$((FSTAR_ASSUME_COUNT + count))
	log_verbose "${fstar_file}: ${count} assume val(s)"
done

if [ "$FSTAR_ASSUME_COUNT" -eq 0 ]; then
	log_ok "Legacy allocator/parser mapping list is empty; remaining foreign contracts checked in Step 5"
else
	log_err "Expected 0 Category B assume vals, found ${FSTAR_ASSUME_COUNT}"
fi

# ---------------------------------------------------------------
# Step 2: Verify each assume val has a C implementation
# ---------------------------------------------------------------
echo ""
echo "--- Step 2: Checking C implementations ---"

C_RUNTIME="${REPO_ROOT}/c/json_lowstar_runtime.c"
if [ ! -f "$C_RUNTIME" ]; then
	log_err "C runtime file not found: c/json_lowstar_runtime.c"
	echo ""
	echo "=== FAILED: ${ERRORS} error(s) ==="
	exit 1
fi

for fstar_sym in "${!ASSUME_VAL_TO_C[@]}"; do
	c_func="${ASSUME_VAL_TO_C[$fstar_sym]}"

	# Search for C function definition (not just declaration)
	if grep -q "${c_func}\b" "$C_RUNTIME"; then
		log_ok "${fstar_sym} → ${c_func}"
	else
		log_err "${fstar_sym}: no C implementation found for ${c_func}"
	fi
done

# ---------------------------------------------------------------
# Step 3: Verify extern "C" in crates/ffi have compiled objects
# ---------------------------------------------------------------
echo ""
echo '--- Step 3: Checking extern "C" declarations in crates/ffi ---'

FFI_SRC="${REPO_ROOT}/crates/ffi/src"

# Extract function names declared inside extern "C" { } blocks.
# We use perl to match multiline extern "C" blocks, then extract fn names.
# This avoids false positives from Rust-only functions (tests, helpers, kani).
EXTERN_FUNCS=$(perl -0777 -ne '
	while (/extern\s+"C"\s*\{([^}]*)\}/gs) {
		my $block = $1;
		while ($block =~ /fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/g) {
			print "$1\n";
		}
	}
' "$FFI_SRC"/*.rs | sort -u)

# C source files that should contain implementations
C_SOURCES=(
	"${REPO_ROOT}/c/jws.c"
	"${REPO_ROOT}/c/jwe.c"
	"${REPO_ROOT}/c/rsa_signatures.c"
	"${REPO_ROOT}/c/json_lowstar_runtime.c"
	"${REPO_ROOT}/c/dpop_error.c"
	"${REPO_ROOT}/c/dcr_error.c"
	"${REPO_ROOT}/c/jose_header_error.c"
	"${REPO_ROOT}/c/logout_token_error.c"
	"${REPO_ROOT}/c/request_object_error.c"
	"${REPO_ROOT}/c/hash_computation_runtime.c"
)

# Also check generated sources
GENERATED_DIRS=(
	"${REPO_ROOT}/generated/everparse"
	"${REPO_ROOT}/generated/lowstar/jose"
	"${REPO_ROOT}/artifacts/karamel"
)

# KaRaMeL-extracted externs that only exist after `nix build .#verified-core`.
# Keep this map empty unless an extern has no checked-in C implementation.
declare -A BUILD_ONLY_EXTERNS=(
)

EXTERN_CHECKED=0
EXTERN_FOUND=0
EXTERN_BUILD_ONLY=0

for func in $EXTERN_FUNCS; do
	EXTERN_CHECKED=$((EXTERN_CHECKED + 1))

	# Skip build-artifact-only externs
	if [[ -v "BUILD_ONLY_EXTERNS[$func]" ]]; then
		EXTERN_BUILD_ONLY=$((EXTERN_BUILD_ONLY + 1))
		log_verbose "extern ${func} — build-only (KaRaMeL extraction)"
		continue
	fi

	found=false

	# Check hand-written C sources
	for csrc in "${C_SOURCES[@]}"; do
		if [ -f "$csrc" ] && grep -q "\b${func}\b" "$csrc"; then
			found=true
			break
		fi
	done

	# Check generated sources
	if ! $found; then
		for dir in "${GENERATED_DIRS[@]}"; do
			if [ -d "$dir" ] && grep -rq "\b${func}\b" "$dir" 2>/dev/null; then
				found=true
				break
			fi
		done
	fi

	if $found; then
		EXTERN_FOUND=$((EXTERN_FOUND + 1))
		log_verbose "extern ${func} — found"
	else
		log_err "extern ${func} — no C source found"
	fi
done

log_ok "Extern \"C\": checked=${EXTERN_CHECKED}, matched=${EXTERN_FOUND}"
log_ok "Extern \"C\": build-only skipped=${EXTERN_BUILD_ONLY}"

# ---------------------------------------------------------------
# Step 4: Verify EverParse schema objects exist
# ---------------------------------------------------------------
echo ""
echo "--- Step 4: Checking EverParse generated artefacts ---"

EVERPARSE_SCHEMAS=(
	"JoseHeader"
	"DCR"
	"DcrRegistration"
	"Dpop"
	"IdTokenSchema"
	"LogoutTokenSchema"
	"RequestObjectSchema"
)

EVERPARSE_DIR="${REPO_ROOT}/generated/everparse"
EP_FOUND=0
EP_TOTAL=${#EVERPARSE_SCHEMAS[@]}

for schema in "${EVERPARSE_SCHEMAS[@]}"; do
	c_file="${EVERPARSE_DIR}/${schema}.c"
	h_file="${EVERPARSE_DIR}/${schema}.h"
	wrapper_c="${EVERPARSE_DIR}/${schema}Wrapper.c"
	wrapper_h="${EVERPARSE_DIR}/${schema}Wrapper.h"

	if [ -f "$c_file" ] && [ -f "$h_file" ] && [ -f "$wrapper_c" ] && [ -f "$wrapper_h" ]; then
		EP_FOUND=$((EP_FOUND + 1))
		log_ok "EverParse ${schema}: .c + .h + Wrapper.c + Wrapper.h"
	else
		missing=""
		[ ! -f "$c_file" ] && missing="${missing} ${schema}.c"
		[ ! -f "$h_file" ] && missing="${missing} ${schema}.h"
		[ ! -f "$wrapper_c" ] && missing="${missing} ${schema}Wrapper.c"
		[ ! -f "$wrapper_h" ] && missing="${missing} ${schema}Wrapper.h"
		log_err "EverParse ${schema}: missing${missing}"
	fi
done

if [ "$EP_FOUND" -eq "$EP_TOTAL" ]; then
	log_ok "All ${EP_TOTAL} EverParse schemas have generated artefacts"
else
	log_err "Missing EverParse artefacts: ${EP_FOUND}/${EP_TOTAL}"
fi

# ---------------------------------------------------------------
# Step 5: Compare exact declarations with the foreign-contract register
# ---------------------------------------------------------------
echo ""
echo "--- Step 5: Registered foreign-assumption source inventory ---"

if python3 "${REPO_ROOT}/scripts/validation/check_foreign_assumption_inventory.py" --root "$REPO_ROOT"; then
	log_ok "First-party .fst/.fsti declarations match the register (including closure-external entries)"
else
	log_err "Foreign-assumption source inventory mismatch"
fi

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
if [ "$ERRORS" -eq 0 ]; then
	echo "=== ${GREEN}PASSED${NC}: FFI source inventory checks passed (contracts remain unqualified) ==="
	exit 0
else
	echo "=== ${RED}FAILED${NC}: ${ERRORS} error(s) detected ==="
	exit 1
fi
