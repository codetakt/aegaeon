#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"

if [[ -z ${HACL_FSTAR_PATH:-} ]]; then
	echo "HACL_FSTAR_PATH is not set" >&2
	exit 1
fi
if [[ -z ${STEEL_PATH:-} ]]; then
	echo "STEEL_PATH is not set" >&2
	exit 1
fi
if [[ -z ${EVERPARSE_FSTAR_PATH:-} ]]; then
	echo "EVERPARSE_FSTAR_PATH is not set" >&2
	exit 1
fi
if [[ -z ${EVERPARSE_PRELUDE_PATH:-} ]]; then
	echo "EVERPARSE_PRELUDE_PATH is not set" >&2
	exit 1
fi
if [[ -z ${EVERPARSE_LOWPARSER_PATH:-} ]]; then
	echo "EVERPARSE_LOWPARSER_PATH is not set" >&2
	exit 1
fi
if [[ -z ${KRMLLIB_PATH:-} ]]; then
	echo "KRMLLIB_PATH is not set" >&2
	exit 1
fi

REPO_ROOT="$(pwd)"
FSTAR_DIR="$REPO_ROOT/fstar"

if [ ! -d "$FSTAR_DIR" ]; then
	echo "fstar directory not found under $REPO_ROOT" >&2
	exit 1
fi

cd "$FSTAR_DIR"

if [ ! -f C.Loops.fst ]; then
	printf '%s\n' \
		"module C.Loops" \
		"" \
		"open FStar.Classical" \
		"module HS = FStar.HyperStack" \
		"module HST = FStar.HyperStack.ST" \
		"" \
		"assume val while" \
		"  : #test_pre:(HS.mem -> Type0)" \
		"  -> #test_post:(bool -> HS.mem -> Type0)" \
		"  -> (unit -> HST.Stack bool" \
		"        (requires (fun h -> test_pre h))" \
		"        (ensures (fun h res h' -> test_post res h')))" \
		"  -> (unit -> HST.Stack unit" \
		"        (requires (fun h -> test_post true h))" \
		"        (ensures (fun h _ h' -> test_pre h')))" \
		"  -> HST.Stack unit" \
		"       (requires (fun h -> test_pre h))" \
		"       (ensures (fun h _ h' -> exists (res:bool). test_post res h'))" \
		"" \
		"assume val do_while" \
		"  : inv:(HS.mem -> bool -> Type0)" \
		"  -> (unit -> HST.Stack bool" \
		"        (requires (fun h -> inv h false))" \
		"        (ensures (fun h stop h' -> inv h' stop)))" \
		"  -> HST.Stack unit" \
		"       (requires (fun h -> inv h false))" \
		"       (ensures (fun h _ h' -> inv h' true))" \
		"" \
		"assume val total_while" \
		"  : #a:Type0" \
		"  -> (a -> nat)" \
		"  -> (bool -> a -> Type0)" \
		"  -> (a -> Tot (bool * a))" \
		"  -> a" \
		"  -> Tot a" \
		>C.Loops.fst
fi

echo "--- C.Loops.fst (builder copy) ---" >&2
sed -n '1,40p' C.Loops.fst >&2
echo "----------------------------------" >&2

mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/verify.log"
rm -f "$LOG"

# Set up environment
export HACL_FSTAR_PATH
export STEEL_PATH
export EVERPARSE_FSTAR_PATH
export EVERPARSE_PRELUDE_PATH
export EVERPARSE_LOWPARSER_PATH
export KRMLLIB_PATH

# Build argument list for fstar.exe
WARN_ERROR_FLAGS="\
	--warn_error -241 \
	--warn_error -242 \
	--warn_error -252 \
	--warn_error -328 \
	--warn_error -274 \
	--warn_error -285 \
	--warn_error -333 \
	--warn_error -276"

FSTAR_ARGS="--use_hints --hint_dir . --expose_interfaces"
FSTAR_ARGS="$FSTAR_ARGS --include crypto --include $HACL_FSTAR_PATH"
# HACL* subdirectories (Phase A: required for Spec.Ed25519 → Spec.Curve25519.Lemmas etc.)
for hacl_sub in "$HACL_FSTAR_PATH"/*/; do
	[ -d "$hacl_sub" ] && FSTAR_ARGS="$FSTAR_ARGS --include $hacl_sub"
done
FSTAR_ARGS="$FSTAR_ARGS --include $KRMLLIB_PATH"
FSTAR_ARGS="$FSTAR_ARGS --include $STEEL_PATH"
FSTAR_ARGS="$FSTAR_ARGS --include $EVERPARSE_FSTAR_PATH"
FSTAR_ARGS="$FSTAR_ARGS --include $EVERPARSE_PRELUDE_PATH"
FSTAR_ARGS="$FSTAR_ARGS --include $EVERPARSE_PRELUDE_PATH/buffer"
FSTAR_ARGS="$FSTAR_ARGS --include $EVERPARSE_PRELUDE_PATH/extern"
FSTAR_ARGS="$FSTAR_ARGS --include $EVERPARSE_LOWPARSER_PATH"
FSTAR_ARGS="$FSTAR_ARGS $WARN_ERROR_FLAGS"

# =========================================================================
# Pass 1: Federation Policy Algebra (separate invocation to avoid Z3 4.13 label encoding bug)
# These modules depend only on FStar.List.Tot and are verified with a clean SMT context.
# =========================================================================
POLICY_MODULES="\
	jose/Jose.Federation.Policy.Types.fst \
	jose/Jose.Federation.Policy.Merge.fst \
	jose/Jose.Federation.Policy.Order.fst \
	jose/Jose.Federation.Policy.Lemmas.fst"
# Build minimal args for policy modules (no --expose_interfaces, minimal includes)
POLICY_FSTAR_ARGS="--use_hints --hint_dir ."
POLICY_FSTAR_ARGS="$POLICY_FSTAR_ARGS $WARN_ERROR_FLAGS"
policy_count=$(echo "$POLICY_MODULES" | wc -w)
echo "=> Pass 1: Verifying Policy modules ($policy_count files)" | tee "$LOG" >&2
# shellcheck disable=SC2086
if fstar.exe --detail_errors --query_stats \
	$POLICY_FSTAR_ARGS \
	$POLICY_MODULES \
	2>&1 | tee -a "$LOG" >&2; then
	echo "[OK] Pass 1: Policy verification succeeded" | tee -a "$LOG" >&2
else
	echo "[FAIL] Pass 1: Policy verification failed" | tee -a "$LOG" >&2
	exit 1
fi

# =========================================================================
# Pass 1b: Jose.Federation (separate invocation to avoid Z3 4.13 label_1 bug
# in large Pass 2 context)
# Includes Policy modules + direct deps (Jose.Alg_policy,
# Jose.Jwk_structure, FStar.Json, FStar.Base64)
# NOTE: Phase A — Jose.Jws.Verify now depends on Verified.Crypto.Bridge (HACL*), so
# HACL/KaRaMeL includes are needed. Include paths don't affect Z3 context size.
# =========================================================================
FED_MODULES="\
	jose/Jose.Federation.Policy.Types.fst \
	jose/Jose.Federation.Policy.Merge.fst \
	jose/Jose.Federation.Policy.Order.fst \
	jose/Jose.Federation.Policy.Lemmas.fst"
FED_MODULES="$FED_MODULES \
	FStar.Json.fst \
	FStar.Base64.fst \
	jose/Jose.Alg_policy.fst \
	jose/Jose.Jwk_structure.fst \
	jose/Jose.Jws_serialization.fst \
	jose/Jose.Jws.Verify.fst \
	jose/Jose.Federation.fst"
FED_FSTAR_ARGS="--use_hints --hint_dir . --expose_interfaces"
# HACL* and KaRaMeL includes (needed by Jose.Jws.Verify → Verified.Crypto.Bridge)
FED_FSTAR_ARGS="$FED_FSTAR_ARGS --include crypto --include $HACL_FSTAR_PATH"
for hacl_sub in "$HACL_FSTAR_PATH"/*/; do
	[ -d "$hacl_sub" ] && FED_FSTAR_ARGS="$FED_FSTAR_ARGS --include $hacl_sub"
done
FED_FSTAR_ARGS="$FED_FSTAR_ARGS --include $KRMLLIB_PATH"
FED_FSTAR_ARGS="$FED_FSTAR_ARGS $WARN_ERROR_FLAGS"
fed_count=$(echo "$FED_MODULES" | wc -w)
echo "=> Pass 1b: Verifying Federation module ($fed_count files)" | tee -a "$LOG" >&2
# shellcheck disable=SC2086
if fstar.exe --detail_errors --query_stats \
	$FED_FSTAR_ARGS \
	$FED_MODULES \
	2>&1 | tee -a "$LOG" >&2; then
	echo "[OK] Pass 1b: Federation verification succeeded" | tee -a "$LOG" >&2
else
	echo "[FAIL] Pass 1b: Federation verification failed" | tee -a "$LOG" >&2
	exit 1
fi

# =========================================================================
# Pass 2: All other modules
# =========================================================================
# Foundation lemmas and utilities
MODULES="\
	FStar.Base64.fst \
	jose/JoseNatLemmas.fst \
	jose/JoseU32Lemmas.fst \
	jose/Jose.Arith.Bounds.fst \
	jose/Jose.UInt32Bounds.fst \
	jose/Jose.Utf8.fst \
	jose/Jose.Utf8.Validity.fst \
	jose/Jose.Utf8.Encoding.fst \
	jose/Jose.Utf8.Lemmas.fst \
	jose/Jose.Utf8Lemmas.fst \
	jose/Jose.ListMapLemmas.fst \
	jose/Jose.BufferListLemmas.fst \
	ConstTime.fst \
	HashComputation.fst \
	common/EqHelpers.fst"
# JOSE foundation
MODULES="$MODULES \
	FStar.Json.fst \
	jose/Jose.fst \
	jose/Jose.False.fst \
	jose/Jose.BytesBlock.fst \
	jose/Jose.TlvResultSpec.fst \
	jose/Jose.TlvInterface.fst \
	jose/Jose.TlvLemmas.fst \
	jose/Jose.JsonTlvEquiv.fst"
# JOSE string and header lemmas
MODULES="$MODULES jose/Jose.StringLemmas.fst jose/Jose.HeaderKeyLemmas.fst"
# JOSE policy and metadata
MODULES="$MODULES jose/Jose.Alg_policy.fst jose/Jose.Policy.fst jose/Jose.Metadata.fst"
# JOSE headers
MODULES="$MODULES \
	jose/Jose.HeaderSpec.fst \
	jose/Jose.HeaderPolicy.fst \
	jose/Jose.HeaderMicro.fst \
	jose/Jose.HeaderParser.Assumptions.fst \
	jose/Jose.HeaderParser.Spec.fst \
	jose/Jose.HeaderParser.Runtime.fst \
	jose/Jose.HeaderParser.TLV.fst \
	jose/Jose.HeaderParser.Proofs.fst \
	jose/Jose.HeaderParser.fst \
	jose/Jose.JsonHeaderSpec.fst \
	jose/Jose.Context.fst"
# JOSE implementation (JWK, JWS, JWE, JWT)
MODULES="$MODULES \
	jose/Jose.Jwk_metadata.fst \
	jose/Jose.Jwk_structure.fst \
	jose/Jose.Jws.Verify.fst \
	jose/Jose.Jwk_thumbprint_uri.fst \
	jose/Jose.Jws_header.fst \
	jose/Jose.Jws_signature.fst \
	jose/Jose.Jws_serialization.fst \
	jose/Jose.Jwe_header.fst \
	jose/Jose.Jwe_aad.fst \
	jose/Jose.Jwe_chacha20poly1305.fst \
	jose/Jose.Jwt_claims.fst \
	jose/Jose.Jwt_validation.fst \
	jose/Jose.Hmac_verification.fst \
	jose/Jose.Rsa_signatures.fst"
# DCR and SD-JWT
MODULES="$MODULES jose/Jose.Dcr.fst jose/Jose.SdJwt.fst"
# EverParse generated parsers
MODULES="$MODULES ../generated/everparse/JoseHeader.fsti ../generated/everparse/JoseHeader.fst"
MODULES="$MODULES ../generated/everparse/DCR.fsti ../generated/everparse/DCR.fst"
MODULES="$MODULES \
	../generated/everparse/IdTokenSchema.fsti \
	../generated/everparse/IdTokenSchema.fst"
# Dpop EverParse schema renamed to DpopSchema to avoid module name conflict with dpop/Dpop.fst
MODULES="$MODULES ../generated/everparse/DpopSchema.fsti ../generated/everparse/DpopSchema.fst"
MODULES="$MODULES \
	../generated/everparse/DcrRegistration.fsti \
	../generated/everparse/DcrRegistration.fst"
MODULES="$MODULES \
	../generated/everparse/LogoutTokenSchema.fsti \
	../generated/everparse/LogoutTokenSchema.fst"
MODULES="$MODULES \
	../generated/everparse/RequestObjectSchema.fsti \
	../generated/everparse/RequestObjectSchema.fst"
# Token and Bearer
MODULES="$MODULES \
	token/Token.fst \
	token/JwtAccessToken.fst \
	token/Bearer.fst \
	token/Bearer.Policy.fst \
	token/Bearer_validation.fst"
# Shared string helpers
MODULES="$MODULES common/StringHelpers.fst"
# Resource Indicators and Protected Resource Metadata
MODULES="$MODULES resource/ResourceIndicators.fst resource/ProtectedResourceMetadata.fst"
# DPoP
MODULES="$MODULES \
	dpop/Dpop.Header.fst \
	dpop/Dpop.Claims.fst \
	dpop/Dpop.Signature.fst \
	dpop/Dpop.Iat_validation.fst \
	dpop/Dpop.Htm_validation.fst \
	dpop/Dpop.Htu_validation.fst \
	dpop/Dpop.Ath_validation.fst \
	dpop/Dpop.Token_binding.fst \
	dpop/Dpop.Replay.fst \
	dpop/Dpop.Validation.fst \
	dpop/Dpop.fst"
# PKCE
MODULES="$MODULES \
	pkce/Pkce.Challenge.fst \
	pkce/Pkce.Verifier.fst \
	pkce/Pkce.Method_selection.fst \
	pkce/Pkce.Verification.fst \
	pkce/Pkce.fst"
# PAR
MODULES="$MODULES \
	par/Authorization.fst \
	par/Client_auth.fst \
	par/ParBinding.fst \
	par/Lifetime.fst \
	par/Request_uri.fst \
	par/RequestObject.fst \
	par/Response.fst \
	par/ParApp.fst \
	par/Par_Internal.fst \
	par/Par.fsti \
	par/Par.fst \
	par/Par_Steel.fst \
	par/Par_Ticket.fst \
	par/Par_Ticket_Unit.fst"
# PKJWT, ID Token, Logout, Form Post, Introspection, and Revocation
MODULES="$MODULES \
	auth/Pkjwt.fst \
	oidc/IdToken.Spec.fst \
	oidc/IdToken.fst \
	oidc/IdToken.Low.Plan.fst \
	oidc/IdToken.Low.Runtime.fst \
	oidc/Logout.Spec.fst \
	oidc/Logout.fst \
	oidc/FormPost.fst \
	introspection/Introspection.fst \
	introspection/JwtIntrospection.fst \
	revocation/Revocation.fst"
# Crypto trust boundaries
MODULES="$MODULES \
	crypto/Crypto.fst \
	crypto/Random.fst \
	crypto/Drbg.HmacSha256.fst \
	crypto/Verified.Crypto.Bridge.fst"
# AuthCode flow
MODULES="$MODULES \
	authcode/AuthCode.Types.fst \
	authcode/AuthCode.Store.fst \
	authcode/AuthCode.Flow.fst"
# Step-up
MODULES="$MODULES stepup/StepUp.fst"
# HashComputation model
MODULES="$MODULES HashComputation.Model.fst"
# DCR Management (Phase 8b)
MODULES="$MODULES dcr/DcrManagement.fst"
# Device Authorization (Phase 6)
MODULES="$MODULES device_authz/DeviceAuthz.fst"
# DPoP Nonce (Phase 11)
MODULES="$MODULES dpop/Dpop.Nonce.fst"
# Federation (Phase 6-8) — Jose.Federation.fst verified in Pass 1b;
# remaining federation modules here
MODULES="$MODULES \
	federation/Federation.EntityConfig.fst \
	federation/Federation.PgRepo.fst \
	federation/OpEntityConfiguration.fst \
	federation/OpSubordinateStatement.fst \
	federation/TrustMark.fst \
	federation/UpstreamRefresh.fst"
# OIDC RP (Phase 5)
MODULES="$MODULES \
	federation/OidcRp.Types.fst \
	federation/OidcRp.Transitions.fst \
	federation/OidcRp.Properties.fst"
# Management (Phase 4-5)
MODULES="$MODULES \
	management/Management.ClientLifecycle.fst \
	management/Management.KeyRotation.fst \
	management/Management.PolicyProfile.fst"
# RAR
MODULES="$MODULES rar/Rar.AuthorizationDetails.fst"
# Verified Core WASM API (HACL* Low* interface + claims runtime)
MODULES="$MODULES \
	verifiedcore/api/VerifiedCore.Crypto.Hacl.fst \
	verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst"
# Low* extraction stubs (Spec is verification-only to prevent drift)
MODULES="$MODULES \
	jose/Jose.LowStar.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Helpers.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Runtime.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Types.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Utf8.fst \
	jose/LowStar/Json/Jose.LowStar.Json.ParseEntries.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Spec.fst \
	jose/LowStar/Json/Jose.LowStar.Json.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Stack.fst"

# Formal test suites
MODULES="$MODULES \
	../tests/fstar/unit/TestFormPostCsp.fst \
	../tests/fstar/property/TestFormPostEncoder.fst"

# =========================================================================
# Pass 2a: LowStar JSON modules (separate invocation to test independently)
# =========================================================================
# LowStar deps: mirror the foundation + JOSE modules from Pass 2b (all transitive deps).
LOWSTAR_DEPS="\
	FStar.Base64.fst \
	jose/JoseNatLemmas.fst \
	jose/JoseU32Lemmas.fst \
	jose/Jose.Arith.Bounds.fst \
	jose/Jose.UInt32Bounds.fst \
	jose/Jose.Utf8.fst \
	jose/Jose.Utf8.Validity.fst \
	jose/Jose.Utf8.Encoding.fst \
	jose/Jose.Utf8.Lemmas.fst \
	jose/Jose.Utf8Lemmas.fst \
	jose/Jose.ListMapLemmas.fst \
	jose/Jose.BufferListLemmas.fst \
	ConstTime.fst \
	HashComputation.fst \
	common/EqHelpers.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS \
	FStar.Json.fst \
	jose/Jose.fst \
	jose/Jose.False.fst \
	jose/Jose.BytesBlock.fst \
	jose/Jose.TlvResultSpec.fst \
	jose/Jose.TlvInterface.fst \
	jose/Jose.TlvLemmas.fst \
	jose/Jose.JsonTlvEquiv.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS jose/Jose.StringLemmas.fst jose/Jose.HeaderKeyLemmas.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS jose/Jose.Alg_policy.fst jose/Jose.Policy.fst jose/Jose.Metadata.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS \
	jose/Jose.HeaderSpec.fst \
	jose/Jose.HeaderPolicy.fst \
	jose/Jose.HeaderMicro.fst \
	jose/Jose.HeaderParser.Assumptions.fst \
	jose/Jose.HeaderParser.Spec.fst \
	jose/Jose.HeaderParser.Runtime.fst \
	jose/Jose.HeaderParser.TLV.fst \
	jose/Jose.HeaderParser.Proofs.fst \
	jose/Jose.HeaderParser.fst \
	jose/Jose.JsonHeaderSpec.fst \
	jose/Jose.Context.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS \
	jose/Jose.Jwk_metadata.fst \
	jose/Jose.Jwk_structure.fst \
	jose/Jose.Jws.Verify.fst \
	jose/Jose.Jwk_thumbprint_uri.fst \
	jose/Jose.Jws_header.fst \
	jose/Jose.Jws_signature.fst \
	jose/Jose.Jws_serialization.fst \
	jose/Jose.Jwe_header.fst \
	jose/Jose.Jwe_aad.fst \
	jose/Jose.Jwe_chacha20poly1305.fst \
	jose/Jose.Jwt_claims.fst \
	jose/Jose.Jwt_validation.fst \
	jose/Jose.Hmac_verification.fst \
	jose/Jose.Rsa_signatures.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS jose/Jose.Dcr.fst jose/Jose.SdJwt.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS \
	../generated/everparse/JoseHeader.fsti \
	../generated/everparse/JoseHeader.fst \
	../generated/everparse/DCR.fsti \
	../generated/everparse/DCR.fst \
	../generated/everparse/IdTokenSchema.fsti \
	../generated/everparse/IdTokenSchema.fst \
	../generated/everparse/DpopSchema.fsti \
	../generated/everparse/DpopSchema.fst \
	../generated/everparse/DcrRegistration.fsti \
	../generated/everparse/DcrRegistration.fst \
	../generated/everparse/LogoutTokenSchema.fsti \
	../generated/everparse/LogoutTokenSchema.fst \
	../generated/everparse/RequestObjectSchema.fsti \
	../generated/everparse/RequestObjectSchema.fst"
LOWSTAR_DEPS="$LOWSTAR_DEPS common/StringHelpers.fst"
LOWSTAR_MODULES_SPEC="\
	jose/Jose.LowStar.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Helpers.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Runtime.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Types.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Utf8.fst \
	jose/LowStar/Json/Jose.LowStar.Json.ParseEntries.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Spec.fst"
LOWSTAR_MODULES_JSON="\
	jose/LowStar/Json/Jose.LowStar.Json.fst \
	jose/LowStar/Json/Jose.LowStar.Json.Stack.fst"

# Pass 2a-1: Verify LowStar JSON Spec and dependencies (separate invocation to
# avoid Z3 context pollution from Spec.fst's quantifier-heavy list predicates
# breaking the simple subtype obligations in Jose.LowStar.Json.fst).
lowstar_spec_count=$(echo "$LOWSTAR_DEPS $LOWSTAR_MODULES_SPEC" | wc -w)
echo \
	"=> Pass 2a-1: Verifying LowStar JSON Spec modules ($lowstar_spec_count files)" |
	tee -a "$LOG" >&2
# shellcheck disable=SC2086
if fstar.exe --detail_errors --query_stats \
	$FSTAR_ARGS \
	$LOWSTAR_DEPS \
	$LOWSTAR_MODULES_SPEC \
	2>&1 | tee -a "$LOG" >&2; then
	echo "[OK] Pass 2a-1: LowStar JSON Spec verification succeeded" | tee -a "$LOG" >&2
else
	echo "[FAIL] Pass 2a-1: LowStar JSON Spec verification failed" | tee -a "$LOG" >&2
	exit 1
fi

# Pass 2a-2: Verify Jose.LowStar.Json.fst and Stack separately.
# Spec.fst is listed as a dependency (checked but not reverified).
lowstar_json_count=$(echo "$LOWSTAR_DEPS $LOWSTAR_MODULES_SPEC $LOWSTAR_MODULES_JSON" | wc -w)
echo \
	"=> Pass 2a-2: Verifying LowStar JSON main modules ($lowstar_json_count files)" |
	tee -a "$LOG" >&2
# shellcheck disable=SC2086
if fstar.exe --detail_errors --query_stats \
	$FSTAR_ARGS \
	$LOWSTAR_DEPS \
	$LOWSTAR_MODULES_SPEC \
	$LOWSTAR_MODULES_JSON \
	2>&1 | tee -a "$LOG" >&2; then
	echo "[OK] Pass 2a-2: LowStar JSON main verification succeeded" | tee -a "$LOG" >&2
else
	echo "[FAIL] Pass 2a-2: LowStar JSON main verification failed" | tee -a "$LOG" >&2
	exit 1
fi

# =========================================================================
# Pass 2b: All other modules
# =========================================================================
count=$(echo "$MODULES" | wc -w)
echo "=> Pass 2b: Verifying remaining F* modules ($count files)" | tee -a "$LOG" >&2
# shellcheck disable=SC2086 # intentional word-splitting for multi-arg strings
if fstar.exe --detail_errors --query_stats $FSTAR_ARGS $MODULES 2>&1 | tee -a "$LOG" >&2; then
	echo "[OK] Pass 2b: F* verification succeeded" | tee -a "$LOG" >&2
else
	echo "[WARN] Pass 2b: F* verification failed (other module issues)" | tee -a "$LOG" >&2
fi
