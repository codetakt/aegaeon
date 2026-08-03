/*
 * Verified Core — Public ABI implementation (vc_* functions)
 *
 * This thin shim wraps the KaRaMeL-extracted F* code and the existing
 * struct-based internal API (VerifiedCore_*_v1) with the clean, stable
 * vc_* public ABI defined in include/verified_core.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "verified_core.h"
#include "verified_core_exports.h"

#include <string.h>  /* memset */
#include <stddef.h>  /* NULL */

/* ================================================================
 * HACL* SHA-256 (Phase D: direct call, no host callback)
 * ================================================================ */

/*
 * Provided by hacl_bridge.c which delegates to Hacl_Hash_SHA2_hash_256.
 * Phase D: replaces the former host_crypto_sha256 host callback.
 */
extern void VerifiedCore_Crypto_Hacl_hacl_sha256(
    uint8_t *output, uint8_t *input, uint32_t input_len);

/* ================================================================
 * Internal constants
 * ================================================================ */

#define VC_PKCE_CHALLENGE_LEN  43u   /* base64url(SHA-256(verifier)) */
#define VC_SHA256_LEN          32u

static const char vc_version_str[] = "0.1.0";

/* Static buffer for vc_pkce_challenge_generate output.
 * Safe because WASM is single-threaded and the caller must consume or
 * copy the slice before the next call. */
static uint8_t vc_pkce_buf[VC_PKCE_CHALLENGE_LEN];

/* ================================================================
 * Base64url encoding (no padding, RFC 4648 §5)
 * ================================================================ */

static const char vc_b64url_table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/*
 * Encode `input_len` bytes to base64url without padding.
 * Returns number of output bytes written, or 0 if output_cap is too small.
 *
 * For SHA-256 (32 bytes): 10 full groups (30 bytes → 40 chars) + 2 remainder
 * bytes → 3 chars = 43 characters total.
 */
static uint32_t vc_base64url_encode_nopad(
    const uint8_t *input,  uint32_t input_len,
    uint8_t       *output, uint32_t output_cap)
{
    uint32_t full = input_len / 3;
    uint32_t rem  = input_len % 3;
    uint32_t out_len = full * 4 + (rem == 0 ? 0 : rem + 1);

    if (out_len > output_cap) {
        return 0;
    }

    uint32_t i = 0, j = 0;

    /* Process full 3-byte groups */
    for (; i + 2 < input_len; i += 3) {
        uint32_t n = ((uint32_t)input[i]     << 16) |
                     ((uint32_t)input[i + 1] <<  8) |
                      (uint32_t)input[i + 2];
        output[j++] = (uint8_t)vc_b64url_table[(n >> 18) & 0x3F];
        output[j++] = (uint8_t)vc_b64url_table[(n >> 12) & 0x3F];
        output[j++] = (uint8_t)vc_b64url_table[(n >>  6) & 0x3F];
        output[j++] = (uint8_t)vc_b64url_table[ n        & 0x3F];
    }

    /* Process remaining bytes (no padding) */
    if (rem == 1) {
        uint32_t n = (uint32_t)input[i] << 16;
        output[j++] = (uint8_t)vc_b64url_table[(n >> 18) & 0x3F];
        output[j++] = (uint8_t)vc_b64url_table[(n >> 12) & 0x3F];
    } else if (rem == 2) {
        uint32_t n = ((uint32_t)input[i]     << 16) |
                     ((uint32_t)input[i + 1] <<  8);
        output[j++] = (uint8_t)vc_b64url_table[(n >> 18) & 0x3F];
        output[j++] = (uint8_t)vc_b64url_table[(n >> 12) & 0x3F];
        output[j++] = (uint8_t)vc_b64url_table[(n >>  6) & 0x3F];
    }

    return j;
}

/* ================================================================
 * Input validation helpers
 * ================================================================ */

/*
 * RFC 7636 §4.1  unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
 */
static int vc_is_unreserved(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '.' || c == '_' || c == '~';
}

/* Validate a PKCE code_verifier: 43-128 unreserved ASCII bytes. */
static int vc_validate_verifier(vc_slice v)
{
    if (v.data == NULL || v.len < 43 || v.len > 128) {
        return 0;
    }
    for (uint32_t i = 0; i < v.len; i++) {
        if (!vc_is_unreserved(v.data[i])) {
            return 0;
        }
    }
    return 1;
}

/* ================================================================
 * Constant-time comparison
 * ================================================================ */

static int vc_ct_eq(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    volatile uint8_t diff = 0;
    for (uint32_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/* ================================================================
 * Small helpers
 * ================================================================ */

static vc_slice vc_null_slice(void)
{
    vc_slice s;
    s.data = (const uint8_t *)0;
    s.len  = 0;
    return s;
}

static int vc_slice_present(vc_slice s)
{
    return s.data != (const uint8_t *)0 && s.len > 0;
}

/* ================================================================
 * PKCE implementation
 * ================================================================ */

vc_result vc_pkce_challenge_generate(vc_slice verifier, uint32_t method)
{
    vc_result r;
    r.data = vc_null_slice();

    /* Only S256 is supported */
    if (method != VC_PKCE_METHOD_S256) {
        r.code = VC_UNSUPPORTED;
        return r;
    }

    if (!vc_validate_verifier(verifier)) {
        r.code = VC_INVALID_ARGUMENT;
        return r;
    }

    /* SHA-256(verifier) → 32 bytes into stack buffer.
     * Phase D: Call HACL* directly — the raw data is already in WASM
     * linear memory, no handle registration needed. */
    uint8_t sha256_buf[VC_SHA256_LEN];
    VerifiedCore_Crypto_Hacl_hacl_sha256(
        sha256_buf, (uint8_t *)verifier.data, verifier.len);

    /* base64url-no-pad encode: 32 bytes → 43 characters */
    uint32_t enc_len = vc_base64url_encode_nopad(
        sha256_buf, VC_SHA256_LEN,
        vc_pkce_buf, sizeof(vc_pkce_buf));

    if (enc_len != VC_PKCE_CHALLENGE_LEN) {
        r.code = VC_INTERNAL_ERROR;
        return r;
    }

    r.code     = VC_OK;
    r.data.data = vc_pkce_buf;
    r.data.len  = VC_PKCE_CHALLENGE_LEN;
    return r;
}

vc_result vc_pkce_challenge_verify(vc_slice verifier,
                                   vc_slice challenge,
                                   uint32_t method)
{
    vc_result r;
    r.data = vc_null_slice();

    if (method != VC_PKCE_METHOD_S256) {
        r.code = VC_UNSUPPORTED;
        return r;
    }

    if (!vc_validate_verifier(verifier)) {
        r.code = VC_INVALID_ARGUMENT;
        return r;
    }

    if (challenge.data == NULL || challenge.len != VC_PKCE_CHALLENGE_LEN) {
        r.code = VC_INVALID_ARGUMENT;
        return r;
    }

    /* Generate expected challenge */
    vc_result gen = vc_pkce_challenge_generate(verifier, method);
    if (gen.code != VC_OK) {
        return gen;
    }

    /* Constant-time comparison prevents timing side-channels */
    if (vc_ct_eq(gen.data.data, challenge.data, VC_PKCE_CHALLENGE_LEN)) {
        r.code = VC_OK;
    } else {
        r.code = VC_INVALID_CLAIMS;
    }

    return r;
}

/* ================================================================
 * DPoP implementation  (delegates to VerifiedCore_dpop_verify_v1)
 * ================================================================ */

vc_result vc_dpop_verify(vc_slice dpop_proof,
                         vc_slice htm,
                         vc_slice htu,
                         vc_slice access_token,
                         uint64_t now_seconds,
                         uint32_t allowed_algs,
                         uint32_t flags,
                         uint32_t max_age_seconds,
                         uint32_t max_skew_seconds)
{
    vc_result r;
    r.data = vc_null_slice();

    if (!vc_slice_present(dpop_proof) ||
        !vc_slice_present(htm) ||
        !vc_slice_present(htu)) {
        r.code = VC_INVALID_ARGUMENT;
        return r;
    }

    /* Register input slices as host-managed handles */
    uint32_t h_dpop = vc_host_register_bytes(dpop_proof.data, dpop_proof.len);
    uint32_t h_htm  = vc_host_register_bytes(htm.data, htm.len);
    uint32_t h_htu  = vc_host_register_bytes(htu.data, htu.len);
    uint32_t h_at   = vc_slice_present(access_token)
                        ? vc_host_register_bytes(access_token.data,
                                                 access_token.len)
                        : 0;

    /* Fail hard if ANY handle registration fails — including optional ones.
     * A silent 0-handle for access_token would skip ath binding, silently
     * downgrading DPoP validation instead of rejecting the request. */
    if (h_dpop == 0 || h_htm == 0 || h_htu == 0 ||
        (vc_slice_present(access_token) && h_at == 0)) {
        if (h_dpop) vc_host_release_handle(h_dpop);
        if (h_htm)  vc_host_release_handle(h_htm);
        if (h_htu)  vc_host_release_handle(h_htu);
        if (h_at)   vc_host_release_handle(h_at);
        r.code = VC_INTERNAL_ERROR;
        return r;
    }

    /* Build the struct-based input for the internal API */
    DpopVerificationInputV1 input;
    memset(&input, 0, sizeof(input));
    input.httpMethodBytesHandle   = h_htm;
    input.httpUriBytesHandle      = h_htu;
    input.dpopCompactJwsHandle    = h_dpop;
    input.accessTokenHandle       = h_at;
    input.replayNamespaceHandle   = 0;  /* host uses default namespace */
    input.nowUnixTimeSeconds      = now_seconds;
    input.maxAgeSeconds           = max_age_seconds;
    input.maxFutureSkewSeconds    = max_skew_seconds;
    input.flags                   = flags;
    input.allowedAlgorithmsBitmask = allowed_algs;

    DpopVerificationOutputV1 output;
    memset(&output, 0, sizeof(output));

    uint32_t rc = VerifiedCore_dpop_verify_v1(&input, &output);

    /* Release all handles */
    vc_host_release_handle(h_dpop);
    vc_host_release_handle(h_htm);
    vc_host_release_handle(h_htu);
    if (h_at) vc_host_release_handle(h_at);

    r.code = (vc_error_code)rc;
    return r;
}

/* ================================================================
 * JWT implementation  (delegates to VerifiedCore_jwt_verify_v1)
 * ================================================================ */

vc_result vc_jwt_verify(vc_slice jwt,
                        vc_slice jwk_set,
                        vc_slice expected_issuer,
                        vc_slice expected_audience,
                        uint64_t now_seconds,
                        uint32_t allowed_algs,
                        uint32_t flags)
{
    vc_result r;
    r.data = vc_null_slice();

    if (!vc_slice_present(jwt) || !vc_slice_present(jwk_set)) {
        r.code = VC_INVALID_ARGUMENT;
        return r;
    }

    /* Register input slices as host-managed handles */
    uint32_t h_jwt = vc_host_register_bytes(jwt.data, jwt.len);
    uint32_t h_key = vc_host_register_bytes(jwk_set.data, jwk_set.len);
    uint32_t h_iss = vc_slice_present(expected_issuer)
                       ? vc_host_register_bytes(expected_issuer.data,
                                                expected_issuer.len)
                       : 0;
    uint32_t h_aud = vc_slice_present(expected_audience)
                       ? vc_host_register_bytes(expected_audience.data,
                                                expected_audience.len)
                       : 0;

    /* Fail hard if ANY handle registration fails — including optional ones.
     * A silent 0-handle for issuer/audience would skip claim validation,
     * silently weakening JWT verification instead of rejecting. */
    if (h_jwt == 0 || h_key == 0 ||
        (vc_slice_present(expected_issuer) && h_iss == 0) ||
        (vc_slice_present(expected_audience) && h_aud == 0)) {
        if (h_jwt) vc_host_release_handle(h_jwt);
        if (h_key) vc_host_release_handle(h_key);
        if (h_iss) vc_host_release_handle(h_iss);
        if (h_aud) vc_host_release_handle(h_aud);
        r.code = VC_INTERNAL_ERROR;
        return r;
    }

    /* Build the struct-based input for the internal API */
    JwtVerificationInputV1 input;
    memset(&input, 0, sizeof(input));
    input.jwtCompactJwsHandle      = h_jwt;
    input.expectedIssuerHandle     = h_iss;
    input.expectedAudienceHandle   = h_aud;
    input.publicKeyBytesHandle     = h_key;
    input.nowUnixTimeSeconds       = now_seconds;
    input.allowedAlgorithmsBitmask = allowed_algs;
    input.publicKeyFormat          = VC_KEY_FMT_JWK_JSON;
    input.flags                    = flags;

    JwtVerificationOutputV1 output;
    memset(&output, 0, sizeof(output));

    uint32_t rc = VerifiedCore_jwt_verify_v1(&input, &output);

    /* Release all handles */
    vc_host_release_handle(h_jwt);
    vc_host_release_handle(h_key);
    if (h_iss) vc_host_release_handle(h_iss);
    if (h_aud) vc_host_release_handle(h_aud);

    r.code = (vc_error_code)rc;
    return r;
}

/* ================================================================
 * Memory management
 * ================================================================ */

void vc_free_slice(vc_slice slice)
{
    /*
     * All current output slices use static buffers (vc_pkce_buf).
     * This function is a no-op but MUST be called for forward-compatibility
     * — future versions may use a bump allocator or host-provided allocator.
     */
    (void)slice;
}

/* ================================================================
 * Introspection
 * ================================================================ */

vc_slice vc_version(void)
{
    vc_slice s;
    s.data = (const uint8_t *)vc_version_str;
    s.len  = sizeof(vc_version_str) - 1;
    return s;
}

uint32_t vc_abi_version(void)
{
    return VC_ABI_VERSION;
}
