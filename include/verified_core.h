/*
 * Verified Core — Public C ABI
 *
 * This header defines the stable public interface for the Aegaeon Verified Core
 * WASM module.  All exported functions use the vc_* prefix.
 *
 * The module is compiled to wasm32-wasi and is intended to be instantiated by a
 * host runtime adapter (TypeScript / Rust).  Functions marked "Host callback"
 * must be provided by the host as WASM imports.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef VERIFIED_CORE_H
#define VERIFIED_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * ABI version — bump on breaking changes
 * ================================================================ */
/* Phase D: ABI v2 — crypto internalized via HACL*, only replay store host callback remains.
 * Breaking changes from v1:
 *   - host_crypto_sha256, host_crypto_verify_signature removed (HACL* internal)
 *   - host_bytes_eq, host_bytes_len removed (C-layer memcmp)
 *   - host_replay_store_check_and_store now takes raw buffer pointers, not handles
 *   - New host callbacks: Host_handle_data_ptr, Host_handle_data_len
 *   - Only EdDSA (Ed25519) is supported in the verified signature path
 */
#define VC_ABI_VERSION 2

/* ================================================================
 * Types
 * ================================================================ */

/** Borrowed byte slice (pointer + length in WASM linear memory). */
typedef struct vc_slice {
    const uint8_t *data;
    uint32_t       len;
} vc_slice;

/** Error codes returned by vc_* functions.
 *  Values mirror VerifiedCore.Api.Claims.Runtime.status_code. */
typedef enum vc_error_code {
    VC_OK                = 0,
    VC_INVALID_ARGUMENT  = 1,
    VC_INVALID_FORMAT    = 2,
    VC_INVALID_SIGNATURE = 3,
    VC_INVALID_CLAIMS    = 4,
    VC_REPLAY            = 5,
    VC_UNAVAILABLE       = 6,
    VC_UNSUPPORTED       = 7,
    VC_INTERNAL_ERROR    = 8
} vc_error_code;

/** Result of a vc_* operation. */
typedef struct vc_result {
    vc_error_code code;
    vc_slice      data;   /* non-empty only when the call produces output */
} vc_result;

/* ================================================================
 * Constants
 * ================================================================ */

/* PKCE challenge method (RFC 7636) — only S256 is supported. */
#define VC_PKCE_METHOD_S256  1

/* Signature algorithm bitmask */
#define VC_ALG_ES256  0x01
#define VC_ALG_RS256  0x02
#define VC_ALG_EDDSA  0x04

/* DPoP verification flags (bitmask) */
#define VC_DPOP_REQUIRE_ATH  0x01
#define VC_DPOP_REQUIRE_JTI  0x02

/* JWT verification flags (bitmask) */
#define VC_JWT_REQUIRE_EXP  0x01
#define VC_JWT_REQUIRE_IAT  0x02
#define VC_JWT_REQUIRE_NBF  0x04

/* Public key format identifiers */
#define VC_KEY_FMT_JWK_JSON    1
#define VC_KEY_FMT_SPKI_DER    2
#define VC_KEY_FMT_RAW_EC_P256 3

/* ================================================================
 * PKCE  (RFC 7636)
 * ================================================================ */

/**
 * Generate a PKCE S256 code challenge from a code verifier.
 *
 * @param verifier  43–128 byte ASCII string of unreserved characters.
 * @param method    Must be VC_PKCE_METHOD_S256.
 * @return vc_result with 43-byte base64url challenge on success.
 *         The data slice points to an internal static buffer and remains
 *         valid until the next call to vc_pkce_challenge_generate.
 *         Call vc_free_slice() when done (currently a no-op).
 */
vc_result vc_pkce_challenge_generate(vc_slice verifier, uint32_t method);

/**
 * Verify a PKCE code challenge against a code verifier (constant-time).
 *
 * @param verifier   Original code_verifier (43–128 bytes).
 * @param challenge  The code_challenge to verify (must be 43 bytes).
 * @param method     Must be VC_PKCE_METHOD_S256.
 * @return vc_result with code == VC_OK on match.
 */
vc_result vc_pkce_challenge_verify(vc_slice verifier,
                                   vc_slice challenge,
                                   uint32_t method);

/* ================================================================
 * DPoP  (RFC 9449)
 * ================================================================ */

/**
 * Verify a DPoP proof.
 *
 * @param dpop_proof      Compact JWS serialisation of the DPoP proof.
 * @param htm             Expected HTTP method (e.g. "POST").
 * @param htu             Expected HTTP URI.
 * @param access_token    Optional access token for ath binding
 *                        (data=NULL / len=0 if absent).
 * @param now_seconds     Current Unix timestamp.
 * @param allowed_algs    Bitmask of VC_ALG_* values.
 * @param flags           Bitmask of VC_DPOP_* values.
 * @param max_age_seconds Maximum acceptable proof age.
 * @param max_skew_seconds Maximum future clock-skew tolerance.
 * @return vc_result with code == VC_OK on success.
 */
vc_result vc_dpop_verify(vc_slice dpop_proof,
                         vc_slice htm,
                         vc_slice htu,
                         vc_slice access_token,
                         uint64_t now_seconds,
                         uint32_t allowed_algs,
                         uint32_t flags,
                         uint32_t max_age_seconds,
                         uint32_t max_skew_seconds);

/* ================================================================
 * JWT / JWS  (RFC 7519 / RFC 7515)
 * ================================================================ */

/**
 * Verify a JWT (compact JWS).
 *
 * @param jwt                 Compact JWS serialisation.
 * @param jwk_set             JSON-encoded JWK Set for signature verification.
 * @param expected_issuer     Optional expected "iss" claim (data=NULL to skip).
 * @param expected_audience   Optional expected "aud" claim (data=NULL to skip).
 * @param now_seconds         Current Unix timestamp.
 * @param allowed_algs        Bitmask of VC_ALG_* values.
 * @param flags               Bitmask of VC_JWT_* values.
 * @return vc_result with code == VC_OK on success.
 */
vc_result vc_jwt_verify(vc_slice jwt,
                        vc_slice jwk_set,
                        vc_slice expected_issuer,
                        vc_slice expected_audience,
                        uint64_t now_seconds,
                        uint32_t allowed_algs,
                        uint32_t flags);

/* ================================================================
 * Memory management
 * ================================================================ */

/**
 * Release a slice returned by a vc_* function.
 *
 * Must be called exactly once per non-empty result slice.
 * After this call the data pointer is no longer valid.
 * Currently a no-op (all output uses static buffers) but must be
 * called for forward-compatibility with future allocator changes.
 */
void vc_free_slice(vc_slice slice);

/* ================================================================
 * Introspection
 * ================================================================ */

/** Return the Verified Core version string (static; do not free). */
vc_slice vc_version(void);

/** Return the ABI version number. */
uint32_t vc_abi_version(void);

/* ================================================================
 * Host callbacks (WASM imports — implemented by the runtime adapter)
 * ================================================================ */

/**
 * Register a byte region in WASM linear memory as a host-managed handle.
 * The host MUST copy the data; the handle remains valid until released.
 * Returns a non-zero handle on success, 0 on failure.
 */
extern uint32_t vc_host_register_bytes(const uint8_t *data, uint32_t len);

/** Release a handle obtained from vc_host_register_bytes. */
extern void vc_host_release_handle(uint32_t handle);

#ifdef __cplusplus
}
#endif

#endif /* VERIFIED_CORE_H */
