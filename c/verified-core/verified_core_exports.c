/* Verified Core Exports — Phase D: WASM Host Boundary Internalization
 *
 * This layer bridges the struct-based internal API (handle-oriented) with the
 * KaRaMeL-extracted F* functions (raw buffer-oriented). It resolves handles
 * to WASM linear memory pointers before calling the verified implementations.
 *
 * Phase D changes:
 *   - F* functions take (ptr, len) pairs instead of opaque handles
 *   - SHA-256 hashing done via HACL* (no host_crypto_sha256 callback)
 *   - Byte comparison done via memcmp (no host_bytes_eq callback)
 *   - Only host_replay_store_check_and_store remains as F*-declared callback
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "verified_core_exports.h"

#include <string.h>
#include <stdbool.h>
#include <stddef.h>   /* NULL */

/* Forward declarations for KaRaMeL-extracted F* functions (Phase D signatures) */

/* VerifiedCore.Api.Claims.Runtime.status_code is extracted as uint8_t by KaRaMeL. */
typedef uint8_t fstar_status_code;

extern fstar_status_code VerifiedCore_Api_Claims_Runtime_dpop_verify_claims_impl(
  uint8_t *signing_input_ptr,
  uint32_t signing_input_len,
  uint8_t *signature_ptr,
  uint32_t signature_len,
  uint8_t *public_key_ptr,
  uint32_t public_key_len,
  uint8_t *replay_namespace_ptr,
  uint32_t replay_namespace_len,
  bool has_ath,
  bool has_jti,
  uint32_t allowed_algs_bitmask,
  uint32_t flags,
  uint64_t iat_seconds,
  uint64_t now_seconds,
  uint32_t max_age_seconds,
  uint32_t max_future_skew_seconds,
  uint8_t *output_replay_key_hash
);

extern fstar_status_code VerifiedCore_Api_Claims_Runtime_jwt_verify_claims_impl(
  uint8_t *signing_input_ptr,
  uint32_t signing_input_len,
  uint8_t *signature_ptr,
  uint32_t signature_len,
  uint8_t *public_key_ptr,
  uint32_t public_key_len,
  uint32_t allowed_algs_bitmask,
  uint32_t flags,
  uint64_t exp_seconds,
  uint64_t nbf_seconds,
  uint64_t iat_seconds,
  uint64_t now_seconds
);

/* HACL* SHA-256 (from hacl_bridge.c) */
extern void VerifiedCore_Crypto_Hacl_hacl_sha256(
  uint8_t *output, uint8_t *input, uint32_t input_len
);

/* Forward declarations */
static uint32_t map_claims_status(fstar_status_code status);

/* ================================================================
 * Handle resolution helpers
 *
 * Phase D: The F* functions take raw buffer pointers. The exports layer
 * resolves handle IDs to (ptr, len) pairs via host callbacks, then passes
 * raw pointers to the verified code.
 * ================================================================ */

static int handle_is_present(uint32_t handle) {
  return handle != 0;
}

/* Compare two handles' data using memcmp.
 * Returns 1 if equal, 0 otherwise. Both handles must be present. */
static int handles_bytes_eq(uint32_t a, uint32_t b) {
  if (a == 0 && b == 0) return 1;
  if (a == 0 || b == 0) return 0;
  uint8_t *ptr_a = Host_handle_data_ptr(a);
  uint32_t len_a = Host_handle_data_len(a);
  uint8_t *ptr_b = Host_handle_data_ptr(b);
  uint32_t len_b = Host_handle_data_len(b);
  if (ptr_a == NULL || ptr_b == NULL) return 0;
  if (len_a != len_b) return 0;
  if (len_a == 0) return 1;
  return memcmp(ptr_a, ptr_b, len_a) == 0;
}

/* Hash handle data with HACL* SHA-256. Writes 32 bytes to output.
 * Returns 1 on success, 0 on failure (invalid handle). */
static int hash_handle_sha256(uint32_t handle, uint8_t *output_32) {
  uint8_t *ptr = Host_handle_data_ptr(handle);
  uint32_t len = Host_handle_data_len(handle);
  if (ptr == NULL) {
    memset(output_32, 0, 32);
    return 0;
  }
  VerifiedCore_Crypto_Hacl_hacl_sha256(output_32, ptr, len);
  return 1;
}

static const char vc_b64url_table[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static uint32_t base64url_encode_nopad(
  const uint8_t *input,
  uint32_t input_len,
  uint8_t *output,
  uint32_t output_cap
) {
  uint32_t full = input_len / 3;
  uint32_t rem = input_len % 3;
  uint32_t out_len = full * 4 + (rem == 0 ? 0 : rem + 1);
  uint32_t i = 0;
  uint32_t j = 0;

  if (out_len > output_cap) {
    return 0;
  }

  for (; i + 2 < input_len; i += 3) {
    uint32_t n = ((uint32_t)input[i] << 16) |
                 ((uint32_t)input[i + 1] << 8) |
                 (uint32_t)input[i + 2];
    output[j++] = (uint8_t)vc_b64url_table[(n >> 18) & 0x3Fu];
    output[j++] = (uint8_t)vc_b64url_table[(n >> 12) & 0x3Fu];
    output[j++] = (uint8_t)vc_b64url_table[(n >> 6) & 0x3Fu];
    output[j++] = (uint8_t)vc_b64url_table[n & 0x3Fu];
  }

  if (rem == 1) {
    uint32_t n = (uint32_t)input[i] << 16;
    output[j++] = (uint8_t)vc_b64url_table[(n >> 18) & 0x3Fu];
    output[j++] = (uint8_t)vc_b64url_table[(n >> 12) & 0x3Fu];
  } else if (rem == 2) {
    uint32_t n = ((uint32_t)input[i] << 16) |
                 ((uint32_t)input[i + 1] << 8);
    output[j++] = (uint8_t)vc_b64url_table[(n >> 18) & 0x3Fu];
    output[j++] = (uint8_t)vc_b64url_table[(n >> 12) & 0x3Fu];
    output[j++] = (uint8_t)vc_b64url_table[(n >> 6) & 0x3Fu];
  }

  return j;
}

static int verify_ath_binding_handles(uint32_t access_token_handle, uint32_t ath_claim_handle) {
  uint8_t digest[32];
  uint8_t encoded[43];
  uint8_t *claim_ptr = Host_handle_data_ptr(ath_claim_handle);
  uint32_t claim_len = Host_handle_data_len(ath_claim_handle);

  if (claim_ptr == NULL || claim_len == 0) {
    return 0;
  }

  if (!hash_handle_sha256(access_token_handle, digest)) {
    return 0;
  }

  if (base64url_encode_nopad(digest, sizeof digest, encoded, sizeof encoded) != sizeof encoded) {
    return 0;
  }

  return claim_len == sizeof encoded && memcmp(claim_ptr, encoded, sizeof encoded) == 0;
}

static const uint8_t *skip_json_ws(const uint8_t *ptr, const uint8_t *end) {
  while (ptr < end) {
    if (*ptr != ' ' && *ptr != '\t' && *ptr != '\r' && *ptr != '\n') {
      break;
    }
    ptr++;
  }
  return ptr;
}

static int hex_nibble(uint8_t c) {
  if (c >= '0' && c <= '9') return (int)(c - '0');
  if (c >= 'a' && c <= 'f') return (int)(c - 'a') + 10;
  if (c >= 'A' && c <= 'F') return (int)(c - 'A') + 10;
  return -1;
}

static void match_decoded_byte(
  uint8_t byte,
  const uint8_t *expected,
  uint32_t expected_len,
  uint32_t *matched,
  int *still_match
) {
  if (!*still_match) {
    return;
  }
  if (*matched >= expected_len || expected[*matched] != byte) {
    *still_match = 0;
    return;
  }
  (*matched)++;
}

static void match_decoded_codepoint(
  uint32_t codepoint,
  const uint8_t *expected,
  uint32_t expected_len,
  uint32_t *matched,
  int *still_match
) {
  if (codepoint <= 0x7Fu) {
    match_decoded_byte((uint8_t)codepoint, expected, expected_len, matched, still_match);
  } else if (codepoint <= 0x7FFu) {
    match_decoded_byte((uint8_t)(0xC0u | (codepoint >> 6)), expected, expected_len, matched, still_match);
    match_decoded_byte((uint8_t)(0x80u | (codepoint & 0x3Fu)), expected, expected_len, matched, still_match);
  } else {
    match_decoded_byte((uint8_t)(0xE0u | (codepoint >> 12)), expected, expected_len, matched, still_match);
    match_decoded_byte((uint8_t)(0x80u | ((codepoint >> 6) & 0x3Fu)), expected, expected_len, matched, still_match);
    match_decoded_byte((uint8_t)(0x80u | (codepoint & 0x3Fu)), expected, expected_len, matched, still_match);
  }
}

static int json_string_matches_expected(
  const uint8_t **cursor,
  const uint8_t *end,
  const uint8_t *expected,
  uint32_t expected_len
) {
  const uint8_t *ptr = *cursor;
  uint32_t matched = 0;
  int still_match = 1;

  if (ptr >= end || *ptr != '"') {
    return 0;
  }
  ptr++;

  while (ptr < end) {
    uint32_t codepoint;

    if (*ptr == '"') {
      ptr++;
      *cursor = ptr;
      return still_match && matched == expected_len;
    }

    if (*ptr != '\\') {
      codepoint = *ptr++;
      match_decoded_codepoint(codepoint, expected, expected_len, &matched, &still_match);
      continue;
    }

    ptr++;
    if (ptr >= end) {
      return 0;
    }

    switch (*ptr) {
      case '"': codepoint = '"'; ptr++; break;
      case '\\': codepoint = '\\'; ptr++; break;
      case '/': codepoint = '/'; ptr++; break;
      case 'b': codepoint = '\b'; ptr++; break;
      case 'f': codepoint = '\f'; ptr++; break;
      case 'n': codepoint = '\n'; ptr++; break;
      case 'r': codepoint = '\r'; ptr++; break;
      case 't': codepoint = '\t'; ptr++; break;
      case 'u': {
        if ((end - ptr) < 5) {
          return 0;
        }
        int d0 = hex_nibble(ptr[1]);
        int d1 = hex_nibble(ptr[2]);
        int d2 = hex_nibble(ptr[3]);
        int d3 = hex_nibble(ptr[4]);
        if (d0 < 0 || d1 < 0 || d2 < 0 || d3 < 0) {
          return 0;
        }
        codepoint = (uint32_t)((d0 << 12) | (d1 << 8) | (d2 << 4) | d3);
        ptr += 5;
        break;
      }
      default:
        return 0;
    }
    match_decoded_codepoint(codepoint, expected, expected_len, &matched, &still_match);
  }

  return 0;
}

static int audience_handle_contains_expected(uint32_t expected_handle, uint32_t audience_handle) {
  uint8_t *expected_ptr = Host_handle_data_ptr(expected_handle);
  uint32_t expected_len = Host_handle_data_len(expected_handle);
  uint8_t *audience_ptr = Host_handle_data_ptr(audience_handle);
  uint32_t audience_len = Host_handle_data_len(audience_handle);
  const uint8_t *cursor;
  const uint8_t *end;

  if (expected_ptr == NULL || audience_ptr == NULL) {
    return 0;
  }

  if (expected_len == audience_len && memcmp(expected_ptr, audience_ptr, expected_len) == 0) {
    return 1;
  }

  cursor = skip_json_ws(audience_ptr, audience_ptr + audience_len);
  end = audience_ptr + audience_len;
  if (cursor >= end) {
    return 0;
  }

  if (*cursor == '"') {
    int matched = json_string_matches_expected(&cursor, end, expected_ptr, expected_len);
    cursor = skip_json_ws(cursor, end);
    return matched && cursor == end;
  }

  if (*cursor != '[') {
    return 0;
  }
  cursor++;

  for (;;) {
    int matched;
    cursor = skip_json_ws(cursor, end);
    if (cursor >= end) {
      return 0;
    }
    if (*cursor == ']') {
      return 0;
    }
    matched = json_string_matches_expected(&cursor, end, expected_ptr, expected_len);
    cursor = skip_json_ws(cursor, end);
    if (matched) {
      if (cursor < end && (*cursor == ',' || *cursor == ']')) {
        return 1;
      }
      return 0;
    }
    if (cursor >= end) {
      return 0;
    }
    if (*cursor == ',') {
      cursor++;
      continue;
    }
    if (*cursor == ']') {
      return 0;
    }
    return 0;
  }
}

/* ================================================================
 * Output reset helpers
 * ================================================================ */

static void reset_dpop_output(DpopVerificationOutputV1 *out) {
  if (out == NULL) {
    return;
  }
  memset(out->jktHash, 0, sizeof out->jktHash);
  memset(out->replayKeyHash, 0, sizeof out->replayKeyHash);
  memset(out->jtiHash, 0, sizeof out->jtiHash);
  out->proofIatSeconds = 0;
  out->flags = 0;
  out->statusCode = VerifiedCoreStatusCode_UNSUPPORTED;
}

static void reset_jwt_output(JwtVerificationOutputV1 *out) {
  if (out == NULL) {
    return;
  }
  memset(out->payloadHash, 0, sizeof out->payloadHash);
  memset(out->kidHash, 0, sizeof out->kidHash);
  out->flags = 0;
  out->statusCode = VerifiedCoreStatusCode_UNSUPPORTED;
  out->reserved0 = 0;
  out->reserved1 = 0;
}

/* ================================================================
 * DPoP verification (full path with parsing)
 * ================================================================ */

uint32_t VerifiedCore_dpop_verify_v1(
  const DpopVerificationInputV1 *input,
  DpopVerificationOutputV1 *output
) {
  if (input == NULL || output == NULL) {
    if (output != NULL) {
      reset_dpop_output(output);
      output->statusCode = VerifiedCoreStatusCode_INVALID_ARGUMENT;
    }
    return VerifiedCoreStatusCode_INVALID_ARGUMENT;
  }

  reset_dpop_output(output);

  /* Parse the DPoP compact JWS via host callback */
  DpopParsedComponents parsed;
  memset(&parsed, 0, sizeof parsed);

  uint32_t parse_status = Host_parse_dpop_compact(input->dpopCompactJwsHandle, &parsed);
  if (parse_status != 0 || parsed.statusCode != 0) {
    output->statusCode = VerifiedCoreStatusCode_INVALID_FORMAT;
    return VerifiedCoreStatusCode_INVALID_FORMAT;
  }

  /* Validate htm matches the input HTTP method (C-layer comparison) */
  if (!handles_bytes_eq(parsed.htmHandle, input->httpMethodBytesHandle)) {
    output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
    return VerifiedCoreStatusCode_INVALID_CLAIMS;
  }

  /* Validate htu matches the input HTTP URI */
  if (!handles_bytes_eq(parsed.htuHandle, input->httpUriBytesHandle)) {
    output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
    return VerifiedCoreStatusCode_INVALID_CLAIMS;
  }

  /* Validate ath binding if access token is provided (RFC 9449 Section 4.2) */
  if (handle_is_present(input->accessTokenHandle)) {
    /* Access token provided - ath claim must be present and match */
    if (!handle_is_present(parsed.athHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
    if (!verify_ath_binding_handles(input->accessTokenHandle, parsed.athHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
  }

  /* Compute jktHash from public key via HACL* SHA-256 */
  hash_handle_sha256(parsed.publicKeyHandle, output->jktHash);

  /* Compute jtiHash from jti if present */
  if (handle_is_present(parsed.jtiHandle)) {
    hash_handle_sha256(parsed.jtiHandle, output->jtiHash);
    output->flags |= 1; /* HAS_JTI flag */
  }

  /* Set HAS_ATH flag if ath present */
  if (handle_is_present(parsed.athHandle)) {
    output->flags |= 2; /* HAS_ATH flag */
  }

  /* Resolve handles to raw buffers for F* function call */
  uint8_t *si_ptr = Host_handle_data_ptr(parsed.signingInputHandle);
  uint32_t si_len = Host_handle_data_len(parsed.signingInputHandle);
  uint8_t *sig_ptr = Host_handle_data_ptr(parsed.signatureBytesHandle);
  uint32_t sig_len = Host_handle_data_len(parsed.signatureBytesHandle);
  uint8_t *pk_ptr = Host_handle_data_ptr(parsed.publicKeyHandle);
  uint32_t pk_len = Host_handle_data_len(parsed.publicKeyHandle);
  uint8_t *ns_ptr = Host_handle_data_ptr(input->replayNamespaceHandle);
  uint32_t ns_len = Host_handle_data_len(input->replayNamespaceHandle);

  if (si_ptr == NULL || sig_ptr == NULL || pk_ptr == NULL) {
    output->statusCode = VerifiedCoreStatusCode_INTERNAL_ERROR;
    return VerifiedCoreStatusCode_INTERNAL_ERROR;
  }

  /* If no replay namespace handle, use empty buffer */
  if (ns_ptr == NULL) {
    ns_ptr = (uint8_t *)"";
    ns_len = 0;
  }

  /* Call the F* extracted claims verification (Phase D: raw buffers) */
  fstar_status_code status =
    VerifiedCore_Api_Claims_Runtime_dpop_verify_claims_impl(
      si_ptr, si_len,
      sig_ptr, sig_len,
      pk_ptr, pk_len,
      ns_ptr, ns_len,
      handle_is_present(parsed.athHandle),  /* has_ath */
      handle_is_present(parsed.jtiHandle),  /* has_jti */
      input->allowedAlgorithmsBitmask,
      input->flags,
      parsed.iatSeconds,
      input->nowUnixTimeSeconds,
      input->maxAgeSeconds,
      input->maxFutureSkewSeconds,
      output->replayKeyHash
    );

  uint32_t result = map_claims_status(status);
  output->statusCode = result;
  output->proofIatSeconds = parsed.iatSeconds;

  return result;
}

/* ================================================================
 * JWT verification (full path with parsing)
 * ================================================================ */

uint32_t VerifiedCore_jwt_verify_v1(
  const JwtVerificationInputV1 *input,
  JwtVerificationOutputV1 *output
) {
  if (input == NULL || output == NULL) {
    if (output != NULL) {
      reset_jwt_output(output);
      output->statusCode = VerifiedCoreStatusCode_INVALID_ARGUMENT;
    }
    return VerifiedCoreStatusCode_INVALID_ARGUMENT;
  }

  reset_jwt_output(output);

  /* Parse the JWT compact JWS via host callback */
  JwtParsedComponents parsed;
  memset(&parsed, 0, sizeof parsed);

  uint32_t parse_status = Host_parse_jwt_compact(input->jwtCompactJwsHandle, &parsed);
  if (parse_status != 0 || parsed.statusCode != 0) {
    output->statusCode = VerifiedCoreStatusCode_INVALID_FORMAT;
    return VerifiedCoreStatusCode_INVALID_FORMAT;
  }

  /* Validate issuer if expected issuer is provided (C-layer comparison) */
  if (handle_is_present(input->expectedIssuerHandle)) {
    if (!handle_is_present(parsed.issHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
    if (!handles_bytes_eq(parsed.issHandle, input->expectedIssuerHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
  }

  /* Validate audience if expected audience is provided */
  if (handle_is_present(input->expectedAudienceHandle)) {
    if (!handle_is_present(parsed.audHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
    if (!audience_handle_contains_expected(input->expectedAudienceHandle, parsed.audHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
  }

  /* Compute payloadHash from signingInput via HACL* SHA-256 */
  hash_handle_sha256(parsed.signingInputHandle, output->payloadHash);

  /* Compute kidHash if present */
  if (handle_is_present(parsed.kidHandle)) {
    hash_handle_sha256(parsed.kidHandle, output->kidHash);
    output->flags |= 1; /* HAS_KID flag */
  }

  /* Build flags for claims verification based on what's present.
   * Preserve caller-supplied flags such as the adapter-side
   * SIGNATURE_PREVERIFIED contract bit. */
  uint32_t claims_flags = input->flags;
  if (parsed.hasExp) {
    claims_flags |= 1; /* REQUIRE_EXP */
  }
  if (parsed.hasIat) {
    claims_flags |= 2; /* REQUIRE_IAT */
  }
  if (parsed.hasNbf) {
    claims_flags |= 4; /* REQUIRE_NBF */
  }

  /* Resolve handles to raw buffers for F* function call */
  uint8_t *si_ptr = Host_handle_data_ptr(parsed.signingInputHandle);
  uint32_t si_len = Host_handle_data_len(parsed.signingInputHandle);
  uint8_t *sig_ptr = Host_handle_data_ptr(parsed.signatureBytesHandle);
  uint32_t sig_len = Host_handle_data_len(parsed.signatureBytesHandle);
  uint8_t *pk_ptr = Host_handle_data_ptr(input->publicKeyBytesHandle);
  uint32_t pk_len = Host_handle_data_len(input->publicKeyBytesHandle);

  if (si_ptr == NULL || sig_ptr == NULL || pk_ptr == NULL) {
    output->statusCode = VerifiedCoreStatusCode_INTERNAL_ERROR;
    return VerifiedCoreStatusCode_INTERNAL_ERROR;
  }

  /* Call the F* extracted claims verification (Phase D: raw buffers) */
  fstar_status_code status =
    VerifiedCore_Api_Claims_Runtime_jwt_verify_claims_impl(
      si_ptr, si_len,
      sig_ptr, sig_len,
      pk_ptr, pk_len,
      input->allowedAlgorithmsBitmask,
      claims_flags,
      parsed.expSeconds,
      parsed.nbfSeconds,
      parsed.iatSeconds,
      input->nowUnixTimeSeconds
    );

  uint32_t result = map_claims_status(status);
  output->statusCode = result;

  return result;
}

/* ================================================================
 * Status code mapping
 * ================================================================ */

/* Map F* extracted status codes to VerifiedCoreStatusCode.
 * KaRaMeL extracts the F* inductive as sequential integers starting at 0. */
static uint32_t map_claims_status(fstar_status_code status) {
  switch (status) {
    case 0:  return VerifiedCoreStatusCode_OK;
    case 1:  return VerifiedCoreStatusCode_INVALID_ARGUMENT;
    case 2:  return VerifiedCoreStatusCode_INVALID_FORMAT;
    case 3:  return VerifiedCoreStatusCode_INVALID_SIGNATURE;
    case 4:  return VerifiedCoreStatusCode_INVALID_CLAIMS;
    case 5:  return VerifiedCoreStatusCode_REPLAY;
    case 6:  return VerifiedCoreStatusCode_UNAVAILABLE;
    case 7:  return VerifiedCoreStatusCode_UNSUPPORTED;
    case 8:
    default: return VerifiedCoreStatusCode_INTERNAL_ERROR;
  }
}

/* ================================================================
 * DPoP claims-only verification (pre-parsed path)
 *
 * Phase D note: The F* function no longer performs HTTP method/URI comparison.
 * Callers of this function are expected to have already validated htm/htu.
 * ================================================================ */

uint32_t VerifiedCore_dpop_verify_claims_v1(
  const DpopClaimsInputV1 *input,
  DpopVerificationOutputV1 *output
) {
  if (input == NULL || output == NULL) {
    if (output != NULL) {
      reset_dpop_output(output);
      output->statusCode = VerifiedCoreStatusCode_INVALID_ARGUMENT;
    }
    return VerifiedCoreStatusCode_INVALID_ARGUMENT;
  }

  reset_dpop_output(output);

  /* Compute jktHash from public key via HACL* SHA-256 */
  hash_handle_sha256(input->publicKeyBytesHandle, output->jktHash);

  /* Compute jtiHash from jti if present */
  if (handle_is_present(input->jtiBytesHandle)) {
    hash_handle_sha256(input->jtiBytesHandle, output->jtiHash);
    output->flags |= 1; /* HAS_JTI flag */
  }

  /* Set HAS_ATH flag if access token hash is present */
  if (handle_is_present(input->accessTokenHashHandle)) {
    output->flags |= 2; /* HAS_ATH flag */
  }

  /* Resolve handles to raw buffers */
  uint8_t *si_ptr = Host_handle_data_ptr(input->signingInputHandle);
  uint32_t si_len = Host_handle_data_len(input->signingInputHandle);
  uint8_t *sig_ptr = Host_handle_data_ptr(input->signatureBytesHandle);
  uint32_t sig_len = Host_handle_data_len(input->signatureBytesHandle);
  uint8_t *pk_ptr = Host_handle_data_ptr(input->publicKeyBytesHandle);
  uint32_t pk_len = Host_handle_data_len(input->publicKeyBytesHandle);
  uint8_t *ns_ptr = Host_handle_data_ptr(input->replayNamespaceHandle);
  uint32_t ns_len = Host_handle_data_len(input->replayNamespaceHandle);

  if (si_ptr == NULL || sig_ptr == NULL || pk_ptr == NULL) {
    output->statusCode = VerifiedCoreStatusCode_INTERNAL_ERROR;
    return VerifiedCoreStatusCode_INTERNAL_ERROR;
  }

  /* If no replay namespace handle, use empty buffer */
  if (ns_ptr == NULL) {
    ns_ptr = (uint8_t *)"";
    ns_len = 0;
  }

  /* Call the F* extracted implementation (Phase D: raw buffers) */
  fstar_status_code status =
    VerifiedCore_Api_Claims_Runtime_dpop_verify_claims_impl(
      si_ptr, si_len,
      sig_ptr, sig_len,
      pk_ptr, pk_len,
      ns_ptr, ns_len,
      handle_is_present(input->accessTokenHashHandle),  /* has_ath */
      handle_is_present(input->jtiBytesHandle),          /* has_jti */
      input->allowedAlgorithmsBitmask,
      input->flags,
      input->iatSeconds,
      input->nowUnixTimeSeconds,
      input->maxAgeSeconds,
      input->maxFutureSkewSeconds,
      output->replayKeyHash
    );

  uint32_t result = map_claims_status(status);
  output->statusCode = result;
  output->proofIatSeconds = input->iatSeconds;

  return result;
}

/* ================================================================
 * JWT claims-only verification (pre-parsed path)
 *
 * Phase D note: The F* function no longer performs issuer/audience comparison.
 * Callers of this function are expected to have already validated iss/aud.
 * ================================================================ */

uint32_t VerifiedCore_jwt_verify_claims_v1(
  const JwtClaimsInputV1 *input,
  JwtVerificationOutputV1 *output
) {
  if (input == NULL || output == NULL) {
    if (output != NULL) {
      reset_jwt_output(output);
      output->statusCode = VerifiedCoreStatusCode_INVALID_ARGUMENT;
    }
    return VerifiedCoreStatusCode_INVALID_ARGUMENT;
  }

  reset_jwt_output(output);

  /* Validate issuer if expected issuer is provided */
  if (handle_is_present(input->expectedIssuerHandle)) {
    if (!handle_is_present(input->claimsIssuerHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
    if (!handles_bytes_eq(input->claimsIssuerHandle, input->expectedIssuerHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
  }

  /* Validate audience membership if an expected audience is provided */
  if (handle_is_present(input->expectedAudienceHandle)) {
    if (!handle_is_present(input->claimsAudienceHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
    if (!audience_handle_contains_expected(input->expectedAudienceHandle, input->claimsAudienceHandle)) {
      output->statusCode = VerifiedCoreStatusCode_INVALID_CLAIMS;
      return VerifiedCoreStatusCode_INVALID_CLAIMS;
    }
  }

  /* Compute payloadHash from signingInput via HACL* SHA-256 */
  hash_handle_sha256(input->signingInputHandle, output->payloadHash);

  /* Note: kidHash cannot be computed here — caller computes separately if needed */

  /* Resolve handles to raw buffers */
  uint8_t *si_ptr = Host_handle_data_ptr(input->signingInputHandle);
  uint32_t si_len = Host_handle_data_len(input->signingInputHandle);
  uint8_t *sig_ptr = Host_handle_data_ptr(input->signatureBytesHandle);
  uint32_t sig_len = Host_handle_data_len(input->signatureBytesHandle);
  uint8_t *pk_ptr = Host_handle_data_ptr(input->publicKeyBytesHandle);
  uint32_t pk_len = Host_handle_data_len(input->publicKeyBytesHandle);

  if (si_ptr == NULL || sig_ptr == NULL || pk_ptr == NULL) {
    output->statusCode = VerifiedCoreStatusCode_INTERNAL_ERROR;
    return VerifiedCoreStatusCode_INTERNAL_ERROR;
  }

  /* Call the F* extracted implementation (Phase D: raw buffers) */
  fstar_status_code status =
    VerifiedCore_Api_Claims_Runtime_jwt_verify_claims_impl(
      si_ptr, si_len,
      sig_ptr, sig_len,
      pk_ptr, pk_len,
      input->allowedAlgorithmsBitmask,
      input->flags,
      input->expSeconds,
      input->nbfSeconds,
      input->iatSeconds,
      input->nowUnixTimeSeconds
    );

  uint32_t result = map_claims_status(status);
  output->statusCode = result;

  return result;
}
