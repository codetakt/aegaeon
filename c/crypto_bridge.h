/* Verified.Crypto.Bridge — C implementation for KaRaMeL-extracted modules.
 *
 * When KaRaMeL extracts F* modules that import Verified.Crypto.Bridge,
 * the bridge is marked as -library, so KaRaMeL generates extern declarations.
 * This file provides the C implementations that call HACL* pre-extracted C code.
 *
 * Type mappings (KaRaMeL conventions):
 *   FStar.Bytes.bytes  → FStar_Bytes_bytes  { uint32_t length; const char *data; }
 *   string             → Prims_string       (const char*)
 *   bool               → bool               (stdbool.h)
 *   pos / int          → Prims_int / int32_t
 */

#ifndef VERIFIED_CRYPTO_BRIDGE_H
#define VERIFIED_CRYPTO_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>
#include "krmllib.h"
#include "krml/internal/compat.h"

/* ── Max input lengths (matching HACL* Spec.Hash.Definitions) ── */

/* SHA-256: max_input_length = Some (pow2 61 - 1) — clamp to INT32_MAX for C */
extern int32_t Verified_Crypto_Bridge_sha256_max_input;
extern int32_t Verified_Crypto_Bridge_sha384_max_input;
extern int32_t Verified_Crypto_Bridge_sha512_max_input;

/* ── Hash functions ── */

/* SHA-256: input → 32-byte hash */
extern FStar_Bytes_bytes
Verified_Crypto_Bridge_sha256_hash(FStar_Bytes_bytes input);

/* SHA-384: input → 48-byte hash */
extern FStar_Bytes_bytes
Verified_Crypto_Bridge_sha384_hash(FStar_Bytes_bytes input);

/* SHA-512: input → 64-byte hash */
extern FStar_Bytes_bytes
Verified_Crypto_Bridge_sha512_hash(FStar_Bytes_bytes input);

/* ── HMAC functions ── */

extern FStar_Bytes_bytes
Verified_Crypto_Bridge_hmac_sha256(FStar_Bytes_bytes key,
                                    FStar_Bytes_bytes data);

extern FStar_Bytes_bytes
Verified_Crypto_Bridge_hmac_sha384(FStar_Bytes_bytes key,
                                    FStar_Bytes_bytes data);

extern FStar_Bytes_bytes
Verified_Crypto_Bridge_hmac_sha512(FStar_Bytes_bytes key,
                                    FStar_Bytes_bytes data);

/* ── Ed25519 signature verification ── */

extern bool
Verified_Crypto_Bridge_ed25519_verify(FStar_Bytes_bytes public_key,
                                       FStar_Bytes_bytes msg,
                                       FStar_Bytes_bytes signature);

/* ── String utilities ── */

extern FStar_Bytes_bytes
Verified_Crypto_Bridge_string_to_bytes(Prims_string s);

extern Prims_string
Verified_Crypto_Bridge_bytes_to_hex_string(FStar_Bytes_bytes b);

extern Prims_string
Verified_Crypto_Bridge_sha256_of_string(Prims_string input);

/* Base64url encoding (RFC 4648 §5, no padding).
 * Used internally by sha256_of_string; exported for consistency. */
extern Prims_string
Verified_Crypto_Bridge_bytes_to_base64url_string(FStar_Bytes_bytes b);

#endif /* VERIFIED_CRYPTO_BRIDGE_H */
