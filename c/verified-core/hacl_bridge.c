/* HACL* bridge — maps KaRaMeL-generated externs to actual HACL* C functions.
 *
 * The F* module VerifiedCore.Crypto.Hacl is marked -library in KaRaMeL,
 * so KaRaMeL generates extern declarations for its functions. This file
 * provides the C implementations that delegate to the HACL* pre-extracted
 * C code (Hacl_Hash_SHA2, Hacl_Ed25519).
 *
 * Parameter order matches the F* declarations:
 *   hacl_sha256:         output, input, input_len
 *   hacl_ed25519_verify: pk, msg_len, msg, sig
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdbool.h>

#include "Hacl_Hash_SHA2.h"
#include "Hacl_Ed25519.h"

void VerifiedCore_Crypto_Hacl_hacl_sha256(
    uint8_t *output,
    uint8_t *input,
    uint32_t input_len)
{
    Hacl_Hash_SHA2_hash_256(output, input, input_len);
}

bool VerifiedCore_Crypto_Hacl_hacl_ed25519_verify(
    uint8_t *pk,
    uint32_t msg_len,
    uint8_t *msg,
    uint8_t *sig_)
{
    return Hacl_Ed25519_verify(pk, msg_len, msg, sig_);
}
