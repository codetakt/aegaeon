#include "rsa_signatures.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "EverCrypt_Ed25519.h"
#include "Hacl_RSAPSS.h"

static bool bit_length(const uint8_t *bytes, uint32_t len,
                       uint32_t *bits_out, uint32_t *offset_out) {
  uint32_t offset = 0;
  while (offset < len && bytes[offset] == 0U) {
    offset++;
  }
  if (offset == len) {
    return false;
  }

  uint8_t high = bytes[offset];
  uint32_t high_bits = 8U;
  while ((high & 0x80U) == 0U) {
    high <<= 1U;
    high_bits--;
  }
  uint32_t remaining = len - offset - 1U;
  if (remaining > (UINT32_MAX - high_bits) / 8U) {
    return false;
  }
  *bits_out = remaining * 8U + high_bits;
  *offset_out = offset;
  return true;
}

bool Jose_Rsa_signatures_verify_rsa_pss(uint8_t *key, uint32_t key_len,
                                        uint8_t *data, uint32_t data_len,
                                        uint8_t *signature, uint32_t signature_len) {
  if (key == NULL || data == NULL || signature == NULL || key_len == 0U ||
      (key_len & 1U) != 0U) {
    return false;
  }

  // The stable jws_rsa_verify ABI carries n || left_pad(e, len(n)).
  uint32_t encoded_modulus_len = key_len / 2U;
  uint8_t *encoded_exponent = key + encoded_modulus_len;
  uint32_t mod_bits = 0U;
  uint32_t modulus_offset = 0U;
  uint32_t exponent_bits = 0U;
  uint32_t exponent_offset = 0U;
  if (!bit_length(key, encoded_modulus_len, &mod_bits, &modulus_offset) ||
      !bit_length(encoded_exponent, encoded_modulus_len, &exponent_bits,
                  &exponent_offset)) {
    return false;
  }

  uint32_t modulus_len = (mod_bits + 7U) / 8U;
  if (modulus_len == 0U || signature_len != modulus_len) {
    return false;
  }

  uint8_t *modulus = key + modulus_offset;
  // The pinned implementation consumes ceil(eBits / 8) bytes even though the
  // generated header documents a modulus-sized buffer. Keep the backing
  // buffer modulus-sized and point at the significant exponent bytes.
  uint8_t *exponent = encoded_exponent + exponent_offset;
  return Hacl_RSAPSS_rsapss_pkey_verify(
      Spec_Hash_Definitions_SHA2_256, mod_bits, exponent_bits, modulus,
      exponent, 32U, signature_len, signature, data_len, data);
}

bool Jose_Rsa_signatures_verify_ed25519(uint8_t *key, uint32_t data_len,
                                        uint8_t *data, uint8_t *signature) {
  return EverCrypt_Ed25519_verify(key, data_len, data, signature);
}
