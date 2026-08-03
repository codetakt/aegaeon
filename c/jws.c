#include "EverCrypt_HMAC.h"
#include "jws.h"
#include "rsa_signatures.h"
#include <stdbool.h>
#include <stdint.h>

// Extracted from Jose.Hmac_verification using KaRaMeL.
// Performs constant-time verification of HMAC-based JWS signatures.
static int ct_eq(jws_buf a, size_t a_len, jws_buf b, size_t b_len) {
  if (a_len != b_len) {
    return 0;
  }
  uint8_t diff = 0;
  for (size_t i = 0; i < a_len; i++) {
    diff |= a.ptr[i] ^ b.ptr[i];
  }
  return diff == 0;
}

jws_rc jws_hmac_verify(jws_alg alg, jws_buf key, size_t key_len, jws_buf msg,
                       size_t msg_len, jws_buf sig, size_t sig_len) {
  Spec_Hash_Definitions_hash_alg hacl_alg;
  size_t mac_len;
  switch (alg) {
  case JWS_ALG_HS256:
    hacl_alg = Spec_Hash_Definitions_SHA2_256;
    mac_len = 32;
    break;
  case JWS_ALG_HS384:
    hacl_alg = Spec_Hash_Definitions_SHA2_384;
    mac_len = 48;
    break;
  case JWS_ALG_HS512:
    hacl_alg = Spec_Hash_Definitions_SHA2_512;
    mac_len = 64;
    break;
  default:
    return JWS_ERR_UNSUPPORTED_ALG;
  }
  uint8_t mac[64];
  EverCrypt_HMAC_compute(hacl_alg, mac, (uint8_t *)key.ptr,
                         (uint32_t)key_len, (uint8_t *)msg.ptr,
                         (uint32_t)msg_len);
  jws_buf mac_buf = (jws_buf){ mac };
  return ct_eq(mac_buf, mac_len, sig, sig_len) ? JWS_OK
                                               : JWS_ERR_INVALID_SIGNATURE;
}

// Verify an RSA-PSS signature (PS256) using Hacl_RSAPSS.
jws_rc jws_rsa_verify(jws_alg alg, jws_buf key, size_t key_len, jws_buf msg,
                      size_t msg_len, jws_buf sig, size_t sig_len) {
  if (alg != JWS_ALG_PS256) {
    return JWS_ERR_UNSUPPORTED_ALG;
  }
  bool ok = Jose_Rsa_signatures_verify_rsa_pss(
      (uint8_t *)key.ptr, (uint32_t)key_len, (uint8_t *)msg.ptr,
      (uint32_t)msg_len, (uint8_t *)sig.ptr, (uint32_t)sig_len);
  return ok ? JWS_OK : JWS_ERR_INVALID_SIGNATURE;
}

// Verify an Ed25519 signature using EverCrypt.
jws_rc jws_ed25519_verify(jws_alg alg, jws_buf key, size_t key_len,
                          jws_buf msg, size_t msg_len, jws_buf sig,
                          size_t sig_len) {
  // Mark unused parameters to avoid warnings
  (void)key_len;
  (void)sig_len;

  if (alg != JWS_ALG_EDDSA) {
    return JWS_ERR_UNSUPPORTED_ALG;
  }
  bool ok = Jose_Rsa_signatures_verify_ed25519(
      (uint8_t *)key.ptr, (uint32_t)msg_len, (uint8_t *)msg.ptr,
      (uint8_t *)sig.ptr);
  uint32_t mask = (uint32_t)-(int32_t)ok;
  return (jws_rc)(JWS_ERR_INVALID_SIGNATURE ^
                  ((JWS_ERR_INVALID_SIGNATURE ^ JWS_OK) & mask));
}
