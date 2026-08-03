#include "jwe.h"
#include "EverCrypt_Chacha20Poly1305.h"
#include <string.h>

// Encrypt using verified EverCrypt ChaCha20-Poly1305.
jwe_rc Jose_Jwe_chacha20poly1305_encrypt(jwe_buf key, size_t key_len,
                                         jwe_buf nonce, size_t nonce_len,
                                         jwe_buf aad, size_t aad_len,
                                         jwe_buf plaintext, size_t pt_len,
                                         jwe_buf ciphertext, jwe_buf tag) {
  if (key_len != 32 || nonce_len != 12) {
    return JWE_ERR_UNSUPPORTED_ALG;
  }
  EverCrypt_Chacha20Poly1305_aead_encrypt(
      key.ptr, nonce.ptr, (uint32_t)aad_len, aad.ptr, (uint32_t)pt_len,
      plaintext.ptr, ciphertext.ptr, tag.ptr);
  return JWE_OK;
}

// Decrypt and authenticate using verified EverCrypt ChaCha20-Poly1305.
jwe_rc Jose_Jwe_chacha20poly1305_decrypt(jwe_buf key, size_t key_len,
                                         jwe_buf nonce, size_t nonce_len,
                                         jwe_buf aad, size_t aad_len,
                                         jwe_buf ciphertext, size_t ct_len,
                                         jwe_buf tag, size_t tag_len,
                                         jwe_buf plaintext) {
  if (key_len != 32 || nonce_len != 12 || tag_len != 16) {
    return JWE_ERR_UNSUPPORTED_ALG;
  }
  uint32_t rc = EverCrypt_Chacha20Poly1305_aead_decrypt(
      key.ptr, nonce.ptr, (uint32_t)aad_len, aad.ptr, (uint32_t)ct_len,
      plaintext.ptr, ciphertext.ptr, tag.ptr);
  return rc == 0 ? JWE_OK : JWE_ERR_DECRYPT_FAILED;
}
