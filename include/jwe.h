#ifndef JWE_H
#define JWE_H

#include <stddef.h>
#include <stdint.h>

/**
 * Lightweight buffer wrapper used across the FFI boundary.
 * Memory pointed to by `ptr` must remain valid for the duration of the call.
 */
typedef struct {
  uint8_t *ptr;
} jwe_buf;

/**
 * Return codes for JWE operations.
 */
typedef enum {
  JWE_OK = 0,
  JWE_ERR_UNSUPPORTED_ALG = 1,
  JWE_ERR_DECRYPT_FAILED = 2
} jwe_rc;

/**
 * Encrypt using ChaCha20-Poly1305.
 */
jwe_rc Jose_Jwe_chacha20poly1305_encrypt(jwe_buf key, size_t key_len,
                                         jwe_buf nonce, size_t nonce_len,
                                         jwe_buf aad, size_t aad_len,
                                         jwe_buf plaintext, size_t pt_len,
                                         jwe_buf ciphertext, jwe_buf tag);

/**
 * Decrypt and authenticate using ChaCha20-Poly1305.
 */
jwe_rc Jose_Jwe_chacha20poly1305_decrypt(jwe_buf key, size_t key_len,
                                         jwe_buf nonce, size_t nonce_len,
                                         jwe_buf aad, size_t aad_len,
                                         jwe_buf ciphertext, size_t ct_len,
                                         jwe_buf tag, size_t tag_len,
                                         jwe_buf plaintext);

#endif // JWE_H
