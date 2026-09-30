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
 *
 * Raw-pointer caller contract: key/nonce/aad/plaintext must be readable for
 * their stated lengths; ciphertext must be writable for pt_len bytes and tag
 * for 16 bytes. Aliasing requirements are those of the selected primitive;
 * this declaration does not impose a new disjointness requirement on raw C
 * callers. The safe Rust interface supplies disjoint mutable output slices.
 * This ABI carries no output capacities, so callers must establish them before
 * entry. The safe Rust wrapper performs these checks on its actual slices.
 * Key/nonce lengths other than 32/12 or aad_len/pt_len above UINT32_MAX are
 * rejected before the primitive is called. No length is silently truncated.
 * On success exactly pt_len ciphertext bytes and 16 tag bytes are written.
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
