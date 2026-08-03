#ifndef JWS_H
#define JWS_H
#include <stddef.h>
#include <stdint.h>

/**
 * Lightweight pointer wrapper used across the FFI boundary.
 * The pointed-to memory is not owned and must remain valid for the
 * duration of the call.
 */
typedef struct {
  const uint8_t *ptr;
} jws_buf;

/**
 * Supported JWS algorithms.
 */
typedef enum {
  JWS_ALG_HS256 = 0, ///< HMAC using SHA-256
  JWS_ALG_HS384 = 1, ///< HMAC using SHA-384
  JWS_ALG_HS512 = 2, ///< HMAC using SHA-512
  JWS_ALG_PS256 = 3, ///< RSA-PSS using SHA-256
  JWS_ALG_EDDSA = 4, ///< Ed25519/EdDSA signatures
  JWS_ALG_UNSUPPORTED = 5 ///< Placeholder for unknown algorithms
} jws_alg;

/**
 * Return codes for JWS operations.
 */
typedef enum {
  JWS_OK = 0,               ///< Signature verified successfully
  JWS_ERR_UNSUPPORTED_ALG = 1, ///< The provided algorithm is not supported
  JWS_ERR_INVALID_SIGNATURE = 2 ///< Verification failed
} jws_rc;

/**
 * Verify an HMAC based JWS signature in constant time.
 *
 * @param alg     The JWS algorithm identifier.
 * @param key     Secret key buffer.
 * @param key_len Length of the key buffer in bytes.
 * @param msg     Message buffer (protected header || '.' || payload).
 * @param msg_len Length of the message buffer in bytes.
 * @param sig     Expected MAC value.
 * @param sig_len Length of the signature buffer in bytes.
 *
 * @return ::JWS_OK on success or one of the ::jws_rc error codes otherwise.
 */
jws_rc jws_hmac_verify(jws_alg alg, jws_buf key, size_t key_len, jws_buf msg,
                       size_t msg_len, jws_buf sig, size_t sig_len);

/**
 * Verify an RSA-PSS based JWS signature using the PS256 algorithm.
 */
jws_rc jws_rsa_verify(jws_alg alg, jws_buf key, size_t key_len, jws_buf msg,
                      size_t msg_len, jws_buf sig, size_t sig_len);

/**
 * Verify an Ed25519 (EdDSA) JWS signature.
 */
jws_rc jws_ed25519_verify(jws_alg alg, jws_buf key, size_t key_len, jws_buf msg,
                          size_t msg_len, jws_buf sig, size_t sig_len);

#endif // JWS_H
