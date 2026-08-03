#ifndef RSA_SIGNATURES_H
#define RSA_SIGNATURES_H
#include <stdbool.h>
#include <stdint.h>

bool Jose_Rsa_signatures_verify_rsa_pss(uint8_t *key, uint32_t key_len,
                                        uint8_t *data, uint32_t data_len,
                                        uint8_t *signature, uint32_t signature_len);

bool Jose_Rsa_signatures_verify_ed25519(uint8_t *key, uint32_t data_len,
                                        uint8_t *data, uint8_t *signature);

#endif // RSA_SIGNATURES_H
