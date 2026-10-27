#ifndef AEGAEON_DUDECT_CANDIDATE
#error This observation requires the inactive candidate runner
#endif
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
#include "jwe.h"

static uint8_t fixed_key[32], nonce[12], message[32], ciphertext[32], tag[16];
static uint8_t expected_failure_output[32];

static jwe_rc decrypt(uint8_t *key, uint8_t *output) {
    return Jose_Jwe_chacha20poly1305_decrypt(
        (jwe_buf){key}, 32, (jwe_buf){nonce}, 12, (jwe_buf){NULL}, 0,
        (jwe_buf){ciphertext}, 32, (jwe_buf){tag}, 16, (jwe_buf){output});
}

uint8_t do_one_computation(uint8_t *data) {
    jwe_rc rc = decrypt(data, data + 32);
    return (uint8_t)rc ^ data[32];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; ++i) {
        uint8_t *key = input_data + i * c->chunk_size, *output = key + 32;
        uint8_t group = classes[i] = randombit();
        unsigned attempts = 0;
        for (;;) {
            dudect_require(++attempts <= 128, "bounded AEAD key rejection sampling");
            if (group) randombytes(key, 32); else memcpy(key, fixed_key, 32);
            dudect_key_draws[group]++;
            memset(output, 0xa5, 32);
            jwe_rc rc = decrypt(key, output);
            if (rc == JWE_ERR_DECRYPT_FAILED) {
                dudect_require(!memcmp(output, expected_failure_output, 32),
                               "identical rejection-write semantics");
                memset(output, 0xa5, 32);
                break;
            }
            dudect_require(group && rc == JWE_OK, "AEAD rejection stratum result");
            dudect_key_excluded[group]++;
        }
    }
}

int main(int argc, char **argv) {
    memset(fixed_key, 0x42, 32); memset(nonce, 0x24, 12); memset(message, 0x5a, 32);
    dudect_require(Jose_Jwe_chacha20poly1305_encrypt(
        (jwe_buf){fixed_key}, 32, (jwe_buf){nonce}, 12, (jwe_buf){NULL}, 0,
        (jwe_buf){message}, 32, (jwe_buf){ciphertext}, (jwe_buf){tag}) == JWE_OK,
        "AEAD valid fixture encryption");
    uint8_t output[32];
    dudect_require(decrypt(fixed_key, output) == JWE_OK && !memcmp(output, message, 32),
                   "AEAD valid fixture decryption");
    tag[0] ^= 1;
    memset(expected_failure_output, 0xa5, 32);
    dudect_require(decrypt(fixed_key, expected_failure_output) == JWE_ERR_DECRYPT_FAILED,
                   "AEAD fixed-key rejection");
    return dudect_run_case("jwe_key_reject", 64, argc, argv);
}
