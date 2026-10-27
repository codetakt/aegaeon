#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
#include <openssl/rand.h>
#include "jwe.h"

#define KEY_LEN 32
#define NONCE_LEN 12
#define PT_LEN 32
#define TAG_LEN 16

static uint8_t key[KEY_LEN];
static uint8_t nonce[NONCE_LEN];
static uint8_t plaintext[PT_LEN];
static uint8_t ciphertext[PT_LEN];
static uint8_t good_tag[TAG_LEN];
static uint8_t output[PT_LEN];

uint8_t do_one_computation(uint8_t *data) {
    jwe_buf key_buf = { key };
    jwe_buf nonce_buf = { nonce };
    jwe_buf aad_buf = { NULL };
    jwe_buf ct_buf = { ciphertext };
    jwe_buf tag_buf = { data };
    jwe_buf pt_buf = { output };
    return Jose_Jwe_chacha20poly1305_decrypt(
        key_buf,
        KEY_LEN,
        nonce_buf,
        NONCE_LEN,
        aad_buf,
        0,
        ct_buf,
        PT_LEN,
        tag_buf,
        TAG_LEN,
        pt_buf
    ) == JWE_OK;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *buf = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(buf, good_tag, TAG_LEN);
        } else {
            memcpy(buf, good_tag, TAG_LEN);
            buf[0] ^= 1;
        }
    }
}

int main(int argc, char **argv) {
    dudect_require(RAND_bytes(key, KEY_LEN) == 1, "random input");
    dudect_require(RAND_bytes(nonce, NONCE_LEN) == 1, "random input");
    dudect_require(RAND_bytes(plaintext, PT_LEN) == 1, "random input");

    jwe_buf key_buf = { key };
    jwe_buf nonce_buf = { nonce };
    jwe_buf aad_buf = { NULL };
    jwe_buf pt_buf = { plaintext };
    jwe_buf ct_buf = { ciphertext };
    jwe_buf tag_buf = { good_tag };
    dudect_require(Jose_Jwe_chacha20poly1305_encrypt(
        key_buf,
        KEY_LEN,
        nonce_buf,
        NONCE_LEN,
        aad_buf,
        0,
        pt_buf,
        PT_LEN,
        ct_buf,
        tag_buf
    ) == JWE_OK, "JWE encryption");

    dudect_require(do_one_computation(good_tag) != 0, "jwe valid class");
    uint8_t invalid[TAG_LEN];
    memcpy(invalid, good_tag, TAG_LEN);
    invalid[0] ^= 1;
    dudect_require(do_one_computation(invalid) == 0, "jwe invalid class");
    return dudect_run_case("jwe", TAG_LEN, argc, argv);
}
