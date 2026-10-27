#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
#include "jws.h"
#include "EverCrypt_HMAC.h"

#define CHUNK_LEN 32

static uint8_t key[16];
static uint8_t msg[32];
static uint8_t good_sig[CHUNK_LEN];

uint8_t do_one_computation(uint8_t *data) {
    jws_buf key_buf = { key };
    jws_buf msg_buf = { msg };
    jws_buf sig_buf = { data };
    return jws_hmac_verify(
        JWS_ALG_HS256,
        key_buf,
        sizeof(key),
        msg_buf,
        sizeof(msg),
        sig_buf,
        CHUNK_LEN
    ) == JWS_OK;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *buf = input_data + i * c->chunk_size;
        memcpy(buf, good_sig, CHUNK_LEN);
        if (classes[i] == 1) {
            buf[0] ^= 1;
        }
    }
}

int main(int argc, char **argv) {
    randombytes(key, sizeof(key));
    randombytes(msg, sizeof(msg));
    EverCrypt_HMAC_compute(
        Spec_Hash_Definitions_SHA2_256,
        good_sig,
        key,
        sizeof(key),
        msg,
        sizeof(msg)
    );

    dudect_require(do_one_computation(good_sig) != 0, "hmac valid class");
    uint8_t invalid[CHUNK_LEN];
    memcpy(invalid, good_sig, CHUNK_LEN);
    invalid[0] ^= 1;
    dudect_require(do_one_computation(invalid) == 0, "hmac invalid class");
    return dudect_run_case("hmac", CHUNK_LEN, argc, argv);
}
