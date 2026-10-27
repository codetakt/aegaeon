#ifndef AEGAEON_DUDECT_CANDIDATE
#error This observation requires the inactive candidate runner
#endif
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
#include "EverCrypt_HMAC.h"
#include "jws.h"

static uint8_t fixed_key[16], message[32], candidate_tag[32];

static jws_rc verify(uint8_t *key) {
    return jws_hmac_verify(JWS_ALG_HS256, (jws_buf){key}, 16,
                          (jws_buf){message}, 32, (jws_buf){candidate_tag}, 32);
}

uint8_t do_one_computation(uint8_t *data) { return (uint8_t)verify(data); }

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; ++i) {
        uint8_t *key = input_data + i * c->chunk_size;
        uint8_t group = classes[i] = randombit();
        unsigned attempts = 0;
        for (;;) {
            dudect_require(++attempts <= 128, "bounded key rejection sampling");
            if (group) randombytes(key, 16); else memcpy(key, fixed_key, 16);
            dudect_key_draws[group]++;
            jws_rc rc = verify(key);
            if (rc == JWS_ERR_INVALID_SIGNATURE) break;
            dudect_require(group && rc == JWS_OK, "HMAC rejection stratum result");
            dudect_key_excluded[group]++;
        }
    }
}

int main(int argc, char **argv) {
    memset(fixed_key, 0x42, sizeof fixed_key);
    memset(message, 0x5a, sizeof message);
    EverCrypt_HMAC_compute(Spec_Hash_Definitions_SHA2_256, candidate_tag,
                          fixed_key, 16, message, 32);
    dudect_require(verify(fixed_key) == JWS_OK, "HMAC valid fixture");
    candidate_tag[0] ^= 1;
    dudect_require(verify(fixed_key) == JWS_ERR_INVALID_SIGNATURE, "HMAC fixed-key rejection");
    return dudect_run_case("hmac_key_reject", 16, argc, argv);
}
