#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "rsa_signatures.h"

#define MSG_LEN 32
#define SIG_LEN 64
#define PK_LEN 32

static uint8_t msg[MSG_LEN];
static uint8_t good_sig[SIG_LEN];
static uint8_t pk[PK_LEN];

uint8_t do_one_computation(uint8_t *data) {
    return Jose_Rsa_signatures_verify_ed25519(pk, MSG_LEN, msg, data);
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *buf = input_data + i * c->chunk_size;
        if (classes[i] == 0) {
            memcpy(buf, good_sig, SIG_LEN);
        } else {
            memcpy(buf, good_sig, SIG_LEN);
            buf[SIG_LEN - 1] ^= 1;
        }
    }
}

int main(void) {
    RAND_bytes(msg, MSG_LEN);
    uint8_t sk[32];
    RAND_bytes(sk, sizeof(sk));
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, sizeof(sk));
    size_t pk_len = PK_LEN;
    EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t siglen = SIG_LEN;
    EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey);
    EVP_DigestSign(ctx, good_sig, &siglen, msg, MSG_LEN);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    dudect_config_t config = {
        .chunk_size = SIG_LEN,
        .number_measurements = 20000,
    };
    dudect_ctx_t dctx;
    dudect_init(&dctx, &config);
    dudect_main(&dctx);
    dudect_state_t state = dudect_main(&dctx);
    double max_t = dudect_get_max_t(&dctx);
    double p = erfc(max_t / sqrt(2.0));
    dudect_free(&dctx);
    printf("{\"state\":%d,\"p\":%f}\n", state, p);
    return 0;
}
