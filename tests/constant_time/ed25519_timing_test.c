#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
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

int main(int argc, char **argv) {
    dudect_require(RAND_bytes(msg, MSG_LEN) == 1, "random input");
    uint8_t sk[32];
    dudect_require(RAND_bytes(sk, sizeof(sk)) == 1, "random input");
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, sizeof(sk));
    dudect_require(pkey != NULL, "Ed25519 private key");
    size_t pk_len = PK_LEN;
    dudect_require(EVP_PKEY_get_raw_public_key(pkey, pk, &pk_len) == 1 &&
                   pk_len == PK_LEN, "Ed25519 public key");

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    dudect_require(ctx != NULL, "Ed25519 signing context");
    size_t siglen = SIG_LEN;
    dudect_require(EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1, "Ed25519 signing init");
    dudect_require(EVP_DigestSign(ctx, good_sig, &siglen, msg, MSG_LEN) == 1 &&
                   siglen == SIG_LEN, "Ed25519 signature");
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    dudect_require(do_one_computation(good_sig) != 0, "ed25519 valid class");
    uint8_t invalid[SIG_LEN];
    memcpy(invalid, good_sig, SIG_LEN);
    invalid[SIG_LEN - 1] ^= 1;
    dudect_require(do_one_computation(invalid) == 0, "ed25519 invalid class");
    return dudect_run_case("ed25519", SIG_LEN, argc, argv);
}
