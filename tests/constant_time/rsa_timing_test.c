#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include "rsa_signatures.h"

#define MSG_LEN 32
#define SIG_LEN 256
#define PK_BUF_LEN 512

static uint8_t msg[MSG_LEN];
static uint8_t good_sig[SIG_LEN];
static uint8_t pk[PK_BUF_LEN];
static size_t pk_len;

uint8_t do_one_computation(uint8_t *data) {
    return Jose_Rsa_signatures_verify_rsa_pss(
        pk,
        pk_len,
        msg,
        MSG_LEN,
        data,
        SIG_LEN
    );
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

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    dudect_require(kctx != NULL, "RSA key context");
    EVP_PKEY *pkey = NULL;
    dudect_require(EVP_PKEY_keygen_init(kctx) > 0, "RSA setup");
    dudect_require(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) > 0, "RSA setup");
    dudect_require(EVP_PKEY_keygen(kctx, &pkey) > 0, "RSA setup");
    EVP_PKEY_CTX_free(kctx);

    /* Match the stable verifier ABI: modulus || left-padded exponent. */
    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;
    dudect_require(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &modulus) == 1 &&
                   EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &exponent) == 1,
                   "RSA public key components");
    dudect_require(BN_num_bits(modulus) == 2048 &&
                   BN_bn2binpad(modulus, pk, SIG_LEN) == SIG_LEN &&
                   BN_bn2binpad(exponent, pk + SIG_LEN, SIG_LEN) == SIG_LEN,
                   "RSA public key encoding");
    pk_len = 2 * SIG_LEN;
    BN_free(modulus);
    BN_free(exponent);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    dudect_require(mctx != NULL, "RSA signing context");
    EVP_PKEY_CTX *pctx;
    dudect_require(EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), NULL, pkey) > 0, "RSA setup");
    dudect_require(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0, "RSA setup");
    dudect_require(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) > 0, "RSA setup");
    size_t siglen = SIG_LEN;
    dudect_require(EVP_DigestSign(mctx, good_sig, &siglen, msg, MSG_LEN) == 1 &&
                   siglen == SIG_LEN, "RSA signature");
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    dudect_require(do_one_computation(good_sig) != 0, "rsa valid class");
    uint8_t invalid[SIG_LEN];
    memcpy(invalid, good_sig, SIG_LEN);
    invalid[SIG_LEN - 1] ^= 1;
    dudect_require(do_one_computation(invalid) == 0, "rsa invalid class");
    return dudect_run_case("rsa", SIG_LEN, argc, argv);
}
