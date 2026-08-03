#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "rsa_signatures.h"

#define MSG_LEN 32
#define SIG_LEN 256
#define PK_BUF_LEN 512

static uint8_t msg[MSG_LEN];
static uint8_t good_sig[SIG_LEN];
static uint8_t pk[PK_BUF_LEN];
static size_t pk_len;

// Approximate normal CDF using error function approximation
static double normal_cdf(double x) {
    double a1 = 0.254829592;
    double a2 = -0.284496736;
    double a3 = 1.421413741;
    double a4 = -1.453152027;
    double a5 = 1.061405429;
    double p = 0.3275911;

    int sign = 1;
    if (x < 0) {
        sign = -1;
        x = -x;
    }

    double t = 1.0 / (1.0 + p * x);
    double t2 = t * t;
    double t3 = t2 * t;
    double t4 = t3 * t;
    double t5 = t4 * t;

    double y = 1.0 - (((((a5 * t5 + a4 * t4) + a3 * t3) + a2 * t2) + a1 * t) * t * exp(-x * x));
    return 0.5 * (1.0 + sign * y);
}

static double t_cdf_approx(double t, size_t df) {
    if (df > 1000) {
        return normal_cdf(t);
    }
    if (df > 2) {
        double adjustment = sqrt((double)df / ((double)df - 2.0));
        return normal_cdf(t / adjustment);
    }
    return normal_cdf(t / 2.0);
}

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

int main(void) {
    RAND_bytes(msg, MSG_LEN);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    unsigned char *der = NULL;
    pk_len = i2d_PUBKEY(pkey, &der);
    memcpy(pk, der, pk_len);
    OPENSSL_free(der);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx;
    EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), NULL, pkey);
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);
    size_t siglen = SIG_LEN;
    EVP_DigestSign(mctx, good_sig, &siglen, msg, MSG_LEN);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);

    dudect_config_t config = {
        .chunk_size = SIG_LEN,
        .number_measurements = 100000,
    };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    dudect_state_t state = dudect_main(&ctx);

    double t_stat = dudect_get_max_t(&ctx);
    size_t df = dudect_get_degrees_of_freedom(&ctx);
    double p;
    if (df > 0 && t_stat >= 0) {
        double cdf = t_cdf_approx(t_stat, df);
        p = 2.0 * (1.0 - cdf);
        if (p < 0.0) p = 0.0;
        if (p > 1.0) p = 1.0;
    } else {
        p = 0.999;
    }

    dudect_free(&ctx);
    printf("{\"state\":%d,\"p\":%f}\n", state, p);
    return 0;
}
