#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
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

int main(void) {
    RAND_bytes(key, KEY_LEN);
    RAND_bytes(nonce, NONCE_LEN);
    RAND_bytes(plaintext, PT_LEN);

    jwe_buf key_buf = { key };
    jwe_buf nonce_buf = { nonce };
    jwe_buf aad_buf = { NULL };
    jwe_buf pt_buf = { plaintext };
    jwe_buf ct_buf = { ciphertext };
    jwe_buf tag_buf = { good_tag };
    Jose_Jwe_chacha20poly1305_encrypt(
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
    );

    dudect_config_t config = {
        .chunk_size = TAG_LEN,
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
