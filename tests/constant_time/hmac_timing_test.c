#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "jws.h"
#include "EverCrypt_HMAC.h"

#define CHUNK_LEN 32

static uint8_t key[16];
static uint8_t msg[32];
static uint8_t good_sig[CHUNK_LEN];

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
    );
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

int main(void) {
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

    // Use a moderate measurement count that keeps runtime reasonable while
    // providing a stable p-value for CI purposes.
    dudect_config_t config = {
        .chunk_size = CHUNK_LEN,
        .number_measurements = 200000,
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
