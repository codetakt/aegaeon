#include <stdio.h>
#include <string.h>
#include <math.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"

#define CHUNK_LEN 32
static uint8_t secret[CHUNK_LEN];

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

uint8_t do_one_computation(uint8_t *data) {
    return ct_eq(data, secret, CHUNK_LEN);
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *buf = input_data + i * c->chunk_size;
        memcpy(buf, secret, CHUNK_LEN);
        if (classes[i] == 1) {
            buf[0] ^= 1;
        }
    }
}

int main(int argc, char **argv) {
    dudect_require(do_one_computation(secret) != 0, "compare valid class");
    uint8_t invalid[CHUNK_LEN];
    memcpy(invalid, secret, CHUNK_LEN);
    invalid[0] ^= 1;
    dudect_require(do_one_computation(invalid) == 0, "compare invalid class");
    return dudect_run_case("compare", CHUNK_LEN, argc, argv);
}
