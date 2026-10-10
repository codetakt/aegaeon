#ifndef AEGAEON_DUDECT_CANDIDATE
#error This observation requires the inactive candidate runner
#endif
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
/* The static helper must come from the actual product translation unit. */
#include "../../c/jws.c"

static uint8_t reference[32];

uint8_t do_one_computation(uint8_t *data) {
    return (uint8_t)ct_eq((jws_buf){reference}, 32, (jws_buf){data}, 32);
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < c->number_measurements; ++i) {
        uint8_t *chunk = input_data + i * c->chunk_size;
        classes[i] = randombit();
        memcpy(chunk, reference, 32);
        /* Uniform mismatch position is chosen before the measured call. */
        if (classes[i]) { uint8_t pos; randombytes(&pos, 1); chunk[pos % 32] ^= 1; }
    }
}

int main(int argc, char **argv) {
    uint8_t input[32] = {0};
    dudect_require(do_one_computation(input) == 1, "product comparison equal input");
    for (size_t i = 0; i < 32; ++i) {
        input[i] = 1;
        dudect_require(do_one_computation(input) == 0, "product comparison mismatch position");
        input[i] = 0;
    }
    return dudect_run_case("compare_product_32", 32, argc, argv);
}
