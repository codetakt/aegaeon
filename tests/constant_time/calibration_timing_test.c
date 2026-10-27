/* Synthetic timing controls. They provide no product/cryptographic coverage. */
#ifndef AEGAEON_DUDECT_CANDIDATE
#error Controls require the versioned observation runner
#endif
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"

static unsigned control;

uint8_t do_one_computation(uint8_t *data) {
    uint32_t iterations;
    memcpy(&iterations, data, sizeof iterations);
    volatile uint64_t result = 0;
    for (uint32_t i = 0; i < iterations; ++i) result += i;
    return (uint8_t)result;
}

void prepare_inputs(dudect_config_t *config, uint8_t *data, uint8_t *classes) {
    for (size_t i = 0; i < config->number_measurements; ++i) {
        uint8_t random[3];
        randombytes(random, sizeof random);
        classes[i] = random[0] & 1;
        uint32_t iterations = (control == 2 ? 2048 : 256) + (random[1] & 31);
        if (classes[i] && control == 1) iterations += 64;
        if (classes[i] && control == 2)
            iterations = (random[2] & 1) ? iterations + 1024 : iterations - 1024;
        memcpy(data + i * config->chunk_size, &iterations, sizeof iterations);
    }
}

int main(int argc, char **argv) {
    uint32_t trials[] = {0, 1, 256, 1024, 3103};
    for (size_t i = 0; i < sizeof trials / sizeof *trials; ++i) {
        uint64_t count = trials[i];
        uint8_t expected = (uint8_t)(count * (count ? count - 1 : 0) / 2);
        dudect_require(do_one_computation((uint8_t *)&trials[i]) == expected,
                       "synthetic control operation");
    }
    const char *names[] = {
        "control_independent", "control_mean_shift", "control_variance_shift"
    };
    for (control = 0; control < 3; ++control) {
        int result = dudect_run_case(names[control], sizeof(uint32_t), argc, argv);
        if (result) return result;
    }
    return 0;
}
