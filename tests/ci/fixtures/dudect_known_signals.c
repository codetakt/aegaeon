/* Deterministic clock injection tests the real native collection/statistics path.
 * No hardware timing or cryptographic constant-time claim is made here. */
#include <stdint.h>
#include <x86intrin.h>
static uint64_t test_clock;
static unsigned test_control, test_fault;
static uint64_t synthetic_clock(void) { return test_clock; }
#define __rdtsc() synthetic_clock()
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"

uint8_t do_one_computation(uint8_t *data) {
    uint32_t delta;
    memcpy(&delta, data, sizeof delta);
    test_clock += delta;
    return (uint8_t)delta;
}

void prepare_inputs(dudect_config_t *config, uint8_t *data, uint8_t *classes) {
    for (size_t i = 0; i < config->number_measurements; ++i) {
        unsigned group = i & 1;
        classes[i] = test_fault == 4 ? 0 : group;
        int sign = (i & 2) ? 1 : -1;
        int spread = test_control == 2 && group && test_fault != 2 ? 5 : 1;
        int shift = group && ((test_control == 1 && test_fault != 1) ||
                            (test_control == 0 && test_fault == 3)) ? 32 : 0;
        uint32_t delta = (uint32_t)(100 + spread * sign + shift);
        memcpy(data + i * config->chunk_size, &delta, sizeof delta);
    }
}

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 1 || argv[1][0] < '0' || argv[1][0] > '4')
        return 2;
    test_fault = (unsigned)(argv[1][0] - '0');
    const char *names[] = {"control_independent", "control_mean_shift", "control_variance_shift"};
    char *arguments[] = {argv[0], "pr"};
    for (test_control = 0; test_control < 3; ++test_control) {
        int result = dudect_run_case(names[test_control], sizeof(uint32_t), 2, arguments);
        if (result) return result;
    }
    return 0;
}
