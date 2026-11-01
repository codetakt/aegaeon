/* Deterministic timer, actual C statistics, trace and ACK protocol. */
#include <stdint.h>
#include <x86intrin.h>
static uint64_t clock_value;
static unsigned frame_number, active_control;
static uint64_t injected_clock(void) { return clock_value; }
#define __rdtsc() injected_clock()
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"
#ifndef TEST_MODE
#define TEST_MODE 3
#endif
uint8_t do_one_computation(uint8_t *data) {
    uint32_t delta;
    memcpy(&delta, data, 4);
#if TEST_MODE >= 200
    if (active_control == 2) {
        if (TEST_MODE == 202 && delta < 2048) delta += 1024;
        if (TEST_MODE == 202 && delta >= 3072) delta -= 1024;
    } else if (active_control == 1 && TEST_MODE == 201 && delta >= 320) {
        delta -= 64;
    }
#endif
    clock_value += delta;
    return (uint8_t)delta;
}
void prepare_inputs(dudect_config_t *config, uint8_t *data, uint8_t *classes) {
    for (size_t i = 0; i < config->number_measurements; ++i) {
        classes[i] = i % 2;
        uint32_t delta = TEST_MODE == 100 && frame_number ? 1000000 + frame_number * 65536 + i : 1000;
        if (TEST_MODE != 100 && frame_number == 1 && i >= 10 && i < 10 + 2 * TEST_MODE && !(i % 2)) delta = 980;
#if TEST_MODE >= 200
        unsigned jitter = (i / 2) % 32;
        if (active_control == 2) delta = (classes[i] ? (i & 2 ? 1024 : 3072) : 2048) + jitter;
        else delta = (active_control == 1 && classes[i] ? 320 : 256) + jitter;
        if (TEST_MODE == 203 && active_control == 0) delta = 256 + (jitter % 16) + 16 * classes[i];
#endif
        memcpy(data + i * config->chunk_size, &delta, 4);
    }
    ++frame_number;
}
int main(int argc, char **argv) {
#if TEST_MODE >= 200
    const char *names[] = {"control_independent", "control_mean_shift", "control_variance_shift"};
    for (active_control = 0; active_control < 3; ++active_control) {
        frame_number = 0;
        int rc = dudect_run_case(names[active_control], 4, argc, argv);
        if (rc) return rc;
    }
    return 0;
#else
    return dudect_run_case("compare", 32, argc, argv);
#endif
}
