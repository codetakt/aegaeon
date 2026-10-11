/* Opt-in candidate support recording; no statistical inference. */
#ifndef AEGAEON_DUDECT_SUPPORT_H
#define AEGAEON_DUDECT_SUPPORT_H
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint64_t count;
    int64_t tick_min, tick_max;
    double value_min, value_max;
} dudect_support_t;

static uint64_t dudect_input_classes[2];
static uint64_t dudect_key_draws[2];
static uint64_t dudect_key_excluded[2];

static void dudect_support_push(dudect_support_t *s, int64_t tick, double value) {
    if (tick < 0 || !isfinite(value) || value < 0 || s->count == UINT64_MAX) abort();
    if (!s->count) {
        s->tick_min = s->tick_max = tick;
        s->value_min = s->value_max = value;
    } else {
        if (tick < s->tick_min) s->tick_min = tick;
        if (tick > s->tick_max) s->tick_max = tick;
        if (value < s->value_min) s->value_min = value;
        if (value > s->value_max) s->value_max = value;
    }
    ++s->count;
}

static void dudect_print_support(const dudect_support_t *s) {
    printf("{\"count\":%" PRIu64 ",\"tick_min\":", s->count);
    if (!s->count) {
        printf("null,\"tick_max\":null,\"value_min_hex\":null,\"value_max_hex\":null}");
    } else {
        printf("%" PRId64 ",\"tick_max\":%" PRId64
               ",\"value_min_hex\":\"%a\",\"value_max_hex\":\"%a\"}",
               s->tick_min, s->tick_max, s->value_min, s->value_max);
    }
}
#endif
