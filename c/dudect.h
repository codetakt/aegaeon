/*
 dudect: dude, is my code constant time?
 https://github.com/oreparaz/dudect
 oscar.reparaz@esat.kuleuven.be

 Based on the following paper:

     Oscar Reparaz, Josep Balasch and Ingrid Verbauwhede
     dude, is my code constant time?
     DATE 2017
     https://eprint.iacr.org/2016/1123.pdf

 This file measures the execution time of a given function many times with
 different inputs and performs a Welch's t-test to determine if the function
 runs in constant time or not. This is essentially leakage detection, and
 not a timing attack.

 Notes:

   - the execution time distribution tends to be skewed towards large
     timings, leading to a fat right tail. Most executions take little time,
     some of them take a lot. We try to speed up the test process by
     throwing away those measurements with large cycle count. (For example,
     those measurements could correspond to the execution being interrupted
     by the OS.) Setting a threshold value for this is not obvious; we just
     keep the x% percent fastest timings, and repeat for several values of x.

   - the previous observation is highly heuristic. We also keep the uncropped
     measurement time and do a t-test on that.

   - we also test for unequal variances (second order test), but this is
     probably redundant since we're doing as well a t-test on cropped
     measurements (non-linear transform)

   - as long as any of the different test fails, the code will be deemed
     variable time.

 LICENSE:

    This is free and unencumbered software released into the public domain.
    Anyone is free to copy, modify, publish, use, compile, sell, or
    distribute this software, either in source code form or as a compiled
    binary, for any purpose, commercial or non-commercial, and by any
    means.
    In jurisdictions that recognize copyright laws, the author or authors
    of this software dedicate any and all copyright interest in the
    software to the public domain. We make this dedication for the benefit
    of the public at large and to the detriment of our heirs and
    successors. We intend this dedication to be an overt act of
    relinquishment in perpetuity of all present and future rights to this
    software under copyright law.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
    OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
    ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.
    For more information, please refer to <http://unlicense.org>
*/

/* Used for improved C++ compatibility */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef DUDECT_IMPLEMENTATION

#ifndef DUDECT_H_INCLUDED
#define DUDECT_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <emmintrin.h>
#include <x86intrin.h>

#ifdef DUDECT_VISIBLITY_STATIC
#define DUDECT_VISIBILITY static
#else
#define DUDECT_VISIBILITY extern
#endif

/*
   The interface of dudect begins here, to be compiled only if DUDECT_IMPLEMENTATION is not defined.
   In a multi-file library what follows would be the public-facing dudect.h
*/

#define DUDECT_ENOUGH_MEASUREMENTS (10000) /* do not draw any conclusion before we reach this many measurements */
#define DUDECT_NUMBER_PERCENTILES  (100)

/* perform this many tests in total:
   - 1 first order uncropped test,
   - DUDECT_NUMBER_PERCENTILES tests
   - 1 second order test
*/
#define DUDECT_TESTS (1+DUDECT_NUMBER_PERCENTILES+1)

typedef struct {
  size_t chunk_size;
  size_t number_measurements;
} dudect_config_t;

#ifdef AEGAEON_DUDECT_CANDIDATE
#include "dudect_support.h"
#include "dudect_context.h"
#endif

typedef struct {
#ifdef AEGAEON_DUDECT_CANDIDATE
  dudect_support_t support[2];
#endif
  double mean[2];
  double m2[2];
  double n[2];
} ttest_ctx_t;

typedef struct {
  int64_t *ticks;
  int64_t *exec_times;
  uint8_t *input_data;
  uint8_t *classes;
  dudect_config_t *config;
  ttest_ctx_t *ttest_ctxs[DUDECT_TESTS];
  int64_t *percentiles;
  size_t batches;
  size_t rejected;
  double pilot_center;
  size_t pilot_count;
  volatile uint8_t sink;
#ifdef AEGAEON_DUDECT_CANDIDATE
  int timing_enabled;
  dudect_context_t timing_before, timing_after;
#endif
} dudect_ctx_t;

typedef enum {
  DUDECT_LEAKAGE_FOUND=0,
  DUDECT_NO_LEAKAGE_EVIDENCE_YET
} dudect_state_t;

/* Public API */

DUDECT_VISIBILITY int dudect_init(dudect_ctx_t *ctx, dudect_config_t *conf);
DUDECT_VISIBILITY void dudect_collect(dudect_ctx_t *c);
DUDECT_VISIBILITY int dudect_free(dudect_ctx_t *ctx);
DUDECT_VISIBILITY void randombytes(uint8_t *x, size_t how_much);
DUDECT_VISIBILITY uint8_t randombit(void);


/* Public configuration */

/* Implementation details */
#include <inttypes.h>
#include <stdint.h>
#include <stddef.h>

// kill this
extern void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes);
extern uint8_t do_one_computation(uint8_t *data);

#endif /* DUDECT_H_INCLUDED */

#else /* DUDECT_IMPLEMENTATION */

#undef DUDECT_IMPLEMENTATION
#include "dudect.h"
#define DUDECT_IMPLEMENTATION

/* The implementation of dudect begins here. In a multi-file library what follows would be dudect.c */

#define DUDECT_TRACE (0)

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
  Online Welch's t-test

  Tests whether two populations have same mean.
  This is basically Student's t-test for unequal
  variances and unequal sample sizes.

  see https://en.wikipedia.org/wiki/Welch%27s_t-test
 */
static void t_push(ttest_ctx_t *ctx, double x, uint8_t clazz) {
  assert(clazz == 0 || clazz == 1);
  ctx->n[clazz]++;
  /*
   estimate variance on the fly as per the Welford method.
   this gives good numerical stability, see Knuth's TAOCP vol 2
  */
  double delta = x - ctx->mean[clazz];
  ctx->mean[clazz] = ctx->mean[clazz] + delta / ctx->n[clazz];
  ctx->m2[clazz] = ctx->m2[clazz] + delta * (x - ctx->mean[clazz]);
}

#ifdef AEGAEON_DUDECT_CANDIDATE
#define DUDECT_PUSH(ctx, id, tick, value, group) do { \
  dudect_support_push(&(ctx)->ttest_ctxs[id]->support[group], tick, value); \
  t_push((ctx)->ttest_ctxs[id], value, group); \
} while (0)
#else
#define DUDECT_PUSH(ctx, id, tick, value, group) \
  t_push((ctx)->ttest_ctxs[id], value, group)
#endif

static void t_init(ttest_ctx_t *ctx) {
  for (int clazz = 0; clazz < 2; clazz ++) {
    ctx->mean[clazz] = 0.0;
    ctx->m2[clazz] = 0.0;
    ctx->n[clazz] = 0.0;
#ifdef AEGAEON_DUDECT_CANDIDATE
    ctx->support[clazz] = (dudect_support_t){0};
#endif
  }
}

static int cmp(const int64_t *a, const int64_t *b) {
    if (*a == *b)
        return 0;
    return (*a > *b) ? 1 : -1;
}

static int64_t percentile(int64_t *a_sorted, double which, size_t size) {
  size_t array_position = (size_t)((double)size * (double)which);
  assert(array_position < size);
  return a_sorted[array_position];
}

/*
 set different thresholds for cropping measurements.
 the exponential tendency is meant to approximately match
 the measurements distribution, but there's not more science
 than that.
*/
static void prepare_percentiles(dudect_ctx_t *ctx) {
  size_t count = 0;
  for (size_t i = 10; i + 1 < ctx->config->number_measurements; ++i) {
    if (ctx->exec_times[i] >= 0) ctx->exec_times[count++] = ctx->exec_times[i];
  }
  ctx->pilot_count = count;
  if (!count) return;
  qsort(ctx->exec_times, count, sizeof(int64_t), (int (*)(const void *, const void *))cmp);
  for (size_t i = 0; i < DUDECT_NUMBER_PERCENTILES; i++) {
    ctx->percentiles[i] = percentile(ctx->exec_times,
        1 - pow(0.5, 10 * (double)(i + 1) / DUDECT_NUMBER_PERCENTILES), count);
  }
}

/* this comes from ebacs */
void randombytes(uint8_t *x, size_t how_much) {
  ssize_t i;
  static int fd = -1;

  ssize_t xlen = (ssize_t)how_much;
  assert(xlen >= 0);
  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom", O_RDONLY);
      if (fd != -1)
        break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576)
      i = xlen;
    else
      i = 1048576;

    i = read(fd, x, (size_t)i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

uint8_t randombit(void) {
  uint8_t ret = 0;
  randombytes(&ret, 1);
  return (ret & 1);
}

/*
 Returns current CPU tick count from *T*ime *S*tamp *C*ounter.

 The candidate follows Intel SDM volume 2, RDTSC: MFENCE;LFENCE orders
 earlier instructions/loads/stores before the timestamp, and the trailing
 LFENCE orders following instructions after it. MFENCE alone is insufficient.
 https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf
 This requires the host's LFENCE execution-serialization semantics; it is
 not a portable clock or a guarantee about a different processor/compiler.
 Historical mode preserves its original timer for explicit legacy replay.
*/
static inline int64_t cpucycles(void) {
  _mm_mfence();
#ifdef AEGAEON_DUDECT_CANDIDATE
  _mm_lfence();
  int64_t ticks = (int64_t)__rdtsc();
  _mm_lfence();
  return ticks;
#else
  return (int64_t)__rdtsc();
#endif
}

static void measure(dudect_ctx_t *ctx) {
  uint8_t result = 0;
  for (size_t i = 0; i < ctx->config->number_measurements; i++) {
    ctx->ticks[i] = cpucycles();
    result ^= do_one_computation(ctx->input_data + i * ctx->config->chunk_size);
  }

  ctx->sink = result; /* Keep the measured work observable under optimization. */
  for (size_t i = 0; i < ctx->config->number_measurements-1; i++) {
    ctx->exec_times[i] = ctx->ticks[i+1] - ctx->ticks[i];
  }
}

static void update_statistics(dudect_ctx_t *ctx) {
  for (size_t i = 10 /* discard the first few measurements */; i < (ctx->config->number_measurements-1); i++) {
    int64_t difference = ctx->exec_times[i];

    if (difference < 0) {
      ctx->rejected++;
      continue; // Record invalid deltas; never count them as observations.
    }

    // t-test on the execution time
    DUDECT_PUSH(ctx, 0, difference, (double)difference, ctx->classes[i]);

    // t-test on cropped execution times, for several cropping thresholds.
    for (size_t crop_index = 0; crop_index < DUDECT_NUMBER_PERCENTILES; crop_index++) {
#ifdef AEGAEON_DUDECT_CANDIDATE
      /* Integer timer quantiles include the complete tied boundary. */
      if (difference <= ctx->percentiles[crop_index]) {
#else
      if (difference < ctx->percentiles[crop_index]) {
#endif
        DUDECT_PUSH(ctx, crop_index + 1, difference, (double)difference, ctx->classes[i]);
      }
    }

    // Freeze a common centering value from the disjoint calibration batch.
    double centered = (double)difference - ctx->pilot_center;
    DUDECT_PUSH(ctx, 1 + DUDECT_NUMBER_PERCENTILES, difference, centered * centered, ctx->classes[i]);
  }
}

/* Collection and inference are separate. Only the strict runner can admit a
 * complete profile; an empty/warm-up context is never a successful test. */
void dudect_collect(dudect_ctx_t *ctx) {
  prepare_inputs(ctx->config, ctx->input_data, ctx->classes);
#ifdef AEGAEON_DUDECT_CANDIDATE
  for (size_t i = 0; i < ctx->config->number_measurements; ++i) {
    if (ctx->classes[i] > 1) abort();
    dudect_input_classes[ctx->classes[i]]++;
  }
#endif
#ifdef AEGAEON_DUDECT_CANDIDATE
  if (ctx->timing_enabled) ctx->timing_before = dudect_context();
#endif
  measure(ctx);
#ifdef AEGAEON_DUDECT_CANDIDATE
  if (ctx->timing_enabled) ctx->timing_after = dudect_context();
#endif
  if (ctx->batches == 0) {
    double total = 0.0;
    size_t count = 0;
    for (size_t i = 10; i + 1 < ctx->config->number_measurements; ++i) {
      if (ctx->exec_times[i] >= 0) {
        total += (double)ctx->exec_times[i];
        count++;
      }
    }
    ctx->pilot_center = count ? total / (double)count : NAN;
    prepare_percentiles(ctx);
  } else {
    update_statistics(ctx);
  }
  ctx->batches++;
}

int dudect_init(dudect_ctx_t *ctx, dudect_config_t *conf)
{
  ctx->batches = 0;
  ctx->rejected = 0;
  ctx->pilot_center = 0;
  ctx->pilot_count = 0;
  ctx->sink = 0;
#ifdef AEGAEON_DUDECT_CANDIDATE
  ctx->timing_enabled = 0;
#endif
  ctx->config = (dudect_config_t*) calloc(1, sizeof(*conf));
  assert(ctx->config);
  assert(conf->number_measurements > 11);
  ctx->config->number_measurements = conf->number_measurements;
  ctx->config->chunk_size = conf->chunk_size;
  ctx->ticks = (int64_t*) calloc(ctx->config->number_measurements, sizeof(int64_t));
  ctx->exec_times = (int64_t*) calloc(ctx->config->number_measurements, sizeof(int64_t));
  ctx->classes = (uint8_t*) calloc(ctx->config->number_measurements, sizeof(uint8_t));
  ctx->input_data = (uint8_t*) calloc(ctx->config->number_measurements * ctx->config->chunk_size, sizeof(uint8_t));

  for (int i = 0; i < DUDECT_TESTS; i++) {
    ctx->ttest_ctxs[i] = (ttest_ctx_t *)calloc(1, sizeof(ttest_ctx_t));
    assert(ctx->ttest_ctxs[i]);
    t_init(ctx->ttest_ctxs[i]);
  }

  ctx->percentiles = (int64_t*) calloc(DUDECT_NUMBER_PERCENTILES, sizeof(int64_t));

  assert(ctx->ticks);
  assert(ctx->exec_times);
  assert(ctx->classes);
  assert(ctx->input_data);
  assert(ctx->percentiles);

  return 0;
}

int dudect_free(dudect_ctx_t *ctx)
{
  for (int i = 0; i < DUDECT_TESTS; i++) {
    free(ctx->ttest_ctxs[i]);
  }
  free(ctx->percentiles);
  free(ctx->input_data);
  free(ctx->classes);
  free(ctx->exec_times);
  free(ctx->ticks);
  free(ctx->config);
  return 0;
}

#endif /* DUDECT_IMPLEMENTATION */

#ifdef __cplusplus
}  /* extern "C" */
#endif
