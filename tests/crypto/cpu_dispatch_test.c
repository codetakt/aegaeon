/* Regression for native SHA CPU dispatch and shared initialization.
 * Inputs and expected full digests are generated independently with hashlib.
 * This Linux/x86-64 probe is linked with --wrap instrumentation; it does not
 * provide timing evidence or inherit a formal proof for the dispatch glue.
 */
#define _DEFAULT_SOURCE 1
#include "EverCrypt_AutoConfig2.h"
#include "EverCrypt_HMAC.h"
#include "EverCrypt_Hash.h"
#include "Hacl_HMAC.h"
#include "Hacl_Hash_SHA2.h"
#include "crypto_init.h"
#include "internal/Vale.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static atomic_ullong asm_blocks, sha_checks, sse_checks, failures, init_calls;
void __real_EverCrypt_AutoConfig2_init(void);
void __wrap_EverCrypt_AutoConfig2_init(void) {
  atomic_fetch_add_explicit(&init_calls, 1, memory_order_relaxed);
  __real_EverCrypt_AutoConfig2_init();
}
uint64_t __real_sha256_update(uint32_t *, uint8_t *, uint64_t, uint32_t *);
uint64_t __real_check_sha(void);
uint64_t __real_check_sse(void);
uint64_t __wrap_sha256_update(uint32_t *s, uint8_t *d, uint64_t n,
                              uint32_t *k) {
  atomic_fetch_add_explicit(&asm_blocks, n, memory_order_relaxed);
  return __real_sha256_update(s, d, n, k);
}
uint64_t __wrap_check_sha(void) {
  atomic_fetch_add_explicit(&sha_checks, 1, memory_order_relaxed);
#ifdef TEST_NO_SHA
  return 0;
#else
  return __real_check_sha();
#endif
}
uint64_t __wrap_check_sse(void) {
  atomic_fetch_add_explicit(&sse_checks, 1, memory_order_relaxed);
#ifdef TEST_NO_SSE
  return 0;
#else
  return __real_check_sse();
#endif
}
struct vector {
  uint32_t k, n;
  uint8_t key[512], data[4096], expected[316];
};
static struct vector *vectors;
static uint32_t count;
static pthread_barrier_t start_barrier;
static void take(void *p, size_t n) {
  if (fread(p, 1, n, stdin) != n)
    exit(20);
}
static uint32_t u32(void) {
  uint8_t b[4];
  take(b, 4);
  return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 |
         (uint32_t)b[3] << 24;
}
static int check(const struct vector *v) {
  aegaeon_crypto_init();
  uint8_t result[316];
  uint8_t *data = (uint8_t *)v->data, *key = (uint8_t *)v->key;
  Hacl_Hash_SHA2_hash_224(result, data, v->n);
  Hacl_Hash_SHA2_hash_256(result + 28, data, v->n);
  Hacl_Hash_SHA2_hash_384(result + 60, data, v->n);
  Hacl_Hash_SHA2_hash_512(result + 108, data, v->n);
  Hacl_HMAC_compute_sha2_256(result + 172, key, v->k, data, v->n);
  Hacl_HMAC_compute_sha2_384(result + 204, key, v->k, data, v->n);
  Hacl_HMAC_compute_sha2_512(result + 252, key, v->k, data, v->n);
  uint8_t other[92];
  aegaeon_crypto_init();
  EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_SHA2_224, other, data,
                                  v->n);
  aegaeon_crypto_init();
  EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_SHA2_256, other + 28,
                                  data, v->n);
  aegaeon_crypto_init();
  EverCrypt_HMAC_compute(Spec_Hash_Definitions_SHA2_256, other + 60, key, v->k,
                         data, v->n);
  return memcmp(result, v->expected, 316) == 0 &&
         memcmp(other, v->expected, 60) == 0 &&
         memcmp(other + 60, v->expected + 172, 32) == 0;
}
static void *worker(void *unused) {
  (void)unused;
  int r = pthread_barrier_wait(&start_barrier);
  if (r != 0 && r != PTHREAD_BARRIER_SERIAL_THREAD)
    abort();
  for (uint32_t i = 0; i < count; i++)
    if (!check(&vectors[i]))
      atomic_fetch_add_explicit(&failures, 1, memory_order_relaxed);
  return NULL;
}
int main(int argc, char **argv) {
  int threads = argc == 2 && !strcmp(argv[1], "--threads");
  if (argc != 1 && !threads)
    return 2;
  uint8_t magic[8];
  take(magic, 8);
  if (memcmp(magic, "AEGDIS01", 8))
    return 3;
  count = u32();
  if (count != 1430)
    return 4;
  vectors = calloc(count, sizeof(*vectors));
  if (!vectors)
    return 5;
  uint64_t expected_blocks = 0;
  for (uint32_t i = 0; i < count; i++) {
    struct vector *v = &vectors[i];
    v->k = u32();
    v->n = u32();
    if (v->k > 512 || v->n > 4096)
      return 6;
    take(v->key, v->k);
    take(v->data, v->n);
    take(v->expected, 316);
    expected_blocks += 2 * ((v->n + 9 + 63) / 64) +
                       (v->k > 64 ? (v->k + 9 + 63) / 64 : 0) +
                       (64 + v->n + 9 + 63) / 64 + 2;
  }
  if (fgetc(stdin) != EOF)
    return 7;
  int accelerated = __real_check_sha() != 0 && __real_check_sse() != 0;
#if defined(TEST_NO_SHA) || defined(TEST_NO_SSE)
  accelerated = 0;
#endif
  /* Raw library use before initialization must retain the scalar policy. */
  uint8_t empty[32], scratch[1] = {0};
  Hacl_Hash_SHA2_hash_256(empty, scratch, 0);
  if (atomic_load(&asm_blocks) != 0 || atomic_load(&init_calls) != 0)
    return 14;
  if (threads) {
    pthread_t ids[16];
    if (pthread_barrier_init(&start_barrier, NULL, 17))
      return 8;
    for (unsigned i = 0; i < 16; i++)
      if (pthread_create(&ids[i], NULL, worker, NULL))
        abort();
    int r = pthread_barrier_wait(&start_barrier);
    if (r != 0 && r != PTHREAD_BARRIER_SERIAL_THREAD)
      abort();
    for (unsigned i = 0; i < 16; i++)
      if (pthread_join(ids[i], NULL))
        abort();
    if (pthread_barrier_destroy(&start_barrier))
      return 9;
  } else
    for (uint32_t i = 0; i < count; i++)
      if (!check(&vectors[i])) {
        fprintf(stderr, "vector %u failed\n", i);
        return 10;
      }
  unsigned copies = threads ? 16 : 1;
  uint64_t blocks = atomic_load_explicit(&asm_blocks, memory_order_relaxed);
  unsigned long long qc = atomic_load_explicit(&sha_checks,
                                               memory_order_relaxed),
                     sc = atomic_load_explicit(&sse_checks,
                                               memory_order_relaxed);
  if (atomic_load(&failures) ||
      blocks != (accelerated ? expected_blocks * copies * 2 : 0) || qc != 1 ||
      sc != 1 || atomic_load(&init_calls) != 1)
    return 11;
  /* Explicit disabling must apply through both HACL and EverCrypt tails.
   * The once guard must preserve a subsequent caller policy change. */
  for (unsigned policy = 0; policy < 2; policy++) {
    if (policy == 0)
      EverCrypt_AutoConfig2_disable_shaext();
    else {
      EverCrypt_AutoConfig2_init();
      EverCrypt_AutoConfig2_disable_sse();
    }
    aegaeon_crypto_init();
    uint8_t direct[32], evercrypt[32];
    Hacl_Hash_SHA2_hash_256(direct, scratch, 0);
    EverCrypt_Hash_Incremental_hash(Spec_Hash_Definitions_SHA2_256, evercrypt,
                                    scratch, 0);
    if (memcmp(direct, empty, 32) || memcmp(evercrypt, empty, 32) ||
        atomic_load(&asm_blocks) != blocks)
      return 15;
    if (policy == 0 && EverCrypt_AutoConfig2_has_shaext())
      return 16;
    if (policy == 1 && EverCrypt_AutoConfig2_has_sse())
      return 17;
  }
  printf("{\"vectors_per_thread\":%u,\"threads\":%u,\"full_digests\":%u,"
         "\"accelerated\":%s,\"sha_blocks\":%llu,\"sha_checks\":%llu,\"sse_"
         "checks\":%llu,\"initial_init_calls\":1,\"disable_policy_checks\":4,"
         "\"timing_executed\":false}\n",
         count, copies, count * 10 * copies, accelerated ? "true" : "false",
         (unsigned long long)blocks, qc, sc);
  free(vectors);
  return 0;
}
