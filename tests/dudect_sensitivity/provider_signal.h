/* Diagnostic-only addition to the full provider. Never linked into the
 * ordinary native package. The generator inserts work only in HMAC message. */
static unsigned diagnostic_batch, diagnostic_scope;
static uint8_t *diagnostic_base;
static uint32_t diagnostic_counts[65536];
static uint64_t diagnostic_prepared;

static unsigned diagnostic_enabled(unsigned batch) {
    return (diagnostic_scope == 1 && batch >= 1 && batch <= 8) ||
           (diagnostic_scope == 2 && batch >= 9 && batch <= 16);
}

__attribute__((noinline)) static uint64_t diagnostic_work(uint32_t count) {
    uint64_t x = 0;
    for (uint32_t j = 0; j < count; ++j)
        __asm__ __volatile__("addq $1, %0" : "+r"(x) : : "cc");
    return x;
}

static void diagnostic_measure(uint8_t *data) {
    size_t sample = (size_t)(data - diagnostic_base) / 32;
    uint64_t work = diagnostic_work(diagnostic_counts[sample]);
    __asm__ __volatile__("" : : "r"(work) : "memory");
}
