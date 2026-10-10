/* Ordered synthetic ct_eq_128 samples, captured outside the timed loop.
 * A private descriptor is supplied by the parent collector. No path is opened
 * here and no runtime product inputs are recorded. Format is x86 little endian.
 */
#ifndef AEGAEON_DUDECT_TRACE_H
#define AEGAEON_DUDECT_TRACE_H
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Dudect sample capture requires a little-endian target
#endif

typedef struct {
    int fd;
    uint8_t *inputs;
    int timing_fd;
    size_t timing_input_width;
} dudect_trace_t;

static size_t dudect_timing_input_width(const char *name) {
    return !strcmp(name, "sha256") || !strcmp(name, "hmac_sha256") ? 32 : 0;
}

static void dudect_trace_write(int fd, const void *data, size_t size) {
    const uint8_t *bytes = data;
    while (size) {
        ssize_t count = write(fd, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        dudect_require(count > 0, "write ordered sample evidence");
        bytes += count;
        size -= (size_t)count;
    }
}

static int dudect_timing_begin(const char *name, dudect_ctx_t *ctx) {
    static int initialized = -1;
    const char *value = getenv("AEGAEON_DUDECT_TIMING_FD");
    if (!value) return -1;
    char *end = NULL;
    errno = 0;
    long fd = strtol(value, &end, 10);
    dudect_require(!errno && end != value && !*end && fd >= 3 && fd <= INT_MAX,
                   "timing evidence descriptor");
    struct stat info;
    dudect_require(!fstat((int)fd, &info) && S_ISREG(info.st_mode),
                   "regular timing evidence file");
    if (initialized < 0) {
        dudect_require(info.st_size == 0 && lseek((int)fd, 0, SEEK_CUR) == 0,
                       "empty timing evidence file");
        dudect_trace_write((int)fd, "AEGTIM02", 8);
        dudect_trace_write((int)fd, AEGAEON_DUDECT_BUILD_SHA256, 64);
        dudect_trace_write((int)fd, AEGAEON_DUDECT_CONTRACT_SHA256, 64);
        dudect_trace_write((int)fd, AEGAEON_DUDECT_NUMERICAL_SHA256, 64);
        initialized = (int)fd;
    }
    dudect_require(initialized == fd && strlen(name) < 64, "timing case identity");
    char case_name[64] = {0};
    memcpy(case_name, name, strlen(name));
    size_t width = dudect_timing_input_width(name);
    dudect_require(!width || ctx->config->chunk_size == width,
                   "contiguous synthetic timing inputs");
    uint64_t layout[5] = {
        ctx->config->chunk_size, width,
        (uintptr_t)ctx->input_data % 4096,
        (uintptr_t)ctx->ticks % 4096,
        (uintptr_t)ctx->classes % 4096
    };
    dudect_trace_write((int)fd, case_name, sizeof case_name);
    dudect_trace_write((int)fd, layout, sizeof layout);
    ctx->timing_enabled = 1;
    /* One inherited descriptor spans all cases; process exit closes it. */
    return (int)fd;
}

static void dudect_timing_batch(int fd, dudect_ctx_t *ctx, size_t batch, size_t width) {
    if (fd < 0) return;
    const dudect_context_t *b = &ctx->timing_before, *a = &ctx->timing_after;
    uint64_t header[18] = {
        batch, ctx->config->number_measurements, b->monotonic_ns, a->monotonic_ns,
        b->cpu, a->cpu, b->minor_faults, a->minor_faults,
        b->major_faults, a->major_faults, b->voluntary_switches, a->voluntary_switches,
        b->involuntary_switches, a->involuntary_switches,
        b->user_us, a->user_us, b->system_us, a->system_us
    };
    dudect_trace_write(fd, header, sizeof header);
    dudect_trace_write(fd, ctx->ticks, ctx->config->number_measurements * sizeof(int64_t));
    dudect_trace_write(fd, ctx->classes, ctx->config->number_measurements);
    if (width) {
        dudect_require(ctx->config->number_measurements <= SIZE_MAX / width,
                       "synthetic timing input dimensions");
        dudect_trace_write(fd, ctx->input_data, ctx->config->number_measurements * width);
    }
}

static dudect_trace_t dudect_trace_begin(const char *name, dudect_ctx_t *ctx) {
    dudect_trace_t trace = {
        -1, NULL, dudect_timing_begin(name, ctx), dudect_timing_input_width(name)
    };
    const char *value = getenv("AEGAEON_DUDECT_TRACE_FD");
    if (!value || strcmp(name, "ct_eq_128")) return trace;
    char *end = NULL;
    errno = 0;
    long fd = strtol(value, &end, 10);
    dudect_require(!errno && end != value && !*end && fd >= 3 && fd <= INT_MAX,
                   "sample evidence descriptor");
    struct stat info;
    dudect_require(!fstat((int)fd, &info) && S_ISREG(info.st_mode) && info.st_size == 0,
                   "empty regular sample evidence file");
    dudect_require(ctx->config->chunk_size == 128 &&
                   ctx->config->number_measurements <= SIZE_MAX / 32,
                   "sample evidence dimensions");
    trace.inputs = malloc(ctx->config->number_measurements * 32);
    dudect_require(trace.inputs != NULL, "sample evidence buffer");
    trace.fd = (int)fd;
    dudect_trace_write(trace.fd, "AEGTRC01", 8);
    dudect_trace_write(trace.fd, AEGAEON_DUDECT_BUILD_SHA256, 64);
    dudect_trace_write(trace.fd, AEGAEON_DUDECT_CONTRACT_SHA256, 64);
    dudect_trace_write(trace.fd, AEGAEON_DUDECT_NUMERICAL_SHA256, 64);
    return trace;
}

static void dudect_trace_batch(dudect_trace_t *trace, dudect_ctx_t *ctx, size_t batch) {
    dudect_timing_batch(trace->timing_fd, ctx, batch, trace->timing_input_width);
    if (trace->fd < 0) return;
    size_t count = ctx->config->number_measurements;
    uint64_t header[4] = {batch, count, ctx->config->chunk_size, 32};
    /* Keep the actual 32-byte comparison inputs, not the unused stride padding.
     * ticks preserve sample order even after the pilot sorts exec_times. */
    for (size_t i = 0; i < count; ++i)
        memcpy(trace->inputs + i * 32, ctx->input_data + i * ctx->config->chunk_size, 32);
    dudect_trace_write(trace->fd, header, sizeof header);
    dudect_trace_write(trace->fd, ctx->ticks, count * sizeof(int64_t));
    dudect_trace_write(trace->fd, ctx->classes, count);
    dudect_trace_write(trace->fd, trace->inputs, count * 32);
}

static void dudect_trace_end(dudect_trace_t *trace) {
    free(trace->inputs);
    if (trace->fd >= 0)
        dudect_require(!close(trace->fd), "close sample evidence descriptor");
}
#endif
