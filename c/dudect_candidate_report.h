/* Included only by the opt-in candidate build. No gate acceptance protocol. */
#ifndef AEGAEON_DUDECT_CONTRACT_SHA256
#error Candidate builds require an exact contract digest
#endif
#ifndef AEGAEON_DUDECT_BUILD_SHA256
#error Candidate builds require an exact source/build manifest digest
#endif
#ifndef AEGAEON_DUDECT_SUITE
#error Candidate builds require their suite identity
#endif
#ifndef AEGAEON_DUDECT_NUMERICAL_SHA256
#error Candidate builds require the exact numerical implementation identity
#endif

#include "dudect_trace.h"

static void dudect_print_candidate(const char *name, const char *profile,
                                   dudect_ctx_t *ctx, size_t batch, size_t look) {
    size_t size = ctx->config->number_measurements;
    printf("{\"schema_version\":4,\"case\":\"%s\",\"profile\":\"%s\","
           "\"binding\":{\"case_id\":\"%s/%s\",\"profile\":\"%s\","
           "\"contract_sha256\":\"%s\",\"build_sha256\":\"%s\",\"numerical_sha256\":\"%s\"},"
           "\"batch_size\":%zu,\"batches\":%zu,\"look\":%zu,"
           "\"executed\":%zu,\"warmup\":%zu,\"rejected\":%zu,"
           "\"input_audit\":{\"class_count\":[%" PRIu64 ",%" PRIu64 "],"
           "\"key_draws\":[%" PRIu64 ",%" PRIu64 "],\"key_excluded\":[%" PRIu64 ",%" PRIu64 "]},"
           "\"pilot\":{\"count\":%zu,\"center\":%.17g,\"cutoffs\":[",
           name, profile, AEGAEON_DUDECT_SUITE, name, profile,
           AEGAEON_DUDECT_CONTRACT_SHA256, AEGAEON_DUDECT_BUILD_SHA256,
           AEGAEON_DUDECT_NUMERICAL_SHA256,
           size, batch, look, size * (batch + 1), size, ctx->rejected,
           dudect_input_classes[0], dudect_input_classes[1],
           dudect_key_draws[0], dudect_key_draws[1], dudect_key_excluded[0], dudect_key_excluded[1],
           ctx->pilot_count, ctx->pilot_center);
    for (size_t i = 0; i < DUDECT_NUMBER_PERCENTILES; ++i)
        printf("%s%" PRId64, i ? "," : "", ctx->percentiles[i]);
    printf("]},\"statistics\":[");
    for (size_t i = 0; i < DUDECT_TESTS; ++i) {
        ttest_ctx_t *t = ctx->ttest_ctxs[i];
        dudect_require(isfinite(t->mean[0]) && isfinite(t->mean[1]) &&
                       isfinite(t->m2[0]) && isfinite(t->m2[1]), "finite moments");
        printf("%s[%.0f,%.0f,%.17g,%.17g,%.17g,%.17g]", i ? "," : "",
               t->n[0], t->n[1], t->mean[0], t->mean[1], t->m2[0], t->m2[1]);
    }
    printf("],\"support\":[");
    for (size_t i = 0; i < DUDECT_TESTS; ++i) {
        printf("%s[", i ? "," : "");
        dudect_print_support(&ctx->ttest_ctxs[i]->support[0]); putchar(',');
        dudect_print_support(&ctx->ttest_ctxs[i]->support[1]); putchar(']');
    }
    printf("]}\n");
}

static int dudect_run_case(const char *name, size_t chunk, int argc, char **argv) {
    int self_test = argc == 2 && !strcmp(argv[1], "--self-test");
    if (argc != 2 || (!self_test && strcmp(argv[1], "pr") && strcmp(argv[1], "periodic")))
        return 2;
    memset(dudect_input_classes, 0, sizeof dudect_input_classes);
    memset(dudect_key_draws, 0, sizeof dudect_key_draws);
    memset(dudect_key_excluded, 0, sizeof dudect_key_excluded);
    dudect_config_t config = {chunk, self_test ? 128 : AEGAEON_DUDECT_BATCH_SIZE};
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    if (self_test) {
        prepare_inputs(&config, ctx.input_data, ctx.classes);
        for (size_t i = 0; i < config.number_measurements; ++i) {
            dudect_require(ctx.classes[i] < 2, "class identity");
            dudect_input_classes[ctx.classes[i]]++;
            ctx.sink ^= do_one_computation(ctx.input_data + i * chunk);
        }
        dudect_require(dudect_input_classes[0] && dudect_input_classes[1], "both fixture classes");
        printf("{\"case_id\":\"%s/%s\",\"self_test\":true,\"timing_executed\":false}\n",
               AEGAEON_DUDECT_SUITE, name);
        dudect_free(&ctx);
        return 0;
    }
    const int periodic = !strcmp(argv[1], "periodic");
    const size_t looks[] = {1, 2, 4, 8, 16, 32, 64, 98};
    size_t look = 0;
    dudect_trace_t trace = dudect_trace_begin(name, &ctx);
    dudect_collect(&ctx);
    dudect_trace_batch(&trace, &ctx, 0);
    for (size_t batch = 1; batch <= (periodic ? 98U : 7U); ++batch) {
        dudect_collect(&ctx);
        dudect_trace_batch(&trace, &ctx, batch);
        if (periodic && batch != looks[look]) continue;
        ++look;
        dudect_require(isfinite(ctx.pilot_center), "finite pilot");
        dudect_print_candidate(name, argv[1], &ctx, batch, look);
        if (fflush(stdout) || getchar() != 'c') {
            dudect_trace_end(&trace); dudect_free(&ctx); return 2;
        }
    }
    dudect_trace_end(&trace);
    dudect_free(&ctx);
    return 0;
}
