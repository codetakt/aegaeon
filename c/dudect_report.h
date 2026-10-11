/* Version 2 observation protocol. Inference and admission live in the runner. */
#ifndef AEGAEON_DUDECT_REPORT_H
#define AEGAEON_DUDECT_REPORT_H
#include <string.h>

#ifndef AEGAEON_DUDECT_BATCH_SIZE
#define AEGAEON_DUDECT_BATCH_SIZE 65536
#endif

static void dudect_require(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "dudect setup failed: %s\n", operation);
        exit(2);
    }
}

#ifdef AEGAEON_DUDECT_CANDIDATE
#include "dudect_candidate_report.h"
#else
static int dudect_run_case(const char *name, size_t chunk, int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "pr") && strcmp(argv[1], "periodic"))) {
        fprintf(stderr, "usage: harness {pr|periodic}; requires the dudect runner\n");
        return 2;
    }
    const int periodic = !strcmp(argv[1], "periodic");
    const size_t periodic_looks[] = {1, 2, 4, 8, 16, 32, 64, 98};
    const size_t final_batch = periodic ? 98 : 7;
    dudect_config_t config = {chunk, AEGAEON_DUDECT_BATCH_SIZE};
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    dudect_collect(&ctx);
    size_t look = 0;
    for (size_t batch = 1; batch <= final_batch; ++batch) {
        dudect_collect(&ctx);
        if (periodic && batch != periodic_looks[look]) continue;
        ++look;
        if (!isfinite(ctx.pilot_center)) { dudect_free(&ctx); return 2; }
        printf("{\"schema_version\":2,\"case\":\"%s\",\"profile\":\"%s\","
               "\"batch_size\":%zu,\"batches\":%zu,\"look\":%zu,"
               "\"executed\":%zu,\"warmup\":%zu,\"rejected\":%zu,"
               "\"pilot\":{\"count\":%zu,\"center\":%.17g,\"cutoffs\":[",
               name, argv[1], config.number_measurements, batch, look,
               config.number_measurements * (batch + 1), config.number_measurements, ctx.rejected,
               ctx.pilot_count, ctx.pilot_center);
        for (size_t i = 0; i < DUDECT_NUMBER_PERCENTILES; ++i) {
            printf("%s%lld", i ? "," : "", (long long)ctx.percentiles[i]);
        }
        printf("]},\"statistics\":[");
        for (size_t i = 0; i < DUDECT_TESTS; ++i) {
            ttest_ctx_t *t = ctx.ttest_ctxs[i];
            if (!isfinite(t->mean[0]) || !isfinite(t->mean[1]) ||
                !isfinite(t->m2[0]) || !isfinite(t->m2[1])) {
                dudect_free(&ctx); return 2;
            }
            printf("%s[%.0f,%.0f,%.17g,%.17g,%.17g,%.17g]", i ? "," : "",
                   t->n[0], t->n[1], t->mean[0], t->mean[1], t->m2[0], t->m2[1]);
        }
        printf("]}\n");
        if (fflush(stdout) || getchar() != 'c') { dudect_free(&ctx); return 2; }
    }
    dudect_free(&ctx);
    return 0;
}
#endif /* candidate report */
#endif
