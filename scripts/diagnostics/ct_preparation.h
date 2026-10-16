/* Research overlay. Original generation and measured callback remain intact.
 * Only ct128 receives the additional preparation pass. Never a gate default. */
static unsigned char *ct_preparation_copy;
static int ct_preparation_mode;
static size_t ct_preparation_frames;
static int ct_preparation_active;

static void ct_preparation_cleanup(void) {
    fprintf(stderr, "CT_PREPARATION mode=%d frames=%zu\n",
            ct_preparation_mode, ct_preparation_frames);
    free(ct_preparation_copy);
}

static void ct_preparation_init(void) {
    const char *mode = getenv("AEGAEON_DUDECT_PREPARATION");
    dudect_require(mode != NULL, "explicit diagnostic preparation mode");
    if (!strcmp(mode, "baseline")) ct_preparation_mode = 0;
    else if (!strcmp(mode, "class0")) ct_preparation_mode = 1;
    else if (!strcmp(mode, "uniform")) ct_preparation_mode = 2;
    else dudect_require(0, "known diagnostic preparation mode");
    dudect_require(!atexit(ct_preparation_cleanup), "preparation cleanup");
}

static void ct_preparation_begin(dudect_config_t *c) {
    ct_preparation_active = c->chunk_size == 128;
    if (!ct_preparation_active) return;
    dudect_require(c->number_measurements <= 65536, "bounded preparation arena");
    if (!ct_preparation_copy) {
        ct_preparation_copy = malloc(65536 * 128);
        dudect_require(ct_preparation_copy != NULL, "preparation arena");
    }
}

static void ct_preparation_finish(dudect_config_t *c, uint8_t *data,
                                  const uint8_t *labels) {
    if (!ct_preparation_active) return;
    ct_preparation_frames++;
    if (!ct_preparation_mode) return;
    const size_t bytes = c->number_measurements * c->chunk_size;
    memcpy(ct_preparation_copy, data, bytes);
    for (size_t i = 0; i < c->number_measurements; i++) {
        if (ct_preparation_mode == 2 || labels[i] == 0)
            memset(data + i * c->chunk_size, 0, c->chunk_size);
    }
    /* Preserve the experimental writes; this is a compiler barrier, not a fence. */
    __asm__ __volatile__("" : : "r"(data) : "memory");
    for (size_t i = 0; i < c->number_measurements; i++)
        memcpy(data + i * c->chunk_size,
               ct_preparation_copy + i * c->chunk_size, c->chunk_size);
}
