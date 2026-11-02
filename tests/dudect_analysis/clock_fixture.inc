/* Test-only deterministic clock; no physical timing claim. */
static unsigned fixture_batch, fixture_sample, active_batch;
static uint8_t fixture_labels[65536];
static uint64_t fixture_calls;
static unsigned sparse_exceptions;
void prepare_inputs(dudect_config_t *c, uint8_t *data, uint8_t *classes) {
    uint32_t state = 0x6e624eb7u ^ fixture_batch;
    active_batch = fixture_batch++; fixture_sample = 0;
    for (size_t i=0; i<c->number_measurements; ++i) {
        state = state * 1664525u + 1013904223u;
        classes[i] = (uint8_t)(state >> 31);
        fixture_labels[i] = classes[i];
        memset(data + i*c->chunk_size, classes[i] ? 0xcc : (TEST_MODE >= 7 ? 0x42 : 0xbb), c->chunk_size);
    }
}
uint8_t do_one_computation(uint8_t *data) {
    uint8_t result = TEST_MODE == 6 ? data[0] : real_callback(data);
    unsigned i = fixture_sample++, group = fixture_labels[i];
    uint32_t hash = (i * 2654435761u) ^ (active_batch * 2246822519u);
    unsigned noise = (hash >> 12) % 1000;
    uint64_t delta = (active_batch ? 50000 : 1000) + noise;
    if (TEST_MODE == 1) delta += group * 200;
    if (TEST_MODE == 2 && active_batch <= 2 && active_batch) delta += group * 200;
    if (TEST_MODE == 3 && active_batch >= 15) delta += group * 200;
    if (TEST_MODE == 4 && noise < 90) delta += group * 30;
    if (TEST_MODE == 5 && i && fixture_labels[i-1]) delta += group * 200;
    if (TEST_MODE == 6 && active_batch) delta = 1000000 + active_batch * 65536 + i;
    if (TEST_MODE >= 7) {
        delta = 1000;
        unsigned count = TEST_MODE == 7 ? 4 : TEST_MODE == 8 ? 5 : 3;
        if (active_batch == 1 && i >= 10 && i < 65535 && group && sparse_exceptions < count) {
            delta = 996; ++sparse_exceptions;
        }
    }
    fixture_clock += delta; ++fixture_calls;
    return result;
}
int main(int argc, char **argv) {
    aegaeon_crypto_init();
    memset(hmac_key, 0x42, HMAC_KEY_LEN);
    current_test = TEST_MODE >= 7 ? TEST_HMAC_SHA256_KEY : TEST_HMAC_SHA256;
    int result = dudect_run_case(TEST_MODE >= 7 ? "hmac_sha256_key" : "hmac_sha256", CHUNK_LEN, argc, argv);
    fprintf(stderr, "FIXTURE_CALLBACKS %llu\n", (unsigned long long)fixture_calls);
    if (!result) dudect_require(fixture_calls == 17u*65536u, "fixture callback count");
    return result;
}
