/* Included only in a separate non-timing executable. */
static uint64_t ct_fixture_state;
static size_t ct_fixture_requests, ct_fixture_bytes;
static void ct_fixture_random(uint8_t *out, size_t length) {
    ct_fixture_requests++;
    ct_fixture_bytes += length;
    for (size_t i = 0; i < length; i++) {
        ct_fixture_state ^= ct_fixture_state << 13;
        ct_fixture_state ^= ct_fixture_state >> 7;
        ct_fixture_state ^= ct_fixture_state << 17;
        out[i] = (uint8_t)ct_fixture_state;
    }
}
static uint8_t ct_fixture_bit(void) {
    uint8_t value;
    ct_fixture_random(&value, 1);
    return value & 1;
}
static void ct_fixture_reset(void) {
    ct_fixture_state = UINT64_C(0x6d3f2c1b98765431);
    ct_fixture_requests = ct_fixture_bytes = 0;
}
#define randombytes ct_fixture_random
#define randombit ct_fixture_bit
