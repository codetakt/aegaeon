/* dudect constant-time harness — HACL* / EverCrypt-backed tests.
 *
 * This harness links against the real HACL/EverCrypt C implementations
 * (SHA-256, HMAC-SHA256, Ed25519 verify) to provide fail-close CT checks
 * for the verified crypto path.
 *
 * Build (recommended):
 *   bash scripts/ci/dudect_check.sh pr
 */

#include <math.h>
#include <stdio.h>
#include <string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "dudect_report.h"

#include "Hacl_Ed25519.h"
#include "Hacl_HMAC.h"
#include "Hacl_Hash_SHA2.h"
/* ── Test selector ── */

typedef enum {
    TEST_CT_EQ,
    TEST_SHA256,
    TEST_HMAC_SHA256,
    TEST_ED25519_VERIFY,
#ifdef AEGAEON_DUDECT_CANDIDATE
    TEST_HMAC_SHA256_KEY,
#endif
    TEST_COUNT
} test_id_t;


static test_id_t current_test = TEST_CT_EQ;

/* ── Shared constants ── */

#define CHUNK_LEN 32
#define HMAC_KEY_LEN 32
#define ED25519_PUBKEY_LEN 32
#define ED25519_SIG_LEN 64
#define ED25519_MSG_LEN 32
#define ED25519_CHUNK_LEN (ED25519_PUBKEY_LEN + ED25519_SIG_LEN + ED25519_MSG_LEN)

static uint8_t secret[CHUNK_LEN] = {0};
static uint8_t hmac_key[HMAC_KEY_LEN] = {0};
#ifdef AEGAEON_DUDECT_CANDIDATE
static uint8_t key_test_message[CHUNK_LEN];
#endif

/* ── Ed25519 test vectors (fixed) ── */

static const uint8_t ed25519_pk[ED25519_PUBKEY_LEN] = {
    0x5a, 0x09, 0xff, 0xb5, 0x83, 0x9c, 0x15, 0x2d,
    0xbe, 0x4c, 0xc6, 0xe9, 0xad, 0xc7, 0xe7, 0xa1,
    0x11, 0x1c, 0x29, 0x0b, 0x7d, 0xc4, 0x56, 0x2e,
    0x60, 0x8a, 0xac, 0x13, 0x39, 0x93, 0x34, 0xa6,
};

static const uint8_t ed25519_msg0[ED25519_MSG_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static const uint8_t ed25519_sig0[ED25519_SIG_LEN] = {
    0xa4, 0x02, 0x57, 0xc3, 0x52, 0xed, 0xed, 0x14,
    0xd4, 0x9b, 0x0e, 0x5b, 0xd3, 0xe0, 0xbf, 0xd1,
    0xbf, 0x3d, 0xa6, 0x37, 0x42, 0xb5, 0x5a, 0x2b,
    0x49, 0x80, 0x2f, 0x7c, 0xe7, 0xe3, 0x46, 0xd6,
    0xc0, 0x63, 0x6d, 0xbb, 0x8e, 0xa0, 0x5b, 0xcf,
    0x2a, 0x23, 0xb3, 0xba, 0xb2, 0xdf, 0x39, 0x19,
    0x58, 0x28, 0x8a, 0x01, 0xb8, 0x65, 0x0e, 0x42,
    0x71, 0x51, 0x9c, 0x75, 0x99, 0x95, 0x2f, 0x0e,
};

static const uint8_t ed25519_msg1[ED25519_MSG_LEN] = {
    0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
    0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
    0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
    0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
};

static const uint8_t ed25519_sig1[ED25519_SIG_LEN] = {
    0x18, 0x73, 0xb0, 0xc4, 0xd0, 0xfb, 0x89, 0x4e,
    0x3b, 0x6d, 0xe6, 0x1c, 0x04, 0x48, 0x5b, 0x81,
    0x1f, 0xf3, 0x24, 0xc6, 0x47, 0x5f, 0xc8, 0xc7,
    0xf2, 0x46, 0xf0, 0xb1, 0x76, 0xde, 0x27, 0xb5,
    0x96, 0x26, 0x54, 0x80, 0x11, 0x8c, 0x2b, 0x49,
    0xd7, 0x17, 0xe3, 0xc9, 0xfb, 0xd1, 0xf3, 0xb1,
    0x72, 0x88, 0x90, 0xf4, 0xdd, 0xcb, 0xc6, 0x10,
    0xe0, 0x37, 0x79, 0x2f, 0xbb, 0xe5, 0x7a, 0x07,
};

/* ── ct_eq: constant-time byte comparison ── */

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint32_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint32_t)a[i] ^ (uint32_t)b[i];
    }
    diff |= -diff; // propagate highest set bit
    return (int)(1U ^ (diff >> 31));
}

/* ── Real HACL* crypto functions ── */

static void real_sha256(const uint8_t *input, uint32_t len, uint8_t output[32]) {
    Hacl_Hash_SHA2_hash_256(output, (uint8_t *)input, len);
}

static void real_hmac_sha256(const uint8_t *key, uint32_t key_len,
                             const uint8_t *data, uint32_t data_len,
                             uint8_t output[32]) {
    Hacl_HMAC_compute_sha2_256(output, (uint8_t *)key, key_len,
                               (uint8_t *)data, data_len);
}

static int real_ed25519_verify(const uint8_t pubkey[32],
                               const uint8_t *msg, uint32_t msg_len,
                               const uint8_t sig[64]) {
    return Hacl_Ed25519_verify((uint8_t *)pubkey, msg_len,
                               (uint8_t *)msg, (uint8_t *)sig);
}

/* ── dudect callbacks ── */

uint8_t do_one_computation(uint8_t *data) {
    uint8_t result = 0;
    switch (current_test) {
    case TEST_CT_EQ:
        for (int i = 0; i < 1000; i++) {
#ifdef AEGAEON_DUDECT_CANDIDATE
            /* Each repetition must read and compare both operands. Without
             * this compiler barrier, Clang hoists the comparison and leaves
             * only 1000 ORs of its cached result. This emits no CPU fence. */
            __asm__ __volatile__("" : : "r"(data), "r"(secret) : "memory");
#endif
            result |= ct_eq(data, secret, CHUNK_LEN);
        }
        /* ct_eq always compares CHUNK_LEN (32) bytes; main() restricts
         * ct_eq tests to chunk_size >= 32 to avoid OOB reads. */
        break;
    case TEST_SHA256: {
        uint8_t hash[32];
        for (int i = 0; i < 100; i++) {
            real_sha256(data, CHUNK_LEN, hash);
            result |= hash[0];
        }
        break;
    }
    case TEST_HMAC_SHA256: {
        uint8_t mac[32];
        for (int i = 0; i < 100; i++) {
            real_hmac_sha256(hmac_key, HMAC_KEY_LEN, data, CHUNK_LEN, mac);
            result |= mac[0];
        }
        break;
    }
#ifdef AEGAEON_DUDECT_CANDIDATE
    case TEST_HMAC_SHA256_KEY: {
        uint8_t mac[32];
        real_hmac_sha256(data, HMAC_KEY_LEN, key_test_message, CHUNK_LEN, mac);
        result = mac[0];
        break;
    }
#endif
    case TEST_ED25519_VERIFY: {
        const uint8_t *pubkey = data;
        const uint8_t *sig = data + ED25519_PUBKEY_LEN;
        const uint8_t *msg = data + ED25519_PUBKEY_LEN + ED25519_SIG_LEN;
        for (int i = 0; i < 10; i++) {
            result |= (uint8_t)real_ed25519_verify(pubkey, msg, ED25519_MSG_LEN, sig);
        }
        break;
    }
    default:
        break;
    }
    return result;
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(input_data, c->number_measurements * c->chunk_size);
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            uint8_t *chunk = input_data + i * c->chunk_size;
            switch (current_test) {
            case TEST_CT_EQ:
                /* Class 0: all zeros (fixed pattern) */
                memset(chunk, 0, c->chunk_size);
                break;
            case TEST_SHA256:
                /* Class 0: fixed input pattern */
                memset(chunk, 0xAA, c->chunk_size);
                break;
            case TEST_HMAC_SHA256:
                /* Class 0: fixed message (key is always hmac_key) */
                memset(chunk, 0xBB, c->chunk_size);
                break;
#ifdef AEGAEON_DUDECT_CANDIDATE
            case TEST_HMAC_SHA256_KEY:
                memset(chunk, 0x42, HMAC_KEY_LEN);
                break;
#endif
            case TEST_ED25519_VERIFY:
                /* Class 0: valid (pk, sig0, msg0) */
                memcpy(chunk, ed25519_pk, ED25519_PUBKEY_LEN);
                memcpy(chunk + ED25519_PUBKEY_LEN, ed25519_sig0, ED25519_SIG_LEN);
                memcpy(chunk + ED25519_PUBKEY_LEN + ED25519_SIG_LEN,
                       ed25519_msg0, ED25519_MSG_LEN);
                break;
            default:
                memset(chunk, 0, c->chunk_size);
                break;
            }
        }
        if (classes[i] == 1 && current_test == TEST_ED25519_VERIFY) {
            /* Class 1: valid (pk, sig1, msg1) */
            uint8_t *chunk = input_data + i * c->chunk_size;
            memcpy(chunk, ed25519_pk, ED25519_PUBKEY_LEN);
            memcpy(chunk + ED25519_PUBKEY_LEN, ed25519_sig1, ED25519_SIG_LEN);
            memcpy(chunk + ED25519_PUBKEY_LEN + ED25519_SIG_LEN,
                   ed25519_msg1, ED25519_MSG_LEN);
        }
        /* Class 1: random data (already filled by randombytes above) */
    }
}

int main(int argc, char **argv) {
    dudect_require(real_ed25519_verify(ed25519_pk, ed25519_msg0, ED25519_MSG_LEN,
                                       ed25519_sig0), "Ed25519 class 0 vector");
    dudect_require(real_ed25519_verify(ed25519_pk, ed25519_msg1, ED25519_MSG_LEN,
                                       ed25519_sig1), "Ed25519 class 1 vector");
    memset(hmac_key, 0x42, HMAC_KEY_LEN);
    const size_t chunks[] = {32, 64, 128, CHUNK_LEN, CHUNK_LEN, ED25519_CHUNK_LEN};
    const test_id_t tests[] = {TEST_CT_EQ, TEST_CT_EQ, TEST_CT_EQ,
                               TEST_SHA256, TEST_HMAC_SHA256, TEST_ED25519_VERIFY};
    const char *names[] = {"ct_eq_32", "ct_eq_64", "ct_eq_128", "sha256",
                           "hmac_sha256", "ed25519_verify"};
    for (size_t i = 0; i < 6; ++i) {
        current_test = tests[i];
        int status = dudect_run_case(names[i], chunks[i], argc, argv);
        if (status) return status;
    }
#ifdef AEGAEON_DUDECT_CANDIDATE
    memset(key_test_message, 0x5a, sizeof key_test_message);
    /* Independently calculated HMAC-SHA256 for key=42*32, message=5a*32. */
    const uint8_t expected_mac[32] = {
        0xd8, 0xcf, 0x2a, 0xad, 0xbc, 0x0e, 0x9e, 0x55,
        0xc9, 0xa7, 0x5e, 0x67, 0x19, 0xd0, 0xc5, 0xe4,
        0x05, 0xee, 0x2b, 0x79, 0x4f, 0x4f, 0x74, 0xed,
        0x11, 0x1d, 0x9e, 0x1d, 0xec, 0x0a, 0xb6, 0x1c
    };
    uint8_t mac[32];
    real_hmac_sha256(hmac_key, HMAC_KEY_LEN, key_test_message, CHUNK_LEN, mac);
    dudect_require(!memcmp(mac, expected_mac, sizeof mac), "HMAC key fixture vector");
    current_test = TEST_HMAC_SHA256_KEY;
    return dudect_run_case("hmac_sha256_key", HMAC_KEY_LEN, argc, argv);
#else
    return 0;
#endif
}
