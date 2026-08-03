#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../generated/lowstar/oidc/hash/HashComputation_Low.h"
#include "crypto_bridge.h"
#include "krml/internal/compat.h"
#include "krml/internal/target.h"

/*
 * HashComputation.Low runtime shim
 * --------------------------------
 * `HashComputation.Low` declares its hashing routines as `assume val` to keep
 * the F* model independent from any concrete crypto provider. This file
 * implements these assumptions by delegating SHA-256/384/512 to the shared
 * Verified.Crypto.Bridge C shim, which already backs the proof-facing HACL*
 * bridge. The KaRaMeL fstar_bytes.c runtime is linked separately to provide
 * `FStar_Bytes_*` functions.
 *
 *  - `HashComputation_Low_evercrypt_hash_incremental_hash` delegates
 *    SHA-256/384/512 to `Verified_Crypto_Bridge_sha*`
 *  - `HashComputation_Low_bytes_prefix_of_buffer` wraps FStar_Bytes_of_buffer
 *  - `HashComputation_Low_free_bytes` mirrors `FStar.Bytes.free` for cleanup
 *  - `__eq__Prims_string` provides string comparison for algorithm lookup
 *
 * The extracted `HashComputation.Low` dispatcher owns the public
 * `HashComputation_Low_compute_oidc_hash_bytes` entrypoint. This shim only
 * provides the host primitives needed by that extracted code.
 */

void HashComputation_Low_free_bytes(FStar_Bytes_bytes bytes) {
    if (bytes.data == NULL || bytes.length == 0) {
        return;
    }
    KRML_HOST_FREE((void *)bytes.data);
}

FStar_Bytes_bytes HashComputation_Low_bytes_prefix_of_buffer(uint8_t *buf, uint32_t len) {
    return FStar_Bytes_of_buffer(len, buf);
}

bool __eq__Prims_string(Prims_string s1, Prims_string s2) {
    if (s1 == NULL || s2 == NULL) {
        return s1 == s2;
    }
    return strcmp(s1, s2) == 0;
}

typedef FStar_Bytes_bytes (*verified_hash_fn)(FStar_Bytes_bytes input);

static bool hash_case_params(HashComputation_Low_hash_case case0, verified_hash_fn *hash_fn,
    uint32_t *digest_len) {
    switch (case0) {
    case HashComputation_Low_HashCaseSha256:
        *hash_fn = Verified_Crypto_Bridge_sha256_hash;
        *digest_len = 32u;
        return true;
    case HashComputation_Low_HashCaseSha384:
        *hash_fn = Verified_Crypto_Bridge_sha384_hash;
        *digest_len = 48u;
        return true;
    case HashComputation_Low_HashCaseSha512:
        *hash_fn = Verified_Crypto_Bridge_sha512_hash;
        *digest_len = 64u;
        return true;
    default:
        return false;
    }
}

static uint32_t hash_into_buffer(
    HashComputation_Low_hash_case case0,
    uint8_t *output_buf,
    FStar_Bytes_bytes input,
    uint32_t input_len) {
    verified_hash_fn hash_fn = NULL;
    uint32_t digest_len = 0;
    if (!hash_case_params(case0, &hash_fn, &digest_len)) {
        return HashComputation_Low_hash_status_computation_failed;
    }

    if (hash_fn == NULL || output_buf == NULL) {
        return HashComputation_Low_hash_status_computation_failed;
    }

    if (input.length != input_len) {
        return HashComputation_Low_hash_status_computation_failed;
    }

    unsigned char empty = 0u;
    FStar_Bytes_bytes normalized_input = input;
    if (normalized_input.length == 0) {
        normalized_input.data = (const char *)&empty;
    } else if (normalized_input.data == NULL) {
        return HashComputation_Low_hash_status_computation_failed;
    }

    FStar_Bytes_bytes digest = hash_fn(normalized_input);
    if (digest.length != digest_len || digest.data == NULL) {
        HashComputation_Low_free_bytes(digest);
        return HashComputation_Low_hash_status_computation_failed;
    }

    memcpy(output_buf, digest.data, digest_len);
    HashComputation_Low_free_bytes(digest);
    return HashComputation_Low_hash_status_ok;
}

uint32_t HashComputation_Low_evercrypt_hash_incremental_hash(HashComputation_Low_hash_case case0,
    uint8_t *output_buf, FStar_Bytes_bytes input, uint32_t input_len) {
    verified_hash_fn hash_fn = NULL;
    uint32_t digest_len = 0;

    if (!hash_case_params(case0, &hash_fn, &digest_len)) {
        return HashComputation_Low_hash_status_computation_failed;
    }

    uint32_t status = hash_into_buffer(case0, output_buf, input, input_len);
    if (status != HashComputation_Low_hash_status_ok && output_buf != NULL) {
        memset(output_buf, 0, digest_len);
    }
    return status;
}
