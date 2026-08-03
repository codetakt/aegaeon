/* Verified.Crypto.Bridge — C implementation for WASM extraction.
 *
 * Provides C implementations of Verified.Crypto.Bridge functions,
 * calling HACL* pre-extracted C code (Hacl_Hash_SHA2, Hacl_HMAC, Hacl_Ed25519).
 *
 * This file is compiled into the WASM binary alongside KaRaMeL-extracted code.
 * The bridge module is marked -library in KaRaMeL, so extracted modules call
 * these extern functions instead of trying to extract the F* bridge directly
 * (which uses Seq/GC types not suitable for WASM).
 *
 * Type conventions follow KaRaMeL:
 *   FStar_Bytes_bytes = { uint32_t length; const char *data; }
 *   Prims_string = const char*
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/* KaRaMeL runtime types */
#include "krmllib.h"
#include "krml/internal/compat.h"

#ifdef AEG_VERIFIED_CORE_WASM_MINIMAL
#include "internal/FStar.h"
#include "internal/Prims.h"
#endif

/* HACL* verified crypto (pre-extracted C from hacl-star dist) */
#include "Hacl_Hash_SHA2.h"
#ifndef AEG_VERIFIED_CORE_WASM_MINIMAL
#include "Hacl_HMAC.h"
#endif
#include "Hacl_Ed25519.h"

#ifndef AEG_VERIFIED_CORE_WASM_MINIMAL
#define AEG_VC_I32_MAX ((krml_checked_int_t)2147483647)
#define AEG_VC_I32_MIN ((krml_checked_int_t)(-2147483647 - 1))

static void
aeg_compat_abort(void) {
    abort();
}

static krml_checked_int_t
aeg_checked_from_i64(int64_t value) {
    if (value > (int64_t)AEG_VC_I32_MAX || value < (int64_t)AEG_VC_I32_MIN) {
        aeg_compat_abort();
    }
    return (krml_checked_int_t)value;
}

/* Minimal KaRaMeL compat shims required by the extracted structural parser. */
krml_checked_int_t
FStar_UInt8_v(uint8_t x) {
    return (krml_checked_int_t)x;
}

krml_checked_int_t
Prims_op_Subtraction(krml_checked_int_t x, krml_checked_int_t y) {
    return aeg_checked_from_i64((int64_t)x - (int64_t)y);
}

bool
Prims_op_LessThanOrEqual(krml_checked_int_t x0, krml_checked_int_t x1) {
    return x0 <= x1;
}

bool
Prims_op_GreaterThan(krml_checked_int_t x0, krml_checked_int_t x1) {
    return x0 > x1;
}
#endif

/* ── Helper: allocate FStar_Bytes_bytes from raw buffer ── */

static FStar_Bytes_bytes
make_bytes(const uint8_t *src, uint32_t len) {
    if (len == 0) {
        return (FStar_Bytes_bytes){ .length = 0, .data = NULL };
    }
    char *copy = (char *)malloc(len);
    if (!copy) {
        /* OOM is fatal: F* spec guarantees total functions returning fixed-length
         * outputs. Returning empty bytes would break the spec and enable fail-open
         * auth bypasses (e.g. PKCE s256 returning "" instead of 32-byte hash). */
        KRML_HOST_EXIT(252);
    }
    if (src) {
        memcpy(copy, src, len);
    } else {
        memset(copy, 0, len);
    }
    return (FStar_Bytes_bytes){ .length = len, .data = copy };
}

/* ── Max input lengths ── */

/* In F*, these are pos = Some?.v (SH.max_input_length SH.SHA2_*).
 * SHA-256/384/512 max_input_length = pow2 61 - 1.
 * Clamped to INT32_MAX for the C int32_t representation.
 * ACCEPTED MISMATCH: WASM linear memory is <4GB, so no input can exceed
 * 2^32 bytes. Both the F* bound (~2^61) and C bound (2^31-1) are unreachable
 * at runtime. The guard exists solely for structural correspondence with
 * the F* spec. */
int32_t Verified_Crypto_Bridge_sha256_max_input = INT32_MAX;
int32_t Verified_Crypto_Bridge_sha384_max_input = INT32_MAX;
int32_t Verified_Crypto_Bridge_sha512_max_input = INT32_MAX;

/* ── SHA-2 hash functions ── */

FStar_Bytes_bytes
Verified_Crypto_Bridge_sha256_hash(FStar_Bytes_bytes input) {
    uint8_t output[32];
    Hacl_Hash_SHA2_hash_256(output, (uint8_t *)input.data, input.length);
    return make_bytes(output, 32);
}

FStar_Bytes_bytes
Verified_Crypto_Bridge_sha384_hash(FStar_Bytes_bytes input) {
    uint8_t output[48];
    Hacl_Hash_SHA2_hash_384(output, (uint8_t *)input.data, input.length);
    return make_bytes(output, 48);
}

FStar_Bytes_bytes
Verified_Crypto_Bridge_sha512_hash(FStar_Bytes_bytes input) {
    uint8_t output[64];
    Hacl_Hash_SHA2_hash_512(output, (uint8_t *)input.data, input.length);
    return make_bytes(output, 64);
}

/* ── HMAC functions ── */

#ifndef AEG_VERIFIED_CORE_WASM_MINIMAL
FStar_Bytes_bytes
Verified_Crypto_Bridge_hmac_sha256(FStar_Bytes_bytes key,
                                    FStar_Bytes_bytes data) {
    uint8_t output[32];
    Hacl_HMAC_compute_sha2_256(output,
                                (uint8_t *)key.data, key.length,
                                (uint8_t *)data.data, data.length);
    return make_bytes(output, 32);
}

FStar_Bytes_bytes
Verified_Crypto_Bridge_hmac_sha384(FStar_Bytes_bytes key,
                                    FStar_Bytes_bytes data) {
    uint8_t output[48];
    Hacl_HMAC_compute_sha2_384(output,
                                (uint8_t *)key.data, key.length,
                                (uint8_t *)data.data, data.length);
    return make_bytes(output, 48);
}

FStar_Bytes_bytes
Verified_Crypto_Bridge_hmac_sha512(FStar_Bytes_bytes key,
                                    FStar_Bytes_bytes data) {
    uint8_t output[64];
    Hacl_HMAC_compute_sha2_512(output,
                                (uint8_t *)key.data, key.length,
                                (uint8_t *)data.data, data.length);
    return make_bytes(output, 64);
}
#endif

/* ── Ed25519 signature verification ── */

bool
Verified_Crypto_Bridge_ed25519_verify(
    FStar_Bytes_bytes public_key,
    FStar_Bytes_bytes msg,
    FStar_Bytes_bytes signature) {
    if (public_key.length != 32 || signature.length != 64) {
        return false;
    }
    if (!public_key.data || !signature.data) {
        return false;
    }
    if (msg.length > 0 && !msg.data) {
        return false;
    }
    return Hacl_Ed25519_verify(
        (uint8_t *)public_key.data,
        msg.length,
        (uint8_t *)msg.data,
        (uint8_t *)signature.data);
}

/* ── String utilities ── */

FStar_Bytes_bytes
Verified_Crypto_Bridge_string_to_bytes(Prims_string s) {
    if (!s) {
        return (FStar_Bytes_bytes){ .length = 0, .data = NULL };
    }
    uint32_t len = (uint32_t)strlen(s);
    return make_bytes((const uint8_t *)s, len);
}

static const char hex_digits[] = "0123456789abcdef";

Prims_string
Verified_Crypto_Bridge_bytes_to_hex_string(FStar_Bytes_bytes b) {
    /* Overflow check: hex_len = b.length * 2.
     * Max safe: UINT32_MAX/2 = 2147483647. Hash outputs are <= 64 bytes. */
    if (b.length > UINT32_MAX / 2) {
        return "";
    }
    uint32_t hex_len = b.length * 2;
    char *result = (char *)malloc(hex_len + 1);
    if (!result) {
        KRML_HOST_EXIT(252);
    }
    if (b.length > 0 && !b.data) {
        free(result);
        return "";
    }
    for (uint32_t i = 0; i < b.length; i++) {
        uint8_t byte = (uint8_t)b.data[i];
        result[i * 2]     = hex_digits[byte >> 4];
        result[i * 2 + 1] = hex_digits[byte & 0x0F];
    }
    result[hex_len] = '\0';
    return result;
}

/* ── Base64url encoding (RFC 4648 §5, no padding) ── */

static const char b64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

Prims_string
Verified_Crypto_Bridge_bytes_to_base64url_string(FStar_Bytes_bytes b) {
    if (b.length == 0) {
        char *empty = (char *)malloc(1);
        if (!empty) { KRML_HOST_EXIT(252); }
        empty[0] = '\0';
        return empty;
    }
    if (b.length > 0 && !b.data) {
        return "";
    }
    /* Output length: ceil(n * 4 / 3) without padding.
     * For 32-byte SHA-256 hash: (32 * 4 + 2) / 3 = 43 chars.
     * Overflow guard: b.length * 4 must not wrap uint32_t.
     * Max safe: (UINT32_MAX - 2) / 4 = 1073741823. Hash outputs are <= 64 bytes. */
    if (b.length > (UINT32_MAX - 2) / 4) {
        return "";
    }
    uint32_t out_len = (b.length * 4 + 2) / 3;
    char *result = (char *)malloc(out_len + 1);
    if (!result) {
        KRML_HOST_EXIT(252);
    }
    uint32_t i = 0, j = 0;
    const uint8_t *src = (const uint8_t *)b.data;
    /* Process full 3-byte groups */
    while (i + 2 < b.length) {
        uint32_t triple = ((uint32_t)src[i] << 16) |
                          ((uint32_t)src[i + 1] << 8) |
                          ((uint32_t)src[i + 2]);
        result[j++] = b64url_table[(triple >> 18) & 0x3F];
        result[j++] = b64url_table[(triple >> 12) & 0x3F];
        result[j++] = b64url_table[(triple >> 6)  & 0x3F];
        result[j++] = b64url_table[ triple        & 0x3F];
        i += 3;
    }
    /* Handle remaining 1 or 2 bytes (no padding chars) */
    if (i < b.length) {
        uint32_t a = (uint32_t)src[i];
        if (i + 1 < b.length) {
            /* 2 bytes remaining -> 3 base64url chars */
            uint32_t b_val = (uint32_t)src[i + 1];
            result[j++] = b64url_table[(a >> 2) & 0x3F];
            result[j++] = b64url_table[((a & 0x03) << 4) | ((b_val >> 4) & 0x0F)];
            result[j++] = b64url_table[((b_val & 0x0F) << 2)];
        } else {
            /* 1 byte remaining -> 2 base64url chars */
            result[j++] = b64url_table[(a >> 2) & 0x3F];
            result[j++] = b64url_table[((a & 0x03) << 4)];
        }
    }
    result[j] = '\0';
    return result;
}

Prims_string
Verified_Crypto_Bridge_sha256_of_string(Prims_string input) {
    FStar_Bytes_bytes input_bytes = Verified_Crypto_Bridge_string_to_bytes(input);
    /* Overlength check (unreachable in practice -- max_input ~ 2^61) */
    if (input_bytes.length >= (uint32_t)Verified_Crypto_Bridge_sha256_max_input) {
        return "";
    }
    FStar_Bytes_bytes hash = Verified_Crypto_Bridge_sha256_hash(input_bytes);
    /* F* spec: FStar.Base64.base64url_encode (sha256_hash input_bytes)
     * Must return base64url (RFC 4648 §5, no padding) -- NOT hex.
     * For 32-byte SHA-256: output is exactly 43 chars.
     * Callers: PKCE S256 (RFC 7636), SD-JWT disclosure digest,
     * JWK thumbprint (RFC 7638). */
    return Verified_Crypto_Bridge_bytes_to_base64url_string(hash);
}

/* ── HashComputation bridge ── */
/* HashComputation.compute_hash is extracted by KaRaMeL since it's in the
 * module list. It calls Verified_Crypto_Bridge_sha256_hash etc. directly.
 * No additional C code needed here — KaRaMeL generates the dispatch. */

#ifdef AEG_VERIFIED_CORE_WASM_MINIMAL
extern unsigned char __heap_base;

#define VC_PAGE_SIZE 65536u
#define VC_ALIGN 16u
#define VC_I32_MAX ((krml_checked_int_t)2147483647)
#define VC_I32_MIN ((krml_checked_int_t)(-2147483647 - 1))

typedef struct VcAllocHeader_s {
    uint32_t size;
    uint32_t reserved;
} VcAllocHeader;

static uintptr_t vc_heap_cursor = 0;
static uintptr_t vc_heap_limit = 0;

static uintptr_t
vc_align_up(uintptr_t value, uintptr_t alignment) {
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static void
vc_abort(void) {
    __builtin_trap();
    __builtin_unreachable();
}

static void
vc_heap_init(void) {
    if (vc_heap_cursor != 0u) {
        return;
    }

    vc_heap_cursor = vc_align_up((uintptr_t)&__heap_base, VC_ALIGN);
    vc_heap_limit = (uintptr_t)__builtin_wasm_memory_size(0) * (uintptr_t)VC_PAGE_SIZE;
}

static void *
vc_bump_alloc(size_t size) {
    vc_heap_init();

    size_t total = vc_align_up((uintptr_t)sizeof(VcAllocHeader) + (uintptr_t)size, VC_ALIGN);
    uintptr_t next = vc_heap_cursor + (uintptr_t)total;
    if (next > vc_heap_limit) {
        uintptr_t deficit = next - vc_heap_limit;
        size_t pages = (size_t)((deficit + VC_PAGE_SIZE - 1u) / VC_PAGE_SIZE);
        size_t previous = __builtin_wasm_memory_grow(0, pages);
        if (previous == (size_t)-1) {
            return NULL;
        }
        vc_heap_limit += (uintptr_t)pages * (uintptr_t)VC_PAGE_SIZE;
    }

    VcAllocHeader *header = (VcAllocHeader *)vc_heap_cursor;
    header->size = (uint32_t)size;
    header->reserved = 0u;

    void *ptr = (void *)(header + 1);
    vc_heap_cursor = next;
    return ptr;
}

static uint32_t
vc_strlen_impl(const char *s) {
    uint32_t len = 0u;
    if (s == NULL) {
        return 0u;
    }
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

static int
vc_memcmp_impl(const void *left, const void *right, size_t len) {
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    for (size_t i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            return (a[i] < b[i]) ? -1 : 1;
        }
    }
    return 0;
}

static void
vc_memcpy_impl(uint8_t *dest, const uint8_t *src, uint32_t len) {
    for (uint32_t i = 0u; i < len; ++i) {
        dest[i] = src[i];
    }
}

static void
vc_memset_impl(uint8_t *dest, uint8_t value, uint32_t len) {
    for (uint32_t i = 0u; i < len; ++i) {
        dest[i] = value;
    }
}

static krml_checked_int_t
vc_checked_from_i64(int64_t value) {
    if (value > (int64_t)VC_I32_MAX || value < (int64_t)VC_I32_MIN) {
        vc_abort();
    }
    return (krml_checked_int_t)value;
}

size_t
strlen(const char *s) {
    return (size_t)vc_strlen_impl(s);
}

int
memcmp(const void *left, const void *right, size_t len) {
    return vc_memcmp_impl(left, right, len);
}

void *
malloc(size_t size) {
    if (size == 0u) {
        size = 1u;
    }
    return vc_bump_alloc(size);
}

void *
calloc(size_t nmemb, size_t size) {
    if (nmemb == 0u || size == 0u) {
        nmemb = 1u;
        size = 1u;
    }
    if (size != 0u && nmemb > (((size_t)-1) / size)) {
        return NULL;
    }

    size_t total = nmemb * size;
    uint8_t *ptr = (uint8_t *)vc_bump_alloc(total);
    if (ptr == NULL) {
        return NULL;
    }
    vc_memset_impl(ptr, 0u, (uint32_t)total);
    return ptr;
}

void *
realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
        return malloc(size);
    }
    if (size == 0u) {
        return ptr;
    }

    VcAllocHeader *header = ((VcAllocHeader *)ptr) - 1;
    size_t old_size = (size_t)header->size;
    uint8_t *next = (uint8_t *)malloc(size);
    if (next == NULL) {
        return NULL;
    }

    size_t copy_len = old_size < size ? old_size : size;
    vc_memcpy_impl(next, (const uint8_t *)ptr, (uint32_t)copy_len);
    return next;
}

void
free(void *ptr) {
    (void)ptr;
}

int
fprintf(void *stream, const char *format, ...) {
    (void)stream;
    (void)format;
    return 0;
}

__attribute__((noreturn)) void
exit(int status) {
    (void)status;
    vc_abort();
}

krml_checked_int_t
FStar_UInt32_v(uint32_t x) {
    if (x > (uint32_t)VC_I32_MAX) {
        return VC_I32_MAX;
    }
    return (krml_checked_int_t)x;
}

uint32_t
FStar_UInt32_uint_to_t(krml_checked_int_t x) {
    if (x < 0) {
        vc_abort();
    }
    return (uint32_t)x;
}

krml_checked_int_t
FStar_UInt8_v(uint8_t x) {
    return (krml_checked_int_t)x;
}

uint32_t
FStar_Bytes_len(FStar_Bytes_bytes b) {
    return b.length;
}

uint8_t
FStar_Bytes_get(FStar_Bytes_bytes b, uint32_t pos) {
    if (b.data == NULL || pos >= b.length) {
        return 0u;
    }
    return (uint8_t)b.data[pos];
}

FStar_Bytes_bytes
FStar_Bytes_create(uint32_t len1, uint8_t value) {
    if (len1 == 0u) {
        return (FStar_Bytes_bytes){ .length = 0u, .data = NULL };
    }

    uint8_t *buf = (uint8_t *)malloc((size_t)len1);
    if (buf == NULL) {
        vc_abort();
    }
    vc_memset_impl(buf, value, len1);
    return (FStar_Bytes_bytes){ .length = len1, .data = (const char *)buf };
}

FStar_Bytes_bytes
FStar_Bytes_sub(FStar_Bytes_bytes b, uint32_t start, uint32_t len) {
    if (len == 0u) {
        return (FStar_Bytes_bytes){ .length = 0u, .data = NULL };
    }
    if (b.data == NULL || start > b.length || len > b.length - start) {
        return (FStar_Bytes_bytes){ .length = 0u, .data = NULL };
    }
    return (FStar_Bytes_bytes){ .length = len, .data = b.data + start };
}

krml_checked_int_t
FStar_String_strlen(Prims_string s) {
    uint32_t len = vc_strlen_impl(s);
    if (len > (uint32_t)VC_I32_MAX) {
        return VC_I32_MAX;
    }
    return (krml_checked_int_t)len;
}

bool
__eq__Prims_string(Prims_string left, Prims_string right) {
    if (left == right) {
        return true;
    }
    if (left == NULL || right == NULL) {
        return false;
    }

    uint32_t left_len = vc_strlen_impl(left);
    uint32_t right_len = vc_strlen_impl(right);
    if (left_len != right_len) {
        return false;
    }
    return vc_memcmp_impl(left, right, (size_t)left_len) == 0;
}

bool
__eq__FStar_Bytes_bytes(FStar_Bytes_bytes left, FStar_Bytes_bytes right) {
    if (left.length != right.length) {
        return false;
    }
    if (left.length == 0u) {
        return true;
    }
    if (left.data == NULL || right.data == NULL) {
        return false;
    }
    return vc_memcmp_impl(left.data, right.data, (size_t)left.length) == 0;
}

krml_checked_int_t
Prims_op_Multiply(krml_checked_int_t x, krml_checked_int_t y) {
    return vc_checked_from_i64((int64_t)x * (int64_t)y);
}

krml_checked_int_t
Prims_op_Division(krml_checked_int_t x, krml_checked_int_t y) {
    if (y == 0) {
        vc_abort();
    }
    return x / y;
}

krml_checked_int_t
Prims_op_Subtraction(krml_checked_int_t x, krml_checked_int_t y) {
    return vc_checked_from_i64((int64_t)x - (int64_t)y);
}

krml_checked_int_t
Prims_op_Addition(krml_checked_int_t x, krml_checked_int_t y) {
    return vc_checked_from_i64((int64_t)x + (int64_t)y);
}

krml_checked_int_t
Prims_op_Modulus(krml_checked_int_t x, krml_checked_int_t y) {
    if (y == 0) {
        vc_abort();
    }
    return x % y;
}

bool
Prims_op_LessThanOrEqual(krml_checked_int_t x0, krml_checked_int_t x1) {
    return x0 <= x1;
}

bool
Prims_op_GreaterThanOrEqual(krml_checked_int_t x0, krml_checked_int_t x1) {
    return x0 >= x1;
}

bool
Prims_op_LessThan(krml_checked_int_t x0, krml_checked_int_t x1) {
    return x0 < x1;
}

krml_checked_int_t
Prims_pow2(krml_checked_int_t x0) {
    if (x0 < 0) {
        vc_abort();
    }
    if (x0 >= 31) {
        return VC_I32_MAX;
    }
    return (krml_checked_int_t)((uint32_t)1u << (uint32_t)x0);
}

Prims_string
Prims_strcat(Prims_string left, Prims_string right) {
    uint32_t left_len = vc_strlen_impl(left);
    uint32_t right_len = vc_strlen_impl(right);
    uint32_t out_len = left_len + right_len;
    char *out = (char *)malloc((size_t)out_len + 1u);
    if (out == NULL) {
        vc_abort();
    }

    for (uint32_t i = 0u; i < left_len; ++i) {
        out[i] = left[i];
    }
    for (uint32_t i = 0u; i < right_len; ++i) {
        out[left_len + i] = right[i];
    }
    out[out_len] = '\0';
    return out;
}

FStar_Char_char
FStar_Char_char_of_u32(uint32_t value) {
    return value;
}

Prims_string
FStar_String_string_of_list(Prims_list__FStar_Char_char *list) {
    uint32_t len = 0u;
    for (Prims_list__FStar_Char_char *cursor = list;
        cursor != NULL && cursor->tag == Prims_Cons;
        cursor = cursor->tl) {
        len++;
    }

    char *out = (char *)malloc((size_t)len + 1u);
    if (out == NULL) {
        vc_abort();
    }

    uint32_t index = 0u;
    for (Prims_list__FStar_Char_char *cursor = list;
        cursor != NULL && cursor->tag == Prims_Cons;
        cursor = cursor->tl) {
        FStar_Char_char codepoint = cursor->hd;
        out[index++] = (codepoint <= 0x7fu) ? (char)codepoint : '?';
    }
    out[index] = '\0';
    return out;
}

#if defined(__SIZEOF_INT128__)
typedef __int128 vc_ti_int;
typedef unsigned __int128 vc_tu_int;

typedef union VcTwoWords_u {
    vc_tu_int all;
    struct {
        uint64_t low;
        uint64_t high;
    } s;
} VcTwoWords;

static void
vc_mul_u64_wide(uint64_t left, uint64_t right, uint64_t *out_low, uint64_t *out_high) {
    uint64_t left_lo = (uint32_t)left;
    uint64_t left_hi = left >> 32;
    uint64_t right_lo = (uint32_t)right;
    uint64_t right_hi = right >> 32;

    uint64_t p00 = left_lo * right_lo;
    uint64_t p01 = left_lo * right_hi;
    uint64_t p10 = left_hi * right_lo;
    uint64_t p11 = left_hi * right_hi;

    uint64_t carry = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
    *out_low = (p00 & 0xffffffffULL) | (carry << 32);
    *out_high = p11 + (p01 >> 32) + (p10 >> 32) + (carry >> 32);
}

vc_ti_int
__multi3(vc_ti_int left, vc_ti_int right) {
    VcTwoWords a = { .all = (vc_tu_int)left };
    VcTwoWords b = { .all = (vc_tu_int)right };
    VcTwoWords result;
    uint64_t low_low = 0u;
    uint64_t low_high = 0u;

    vc_mul_u64_wide(a.s.low, b.s.low, &low_low, &low_high);
    result.s.low = low_low;
    result.s.high = low_high;
    result.s.high += a.s.low * b.s.high;
    result.s.high += a.s.high * b.s.low;
    return (vc_ti_int)result.all;
}
#endif
#endif
