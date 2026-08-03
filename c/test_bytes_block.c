// Standalone test for bytes_block implementation
// Phase 3.2: bytes_block C Support

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>

// Minimal checked_alloc implementation for testing
static inline void *checked_alloc(size_t count, size_t size) {
    if (count == 0) {
        count = 1;
    }
    size_t total = count * size;
    void *ptr = calloc(1, total);
    if (ptr == NULL) {
        abort();
    }
    return ptr;
}

// bytes_block struct definition from Phase 3.2
typedef struct {
    uint8_t *buf;
    uint32_t len;
} Jose_LowStar_Json_bytes_block;

// Prims_string type alias
typedef char* Prims_string;

// bytes_block functions from Phase 3.2
Jose_LowStar_Json_bytes_block
Jose_LowStar_Json_malloc_bytes_block(uint32_t len) {
    Jose_LowStar_Json_bytes_block bb;
    bb.len = len;
    if (len == 0) {
        bb.buf = NULL;
    } else {
        bb.buf = (uint8_t *)checked_alloc((size_t)len, sizeof(uint8_t));
    }
    return bb;
}

void Jose_LowStar_Json_free_bytes_block(Jose_LowStar_Json_bytes_block *bb) {
    if (bb == NULL) {
        return;
    }
    if (bb->buf != NULL) {
        free(bb->buf);
        bb->buf = NULL;
    }
    bb->len = 0;
}

Jose_LowStar_Json_bytes_block
Jose_LowStar_Json_copy_bytes_block(Jose_LowStar_Json_bytes_block src) {
    Jose_LowStar_Json_bytes_block dest;
    dest.len = src.len;
    if (src.len == 0 || src.buf == NULL) {
        dest.buf = NULL;
    } else {
        dest.buf = (uint8_t *)checked_alloc((size_t)src.len, sizeof(uint8_t));
        memcpy(dest.buf, src.buf, (size_t)src.len);
    }
    return dest;
}

bool Jose_LowStar_Json_validate_bytes_block(Jose_LowStar_Json_bytes_block bb) {
    if (bb.len == 0) {
        return bb.buf == NULL;
    }
    return bb.buf != NULL;
}

// Phase 3.2.3: UTF-8 conversion functions
uint8_t *Jose_LowStar_Json_allocate_bytes_from_bytes_block(Jose_LowStar_Json_bytes_block bb) {
    if (bb.len == 0 || bb.buf == NULL) {
        return NULL;
    }
    uint8_t *buf = (uint8_t *)checked_alloc((size_t)bb.len, sizeof(uint8_t));
    memcpy(buf, bb.buf, (size_t)bb.len);
    return buf;
}

Jose_LowStar_Json_bytes_block
Jose_LowStar_Json_encode_utf8_bytes_block(Prims_string s) {
    Jose_LowStar_Json_bytes_block result;

    if (s == NULL) {
        result.buf = NULL;
        result.len = 0;
        return result;
    }

    size_t len = strlen(s);
    if (len > UINT32_MAX) {
        abort();
    }

    result.len = (uint32_t)len;
    if (len == 0) {
        result.buf = NULL;
    } else {
        result.buf = (uint8_t *)checked_alloc(len, sizeof(uint8_t));
        memcpy(result.buf, s, len);
    }

    return result;
}

// Unit tests
void test_malloc_bytes_block_zero() {
    printf("Test: malloc_bytes_block with zero length... ");
    Jose_LowStar_Json_bytes_block bb = Jose_LowStar_Json_malloc_bytes_block(0);
    assert(bb.len == 0);
    assert(bb.buf == NULL);
    assert(Jose_LowStar_Json_validate_bytes_block(bb));
    printf("PASS\n");
}

void test_malloc_bytes_block_nonzero() {
    printf("Test: malloc_bytes_block with non-zero length... ");
    Jose_LowStar_Json_bytes_block bb = Jose_LowStar_Json_malloc_bytes_block(10);
    assert(bb.len == 10);
    assert(bb.buf != NULL);
    assert(Jose_LowStar_Json_validate_bytes_block(bb));

    // Check memory is zeroed
    for (uint32_t i = 0; i < bb.len; i++) {
        assert(bb.buf[i] == 0);
    }

    Jose_LowStar_Json_free_bytes_block(&bb);
    assert(bb.len == 0);
    assert(bb.buf == NULL);
    printf("PASS\n");
}

void test_copy_bytes_block() {
    printf("Test: copy_bytes_block... ");
    Jose_LowStar_Json_bytes_block src = Jose_LowStar_Json_malloc_bytes_block(5);

    // Fill with test data
    for (uint32_t i = 0; i < src.len; i++) {
        src.buf[i] = (uint8_t)(i + 1);
    }

    Jose_LowStar_Json_bytes_block dest = Jose_LowStar_Json_copy_bytes_block(src);
    assert(dest.len == src.len);
    assert(dest.buf != NULL);
    assert(dest.buf != src.buf); // Different buffers

    // Verify copied data
    for (uint32_t i = 0; i < dest.len; i++) {
        assert(dest.buf[i] == src.buf[i]);
    }

    Jose_LowStar_Json_free_bytes_block(&src);
    Jose_LowStar_Json_free_bytes_block(&dest);
    printf("PASS\n");
}

void test_copy_zero_length() {
    printf("Test: copy_bytes_block with zero length... ");
    Jose_LowStar_Json_bytes_block src = Jose_LowStar_Json_malloc_bytes_block(0);
    Jose_LowStar_Json_bytes_block dest = Jose_LowStar_Json_copy_bytes_block(src);

    assert(dest.len == 0);
    assert(dest.buf == NULL);
    assert(Jose_LowStar_Json_validate_bytes_block(dest));

    printf("PASS\n");
}

void test_validate_invalid() {
    printf("Test: validate_bytes_block with invalid block... ");

    // Invalid: non-zero length with NULL buf
    Jose_LowStar_Json_bytes_block invalid;
    invalid.len = 10;
    invalid.buf = NULL;
    assert(!Jose_LowStar_Json_validate_bytes_block(invalid));

    printf("PASS\n");
}

void test_struct_size_alignment() {
    printf("Test: bytes_block struct size and alignment... ");

    // Verify field offsets
    Jose_LowStar_Json_bytes_block bb;
    ptrdiff_t buf_offset = (char*)&bb.buf - (char*)&bb;
    ptrdiff_t len_offset = (char*)&bb.len - (char*)&bb;

    assert(buf_offset == 0); // buf should be first
    assert(len_offset == sizeof(uint8_t*)); // len should be after buf

    // Log actual struct size (may have padding due to alignment)
    printf("(struct size: %zu bytes, buf: %zu, len: %zu) ",
           sizeof(Jose_LowStar_Json_bytes_block),
           sizeof(uint8_t*),
           sizeof(uint32_t));

    printf("PASS\n");
}

// Phase 3.2.3 tests
void test_encode_utf8_bytes_block() {
    printf("Test: encode_utf8_bytes_block with ASCII string... ");

    const char *test_str = "Hello, World!";
    Jose_LowStar_Json_bytes_block bb = Jose_LowStar_Json_encode_utf8_bytes_block((Prims_string)test_str);

    assert(bb.len == strlen(test_str));
    assert(bb.buf != NULL);
    assert(Jose_LowStar_Json_validate_bytes_block(bb));

    // Verify content matches
    for (size_t i = 0; i < bb.len; i++) {
        assert(bb.buf[i] == (uint8_t)test_str[i]);
    }

    Jose_LowStar_Json_free_bytes_block(&bb);
    printf("PASS\n");
}

void test_encode_utf8_bytes_block_empty() {
    printf("Test: encode_utf8_bytes_block with empty string... ");

    Jose_LowStar_Json_bytes_block bb = Jose_LowStar_Json_encode_utf8_bytes_block((Prims_string)"");

    assert(bb.len == 0);
    assert(bb.buf == NULL);

    printf("PASS\n");
}

void test_encode_utf8_bytes_block_null() {
    printf("Test: encode_utf8_bytes_block with NULL... ");

    Jose_LowStar_Json_bytes_block bb = Jose_LowStar_Json_encode_utf8_bytes_block(NULL);

    assert(bb.len == 0);
    assert(bb.buf == NULL);

    printf("PASS\n");
}

void test_allocate_bytes_from_bytes_block() {
    printf("Test: allocate_bytes_from_bytes_block... ");

    // Create source bytes_block
    Jose_LowStar_Json_bytes_block src = Jose_LowStar_Json_malloc_bytes_block(5);
    for (uint32_t i = 0; i < src.len; i++) {
        src.buf[i] = (uint8_t)(i + 1);
    }

    // Allocate buffer from bytes_block
    uint8_t *buf = Jose_LowStar_Json_allocate_bytes_from_bytes_block(src);
    assert(buf != NULL);
    assert(buf != src.buf); // Different buffers

    // Verify copied data
    for (uint32_t i = 0; i < src.len; i++) {
        assert(buf[i] == src.buf[i]);
    }

    free(buf);
    Jose_LowStar_Json_free_bytes_block(&src);
    printf("PASS\n");
}

void test_allocate_bytes_from_bytes_block_empty() {
    printf("Test: allocate_bytes_from_bytes_block with empty block... ");

    Jose_LowStar_Json_bytes_block empty;
    empty.buf = NULL;
    empty.len = 0;

    uint8_t *buf = Jose_LowStar_Json_allocate_bytes_from_bytes_block(empty);
    assert(buf == NULL);

    printf("PASS\n");
}

int main() {
    printf("=== bytes_block Unit Tests (Phase 3.2) ===\n\n");

    // Phase 3.2.1-3.2.2 tests
    test_malloc_bytes_block_zero();
    test_malloc_bytes_block_nonzero();
    test_copy_bytes_block();
    test_copy_zero_length();
    test_validate_invalid();
    test_struct_size_alignment();

    // Phase 3.2.3 tests
    printf("\n--- Phase 3.2.3: UTF-8 Conversion Functions ---\n");
    test_encode_utf8_bytes_block();
    test_encode_utf8_bytes_block_empty();
    test_encode_utf8_bytes_block_null();
    test_allocate_bytes_from_bytes_block();
    test_allocate_bytes_from_bytes_block_empty();

    printf("\n=== All tests passed! ===\n");
    return 0;
}
