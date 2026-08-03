// JSON Low* Runtime - FFI implementation for Jose.LowStar.Json
//
// This file provides C implementations for assume val declarations in
// fstar/lowstar/json/Jose.LowStar.Json.fst that are marked noextract.
//
// These functions bridge between the verified Low* code and Rust allocators.

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stddef.h>

// Include forward declarations for F* types
#include "Jose_LowStar_Json_Stack.h"
#include "krmllib.h"

// Primitive operators required by Low* extraction
krml_checked_int_t Prims_op_Addition(krml_checked_int_t x, krml_checked_int_t y) {
    return x + y;
}

bool Prims_op_LessThan(krml_checked_int_t x, krml_checked_int_t y) {
    return x < y;
}

krml_checked_int_t Prims_pow2(krml_checked_int_t x) {
    return (krml_checked_int_t)1 << x;
}

// Phase 3.2.4: Define types locally (generated headers not available in repo)
// These types support legacy functions and FFI boundaries

// Output type for JSON entries (matches Rust FFI JsonEntryOut)
typedef struct {
    const uint8_t *entry_key_ptr;
    uint32_t entry_key_len;
    const uint8_t *entry_value_ptr;
    uint32_t entry_value_len;
} Jose_LowStar_Json_json_entry_out;

// Legacy list type for uint8_t (used by allocate_bytes_from_list)
typedef struct Prims_list__uint8_t_s Prims_list__uint8_t;
struct Prims_list__uint8_t_s {
    uint8_t tag;  // Prims_Nil=0, Prims_Cons=1
    uint8_t hd;   // head element (only valid if tag==Prims_Cons)
    Prims_list__uint8_t *tl;  // tail (only valid if tag==Prims_Cons)
};

// Prims list tags (already defined in Jose_LowStar_Json_Stack.h but duplicated for clarity)
#ifndef Prims_Nil
#define Prims_Nil 0
#define Prims_Cons 1
#endif

// Legacy type alias (old name -> new Stack type)
typedef Jose_LowStar_Json_Stack_json_member_c Jose_LowStar_Json_json_member_c;

// JSON parse error enum (matches Rust JsonError)
typedef uint8_t Jose_LowStar_Json_json_parse_error;
#define Jose_LowStar_Json_JsonParseOk 0  // Success
#define Jose_LowStar_Json_JsonParseErrorUnknownKey 1
#define Jose_LowStar_Json_JsonParseErrorInvalidKeyEncoding 2
#define Jose_LowStar_Json_JsonParseErrorInvalidValueUtf8 3
#define Jose_LowStar_Json_JsonParseErrorPolicyViolation 4
#define Jose_LowStar_Json_JsonParseErrorBufferTooShort 5
#define Jose_LowStar_Json_JsonParseErrorInternal 6

// JSON parse result type (matches Rust JsonParseResultC)
typedef struct {
    Jose_LowStar_Json_json_entry_out *result_entries;
    uint32_t result_entry_count;
    Jose_LowStar_Json_json_parse_error result_error;
    uint8_t *result_error_message;  // Non-const to avoid memcpy warning
    uint32_t result_error_message_len;
} Jose_LowStar_Json_json_parse_result_c;
// Bridge for the assumed u32_of_nat helper in F*.
uint32_t Jose_LowStar_Json_u32_of_nat(krml_checked_int_t n) {
    if (n < 0 || (uint64_t)n > UINT32_MAX) {
        abort();
    }
    return (uint32_t)n;
}

static inline void *
checked_alloc(size_t count, size_t size) {
    if (count == 0) {
        count = 1; // ensure malloc never returns NULL for zero-sized request
    }
    size_t total = count * size;
    void *ptr = calloc(1, total);
    if (ptr == NULL) {
        abort();
    }
    return ptr;
}

uint8_t *Jose_LowStar_Json_malloc_bytes(krml_checked_int_t len) {
    if (len < 0) {
        abort();
    }
    size_t count = (size_t)len;
    return (uint8_t *)checked_alloc(count, sizeof(uint8_t));
}

// Stack module malloc_bytes (Phase 3.2.4)
uint8_t *Jose_LowStar_Json_Stack_malloc_bytes(krml_checked_int_t len) {
    if (len < 0) {
        abort();
    }
    size_t count = (size_t)len;
    return (uint8_t *)checked_alloc(count, sizeof(uint8_t));
}

void Jose_LowStar_Json_free_bytes(uint8_t *buf) {
    free(buf);
}

Jose_LowStar_Json_json_entry_out *
Jose_LowStar_Json_malloc_entry_array(uint32_t len) {
    size_t count = (size_t)len;
    return (Jose_LowStar_Json_json_entry_out *)checked_alloc(
        count,
        sizeof(Jose_LowStar_Json_json_entry_out)
    );
}

void Jose_LowStar_Json_free_entry_array(Jose_LowStar_Json_json_entry_out *buf) {
    free(buf);
}

// Free nested key/value buffers for entries[idx..count-1].
void
Jose_LowStar_Json_free_entry_array_contents(
    Jose_LowStar_Json_json_entry_out *entries,
    uint32_t count,
    uint32_t idx
) {
    if (entries == NULL) {
        return;
    }

    if (idx > count) {
        idx = count;
    }

    for (uint32_t i = idx; i < count; ++i) {
        Jose_LowStar_Json_json_entry_out *entry = &entries[i];

        if (entry->entry_key_ptr != NULL) {
            free((void *)entry->entry_key_ptr);
            entry->entry_key_ptr = NULL;
        }
        entry->entry_key_len = 0;

        if (entry->entry_value_ptr != NULL) {
            free((void *)entry->entry_value_ptr);
            entry->entry_value_ptr = NULL;
        }
        entry->entry_value_len = 0;
    }
}

// ============================================================================
// Phase 3.2: bytes_block Support
// ============================================================================
//
// C representation of F* bytes_block type from Jose.LowStar.Json.fst:
//   type bytes_block = {
//     buf: buffer UInt8.t;
//     len: UInt32.t;
//     len_bound: squash (UInt32.v len <= LowStar.Buffer.length buf)
//   }
//
// Note: len_bound is a proof-only field (squash) and not extracted to C.
//
typedef struct {
    uint8_t *buf;
    uint32_t len;
} Jose_LowStar_Json_bytes_block;

// Allocate a new bytes_block with specified length.
// Aborts if allocation fails.
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

// Free a bytes_block (frees buf, zeros struct for safety).
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

// Copy bytes_block contents to new buffer.
// Returns new bytes_block with copied data.
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

// Validate bytes_block (defensive check).
// Returns true if bytes_block is valid, false otherwise.
bool Jose_LowStar_Json_validate_bytes_block(Jose_LowStar_Json_bytes_block bb) {
    if (bb.len == 0) {
        return bb.buf == NULL; // zero-length should have NULL buf
    }
    return bb.buf != NULL; // non-zero length requires valid buf
}

// Allocate a new buffer from bytes_block (creates independent copy).
// Returns new uint8_t* buffer that caller must free.
uint8_t *Jose_LowStar_Json_allocate_bytes_from_bytes_block(Jose_LowStar_Json_bytes_block bb) {
    if (bb.len == 0 || bb.buf == NULL) {
        return NULL;
    }
    uint8_t *buf = (uint8_t *)checked_alloc((size_t)bb.len, sizeof(uint8_t));
    memcpy(buf, bb.buf, (size_t)bb.len);
    return buf;
}

// Encode UTF-8 string to bytes_block.
// Phase 3.2.3: Replaces Jose_Utf8Lemmas_encode_utf8_bytes (list-based).
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
        // String too long for UInt32.t
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

// ============================================================================
// Legacy list-based functions (to be removed in Phase 3.2.5)
// ============================================================================

uint8_t *Jose_LowStar_Json_allocate_bytes_from_list(Prims_list__uint8_t *xs) {
    size_t len = 0;
    for (Prims_list__uint8_t *p = xs; p && p->tag == Prims_Cons; p = p->tl) {
        ++len;
    }

    uint8_t *buf = (uint8_t *)checked_alloc(len, sizeof(uint8_t));
    size_t i = 0;
    for (Prims_list__uint8_t *p = xs; p && p->tag == Prims_Cons; p = p->tl) {
        buf[i++] = p->hd;
    }
    return buf;
}

Jose_LowStar_Json_json_member_c
Jose_LowStar_Json_index_member_with_liveness(
    Jose_LowStar_Json_json_member_c *members,
    uint32_t count32,
    uint32_t idx32
) {
    if (members == NULL || idx32 >= count32) {
        abort();
    }

    return members[idx32];
}

// -----------------------------------------------------------------------------
// UTF-8 encoding support (bridges Jose.Utf8Lemmas.encode_utf8_bytes)
// -----------------------------------------------------------------------------

Prims_list__uint8_t *Jose_Utf8Lemmas_encode_utf8_bytes(Prims_string s) {
    if (s == NULL) {
        return NULL;
    }

    size_t len = strlen(s);
    Prims_list__uint8_t *head = NULL;

    for (size_t i = len; i > 0; --i) {
        Prims_list__uint8_t *node = (Prims_list__uint8_t *)checked_alloc(
            1,
            sizeof(Prims_list__uint8_t)
        );
        node->tag = Prims_Cons;
        node->hd = (uint8_t)s[i - 1];
        node->tl = head;
        head = node;
    }

    return head;
}

// -----------------------------------------------------------------------------
// Rust UTF-8 decoding FFI (from crates/ffi/src/lib.rs)
// -----------------------------------------------------------------------------

// Decode UTF-8 bytes to a C string
// Returns 0 on success, 3 for invalid UTF-8, 6 for internal error
extern uint8_t aegaeon_ffi_decode_utf8(
    const uint8_t *bytes,
    size_t len,
    char **out_string
);

// Free a string allocated by aegaeon_ffi_decode_utf8
extern void aegaeon_ffi_free_string(char *s);

// -----------------------------------------------------------------------------
// JSON parsing entry point (assume val from Jose.LowStar.Json)
// -----------------------------------------------------------------------------

// Helper: compute length of a Prims_list__uint8_t
static krml_checked_int_t list_length_uint8_t(Prims_list__uint8_t *xs) {
    krml_checked_int_t len = 0;
    for (Prims_list__uint8_t *p = xs; p && p->tag == Prims_Cons; p = p->tl) {
        ++len;
    }
    return len;
}

// Helper: convert list to byte buffer for Rust FFI
static uint8_t *list_to_buffer(Prims_list__uint8_t *xs, krml_checked_int_t len) {
    if (len == 0) {
        return NULL;
    }
    uint8_t *buf = Jose_LowStar_Json_malloc_bytes(len);
    krml_checked_int_t i = 0;
    for (Prims_list__uint8_t *p = xs; p && p->tag == Prims_Cons; p = p->tl) {
        buf[i++] = p->hd;
    }
    return buf;
}

// Helper: free members u32 list (Phase 3.2.4)
// Memory ownership: Each json_member_u32 owns its bytes_block buffers.
// This function frees:
// 1. u32_key.buf for each member
// 2. u32_value._0.buf if u32_value is Some
// 3. The list node itself
static void free_members_u32_list(Prims_list__Jose_LowStar_Json_Stack_json_member_u32 *members) {
    while (members != NULL && members->tag == Prims_Cons) {
        Prims_list__Jose_LowStar_Json_Stack_json_member_u32 *next = members->tl;

        // Free bytes_block buffers in the member
        Jose_LowStar_Json_Stack_json_member_u32 *member = &members->hd;
        if (member->u32_key.buf != NULL) {
            free(member->u32_key.buf);
        }
        if (member->u32_value.tag == Jose_LowStar_Json_Stack_BytesBlockSome &&
            member->u32_value._0.buf != NULL) {
            free(member->u32_value._0.buf);
        }

        free(members);
        members = next;
    }
}

// Helper: build error result
static Jose_LowStar_Json_json_parse_result_c build_error_result(
    Jose_LowStar_Json_json_parse_error error,
    const char *message
) {
    Jose_LowStar_Json_json_parse_result_c result;
    result.result_entries = NULL;
    result.result_entry_count = 0;
    result.result_error = error;

    if (message) {
        size_t msg_len = strlen(message);
        result.result_error_message = Jose_LowStar_Json_malloc_bytes(msg_len);
        memcpy(result.result_error_message, message, msg_len);
        result.result_error_message_len = (uint32_t)msg_len;
    } else {
        result.result_error_message = NULL;
        result.result_error_message_len = 0;
    }

    return result;
}

Jose_LowStar_Json_json_parse_result_c
Jose_LowStar_Json_json_parse_entries_to_c(
    Jose_LowStar_Json_json_member_c *members,
    uint32_t count
) {
    // Step 1: Collect u32 members using extracted Low* function (Phase 3.2.4)
    Prims_list__Jose_LowStar_Json_Stack_json_member_u32 *u32_members =
        Jose_LowStar_Json_Stack_collect_members_u32_stack(members, count);

    if (u32_members == NULL) {
        return build_error_result(
            Jose_LowStar_Json_JsonParseErrorInternal,
            "failed to collect u32 members"
        );
    }

    // Step 3: Count entries and validate (Phase 3.2.4)
    krml_checked_int_t entry_count = 0;
    for (Prims_list__Jose_LowStar_Json_Stack_json_member_u32 *p = u32_members;
        p && p->tag == Prims_Cons;
        p = p->tl) {
        Jose_LowStar_Json_Stack_json_member_u32 *member = &p->hd;
        if (member->u32_value_kind == Jose_LowStar_Json_Stack_JsonValueNull) {
            continue;
        }
        ++entry_count;
    }

    if (entry_count > UINT32_MAX) {
        free_members_u32_list(u32_members);
        return build_error_result(
            Jose_LowStar_Json_JsonParseErrorPolicyViolation,
            "json-entry-count-overflow"
        );
    }

    // Step 4: Allocate result array
    uint32_t entry_count_u32 = (uint32_t)entry_count;
    Jose_LowStar_Json_json_entry_out *entries =
        Jose_LowStar_Json_malloc_entry_array(entry_count_u32);

    // Step 5: Decode UTF-8 and populate entries (Phase 3.2.4)
    krml_checked_int_t i = 0;
    for (Prims_list__Jose_LowStar_Json_Stack_json_member_u32 *p = u32_members;
        p && p->tag == Prims_Cons;
        p = p->tl) {

        Jose_LowStar_Json_Stack_json_member_u32 *member = &p->hd;

        // Skip null values (treated as missing entries)
        if (member->u32_value_kind == Jose_LowStar_Json_Stack_JsonValueNull) {
            continue;
        }

        // Decode key UTF-8 - Direct bytes_block access (Phase 3.2.4)
        uint8_t *key_buf = member->u32_key.buf;
        size_t key_len = (size_t)member->u32_key.len;
        char *key_str = NULL;

        uint8_t key_result = aegaeon_ffi_decode_utf8(key_buf, key_len, &key_str);
        // No free needed - bytes_block is owned by member

        if (key_result != 0) {
            // Free already-allocated entries
            for (krml_checked_int_t j = 0; j < i; ++j) {
                aegaeon_ffi_free_string((char*)entries[j].entry_key_ptr);
                aegaeon_ffi_free_string((char*)entries[j].entry_value_ptr);
            }
            Jose_LowStar_Json_free_entry_array(entries);
            free_members_u32_list(u32_members);
            return build_error_result(
                Jose_LowStar_Json_JsonParseErrorInvalidKeyEncoding,
                "header key is not valid UTF-8"
            );
        }

        // Decode value UTF-8 - Handle option bytes_block (Phase 3.2.4)
        if (member->u32_value.tag != Jose_LowStar_Json_Stack_BytesBlockSome) {
            aegaeon_ffi_free_string(key_str);
            // Free already-allocated entries
            for (krml_checked_int_t j = 0; j < i; ++j) {
                aegaeon_ffi_free_string((char*)entries[j].entry_key_ptr);
                aegaeon_ffi_free_string((char*)entries[j].entry_value_ptr);
            }
            Jose_LowStar_Json_free_entry_array(entries);
            free_members_u32_list(u32_members);
            return build_error_result(
                Jose_LowStar_Json_JsonParseErrorInternal,
                "string value has no bytes_block"
            );
        }

        uint8_t *value_buf = member->u32_value._0.buf;
        size_t value_len = (size_t)member->u32_value._0.len;
        char *value_str = NULL;

        uint8_t value_result = aegaeon_ffi_decode_utf8(value_buf, value_len, &value_str);
        // No free needed - bytes_block is owned by member

        if (value_result != 0) {
            aegaeon_ffi_free_string(key_str);
            // Free already-allocated entries
            for (krml_checked_int_t j = 0; j < i; ++j) {
                aegaeon_ffi_free_string((char*)entries[j].entry_key_ptr);
                aegaeon_ffi_free_string((char*)entries[j].entry_value_ptr);
            }
            Jose_LowStar_Json_free_entry_array(entries);
            free_members_u32_list(u32_members);
            return build_error_result(
                Jose_LowStar_Json_JsonParseErrorInvalidValueUtf8,
                "header value is not valid UTF-8"
            );
        }

        // Check UTF-8 lengths fit in uint32_t
        size_t key_str_len = strlen(key_str);
        size_t value_str_len = strlen(value_str);

        if (key_str_len > UINT32_MAX || value_str_len > UINT32_MAX) {
            aegaeon_ffi_free_string(key_str);
            aegaeon_ffi_free_string(value_str);
            // Free already-allocated entries
            for (krml_checked_int_t j = 0; j < i; ++j) {
                aegaeon_ffi_free_string((char*)entries[j].entry_key_ptr);
                aegaeon_ffi_free_string((char*)entries[j].entry_value_ptr);
            }
            Jose_LowStar_Json_free_entry_array(entries);
            free_members_u32_list(u32_members);
            return build_error_result(
                Jose_LowStar_Json_JsonParseErrorPolicyViolation,
                "json-utf8-length-overflow"
            );
        }

        // Populate entry
        entries[i].entry_key_ptr = (uint8_t*)key_str;
        entries[i].entry_key_len = (uint32_t)key_str_len;
        entries[i].entry_value_ptr = (uint8_t*)value_str;
        entries[i].entry_value_len = (uint32_t)value_str_len;

        ++i;
    }

    free_members_u32_list(u32_members);

    // Step 6: Build success result
    Jose_LowStar_Json_json_parse_result_c result;
    result.result_entries = entries;
    result.result_entry_count = (uint32_t)entry_count;
    result.result_error = Jose_LowStar_Json_JsonParseOk;
    result.result_error_message = NULL;
    result.result_error_message_len = 0;

    return result;
}

// ============================================================================
// Phase 3.2.4: Stack Module Implementation (assume val in F*)
// ============================================================================
//
// C implementation of Jose_LowStar_Json_Stack_collect_members_u32_stack_aux.
// This function is declared as `assume val` in F* due to complex liveness proofs,
// but the implementation is straightforward list construction.

Prims_list__Jose_LowStar_Json_Stack_json_member_u32
*Jose_LowStar_Json_Stack_collect_members_u32_stack_aux(
  Jose_LowStar_Json_Stack_json_member_c *members,
  uint32_t count32,
  uint32_t idx32
) {
    // Base case: reached end of array
    if (idx32 >= count32) {
        return NULL;  // Empty list (Prims_Nil)
    }

    // Recursive case: process current member and cons to rest
    Jose_LowStar_Json_Stack_json_member_c member_c = members[idx32];

    // Convert current member to u32 representation using extracted F* function
    Jose_LowStar_Json_Stack_json_member_u32 member_u32 =
        Jose_LowStar_Json_Stack_read_member_u32_stack(member_c);

    // Recursively process remaining members
    Prims_list__Jose_LowStar_Json_Stack_json_member_u32 *rest =
        Jose_LowStar_Json_Stack_collect_members_u32_stack_aux(members, count32, idx32 + 1);

    // Allocate Cons node and populate
    Prims_list__Jose_LowStar_Json_Stack_json_member_u32 *cons =
        malloc(sizeof(Prims_list__Jose_LowStar_Json_Stack_json_member_u32));

    if (cons == NULL) {
        abort();  // Out of memory
    }

    cons->tag = Prims_Cons;
    cons->hd = member_u32;
    cons->tl = rest;

    return cons;
}

// ============================================================================
// Phase 3.2.4: Jose.Context API Implementation
// ============================================================================
//
// Provides Jose.Context functions expected by FFI layer.
// The Stack module doesn't use contexts; these are minimal stubs for compatibility.

// Jose.Context default context value (4096 bytes maximum header length)
const uint32_t Jose_Context_default_context = 4096u;

// Create a new Jose.Context with specified maximum length
uint32_t Jose_Context_make_context(uint32_t max_len) {
    if (max_len == 0) {
        abort(); // Invalid context
    }
    return max_len;
}

// ============================================================================
// Phase 3.2.4: Memory Management for Parse Results
// ============================================================================

// Free a parse result returned by Jose_LowStar_Json_json_parse_entries_to_c
void Jose_LowStar_Json_json_parse_free_result(
    Jose_LowStar_Json_json_parse_result_c *result
) {
    if (result == NULL) {
        return;
    }

    // Free each entry's buffers (allocated by Stack module)
    if (result->result_entries != NULL) {
        Jose_LowStar_Json_free_entry_array_contents(
            result->result_entries,
            result->result_entry_count,
            0
        );

        // Free the entries array
        Jose_LowStar_Json_free_entry_array(result->result_entries);
        result->result_entries = NULL;
    }

    result->result_entry_count = 0;
    result->result_error = Jose_LowStar_Json_JsonParseOk;
    result->result_error_message = NULL;
    result->result_error_message_len = 0;
}
