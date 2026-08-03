# JSON Low*/FFI Contract Summary

Last updated: 2025-11-16

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This note captures the contracts relied upon by `fstar/jose/LowStar/Json/Jose.LowStar.Json*.fst`
via `assume val` declarations. Each entry lists the F* assumption, the concrete
C implementation in `c/json_lowstar_runtime.c`, and the behavioural obligations
we expect the runtime to uphold.  The goal is to make every FFI boundary explicit
until we can replace the assumptions with verified proofs.

## Indexing helpers

| F* symbol | C implementation | Contract |
|-----------|-----------------|----------|
| `index_member_with_liveness` | `Jose_LowStar_Json_index_member_with_liveness` | Returns the `idx`'th `json_member_c` when `members` is live and `idx < count`. Aborts on out-of-range access. Keeps existing buffers alive. |
| `collect_members_u32_stack_aux` | `Jose_LowStar_Json_Stack_collect_members_u32_stack_aux` | Recursively converts an array of `json_member_c` into the `json_member_u32` list used by the stack interface. Allocates list cells with `malloc`, aborts on allocation failure. |

## Integer conversions

| F* symbol | C implementation | Contract |
|-----------|-----------------|----------|
| `u32_of_nat` | `Jose_LowStar_Json_u32_of_nat` | Casts a non-negative integer `< 2^32` to `uint32_t`. Performs bounds check and aborts on failure. |
| `lemma_u32_of_nat_inv` | same as above | Ensures `FStar.UInt32.v (u32_of_nat n) == n` for in-range inputs. |

## UTF-8 bridge

| F* symbol | C implementation | Contract |
|-----------|-----------------|----------|
| `encode_utf8_bytes_runtime` | `Jose_Utf8Lemmas_encode_utf8_bytes` | Produces a list of bytes matching `encode_utf8_bytes`. Used only at spec-level. |
| `lemma_encode_utf8_bytes_runtime_correct` | same | Guarantee that runtime output equals the verified `encode_utf8_bytes`. |

## Buffer management

| F* symbol | C implementation | Contract |
|-----------|-----------------|----------|
| `malloc_entry_array` | `Jose_LowStar_Json_malloc_entry_array` | Allocates an array of `json_entry_out` of length `len`. Aborts on failure. |
| `free_entry_array` | `Jose_LowStar_Json_free_entry_array` | Frees a previously allocated entries array. Safe to call with live buffer only. |
| `free_entry_array_contents` | `Jose_LowStar_Json_free_entry_array_contents` | Iterates through the array freeing the nested buffers before `free_entry_array`. Requires the `entries_*` predicates used in F* to hold. |
| `allocate_bytes_from_list` | `Jose_LowStar_Json_allocate_bytes_from_list` | Copies a list of bytes into a freshly allocated buffer of exact length. |

## Parsing entrypoints

| F* symbol | C implementation | Contract |
|-----------|-----------------|----------|
| `json_parse_entries_to_c` | `Jose_LowStar_Json_json_parse_entries_to_c` | Materialises the F* JSON parsing result as the C struct expected by Rust callers. Handles UTF-8 length checks, allocates result buffers, and records error metadata. |

## Known helper assumptions that remain

| F* symbol | Status | Notes |
|-----------|--------|-------|
| `lemma_utf8_bytes_length_bound` | Pending proof | Prove in F* using `lemma_encode_utf8_bytes_length_bound` to bind encoded length. |
| `lemma_utf8_bytes_cstring_length_bound` | Pending proof | Use existing bounds plus `+1` for terminator. |

## How these contracts are validated

* Every routine above performs **defensive checks** (bounds, null pointers) and
  aborts on violation.  This mirrors the F* preconditions and prevents silent UB.
* Functions that allocate memory funnel through `checked_alloc` helpers, which
  zero out `malloc` failures.
* Integration tests exercise both the F* and C/Rust paths during CI runs (`nix
  run .#security-suite`).  Failures or mismatches (for example, unexpected policy
  strings) bubble up via existing unit / integration tests.
* Static analysis tools (e.g. `clang-tidy`, `cargo clippy`) are wired into the CI
  pipeline; runtime code is covered by those passes.

### Future work

* Replace the helper lemma assumptions (`lemma_utf8_bytes_length_bound`,
  `collect_members_u32_stack_aux`, etc.) with constructive proofs when the
  low-level witnesses are available.
* Extend fuzzing (`fuzz_json_parser`) to cover the path exercised by
  `json_parse_entries_to_c` so the FFI entrypoint receives additional coverage.
* Document the memory lifecycle (`malloc_entry_array`/`free_entry_array`) in a
  design doc once deterministic property tests are in place.
