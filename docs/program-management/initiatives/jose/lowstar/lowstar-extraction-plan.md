# JOSE Low\*/C Extraction Plan

Last updated: 2026-07-08

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document breaks down the work required to extract the JOSE verification
modules from F\* to Low\*/C and integrate the generated artefacts back into the
Rust codebase. The goal is to replace the current Rust-only parsing/crypto
helpers with verified Low\*/C components that expose the same FFI surface.

## Guiding Objectives

1. **Preserve Verified Behaviour** – Existing F\* lemmas (e.g. `Jose.Jwe_header`,
   `Jose.Jwe_aad`, `Jose.Jws_header`) must keep proving after refactoring for
   extraction.
2. **Maintain Constant-Time Guarantees** – Extracted code should avoid
   data-dependent branching and pass dudect checks once wired into the binary.
3. **Incremental Replacement** – Swap Rust implementations one surface at a
   time (JWS header parsing → JWE header validation → AAD computation → RSA
   signature checks) to minimise regression risk.
4. **CI Automation** – Ensure KaRaMeL extraction, C compilation, and Rust FFI
   build steps run deterministically in CI (`nix flake check`, `verification.yml`).

## Phase Breakdown

### Phase 0 – Toolchain & Repository Layout
- Pin F\*, KaRaMeL, and Z3 versions (record in `nix/` inputs; index and runbooks live under `docs/verification/`).
- Ensure `nix develop .#verification` (or equivalent) exposes `fstar.exe`,
  `kamel.exe`, and the C toolchain required for Low\* compilation.
- Create repository structure for generated artefacts:
  - `generated/lowstar/jose/` (C sources)
  - `include/` (headers)
  - `c/` (static libs, build scripts)
- Update `Cargo.toml`/`build.rs` in `crates/ffi` to link against the future
  static library outputs.
- **Status (2025-10-20)**: ✅ Completed — tool versions pinned in `flake.nix`, scaffolding directories created, and dev shells
  confirmed to expose F\*/KaRaMeL/Z3 via `flake.nix` (see `docs/verification/README.md` for entrypoints).

### Phase 1 – F\* Module Preparation
- Refactor JOSE F\* modules to cleanly separate:
  - Pure specification functions (`Jose.Jwe_header`, `Jose.Jwe_aad`, `Jose.Jws_signature`)
  - Low\* extraction-ready bodies (no implicit heap effects, explicit
    allocation discipline).
- Add module-specific tests (`tests/property/*.fst`) covering JOSE cases
  targeted for extraction.
- Prove any missing lemmas needed to justify totality/typing constraints for
  KaRaMeL (e.g., bounded string lengths, enum domains).
- Document assumptions and invariants in module headers for future auditing.
- **Status (2025-11-08)**: ✅ Phase 1 Complete — Implemented per-request context
  infrastructure:
  - Created `Jose.Context.fst` defining `jose_context` type with `header_max_length`
    field constrained to `(n:nat{n > 0 /\ n < pow2 32})` for safe UInt32 conversion.
  - Created `Jose.Arith.Bounds.fst` with lemmas proving String.length ↔ UInt32
    conversion safety under context bounds (`lemma_string_length_bounded_by_context`,
    `string_length_to_u32`, round-trip lemmas).
  - Extended `Jose.Policy.fst` and `Jose.HeaderPolicy.fst` with context-based
    accessors (`get_header_max_length`) while preserving legacy constants for
    backward compatibility.
  - Implemented previously unimplemented lemmas `lemma_parse_length_bound` in
    `Jose.Jwe_header.fst` and `Jose.Jws_header.fst` proving successful parse ⇒
    input length ≤ context limit < 2^32.
  - **Phase 2 Updates (2025-11-08)**: Extended Low* layer with context-based APIs:
    - `Jose.LowStar.fst`: Added `jwe_parse_header_with_context` and
      `jws_parse_header_with_context` accepting `jose_context` parameter. Legacy
      functions preserved as wrappers using `default_context` for backward compatibility.
    - `Jose.HeaderParser.fst`: Added `parse_jwe_buffer_with_context` and
      `parse_jws_buffer_with_context` with refined types ensuring `len <=
      ctx.header_max_length`. Legacy buffer parsers preserved.
  - **F* Type Checking Status (2025-11-08)**: ✅ All modules verified successfully:
    - `Jose.Context.fst` — All verification conditions discharged
    - `Jose.Arith.Bounds.fst` — All verification conditions discharged
    - `Jose.Policy.fst` — All verification conditions discharged
    - `Jose.Jwe_header.fst` — All verification conditions discharged
    - `Jose.Jws_header.fst` — All verification conditions discharged
    - `Jose.LowStar.fst` — All verification conditions discharged
    - `Jose.HeaderParser.fst` — All verification conditions discharged
  - **Extraction Infrastructure (2025-11-08)**: Updated for context support:
    - Added Jose.Context to extraction module list in run_jose_lowstar.sh
    - Added missing lemmas in Jose.BufferListLemmas.fst (lemma_idx_succ_bound_for_rest,
      lemma_idx_lt_from_tail) required for buffer operations
    - Note: context propagation is wired end-to-end (F\* → Low\*/C → Rust). See
      `docs/program-management/historical/initiatives/jose/context-migration-phase1-4-summary.md`.

### Phase 2 – KaRaMeL Extraction Pipeline
- Author extraction scripts (`scripts/extraction/run_jose_lowstar.sh`) that:
  1. Run `fstar.exe` with `--codegen Kremlin` on JOSE modules.
  2. Invoke KaRaMeL to translate Low\* to C (`kamel` invocation).
  3. Emit C/headers into `generated/lowstar/jose/`.
- Ensure deterministic output by clearing previous artefacts and sorting
  generated file lists.
- Add sanity checks (e.g., verify header guards, ensure no `printf` or
  panicking code) before copying into `include/`.
- Ensure CI runs `scripts/extraction/run_jose_lowstar.sh` and fails if generated
  artefacts change without being committed (see `.github/workflows/ci.yml`).
- **Status (2025-10-20)**: ✅ Completed — `scripts/extraction/run_jose_lowstar.sh`
  runs in CI and `git diff` on `generated/everparse/` and `generated/lowstar/`
  is enforced to be clean. Run locally via:
  `nix develop .#verification --command scripts/extraction/run_jose_lowstar.sh`.

### Phase 2.1 – JWE/JWS Header Pipeline (High-Assurance Roadmap)

To replace the current JSON-driven Rust implementation with a verified Low*/C
version, we adopt the following high-verification-strength roadmap:

1. **Specification Refresh**
   - Catalogue all RFC 7515/7516 header fields in scope (`alg`, `enc`, `kid`,
     `crit`, etc.), their allowed values, and length constraints.
   - Record runtime policies (`policy.joseHeaderMaxLen`, allow-listed algorithms)
     plus existing Rust invariants. Update this document and the compliance
     matrix to cross-reference the proof/test artefacts that will justify each
     requirement.

2. **F* Specification Layer Split**
   - Separate specification-only modules (still speaking JSON) from Low*‑ready
     modules that operate on lightweight records and enumerations.
   - Provide soundness/completeness lemmas between the two layers and re-home
     length/finiteness proofs so they apply to the Low* representations.

3. **Verified Parsing Micro-language**
   - Define a dedicated JSON micro-language for JOSE headers and generate the
     parser with EverParse/LowParse after Base64URL decoding.
   - Prove per-field bounds and key name constraints in F*, ensuring the
     generated C respects the specification.
   - Reuse existing verified Base64URL/UTF-8 components and codify their
     contracts in F*.

4. **Low*/C Extraction Layer**
   - Implement `Jose.LowStar` helpers that expose deterministic records (`struct
     { alg_tag; enc_string; kid_state; … }`) using machine integers (e.g.
     `UInt32`) rather than `nat`.
   - Ensure KaRaMeL runs without Warning 4/15 by keeping the public interface
     free of ghost-only types and JSON dependencies.

5. **End-to-End Verification**
   - Extend F\* with equivalence lemmas (spec ↔ Low\*) and discharge them.
   - Run EverParse `spec-check`, dudect (constant-time paths), and Kani harnesses
     (panic freedom, bounds) on the generated code.
   - Validate against RFC 7520 vectors and current Rust behaviour.

6. **Integration & CI**
   - Wire the new C artefacts into `crates/ffi`, expose conversion helpers on
     the Rust side, and guard with feature flags during rollout.
   - Extend `nix flake check` / `verification.yml` to execute the full pipeline
     (F*, EverParse generation, KaRaMeL extraction, C build, Rust tests,
     dudect/Kani). Publish artefacts under `artifacts/lowstar/jose/`.
   - Update the compliance matrix and security review documents once proofs and
     tests are green.

#### Specification Refresh (2025-10-20)

| Header | Field | RFC Reference | Required | Value / Length Constraints | Current Handling | Gaps / Follow-ups |
| --- | --- | --- | --- | --- | --- | --- |
| JWE Protected | `alg` | RFC 7516 §4.1.1 | Yes | Sender authentication policy; accept only algorithms in `Jose.Alg_policy` allowlist | Parsed as string; mapped to `JweHeaderFound alg enc` | ✅ F* guard + runtime `JweHeader::validate` enforce allowlist |
| JWE Protected | `enc` | RFC 7516 §4.1.2 | Yes | Must be AEAD alg (e.g. `A256GCM`, `A128GCM`, `A256CBC-HS512`) per policy | Parsed as string (no validation) | ✅ Allowlist (`A256GCM`) enforced in F* and runtime; extend as additional enc modes land |
| JWE Protected | `zip` | RFC 7516 §4.1.3 | Optional | Only `DEF` permitted; others rejected | Currently ignored | ✅ Default posture now rejects all `zip`; revisit when compression feature scheduled |
| JWE Protected | `cty` / `typ` | RFC 7516 §4.1.12 / RFC 7515 §4.1.9 | Optional | ASCII token ≤ 255 chars (policy TBD) | Not parsed | Decide passthrough vs rejection; add bounds check |
| JWE Protected | `crit` | RFC 7515 §4.1.11 | Optional | Must understand every entry; else error | Not parsed | ✅ Reject in F* (`forbid_crit`) and runtime `JweHeader::validate` |
| JWS Protected | `alg` | RFC 7515 §4.1.1 | Yes | Same allowlist as JWE | Enumerated via `Jose.Alg_policy.alg` | ✅ Enforced via F* guard + runtime header parsing |
| JWS Protected | `kid` | RFC 7515 §4.1.4 | Optional | Non-empty ASCII identifier, ≤ 255 chars | Optional string | ✅ Length/ASCII bounds enforced (F* `valid_kid_string`, runtime `JwsHeader::validate`) |
| JWS Protected | `crit` | RFC 7515 §4.1.11 | Optional | Same as above | Not parsed | ✅ Reject in F* and runtime parsing |
| JWS Protected | `typ` / `cty` | RFC 7515 §4.1.9 / §4.1.10 | Optional | ASCII hints only | Not parsed | Clarify policy; potential passthrough |

### Runtime / Policy Anchors

- `policy.joseHeaderMaxLen` (default 4096) – documented in
  `docs/configurations/environment/README.md` and enforced via `Policy.header_max_length`.
  F\* lemma `lemma_jwe_parse_length_sound` already shows successful parse ⇒
  length ≤ policy; Low* layer must reuse machine integers and annotate
  `requires len ≤ max`.
- Algorithm allowlist: centralised in `Jose.Alg_policy` and split into
  **verified allowlist** (HACL*/EverCrypt only) vs **compat allowlist**
  (ring/aws-lc/mbedtls/p256). Compliance matrix rows
  `RFC7515.alg-allowlist`, `RFC7516.alg-allowlist` must reflect the verified
  profile; compat profiles remain supported but out of scope for strong‑constraint
  claims. The planned OIDC `RS256 Required Slice` / `RS256 Interop Slice` should
  be treated as explicit boundary-promotion work, not as silent expansion of the
  general verified allowlist.
- Base64URL / UTF-8: current Rust path uses `base64ct` + `String::from_utf8`.
  Low\* plan will depend on verified decoders (HACL\*/EverCrypt) and prove
  decoded input respects `policy.joseHeaderMaxLen` and printable subset.
- `fstar/jose/Jose.HeaderSpec.fst` introduces sanitised header records (`sanitized_jwe`,
  `sanitized_jws`) and `parse_*_sanitized` helpers that reuse existing lemmas.
  `fstar/jose/Jose.HeaderMicro.fst` layers a simple string-based micro-language on top,
  mapping `list (string * string)` pairs to the sanitised structures, and
  `fstar/jose/Jose.HeaderParser.fst` provides TLV buffer entry points plus JSON member
  normalisation (`parse_{jwe,jws}_json_members`). JSON normalisation is implemented
  via `JSON.parse_json_pairs_result` and surfaced to Rust via the extracted Low*/C
  bridge. If we want a verified byte-level JSON parser, it should be tracked as a
  separate epic (do not conflate it with the existing policy bridge).
- EverParse schema skeleton `fstar/lowparse/JoseHeader.3d` and design notes in
  `docs/program-management/initiatives/jose/parser/header-parser-spec.md` document the intended
  input/output contract for future generated parsers.

- **Action Items**

- [x] Update `spec/compliance-matrix.yaml` rows for `RFC7516.alg`,
  `RFC7516.enc`, `RFC7515.alg`, `RFC7515.kid`, `RFC7515.crit` with placeholders
  referencing this roadmap and planned artefacts.
- [x] Extend `docs/policies/jose-header-policy.md` to specify handling for
  `zip`, `crit`, `typ`, `cty` while Low* work is underway.
- [x] Ensure future Low* modules emit records using machine integers to remove
  Warning 15 and document the change in the policy doc.
  - Completed for the current JOSE header JSON path by the
    `Jose.LowStar.Json.Stack` / `bytes_block` migration, which stores header
    member lengths and buffers through `UInt32`-backed machine-integer records
    instead of nat-heavy public structs. See Phase 3.2.4 below and
    `docs/policies/jose-header-policy.md`.

### Phase 3 – C Build & Rust FFI Wiring
- Write `c/Makefile` (or CMake/Nix expression) to compile generated C into a
  static library (e.g., `libaegaeon_jose.a`).
- Update `crates/ffi/build.rs` to:
  - Link the static library.
  - Expose extern functions consistent with current Rust stubs (e.g.,
    `aeg_jws_verify`, `aeg_jwe_validate_header`).
- Migrate Rust call sites in `crates/jose` to use the FFI layer where
  functionality is parity complete.
- Provide feature flags (e.g., `--cfg jose_lowstar`) to allow gradual
  migration and fallback to Rust implementations during development.
- **Status (2025-11-05)**: ✅ JSON header parsing is now wired through the Low*/C
  pipeline by compiling `generated/lowstar/jose/Jose_LowStar_Json.c` together with
  the handwritten runtime (`c/json_lowstar_runtime.c`) via `crates/ffi/build.rs`
  (`cc::Build`). The Rust bridge `crates/ffi/src/lib.rs` exposes
  `parse_json_entries`, and higher-level logic (`crates/jose/src/json_lowstar.rs`,
  `jws.rs`, `jwe.rs`) attempts the Low*/C path first. The default compatibility
  build still retains a local fallback when the parser is unavailable;
  `verified-claim` turns that condition into fail-closed behavior. Other JOSE
  surfaces (JWE AAD, signature checks, etc.) remain pending and will follow the
  same wiring pattern.
- **Phase 3.2.4 – Memory Optimization (2025-11-09)**: ✅ **COMPLETE**. Migrated `json_to_kv_pairs_low`
  from list-based to bytes_block-based (UInt32) implementation using Stack module
  (`Jose.LowStar.Json.Stack`). Eliminated intermediate allocations (~93% reduction)
  by using direct memory access via `member->u32_key.buf` instead of `list_to_buffer()`.
  Stack module extracted separately with `-skip-compilation` flag; automated
  `internal/FStar.h` stub generation added to `scripts/extraction/run_jose_lowstar.sh`.
  Build system updated to compile Stack module (`artifacts/karamel/Jose_LowStar_Json_Stack.c`)
  and KaRaMeL runtime (`lib/krml/dist/generic/fstar_uint32.c`). Implementation is
  production-ready and backward-compatible with all `aegaeon-jose` tests passing.
  Security improvements: Early header length validation before cryptographic operations
  (DoS mitigation). See: `docs/verification/jose/phase4-verification-summary.md`
  and commits e1ce5ae, 492f206, c3fb0e3.

### Phase 4 – Verification & Testing
- Add unit tests binding the extracted C functions via Rust FFI; confirm
  existing RFC 7520 vectors pass unchanged.
- Introduce dudect harnesses for the new code paths (`tests/constant_time/`), ensuring
  `|t| < 4.5` remains true post-extraction.
- Expand Kani coverage:
  - Model FFI boundary functions for panic freedom and buffer bounds.
  - Ensure harnesses compile by stubbing required `extern "C"` functions when
    running under `cargo kani`.
- Capture bench results (optional) to compare Rust vs Low\*/C performance.
- **Status (2025-11-09)**: ✅ **COMPLETE** — All Phase 4 verification and testing work
  finished for the Phase 3.2.4 Stack module implementation.
- **Integration Tests (2025-11-08)**: ✅ Parity tests for JSON vs TLV headers run under
  `cargo test -p aegaeon-jose --test tlv_parity` and cover the new Low*/C path.
  Integration into both `nix run .#security-suite` and `verification.yml` (jose-vectors
  job) is complete with comprehensive artifact collection on failure (test output,
  failure summary, git diff, source files, environment info). All `aegaeon-jose`
  tests pass with the bytes_block implementation.
- **Kani Coverage (2025-11-09)**: ✅ Added 8 new FFI boundary harnesses in
  `crates/ffi/src/kani_tests.rs` covering bytes_block Stack module:
  - `verify_json_member_c_layout` — FFI structure layout (32 bytes, 8-byte alignment)
  - `verify_utf8_decode_null_safety` — Null pointer handling
  - `verify_utf8_decode_valid_input` — Valid UTF-8 decoding
  - `verify_free_string_null_safety` — String deallocation safety
  - `verify_jose_context_bounds` — Context bounds validation
  - `verify_parse_json_entries_null_pointer` — Null pointer rejection
  - `verify_parse_json_entries_count_overflow` — Integer overflow prevention
  - `verify_json_member_c_pointer_validity` — Pointer validity checks

  Previous JSON preprocessing harnesses (`proof_json_header_parsing_no_panic`,
  `proof_json_empty_object_handling`, `proof_json_single_field_parsing`,
  `proof_json_multiple_fields_no_panic`) continue to test pure Rust validation logic.
  **Scope limitation**: The Low\* C FFI boundary is not tested by Kani as it requires
  extern "C" function stubs. The Low\* implementation itself is verified separately
  through F\* type checking and extraction to C via KaRaMeL.
- **dudect Coverage (2025-11-09)**: ⊘ Intentionally omitted for Stack module. The
  Stack module (`Jose.LowStar.Json.Stack`) provides memory layout infrastructure, not
  cryptographic operations. Existing dudect harnesses already cover cryptographic
  operations that USE the Stack module:
  - `hmac_timing_test.c` — HMAC-SHA256 constant-time verification
  - `ed25519_timing_test.c` — Ed25519 signature constant-time verification
  - `rsa_timing_test.c` — RSA signature constant-time verification
  - `jwe_timing_test.c` — JWE decryption constant-time verification
  - `compare_timing_test.c` — Generic comparison constant-time verification

  JSON header parsing is inherently variable-time (depends on string lengths, object
  field counts) and does not require constant-time guarantees. Unlike cryptographic
  primitives (HMAC, comparison), JSON parsing correctness is independent of timing
  side-channels. Future Low* functions requiring constant-time properties (e.g., JWT
  signature verification) will have dedicated dudect harnesses.
- **Performance Benchmarks (2025-11-09)**: ✅ Created comprehensive criterion-based
  benchmarks in `crates/jose/benches/json_parsing.rs` to establish performance baseline
  for the bytes_block implementation:
  - Minimal header (1 field): 782 ns
  - Typical JWS header (2 fields): 1.54 µs
  - Complex header (4 fields): 2.85 µs
  - Linear scaling: ~650-700 ns per field
  - Size-based scaling (15-135 bytes)

  Detailed results documented in `docs/performance/jose-json-parsing-baseline.md`.
  Benchmark artifacts archived in `artifacts/perf/json-parsing-baseline-2025-11-09.txt`
  (local only). Run with `cargo bench -p aegaeon-jose --bench json_parsing`.

### Phase 5 – CI & Compliance Integration
- **Status (2025-11-09)**: ✅ **COMPLETE** — CI enforcement of extraction parity,
  compliance matrix updates, and documentation complete.
- **CI Enforcement (2025-11-09)**: ✅ Added extraction diff check to `verification.yml`:
  - `jose-vectors` job now runs `scripts/extraction/run_jose_lowstar.sh` using
    `nix develop .#verification` environment.
  - Fails build if generated artifacts differ from committed versions (`git diff
    --exit-code generated/lowstar/jose artifacts/karamel`).
  - Uploads extraction artifacts on failure for debugging.
  - Nix setup includes cachix caching for faster CI builds.
- **Artifact Regeneration Documentation (2025-11-09)**: ✅ Added to `README.md`:
  - New "Regenerating Low* Extraction Artifacts" section in Development Environment.
  - Documents when to regenerate (after F* source changes, on CI diff errors).
  - Provides step-by-step regeneration procedure using `nix develop .#verification`.
  - Explains CI enforcement mechanism.
- **Compliance Matrix Updates (2025-11-09)**: ✅ Added 4 new entries to
  `spec/compliance-matrix.yaml`:
  - **7515-005**: Low* Stack module implementation with memory safety guarantees
    (bytes_block, Phase 3.2.4).
  - **7515-006**: JSON/TLV parity verification (parity + RFC 7520 vectors exercised in CI).
  - **7515-007**: FFI boundary safety with Kani (8 harnesses covering layout, null
    safety, overflow, UTF-8 validation).
  - **7515-008**: Performance baseline and characteristics (criterion benchmarks,
    782ns-2.85µs, linear scaling ~650-700ns/field).
  - All entries reference verification artifacts, tests, and CI checks.
- **Original Phase 5 Tasks**:
- Update `verification.yml` to include:
  - Extraction script invocation.
  - Build of static libs.
  - Rust tests against the Low\*/C-backed implementation.
- Wire artefact publication (e.g., upload generated C/headers) for traceability.
- Refresh compliance artefacts:
  - `spec/compliance-matrix.yaml` references new tests/paths.
  - `docs/security/security-review/threat-vulnerability-and-formal-review.md` notes replacement of Rust stubs with
    verified code and closes the Phase 6 “Next Steps”.
- Document the migration in `CHANGELOG.md` and `docs/program-management/`.

## Workstream Cross-Cutting Concerns

- **Security Review Alignment** – Keep the security-review document updated as
  JOSE surfaces migrate to Low\* (ensures auditors track the provenance change).
- **Dependency Governance** – Ensure KaRaMeL/F\* pins are reflected in Flake
  inputs and locked for reproducibility; update SBOM tooling if new native
  libraries are introduced.
- **Fallback Strategy** – Maintain a capability to switch back to the Rust
  implementation (feature flag or config file) while the extracted code matures.
- **Documentation** – For each completed phase, add entries to
  `docs/program-management/initiatives/jose/jose-implementation-plan.md` (Phase 7+), update
  `AGENTS.md` with operational steps, and extend runbooks as needed.

## Tracking & Deliverables

- **Primary Owner**: Formal Verification workstream
- **Artifacts**:
  - `generated/lowstar/jose/*.c`, `*.h`
  - `c/libaegaeon_jose.a`
  - `crates/ffi/src/lib.rs` (updated externs)
  - Updated compliance matrix entries (RFC 7515/7516 rows pointing to FFI-backed tests)
- **Key Acceptance Criteria**:
  1. Extraction pipeline deterministic and reproducible under Nix/CI.
  2. All existing JOSE tests (unit, integration, conformance) pass with the
     Low\*/C implementation enabled.
  3. dudect/Kani coverage restored with no regressions.
  4. Security review “Next Steps” closed with documented verification evidence.

Completion of these phases will set the stage for extending the verified JOSE
surface area (e.g., RSA signature generation, JWK parsing) and for future FFI
harness automation in Kani.
