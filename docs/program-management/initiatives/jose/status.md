# JOSE Initiative Status and Milestones

Last updated: 2026-07-08

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document carries the detailed JOSE workstream status, dependency order,
recent milestones, and remaining next steps. Use `README.md` as the navigation
entrypoint.

## Current Status (2026-05-19)

**Phase 6 public-architecture simplification / claim-boundary refinement**: COMPLETE

- **Stack Module Implementation**: bytes_block-based Low* implementation with UInt32
  buffer representation, eliminating intermediate allocations.
- **Low* JSON bridge**: Rust now routes JWS and JWE protected headers through
  the shared `json::parse_json_header` entry point, which selects the active
  verified surface (`json_lowstar` or the opt-in TLV/FFI bridge) and retains
  the compat fallback only for `ParserUnavailable`.
  The default verified normalization step remains
  `json_lowstar::parse_json_header_lowstar`
  (duplicate-preserving serde_json tokenization -> Low*/C `parse_json_entries_safe`).
  The same duplicate-preserving top-level object admission is now centralized in
  `aegaeon_jose::raw_json` and reused by JOSE header parsing plus Request Object
  raw payload handling; server-side DCR admission also consumes that helper.
  The helper now records the requesting surface in its parse report, so a future
  verified backend swap can happen at one surface-aware selector instead of in
  each call site. The same module now exposes the current claim posture
  explicitly. In normal builds, `ALL_RAW_JSON_SURFACES` now inventories the 11
  promoted surfaces:
  `jose-header`, `request-object`, `client-registration`,
  `software-statement`, `private-key-jwt-payload`,
  `jwt-bearer-assertion-payload`, `oidc-id-token-payload`,
  `jwt-access-token-header`, `jwt-access-token-payload`,
  `federation-entity-statement`, and
  `federation-trust-mark` now use the `verified-structural-v1` backend and the
  `raw-bytes` boundary. The legacy `generic-object` surface is isolated to
  `test` builds, where it remains compat-only at `SerdeCompat` plus
  `top-level-object-members`. It also classifies
  whole-object trailing bytes and non-object top-level shapes centrally, so
  promoted surfaces do not need surface-local trailing-byte detectors. The
  `verified-structural-v1` backend is now source-managed and defaulted for
  those eleven promoted surfaces only; the legacy compat-only surface still
  rejects that backend fail-closed when explicitly enabled. The `jose-header` Phase 1 structural
  landing, the Phase 2 typed decoder / `raw-bytes` promotion, the full Phase 3
  narrow-claim promotion set, the Phase 4 broad-surface cleanup, and the Phase
  5 generic-object isolation are now complete. Phase 6 now makes the public
  architecture explicit in code: `PROMOTED_RAW_JSON_SURFACES` /
  `COMPAT_ONLY_RAW_JSON_SURFACES` classify the surface inventory, and the
  broad semantic object decode helpers are explicitly named as compat-only
  helpers rather than implicitly serving promoted paths. Required-RS256 OIDC
  verification, Request Object verification, client-registration parsing, JWT
  access-token validation, federation entity-statement parsing, and federation
  trust-mark parsing now all consume surface-specific typed decoders over
  verified structural IR, while software statements, promoted
  `private_key_jwt`, and JWT bearer assertions now bind to their own dedicated
  promoted surfaces instead of sharing `generic-object`; DPoP nonce extraction
  now comes directly from the verifier result. All concrete claim-bearing
  raw-JSON surfaces are now promoted; no compat-only surface remains in the
  normal build inventory.
  The default compatibility build retains a local fallback only for
  `JsonError::ParserUnavailable`; `--features verified-claim` disables that
  fallback and fails closed.
- **Verification**: `scripts/verify/verify_fstar_ci.sh` passed (108 modules) on
  2026-02-06; `nix build .#verify-kani -L`, `nix build .#verify-dudect -L`,
  and the `auth-code` plus default-posture `dpop` load baseline refreshes via
  `nix run .#perf-load` all passed on 2026-05-15. The
  HashMap-heavy Kani ICE caveat still applies to specific reproducers.
- **Extraction**: `scripts/extraction/run_jose_lowstar.sh` succeeded on
  2026-05-15. The extraction set now includes `Jose.LowStar.Json.Types`, so
  KaRaMeL emits `json_parse_free_result{,_data}` cleanly and the previous
  Warning 4 about `json_parse_result_c` is gone. Remaining steady-state output
  is limited to generic EverParse/LowParse warnings
  (Warning 274 namespace shadowing; Warning 241/247 LowParse cache warm-up;
  Warning 337 multiple decreases; Warning 361/331/328/271 LowParse internals).
  EverParse Low* generation is still opt-in (`GENERATE_EVERPARSE_LOWSTAR=1`).
  The hosted extraction gate is `nix run .#verify-lowstar`, which re-runs the
  extraction, checks `generated/everparse` + `generated/lowstar` + `artifacts/karamel`
  for drift, and fails on wrapper ABI hygiene regressions.
- **Testing**:
  - `cargo test -p aegaeon-jose --test rfc7520_vectors`
  - `cargo test -p aegaeon-jose --test tlv_parity`
  - `cargo test -p aegaeon-jose --test rfc7520_vectors --features everparse_jose_header_entry`
  - `cargo test -p aegaeon-jose --test tlv_parity --features everparse_jose_header_entry`
  - `cargo test -p aegaeon-jose --test rfc7520_vectors --features verified-claim`
  - `cargo test -p aegaeon-jose --test tlv_parity --features verified-claim`
  - `cargo test -p aegaeon-jose --test rfc7520_vectors --features ffi_jose_header_tlv`
  - `cargo test -p aegaeon-jose --test tlv_parity --features ffi_jose_header_tlv`
  - `cargo test -p aegaeon-jose --test rfc7520_vectors --features ffi_jose_header_tlv,verified-claim`
  - `cargo test -p aegaeon-jose --test tlv_parity --features ffi_jose_header_tlv,verified-claim`
  - `AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER=verified-structural-v1 cargo test -p aegaeon-jose structural_backend_override_`
  - `nix develop .#default --command scripts/security/run_security_suite.sh --stage jose-boundaries`
  all passed on 2026-05-16.
  The dedicated Phase 1 completion checks
  - `cargo test -p aegaeon-jose --lib`
  - `nix build .#server`
  - `nix build .#verifyJose`
  all passed on 2026-05-18.
  The dedicated Phase 5 completion checks
  - `nix develop .#default --command cargo check -p aegaeon-server --lib`
  - `nix develop .#default --command cargo test -p aegaeon-server software_statement_rejects_unknown_surface_raw_json_backend_override --lib -- --nocapture`
  - `nix develop .#default --command cargo test -p aegaeon-server test_extract_nonce_from_proof_ --lib -- --nocapture`
  - `nix develop .#default --command cargo test -p aegaeon-server --test private_key_jwt_tests unknown_surface_raw_json_backend_override -- --nocapture`
  - `nix develop .#default --command cargo test -p aegaeon-server --test request_guardrails_test token_private_key_jwt_rejects_unknown_surface_raw_json_backend_override -- --nocapture`
  - `nix develop .#default --command cargo test -p aegaeon-server --test jwt_bearer_grant_http_test jwt_bearer_grant_rejects_unknown_surface_raw_json_backend_override -- --nocapture`
  all passed on 2026-05-18.
  The dedicated Phase 6 completion checks
  - `nix develop .#default --command cargo test -p aegaeon-jose raw_json::tests:: --lib`
  - `nix develop .#default --command cargo test -p aegaeon-server deserialize_compat_json_object_ --lib -- --nocapture`
  - `nix develop .#default --command cargo test -p aegaeon-server required_rs256_rejects_duplicate_claim_keys --lib -- --nocapture`
  - `nix develop .#default --command cargo check -p aegaeon-server --lib`
  all passed on 2026-05-18.

See `lowstar/lowstar-extraction-plan.md` for detailed status.

## Directory Structure

```text
initiatives/jose/
├─ phase0-foundations.md             # Phase 0 decisions (API/FFI/crypto footprint)
├─ jose-implementation-plan.md       # End-to-end programme tracker
├─ raw-json-optimal-architecture-plan.md # Long-horizon path to the greenfield-optimal raw JSON architecture
├─ parser/                           # Header-parser specific plans/specs
│   ├─ header-parser-plan.md
│   └─ header-parser-spec.md
├─ json-tlv/                         # JSON↔TLV normalisation work
│   └─ json-tlv-proof-plan.md
└─ lowstar/                          # Low*/C extraction and FFI integration
    ├─ lowstar-extraction-plan.md           # Main extraction roadmap
    └─ warning15-machine-integer.md         # Warning 15 background / design notes
```

Completed Phase 1 raw-JSON and context-migration records live under
`../../historical/initiatives/jose/`.

## Execution Order & Dependencies

1. **Parser foundation (parser/)** – Finalise the F* header specification and
   Rust integration (`parser/header-parser-plan.md` → `parser/header-parser-spec.md`).
2. **JSON/TLV parity (json-tlv/)** – Keep the JSON ↔ TLV policy contract aligned
   with the promoted `jose-header` raw-byte path and track any future
   surface-by-surface promotion work beyond the current `jose-header` landing.
3. **Optimal-architecture route** – `raw-json-optimal-architecture-plan.md`
   tracks the longer-horizon route from today's migration-friendly helper
   architecture to the greenfield-optimal surface-first design.
4. **Low*/FFI extraction (lowstar/)** – Uses the stabilised parser + TLV layout
   to expose the C ABI; requires completion of the previous two steps.
5. **Implementation tracker** – `jose-implementation-plan.md` aggregates status
   across phases and ties into the global compliance matrix.

## Recent Milestones

- **2026-04-27**: The duplicate-preserving top-level JSON object helper
  (`aegaeon_jose::raw_json`) now serves JOSE headers, Request Object raw payloads,
  and server-side DCR admission, reducing the number of Rust raw-admission
  implementations that must be replaced to close the parser boundary.
- **2026-04-27**: `aegaeon_jose::raw_json` became surface-aware
  (`jose-header` / `request-object` / `client-registration` /
  `oidc-id-token-payload` /
  `jwt-access-token-header` / `jwt-access-token-payload` /
  `federation-entity-statement` / `federation-trust-mark` / generic) and now
  reports which ingress selected the current backend. The default backend is
  still `SerdeCompat`; selection now flows through a dedicated dispatch point
  so one surface can be switched independently once a verified raw parser
  exists.
- **2026-04-27**: `aegaeon_jose::raw_json` gained a pure backend-policy parser
  for global / surface override values (`AEGAEON_RAW_JSON_BACKEND*`). It fixes
  precedence and fail-closed parsing semantics for future backend rollout, but
  it does not yet switch the active runtime parser away from `SerdeCompat`.
- **2026-05-18**: `jose-header` completed the raw JSON Phase 1 + Phase 2 route.
  `verified-structural-v1` is now the default source-managed backend for that
  surface, `current_claim_posture_for_surface(RawJsonSurface::JoseHeader)` now
  reports `raw-bytes`, the JOSE Low*/TLV paths share a typed
  `key + (string | null)` decoder derived directly from verified structural IR,
  and unsupported surfaces still reject structural-backend selection fail-closed.
- **2026-05-18**: `oidc-id-token-payload` is the
  first promoted narrow claim surface beyond `jose-header`. It now defaults to
  `verified-structural-v1`, reports `raw-bytes`, and the Required-RS256 OIDC
  verification path decodes `IdTokenClaims` directly from structural IR instead
  of `serde_json::from_value(...)`. The FFI structural fallback was widened to
  scan number / bool / array / object values so the promoted OIDC path remains
  fail-closed even when the extracted parser reports `ParserUnavailable`.
- **2026-05-18**: `jwt-access-token-header` is now the second promoted narrow
  claim surface in Phase 3. It defaults to `verified-structural-v1`, reports
  `raw-bytes`, and the access-token validator now decodes `kid` and `typ`
  directly from structural IR on the promoted path instead of reading them from
  a broad `serde_json::Value` header object.
- **2026-05-18**: `jwt-access-token-payload` is now the third promoted narrow
  claim surface in Phase 3. It defaults to `verified-structural-v1`, reports
  `raw-bytes`, and the access-token validator now decodes
  `iss` / `sub` / `aud` / `exp` / `iat` / `jti` directly from structural IR on
  the promoted path instead of reading them from a broad `serde_json::Value`
  payload object.
- **2026-05-18**: `federation-entity-statement` is now the fourth promoted
  narrow claim surface in Phase 3. It defaults to `verified-structural-v1`,
  reports `raw-bytes`, and federation entity-statement parsing now decodes
  `iss` / `sub` / `iat` / `exp` directly from structural IR while admitting
  `jwks`, `metadata`, `metadata_policy`, `constraints`, `trust_marks`,
  `authority_hints`, and `source_endpoint` only as bounded per-member JSON
  values.
- **2026-05-18**: `federation-trust-mark` is now the fifth promoted narrow
  claim surface in Phase 3. It defaults to `verified-structural-v1`, reports
  `raw-bytes`, and federation trust-mark parsing now decodes
  `iss` / `sub` / `id` / `iat` / `exp` / `ref_` directly from structural IR
  instead of routing that path through a broad `serde_json::Value` object.
- **2026-05-18**: Phase 3 is complete across `oidc-id-token-payload`,
  `jwt-access-token-header`, `jwt-access-token-payload`,
  `federation-entity-statement`, and `federation-trust-mark`.
- **2026-05-18**: `request-object` and `client-registration` completed the
  Phase 4 broad-surface cleanup route. Both surfaces now default to
  `verified-structural-v1`, report `raw-bytes`, decode their typed top-level
  fields directly from structural admission, and keep open-ended JSON (`authorization_details`,
  `jwks`) bounded as per-member values.
- **2026-05-18**: Phase 5 is complete. Software statements, promoted
  `private_key_jwt`, and JWT bearer assertions now use dedicated `raw_json`
  surfaces instead of the shared `generic-object` selector; DPoP nonce
  extraction now comes directly from the verifier result. The remaining
  raw-JSON architectural work is Phase 6 simplification and future
  surface-by-surface promotion decisions for those paths.
- **2026-05-18**: Phase 6 is complete. `raw_json` now publishes the promoted
  vs compat-only surface inventories in code, compat semantic-decode helpers
  are explicitly separated from promoted typed decoders, and the steady-state
  architecture can be described in surface-first terms without referring to a
  generic semantic decode layer for promoted paths.
- **2026-05-19**: `private-key-jwt-payload` is now the first post-Phase-6
  JWT-family payload promotion. It defaults to `verified-structural-v1`,
  reports `raw-bytes`, and keeps the claim precise to raw JSON admission plus
  registered-claim shape for the promoted RS256 `private_key_jwt` slice.
- **2026-05-19**: `jwt-bearer-assertion-payload` is now promoted to
  `verified-structural-v1` plus `raw-bytes`, with the claim limited to raw JSON
  admission and registered-claim shape for the JWT bearer grant assertion path.
- **2026-05-19**: `software-statement` is now promoted to
  `verified-structural-v1` plus `raw-bytes` under SSA Profile v1. The promoted
  claim covers raw JSON admission, registered JWT claim shape, and recognized
  DCR metadata fields decoded through the typed `ClientRegistration` parser.
  Unknown SSA extension claims are preserved outside the promoted profile
  claim, while nested `software_statement` and DCR metadata alias collisions
  fail closed. The normal public inventory is now eleven promoted surfaces;
  legacy `generic-object` compatibility is isolated to `test` builds.
- **2026-05-15**: `aegaeon_jose::raw_json` gained an explicit source-managed
  claim boundary / posture API. At that checkpoint every raw JSON surface was
  still `SerdeCompat` + `top-level-object-members`; later entries record the
  surface-by-surface raw-byte promotions.
- **2026-05-16**: raw JSON boundary tests now explicitly cover all current
  `raw_json` surfaces plus the shared server-side `generic-object` mapping and
  the real-environment backend-policy precedence path
  (`surface > global > default`), so unsupported per-surface overrides are
  recorded as fail-closed behaviour at both the base-layer and consumer
  boundaries.
- **2026-05-16**: `aegaeon_jose::raw_json` now exports
  `ALL_RAW_JSON_SURFACES` and centralizes the per-surface name / backend-env /
  default-backend / claim-boundary metadata behind one lookup table, reducing
  drift between rollout planning, tests, and the source-managed claim posture.
- **2026-04-27**: DCR now preflights the raw JSON backend policy for the
  `client-registration` surface and treats unsupported override values as
  server-side misconfiguration (HTTP 500) rather than client metadata errors.
- **2026-04-27**: JOSE header raw admission now preflights the `jose-header`
  backend policy before either the Low*/C bridge or the compatibility fallback
  runs, so unsupported backend overrides fail closed instead of silently
  dropping into the serde compatibility path.
- **2026-04-27**: Request Object raw admission now preflights the
  `request-object` backend policy and the `/authorize?request=...` path returns
  HTTP 500 / `internal_error` for unsupported backend overrides instead of
  collapsing them into `invalid_request`.
- **2026-05-15**: federation entity statements and trust mark claim payloads
  now use dedicated `raw_json` surfaces instead of the shared `generic-object`
  selector, so future backend rollout can target federation admission
  independently of the remaining generic JSON helpers.
- **2026-05-15**: JWT access-token header/payload duplicate-key admission now
  also uses dedicated `raw_json` surfaces instead of the shared
  `generic-object` selector, so backend rollout for signed bearer-token
  validation can be staged independently of unrelated generic JSON parsing.
- **2026-05-15**: OIDC required-`RS256` ID Token payload admission now also
  uses the dedicated `oidc-id-token-payload` `raw_json` surface instead of a
  local serde duplicate-key parser, so backend rollout for promoted ID Token
  verification can be staged independently of the remaining generic JSON
  helpers.
- **2026-04-27**: Upstream OIDC ID Token verification on the RS256 required
  slice now preserves JOSE header parser internal failures as HTTP 500 server
  errors instead of collapsing them into upstream signature failures.
- **2026-04-23**: Request Object verification now re-parses raw JWT payload
  bytes, preserves `authorization_details`, and rejects duplicate top-level
  claim keys before normalization.
- **2026-04-23**: Strict-profile JOSE tests passed:
  `rfc7520_vectors` and `tlv_parity` both run cleanly under
  `--features verified-claim`.
- **2026-05-15**: `verify-jose`, `verification.yml`, and the security-suite JOSE
  boundary stage now cover the opt-in `ffi_jose_header_tlv` path in both compat
  and `verified-claim` profiles, so RFC 7520 vectors and TLV parity are gated
  across all supported JOSE header parser profiles.
- **2026-05-16**: the standalone compat-only
  `everparse_jose_header_entry` lane is now also gated in `verify-jose`,
  `verification.yml`, and the security-suite TLV parity stage, so RFC 7520
  vectors and TLV parity no longer rely on `verified-claim` as the only CI
  evidence for the native EverParse entry-validator path.
- **2026-05-15**: `verify-jose` now also covers the adjacent OIDC strict-boundary
  regressions that depend on the same promoted verification slice: compat
  tolerance for `check_id_token_jwt(...)`, strict fail-closed behaviour for
  OIDC ID Token structure-parser unavailability, and OIDC hash runtime
  vector / error-mapping checks across compat fallback, strict fail-closed,
  and oversized-input handling.
- **2026-05-15**: the strict OIDC hash runtime lane now also checks Rust-digest
  equivalence across the supported `RS*` / `ES*` / `HS*` families, expected
  truncation lengths, empty-input handling, and interior-NUL algorithm
  rejection. Server-side unit coverage now also fixes the `finalize_hash_result`
  mapping for `InputTooLarge`, compat fallback on `ComputationFailed` /
  `NullDigest`, and strict fail-closed handling for `NullDigest`.
- **2026-05-15**: `generated/lowstar/oidc/id_token/` is now source-managed and
  `verify-jose` compile-checks the opt-in `ffi --features verified-claim,idtoken_runtime`
  build so the extracted OIDC layout/runtime artefacts remain reproducible even
  though they are still outside the active strict claim.
- **2026-05-15**: the strict OIDC hash lane now source-manages
  `generated/lowstar/oidc/hash/HashComputation_Low.{c,h}` and routes the
  public `HashComputation_Low_compute_oidc_hash_bytes(...)` entrypoint through
  extracted dispatch/truncation logic. The remaining hand-written shim is
  narrowed to the host SHA primitive adapter in
  `c/hash_computation_runtime.c`.
- **2026-05-15**: the OIDC hash F* model and extracted
  `HashComputation.Low` dispatcher now match the current server policy by
  rejecting `PS256` / `PS384` / `PS512` as invalid algorithms instead of
  leaving those policy-disabled cases reachable in the host hash adapter.
- **2026-05-15**: `c/hash_computation_runtime.c` now delegates SHA-256/384/512
  to `Verified_Crypto_Bridge_sha{256,384,512}_hash(...)`, so the OIDC hash
  runtime no longer carries a separate OIDC-only mbedTLS SHA adapter beside
  the proof model's existing shared HACL* bridge.
- **2026-05-15**: the OIDC additional-JWKS merge helper now keeps a
  Kani-compatible validated runtime path instead of projecting runtime signing
  keys into the bounded byte-sized `aegaeon_pure::Jwk` model, restoring the
  `verify-kani` server build after the pure Kani JWKS model tightened.
- **2026-05-15**: the `auth-code` performance smoke baseline was refreshed via
  `nix run .#perf-load` and recorded in
  `docs/performance/load-baseline-auth-code.md`. The flake perf apps now ship
  `krml`, `scripts/perf/run_load_tests.sh` preserves the JSON report plus
  legacy copy on failure, and `aegaeon-loadtest` now excludes warmup time from
  the measured main-phase duration so throughput baselines reflect the actual
  requested run window.
- **2026-05-15**: the default-posture `dpop` performance smoke baseline was
  recorded in `docs/performance/load-baseline-dpop.md`. `aegaeon-loadtest` now
  handles RFC 9449 `DPoP-Nonce` challenges by retrying the token exchange once
  with a fresh nonce-bearing proof and uses an absolute token-endpoint `htu`
  that matches server-side validation.
- **2026-05-15**: `crates/ffi/tests/jose_header_runtime_test.rs` now gives the
  JOSE header EverParse bridge direct native coverage in the verification shell
  and `verify-jose`, covering valid framing, truncation, and the current
  framing-only prefix scope of `JoseHeader.3d`.
- **2026-05-15**: `crates/jose/tests/tlv_parity.rs` now exercises the raw TLV
  parser directly when `everparse_jose_header_entry` is enabled, covering both
  accepted valid headers and preserved `Truncated` mapping on the native
  entry-validator path.
- **2026-05-15**: `scripts/extraction/run_jose_lowstar.sh` now extracts
  `Jose.LowStar.Json.Types`, emits the `json_parse_free_result*` helpers
  without KaRaMeL Warning 4, and normalizes KaRaMeL header/source whitespace so
  `verify-lowstar` can treat the generated trees as reproducible artefacts.
- **2026-04-23**: JWE protected-header parsing is aligned with the same
  `json_lowstar::parse_json_header_lowstar` pipeline used by JWS.
- **2026-04-23**: The raw JSON tokenization step no longer materializes a
  `serde_json::Value` object for headers; it preserves member order and rejects
  duplicate keys before the Low*/C bridge or compat fallback runs.
- **2026-02-06**: `scripts/verify/verify_fstar_ci.sh` passed all 108 modules
  (`result/verify.log`).
- **2026-02-06**: `scripts/extraction/run_jose_lowstar.sh` completed; Warning 4/15
  cleared and only generic KaRaMeL warnings remain (274; 241 is cache warm-up).
- **2026-02-06**: `cargo test -p aegaeon-jose` passed (TLV parity + RFC 7520 vectors).
- **2025-11-09**: Phase 3.2.4 Stack module implementation recorded.
- **2025-11-08**: Context infrastructure verification recorded (see
  `lowstar/lowstar-extraction-plan.md`; re-run recommended).
- **2025-11-05**: JSON header parsing wired through Low*/C pipeline (serde_json front-end).
- **2025-10-20**: KaRaMeL extraction integrated into CI.

## Next Steps

- Keep the legacy compat-only raw JSON surface (`generic-object`) at the
  `top-level-object-members` interface only for tests.
- Treat any remaining generic-object cleanup as test compatibility removal
  rather than as an implied widening of the released claim. DPoP nonce handling
  no longer depends on a separate raw JSON helper surface.
- Promote `verified-claim` from smoke-tested scaffolding to a release-quality
  claim-bearing profile only after the remaining post-closure evidence refresh
  is addressed. If a future increment widens the boundary beyond
  the current surface-specific posture, treat raw-byte parser promotion as a
  separate prerequisite for that stronger claim rather than as a standing
  dependency of the default roadmap. The current strict profile now uses an extracted
  `HashComputation.Low` dispatcher/truncation path, matches the current non-`PS*`
  server policy, and delegates SHA-2 primitives through the same
  `Verified.Crypto.Bridge` HACL* host bridge used
  by the proof model.
- Continue EverParse integration for header parsing as opt-in internal
  validation, without conflating it with network-facing JSON parsing.
- Keep both checked-in perf baselines (`auth-code` and default-posture `dpop`)
  refreshed when sender-constraint handling or JOSE verification paths change.

When a sub-plan is completed, move the supporting notes to
the appropriate permanent location (`docs/verification/`, `docs/policies/`,
or `docs/operations/`) and update the implementation tracker.
Avoid keeping “archive” copies; rely on Git history / CI artefacts instead.
