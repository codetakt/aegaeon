# Verification Maturity Fresh Evidence

Last updated: 2026-07-08

Status: snapshot

Owner: Verification

Audience: verification reviewers, maintainers

> **Status note (2026-07-08):** Snapshot of the current verification maturity assessment; rerun the evidence checks before using it for a new release review.

This document is part of the split verification maturity-status snapshot.

## 1. Fresh Evidence Used For This Assessment

- `nix build .#verify-jose -L`
  - passed on 2026-05-16
  - covers JOSE conformance, RFC 7520 / TLV parity across the default,
    `everparse_jose_header_entry`, `ffi_jose_header_tlv`, and
    `verified-claim` profiles, plus the OIDC compat `id_token`
    structure-precheck tolerance and strict structure-parser/hash fail-closed
    regressions, Rust-digest equivalence and truncation checks for the strict
    OIDC hash runtime lane, and a compile-only smoke build for
    `ffi --features verified-claim,idtoken_runtime`
- `nix develop .#default --command scripts/security/run_security_suite.sh --stage jose-boundaries`
  - passed on 2026-05-16
  - covers TLV parity artifact collection across the default,
    `everparse_jose_header_entry`, `ffi_jose_header_tlv`, and
    `verified-claim` JOSE profiles, plus the optional `context_boundary` lane
- `nix develop .#ci --command cargo test -p aegaeon-jose --lib`
  - passed on 2026-05-16
  - covers the current `raw_json` posture / backend tables across all current
    surfaces plus the broader JOSE unit-test baseline
- `nix develop .#default --command cargo test -p aegaeon-jose raw_json::tests:: --lib`
  - passed on 2026-05-18
  - covers the source-managed promoted-vs-compat surface inventories and the
    raw JSON posture table after the Phase 6 API simplification
- `nix develop .#default --command cargo test -p aegaeon-server deserialize_compat_json_object_ --lib -- --nocapture`
  - passed on 2026-05-18
  - covers the explicitly compat-only server-side semantic decode helpers for
    trailing bytes, invalid shape, duplicate keys, and backend-policy
    fail-closed handling
- `nix develop .#ci --command cargo test -p aegaeon-jose backend_policy_ --lib`
  - passed on 2026-05-16
  - covers real-environment raw JSON backend-policy precedence
    (`surface > global > default`) and fail-closed handling for invalid
    per-surface overrides
- `nix develop .#default --command cargo check -p aegaeon-server --lib`
  - passed on 2026-05-18
  - covers the Phase 5 surface split and the Phase 6 API simplification
    compiling cleanly in the supported dev shell
- `nix develop .#default --command cargo test -p aegaeon-server software_statement_rejects_unknown_surface_raw_json_backend_override --lib -- --nocapture`
  - passed on 2026-05-18
  - covers fail-closed backend-policy handling for the dedicated
    `software-statement` surface
- `nix develop .#default --command cargo test -p aegaeon-server test_extract_nonce_from_proof_ --lib -- --nocapture`
  - passed on 2026-05-18
  - covers duplicate-key rejection for the DPoP proof nonce extraction path,
    which no longer depends on a separate raw JSON helper surface
- `nix develop .#default --command cargo test -p aegaeon-server --test private_key_jwt_tests unknown_surface_raw_json_backend_override -- --nocapture`
  - passed on 2026-05-18
  - covers fail-closed backend-policy handling for the dedicated
    `private-key-jwt-payload` and `jwt-bearer-assertion-payload` surfaces
- `nix develop .#default --command cargo test -p aegaeon-server --test request_guardrails_test token_private_key_jwt_rejects_unknown_surface_raw_json_backend_override -- --nocapture`
  - passed on 2026-05-18
  - covers route-level fail-closed handling for dedicated
    `private-key-jwt-payload` misconfiguration on the `invalid_client` path
- `nix develop .#default --command cargo test -p aegaeon-server --test jwt_bearer_grant_http_test jwt_bearer_grant_rejects_unknown_surface_raw_json_backend_override -- --nocapture`
  - passed on 2026-05-18
  - covers route-level fail-closed handling for dedicated
    `jwt-bearer-assertion-payload` misconfiguration on the `invalid_grant`
    path
- `nix develop .#default --command cargo test -p aegaeon-jose raw_json::tests:: --lib -- --nocapture`
  - passed on 2026-05-19
  - covers the final raw JSON inventory of eleven promoted surfaces and one
    compat-only surface, including direct structural parsing for
    `software-statement`
- `nix develop .#default --command cargo test -p aegaeon-server software_statement_ --lib -- --nocapture`
  - passed on 2026-05-19
  - covers SSA Profile v1 admission for `software-statement`, including
    structural backend selection, typed DCR metadata parsing, alias-collision
    rejection, malformed `redirect_uris` rejection, nested
    `software_statement` rejection, and extension preservation
- `nix develop .#default --command cargo test -p aegaeon-server --test dcr_management_test software_statement -- --nocapture`
  - passed on 2026-05-19
  - covers route-level fail-closed SSA verification on DCR create and update
- `nix develop .#default --command cargo test -p aegaeon-server required_rs256_rejects_duplicate_claim_keys --lib -- --nocapture`
  - passed on 2026-05-18
  - covers the OIDC Required-RS256 promoted path after the Phase 6 compat-helper
    API separation
- `nix develop .#default --command cargo check -p aegaeon-jose -p aegaeon-server`
  - passed on 2026-04-27
- `nix develop .#default --command cargo test -p aegaeon-server --lib parse_client_registration_rejects_duplicate_keys -- --nocapture`
  - passed on 2026-04-27
- `nix develop .#default --command cargo test -p aegaeon-server --test dcr_management_test dcr_post_rejects_duplicate_top_level_keys -- --nocapture`
  - passed on 2026-04-27
- `nix develop .#default --command cargo test -p aegaeon-server --lib duplicate --features verified-claim -- --nocapture`
  - passed on 2026-04-27
- `python3 scripts/validation/validate_compliance_matrix.py`
  - passed on 2026-04-23
- `nix build .#verify-jose -L`
  - passed on 2026-04-23 (`pass rate: 100.00% (20/20)`)
- `cargo test -p aegaeon-jose --lib verified_claim_profile_rejects_parser_unavailable --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --lib verified_claim_profile_rejects_jwe_parser_unavailable --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --test rfc7520_vectors --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --test tlv_parity --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --lib verified_claim_profile_rejects_unavailable_everparse_entry_validator --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p ffi --test oidc_hash_runtime_test --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib verified_claim_profile_rejects_unavailable_id_token_structure_parser --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test oidc_hash_vectors --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib verified_claim_profile_rejects_unavailable_hash_runtime --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib verified_claim_profile_rejects_failed_hash_runtime --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib verified_claim_profile_requires_dcr_self_check_without_env_gate --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib verified_claim_profile_requires_request_object_self_check_without_env_gate --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib compat_profile_allows_dcr_self_check_bypass_when_disabled`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib compat_profile_allows_request_object_self_check_bypass_when_disabled`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --lib request_object_raw_parser_preserves_authorization_details`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --lib request_object_verification_rejects_duplicate_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --lib request_object_verification_rejects_duplicate_claim_keys --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --lib request_object_rs256_promoted_rejects_duplicate_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-jose --lib request_object_rs256_promoted_rejects_duplicate_claim_keys --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib parse_client_registration_rejects_duplicate_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib required_rs256_rejects_duplicate_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib raw_id_token_payload_parser_rejects_duplicate_claim_keys --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib software_statement_rejects_duplicate_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib software_statement_rejects_duplicate_claim_keys --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib test_jwt_access_token_validator_rejects_duplicate_payload_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib test_jwt_access_token_validator_rejects_duplicate_header_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib parse_entity_statement_payload_rejects_duplicate_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib parse_trust_mark_claims_payload_rejects_duplicate_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib test_extract_nonce_from_proof_rejects_duplicate_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --lib duplicate --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test private_key_jwt_tests private_key_jwt_duplicate_claim_keys_are_rejected`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test private_key_jwt_tests private_key_jwt_duplicate_claim_keys_are_rejected --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test jwt_bearer_grant_http_test jwt_bearer_grant_rejects_duplicate_claim_keys`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test jwt_bearer_grant_http_test jwt_bearer_grant_rejects_duplicate_claim_keys --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test jar_par_binding_test jar_request_parameter_rejects_duplicate_claim_keys_rs256`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test jar_par_binding_test jar_request_parameter_rejects_duplicate_claim_keys_rs256 --features verified-claim`
  - passed on 2026-04-23
- `cargo test -p aegaeon-server --test dcr_management_test dcr_post_rejects_duplicate_top_level_keys`
  - passed on 2026-04-23
- Code review of current runtime and verification linkage:
  - `crates/server/src/middleware/dpop.rs`
  - `crates/server/src/dcr.rs`
  - `crates/jose/src/json_lowstar.rs`
  - `crates/jose/src/jws.rs`
  - `crates/jose/src/jwe.rs`
- `crates/server/src/oidc/id_token.rs`
- `crates/server/src/oidc/required_rs256.rs`
- `crates/server/src/client_registry.rs`
- `crates/server/src/util.rs`
- `crates/server/src/authcode/store.rs`
- `crates/server/src/federation.rs`
  - `crates/server/src/authcode/token.rs`
  - `crates/server/src/par.rs`
  - `crates/server/src/middleware/replay_store.rs`
  - `crates/jose/src/request_object.rs`
  - `crates/ffi/src/dcr.rs`
  - `crates/ffi/src/dcr_parser.rs`
  - `crates/ffi/src/request_object_parser.rs`
  - `crates/ffi/src/id_token.rs`
  - `crates/ffi/src/lib.rs`
  - `crates/ffi/Cargo.toml`
  - `crates/jose/Cargo.toml`
  - `fstar/crypto/Verified.Crypto.Bridge.fst`
  - `fstar/verifiedcore/api/VerifiedCore.Crypto.Hacl.fst`
  - `fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst`
  - `fstar/jose/Jose.Jws.Verify.fst`
  - `fstar/HashComputation.fst`
  - `fstar/jose/Jose.SdJwt.fst`
