# Verification Maturity Current Level

Last updated: 2026-07-08

Status: snapshot

Owner: Verification

Audience: verification reviewers, maintainers

> **Status note (2026-07-08):** Snapshot of the current verification maturity assessment; rerun the evidence checks before using it for a new release review.

This document is part of the split verification maturity-status snapshot.

## 2. Current Assessed Level

**Assessed level: Level 1 — Linked decision kernels**

**Not yet achieved:** Level 2, Level 3, or Level 4.

## 3. Why Level 0 Is Satisfied

Level 0 requires proof-backed subsystems without claiming full implementation
closure.

That bar is satisfied because:

- the compliance matrix contains many `status: verified` rows with formal proof
  references and `runtime_link` mappings
- `validate_compliance_matrix.py` passed on 2026-04-23
- `verify-jose` passed on 2026-04-23
- the repository contains active F*/Low*/EverParse/Tamarin/Kani artefacts for
  JOSE, PKCE, DPoP, DCR, OIDC, PAR, revocation, introspection, bearer policy,
  and related server requirements

## 4. Why Level 1 Is Satisfied

Level 1 requires that at least some verified decision kernels are genuinely
linked into runtime paths, even if non-verified fallbacks still remain.

Fresh code evidence shows this is true:

- **DPoP verification is wired into a live runtime decision path.**
  - `crates/server/src/middleware/dpop.rs` uses `ffi::verify_dpop` in the
    non-test build and treats replay-store backend failure as fail-closed.
- **DCR policy validation is wired into a live runtime decision path.**
  - `crates/server/src/dcr.rs` calls `ffi::dcr::validate_metadata(...)`.
  - `crates/ffi/src/dcr.rs` routes the production path to
    `Jose_Dcr_validate_dcr_metadata_c(...)`.
- **JOSE header validation attempts the Low* path in runtime code.**
  - `crates/jose/src/jws.rs` and `crates/jose/src/jwe.rs` call
    `crate::json_lowstar::parse_json_header_lowstar(...)` before any local
    fallback.
- **OIDC ID Token structure precheck is wired into the promoted RS256 slice.**
  - `crates/server/src/oidc/required_rs256.rs` calls
    `ffi::id_token::check_id_token_jwt(...)` before signature verification.
  - In `--features verified-claim`, `ParserUnavailable` becomes an explicit
    fail-closed internal error instead of a best-effort skip.
- **OIDC hash computation attempts the Low* helper in runtime code.**
  - `crates/server/src/oidc/id_token.rs` first calls
    `ffi::id_token::compute_oidc_hash_bytes(...)`.

This is enough for Level 1 because the verified decision kernels are not merely
documented; some of them are actually invoked by released runtime code.
