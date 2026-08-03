# Formal Verification Evidence Confidence Summary

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split formal verification assurance case.

## 5. Verification Confidence Summary

| Layer | Tool | Confidence | Key caveat |
|---|---|---|---|
| Protocol design | Tamarin (247 lemmas) | **High** | Symbolic model — real crypto may have implementation flaws |
| Specification logic | F\* (155 unique modules, 0 admit) | **High** | 12 assume vals: 6 crypto + 2 HACL\* linkage + 1 EverParse linkage + 2 OIDC hash runtime linkage + 1 WASM host (see [Assumption Register](../assumptions/current-register.md)) |
| Rust memory safety | Kani (139 harnesses) | **Medium** | Bounded inputs only; HashMap paths excluded due to CBMC limits |
| Binary parsing | EverParse (7/7 verified) | **High** | Defense-in-depth layer only; Dpop verified as DpopSchema (renamed copy) |
| Promoted OIDC `RS256 Required Slice` and `RS256 Interop Slice` | F* + EverParse + Tamarin + Kani + runtime tests | **Included by exception** | Narrow OIDC ID Token, signed Request Object / `request_uri`, JWT bearer, and `private_key_jwt` `RS256` surfaces only; not a general RSA reclassification |
| Runtime compat crypto | aws-lc-rs / ring / pure-Rust compat crypto | **External** | Remaining compat crypto surfaces stay outside the current strong-constraint claim |
| Infrastructure | axum, PostgreSQL, OS | **Assumed** | Industry-standard, no formal verification |
| Assumption boundary | 12 assume vals (see [Register](../assumptions/current-register.md)) | **Documented** | 6 crypto (A), 2 HACL\* linkage (B'), 1 EverParse linkage (B''), 2 OIDC hash runtime linkage (B'''), 1 WASM host (C). Categories B (FFI) and E (encoding) fully eliminated. |

**Bottom line:** Aegaeon's verification establishes high confidence that the
OAuth/OIDC *protocol logic* and *specification-level algorithms* are correct and
secure. The verification does NOT cover broad runtime cryptographic
implementations, network handling, database operations, or third-party
dependencies. The explicit exceptions are the OIDC `RS256 Required Slice` and
server-side `RS256 Interop Slice`, which are promoted into the claim as narrow
boundary-closure items rather than as a general RSA reclassification. The 12
`assume val` declarations form the
explicit, auditable trust boundary between verified specifications and
unverified runtime components: 6 are honest cryptographic hardness assumptions
on HACL\* specs, 2 are HACL\* linkage assumptions, 1 is an EverParse linkage
assumption, 2 are OIDC hash runtime linkage assumptions, and 1 is a WASM host
import contract. See [Assumption Register](../assumptions/current-register.md) for the complete
list.
