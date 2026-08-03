# Verification blockers and upstream dependency analysis

Last updated: 2026-07-07

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document cross-checks the current "blocker" narrative against the actual
codebase. It clarifies which items are truly upstream dependencies versus local
runtime/FFI obligations or design choices.

## Summary

- **C.Loops**: not an upstream blocker. A local stub is generated and no module
  in this repo depends on the upstream KaRaMeL API at runtime.
- **HACL*/EverCrypt integration**: only partial. Current runtime uses aws-lc-rs
  and mbedTLS; this is a design gap, not a hard upstream blocker.
- **LowStar FFI bridge**: depends on KaRaMeL ABI and local C runtime correctness.
  The blocker is internal maintenance, not an upstream availability issue.

## Cross-check detail

### C.Loops (KaRaMeL OCaml primitives)

**Claim**: "C.Loops is an upstream KaRaMeL dependency."

**Observed**:
- `scripts/flake/verify_fstar.sh` generates `fstar/C.Loops.fst` on the fly with
  `assume val` stubs for `while`, `do_while`, and `total_while`.
- The only reference to `C.Loops` is the generated file itself; no F* modules in
  this repo import or use it.

**Conclusion**:
- This is **not** a hard upstream blocker. It is a **local stub** maintained in
  our verification script. If we want parity with KaRaMeL, we can update the stub,
  but verification does not currently depend on KaRaMeL's OCaml primitives.

### HACL/EverCrypt integration ("14 primitives")

**Claim**: "HACL/EverCrypt integration (14 primitives) is blocked upstream."

**Observed**:
- The repository only integrates HACL* via `HACL_Wrapper.fst` for:
  - HMAC (SHA-256/384/512)
  - ChaCha20-Poly1305
- Runtime crypto is primarily implemented via **aws-lc-rs** and **mbedTLS**:
  - `crates/jose/src/jws.rs`, `crates/jose/src/jwe.rs` use aws-lc-rs.
  - `crates/jose/src/algorithms/rsa_pss.rs` uses aws-lc-rs.
  - `c/rsa_signatures.c` uses mbedTLS for RSA-PSS verification.

**Conclusion**:
- The "14 primitives" statement is **not evidenced** by the repo.
- This is a **design gap** (using aws-lc-rs/mbedTLS instead of EverCrypt), not a
  strict upstream blocker. A migration plan would need an explicit, agreed list
  of primitives and a decision on whether RSA-PSS is expected to come from
  EverCrypt or remain in the system crypto.

### LowStar FFI bridge (malloc/free, runtime contracts)

**Claim**: "LowStar FFI bridge is blocked on KaRaMeL."

**Observed**:
- F* modules assume C runtime functions such as `malloc_bytes`/`free_bytes`
  (`fstar/jose/Jose.BytesBlock.fst`, `fstar/jose/LowStar/Json/Jose.LowStar.Json.Stack.fst`).
- The runtime implementation lives in `c/json_lowstar_runtime.c` and relies on
  KaRaMeL-generated headers and ABI stability.

**Conclusion**:
- The dependency is **real**, but it is **internal**: maintaining the C runtime
  and tracking KaRaMeL ABI drift. This is not a "waiting on upstream" blocker;
  it is a local maintenance/verification obligation.

## Revised blocker classification

### Upstream (true blockers)
None observed in the current repo state for these three items. The only
documented upstream noise is EverParse/LowParse warning churn (tracked in
`docs/verification/README.md`).

### Local stubs / maintenance
- `C.Loops` stub in `scripts/flake/verify_fstar.sh` (verification-only).
- LowStar C runtime (`c/json_lowstar_runtime.c`) and its ABI coupling to KaRaMeL.

### Design gaps (explicit decisions needed)
- Crypto primitives backed by aws-lc-rs / mbedTLS vs EverCrypt/HACL*.
- If migrating, define the exact primitive list and the runtime binding strategy
  (EverCrypt, HACL*, or system crypto).

## Follow-up actions (recommended)

1. **Document the target crypto primitive list** and decide which are expected
   to be EverCrypt-backed versus system crypto. Capture this in
   `docs/verification/runbooks/hacl-integration.md`.
2. **Pin KaRaMeL ABI assumptions** in a small compatibility note (header
   expectations) and add a smoke test that exercises the LowStar runtime bridge.
3. **Track C.Loops stub ownership** in the verification runbook to avoid drift.
