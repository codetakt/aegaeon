# OIDC-1 Formal Verification Scope & Definition of Done

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This document defines what we mean by “formal verification” for **Sprint OIDC-1**
and what constitutes “done” for the **F\*/EverParse/Tamarin/Kani/dudect** tracks.

It is intentionally explicit about **what we can claim is verified** vs **what
is defended in Rust only** (and therefore not covered by the proof chain).

## 1. What we want to be able to claim (and what we do not)

### Verified claims (OIDC-1 scope)

1. **ID Token semantics are specified and machine-checked in F\***:
    issuer/audience/azp/time/nonce/max_age invariants and their relationship to
    `openid` requests.
2. **`at_hash` / `c_hash` semantics are specified** and we have deterministic
    test vectors that confirm the truncation rules used by the runtime.
3. **Boundary framing is unambiguous**: a JWS Compact serialization used as an
    ID Token is canonicalised into a length-prefixed buffer, and EverParse
    schemas validate the structural invariants of that buffer.
4. **Session-level security properties are modelled and proven in Tamarin** for
    nonce-based replay prevention and issuer mix-up resistance (for the OIDC-1
    flows we actually support).
5. **FFI/boundary helpers are checked with Kani** for panic/overflow-safety on
    representative, bounded inputs.
6. **Constant-time posture is continuously monitored** via dudect for the CT
    primitives used by the verified crypto path.

### Non-claims (explicitly out of scope for OIDC-1)

- “We parse and validate OIDC JSON inputs with a verified JSON parser.”
  - We currently decode JSON via Rust (Serde) and apply fail-close validation.
  - EverParse is used for **length-prefixed binary schemas**, not RFC 7591/8414
    style JSON grammar.
- “General-purpose JOSE/JWS signing is verified end-to-end.”
  - OIDC-1 focuses on *claims semantics* and *structural framing*. The mandatory
    OIDC `RS256 Required Slice` is now a promoted boundary exception, but broad
    JOSE/JWS algorithm coverage and interoperability surfaces are tracked separately.

### Follow-on scope for full OIDC Core positioning

The non-claim above remains true for the **current** verified artifact.
The broader program target is now split as follows:

1. **`RS256 Required Slice`** — complete; the OIDC Core mandatory ID Token
    `RS256` issuance / validation path is promoted into the verification boundary.
2. **`RS256 Interop Slice`** — complete; signed Request Objects,
    `request_uri`, JWT bearer grant assertions, and `private_key_jwt` when they
    use `RS256` are promoted into the server-claim boundary as narrow
    interoperability exceptions.

This follow-on scope does **not** imply general-purpose RSA verification. The
intended posture remains: modern crypto lives in the default verified core;
RSA stays legacy / compat except for the OIDC-specific `RS256` slices.

## 2. Track-by-track DoD (release-blocking for OIDC-1)

### Track A — F\* (semantics)

**Goal**: The OIDC-1 ID Token rules we enforce in Rust are also represented in
F\* as contracts/lemmas.

#### DoD

- `nix build .#verify-fstar` passes and includes `fstar/oidc/IdToken.fst` (which
  includes `fstar/oidc/IdToken.Spec.fst`).
- `IdToken.Spec` contains no new `admit()` / global `assume val` beyond the
  project-wide trust assumptions recorded in `docs/verification/claims/assumptions/current-register.md`.
- Compliance matrix rows for OIDC-1 semantics are `verified` with pointers to:
  - F\* module(s) and key invariants/lemmas
  - runtime tests that exercise the same behaviours

### Track B — EverParse (structural schemas)

**Goal**: Structural invariants that must hold *before* claim semantics are
applied are captured as EverParse schemas and built reproducibly.

#### DoD

- `fstar/lowparse/IdTokenSchema.3d` is present and its generated artefacts are
  checked in under `generated/everparse/IdTokenSchema*`.
- The workspace build fails closed if the artefacts are missing (enforced by
  `crates/ffi/build.rs`).
- EverParse usage is described as **structural validation of length-prefixed
  buffers**, not a verified JSON parser.

### Track C — Tamarin (symbolic security)

**Goal**: OIDC-1 session integrity and replay/mix-up resistance are proven in
the Tamarin models that match the supported flows.

#### DoD

- `nix build .#verify-tamarin` is green.
- At minimum, the OIDC proofs under `proofs/tamarin/oidc/` are discharged and
  referenced from compliance matrix rows.

### Track D — Kani (runtime/FFI safety)

**Goal**: Critical OIDC-1 boundary helpers are proven panic/overflow-safe under
bounded symbolic inputs.

#### DoD

- `nix build .#verify-kani` is green.
- At minimum, Kani covers the **ID Token compact serialization canonicaliser**
  (segment count, base64url character guardrails, non-empty segments, bounded
  memory) and rejects malformed inputs without panics.

### Track E — dudect (constant-time monitoring)

**Goal**: The CT primitives relied upon by verified cryptographic code paths are
continuously monitored for leakage.

#### DoD

- `nix build .#verify-dudect` (or the repo’s standard dudect runner) is green.
- The current OIDC server claim relies on the project-wide dudect harnesses in
  `tests/constant_time/` for:
  - compare / constant-time equality
  - HMAC
  - Ed25519
  - RSA
  - JWE decrypt glue
- If OIDC introduces new secret-dependent compare/crypto glue, it must be added
  to that suite; otherwise we rely on the existing project-wide CT coverage.
- The promoted `RS256 Required Slice`, `RS256 Interop Slice`, and JWKS overlap
  validation do not currently add new secret-dependent primitives beyond the
  existing dudect harness set.

## 3. Evidence and cross-references

- Roadmap: `docs/program-management/historical/roadmaps/oidc-execution-plan.md`
- Boundary strategy: `docs/verification/oidc/rs256-required-slice.md`,
  `docs/verification/claims/crypto-allowlist.md`,
  `docs/verification/workplans/verification-boundary-roadmap.md`
- Compliance tracking: `spec/compliance-matrix.yaml` (`openid_core` / OIDC-1 rows)
- F\*: `fstar/oidc/IdToken.Spec.fst`, `fstar/HashComputation.Model.fst`
- EverParse: `fstar/lowparse/IdTokenSchema.3d`,
  `generated/everparse/IdTokenSchema*.{c,h,fst,fsti,checked}`
- Tamarin: `proofs/tamarin/oidc/*.spthy`
- Kani: `nix build .#verify-kani` and the harnesses referenced from the OIDC-1 rows
