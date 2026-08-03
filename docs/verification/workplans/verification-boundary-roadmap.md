# Verification Boundary Roadmap (When Boundary Crossing Is Required)

Last updated: 2026-07-27

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This roadmap describes the work needed to **cross the crypto / FFI / RNG / WASM-host boundaries**
so the system can credibly claim “formally verified” with a minimized TCB.
It is intentionally high‑effort and multi‑phase.

## Implementation Connection Maturity Ladder

This ladder defines the implementation-connection claim for this roadmap. It
does not widen the released claim by itself; released wording remains governed
by `docs/verification/claims/assurance-case/claim-definition.md` and
`docs/product-positioning.md`.

| Level | Meaning | Attainment command |
|---|---|---|
| Level 1 | Current baseline: specification proofs plus `runtime_link` file references, Kani bounded checks, and limited extracted C linkage. | `python3 scripts/validation/verify_verified_reqs.py --strict` |
| Level 1.5 | Machine-auditable connection: `runtime_link` can be checked at `path#symbol` granularity, and `spec_oracle_test` is green in CI for the pilot surfaces. | `python3 scripts/validation/verify_verified_reqs.py --strict` and `cargo test -p aegaeon-server --test spec_oracle_test` |
| Level 2 | Refinement traces exist for MUST-level `VerifiedReqs`, mapping F* specification functions to Rust implementation functions for the selected feature surface. | `python3 scripts/validation/verify_verified_reqs.py --strict --require-trace-must` |
| Level 3 | Direct extracted-code linkage covers most claim-bearing decision kernels, with compatibility paths excluded from the claim boundary. | `nix build .#verify-fstar -L` and claim-bearing profile tests for the extracted runtime path |
| Level 4 | Direct extracted-code linkage covers the full claim-bearing security kernel; remaining dependencies are explicit TCB elements. | `nix build .#verify-fstar -L && nix run .#security-suite` with the Level 4 claim gate active |

Level 1.5 was the original pre-release target for this roadmap. As of
2026-07-29, **Level 2 is attained**: all 161 MUST-level `VerifiedReqs` carry a
validated refinement trace (`Refinement Trace: 161/161`, oracle=11,
structural=2, guard=109, exempt=39) and the attainment command
(`--require-trace-must`) is enforced in CI via `.#verified-reqs`. Levels 3-4
(extracted-C linkage) remain future work.

## 0. Scope and Success Criteria

**Goal:** eliminate (or radically shrink) assumptions in these boundary areas:
- Cryptographic verification (JWS/JWT/DPoP, hashes)
- FFI/C runtime stubs (LowStar JSON allocator + parser entrypoints)
- RNG (secure randomness + challenge IDs)
- WASM host imports (VerifiedCore)

**Success Criteria (boundary‑crossing):**
1. No **Category A crypto-function** assume vals remain (hash/HMAC/signature
   verification are concrete or conservative verified models); only
   cryptographic hardness lemmas remain as explicit Category A assumptions.
2. No FFI/C runtime assume vals remain; all JSON/TLV parsing code is extractable Low*/KaRaMeL.
3. RNG is either verified or removed from the formal boundary (modeled as external input).
4. WASM host callbacks are verified or replaced by embedded verified code.
   (If the server uses the **native C** output, this boundary applies only to the
   **portable WASM artifact**; the server runtime is unaffected.)
5. Compliance matrix: “verified” rows all have formal proof references.

**Impossibility note:** Even with boundary‑crossing, certain guarantees remain
assumption‑qualified in any realistic von Neumann system with I/O: computational
hardness (EUF‑CMA/collision resistance) stated as theorem premises, OS/device
entropy sources modeled as external contracts, and external host/storage
behaviour modeled as explicit interface contracts or TCB boundaries. These are
explicitly documented as assumptions and remain outside the formal claim.

## 1. Phase A — Crypto Replacement (Highest Effort)

**Objective:** replace **crypto-function assume vals** with verified, extracted implementations.

**Status (2026-03-26):** Partially complete. The modern verified allowlist is
limited to HS256/384/512 + EdDSA (HACL*/EverCrypt). The OIDC `RS256 Required
Slice` and `RS256 Interop Slice` are now closed as explicit boundary
exceptions for the server claim; remaining RSA/ECDSA surfaces stay
non-verified unless separately promoted. The promoted RS256 verifier now uses
`aws-lc-rs` rather than project-local bigint arithmetic, but RC-7 remains an
unverified runtime contract.

**Program policy update (2026-03-09):** Phase A is now split conceptually into
three layers:

- a **modern verified core** (HS*/EdDSA and future modern primitives),
- a promoted **`RS256 Required Slice`** for OIDC Core mandatory ID Token support,
- a promoted **`RS256 Interop Slice`** for OIDC `SHOULD` / interoperability
  surfaces such as signed Request Objects, `request_uri`, JWT bearer grant
  assertions, and `private_key_jwt`.

General-purpose RSA/ECDSA remains legacy / compat unless separately justified.

**Deliverables:**
- Keep the **modern verified core** on HACL*/EverCrypt-backed algorithms by default
- ✅ Promote a verified **`RS256 Required Slice`** covering OIDC Core mandatory ID Token
  issuance / validation semantics
- ✅ Promote a verified **`RS256 Interop Slice`** for signed Request Objects,
  `request_uri`, JWT bearer grant assertions, and `private_key_jwt` when they use `RS256`
- F* implementation of SHA‑256 and hash‑based construction used by SD‑JWT / OIDC hash
- Future extraction / integration of a verified RSA backend for the RS256
  slices; current Rust code uses the narrower `aws-lc-rs` verifier for those
  specific surfaces
- Constant‑time verification (dudect) integrated for extracted functions / glue

**Dependencies:** HACL*/EverCrypt pinning, KaRaMeL extraction pipeline stability

**Exit Criteria:**
- All Category A crypto _functions_ are concrete or conservative verified
  models (hash/HMAC/verify); no Category A crypto-function assume vals remain.
- Cryptographic hardness remains as explicit lemmas (collision resistance / EUF-CMA), documented.
- CI gates include dudect for extracted crypto

**Risks:** general RSA coverage remains extremely expensive; the OIDC-specific
`RS256` slices are smaller but still non-trivial.

## 2. Phase B — Remove FFI/C Runtime Assumptions

**Objective:** eliminate all LowStar JSON allocator + parser assume vals.

**Status (2026-05-16):** In progress. A non-default `verified-claim` build
profile now fail-closes JOSE header serde fallback, requires the canonical
EverParse self-checks for DCR / Request Object payloads, and routes OIDC hash
through the `lowstar_hash` runtime shim instead of the Rust fallback. DCR,
Request Object, Required-RS256 ID Token, and promoted RS256 `private_key_jwt`
claim handling now re-parse the raw top-level object and reject duplicate keys
before normalization / deserialization. The same duplicate-claim rejection is
also applied to software statements, JWT bearer assertions, JWT access tokens,
federation entity statements, and federation trust marks; the Rust-side DPoP
nonce extraction helper likewise rejects duplicate top-level keys before
selecting `nonce`. JOSE header parsing, Request Object raw payload handling,
and server-side DCR admission now share a single duplicate-preserving
top-level object helper (`aegaeon_jose::raw_json`), reducing the number of
raw-admission implementations that must be replaced to close the parser
boundary. That helper is now surface-aware (`generic-object`, `jose-header`,
`request-object`, `client-registration`, `oidc-id-token-payload`,
`jwt-access-token-header`, `jwt-access-token-payload`,
`federation-entity-statement`, `federation-trust-mark`) and records which
ingress selected the current backend. Selection already flows through a
dedicated dispatch point, but the only available backend remains
`SerdeCompat`. The released raw JSON claim boundary is now also source-managed
at that helper: every current surface maps to `top-level-object-members`,
while raw-byte admission remains outside the claim until a verified backend is
promoted. Global / surface override parsing semantics
(`AEGAEON_RAW_JSON_BACKEND*`) are now fixed in a pure policy helper, and the
base-layer env precedence path (`surface > global > default`) is covered by
targeted unit tests. Unsupported override values therefore fail closed instead
of silently dropping into the serde compatibility path. Surface-specific HTTP
consumers such as DCR / Request Object, plus the upstream OIDC RS256
required-slice verifier, already map those failures to explicit server-side
misconfiguration handling. The shared `generic-object` surface is also now
covered by targeted fail-closed tests at the helper boundary (generic error
mapping, software statement parsing, DPoP nonce extraction, promoted
`private_key_jwt`, JWT bearer assertions) and at the HTTP boundary
(`private_key_jwt` -> `invalid_client`, JWT bearer grant -> `invalid_grant`).
The helper is not yet authoritative for a verified raw-byte parser because no
such backend is available yet. CI also covers the `/authorize` JAR RS256
duplicate-claim regression in both compatibility and `verified-claim`
profiles. Raw-byte verified parsing and the extracted OIDC hash runtime are
still open.

**Deliverables:**
- Low* implementation of JSON parse pipeline (including `json_parse_entries_to_c`)
- Replace C runtime (`json_lowstar_runtime.c`) with extracted code
- Prove memory safety (buffer liveness/disjointness) within Low*

**Exit Criteria:**
- `malloc/free` and `json_parse_entries_to_c` assume vals removed
- All JSON parsing paths use extracted Low* code

**Risks:** heavy proof effort; performance regressions possible

## 3. Phase C — RNG Boundary Crossing

**Objective:** remove RNG assume vals or eliminate RNG from the formal boundary.

**Option 1 (Full verification):**
- Formalize a deterministic RNG model + extraction (rarely practical)

**Option 2 (Boundary separation):**
- Redefine interfaces so RNG output is external input (passed in by the environment)
- Remove RNG from formal claims; document as external assumption

**Exit Criteria:**
- `generate_secure_random` / `fresh_challenge_id` assume vals removed or moved outside proof

## 4. Phase D — WASM Host Boundary Crossing

**Objective:** eliminate or formally verify WASM host imports for the portable
`verified_core.wasm` artifact. If the server links the native C output directly,
Phase D is only required for **client distribution** claims.

> **Status (2026-03-08):** Phase D complete. The "raw buffer + HACL\* direct"
> approach eliminated 4 of 5 WASM host assume vals (#8–#11) by having the C
> exports layer resolve handles to raw pointers and using HACL\* functions
> (declared as `-library` modules) directly from F\*. Two HACL\* linkage assume
> vals (B') were added for `hacl_sha256` and `hacl_ed25519_verify`. Only
> `host_replay_store_check_and_store` (#12) remains as a permanent host
> boundary. Total: 11 → 9 (effective 7 excl. verified foreign code).
> See `phase-d/README.md` for details.

**Deliverables:**
- ~~Verified implementations of host callbacks (hash, signature verify, replay store)
  embedded in WASM module~~ → **HACL\* internalization** for SHA-256 and Ed25519;
  replay store remains permanent host boundary
- `VerifiedCore.Crypto.Hacl.fsti`: HACL\* Low\* interface module (`-library`, not assume val)
- Rewritten `dpop_verify_claims_impl` / `jwt_verify_claims_impl` using raw buffers
- Updated C exports layer for handle→pointer resolution

**Exit Criteria:**
- `host_bytes_len`, `host_bytes_eq`, `host_crypto_sha256`, `host_crypto_verify_signature`
  removed from F\*
- Only `host_replay_store_check_and_store` remains as assume val in
  `VerifiedCore.Api.Claims.Runtime.fst`
- `nix build .#verify-fstar` green

**Risks:** ~~extremely high cost; cross‑toolchain verification required~~ →
Medium cost. HACL\* C code already compiled into WASM binary; main risk is
Low\* buffer precondition engineering.

## 5. Phase E — End‑to‑End Assurance Closure

**Objective:** ensure protocol claims and implementation proofs line up.

**Deliverables:**
- Full proof references in compliance matrix
- Formal “spec → implementation” refinement traces for critical endpoints
- Updated assurance case and TCB statement
- Disaggregate OIDC Core roll-up entries into individually tracked discrete MUST requirements
- Prove the remaining MUST-level entries that are currently `implemented` or `partial`

**Exit Criteria:**
- “Formally verified” claim is defendable in external review

**Status (2026-03-08):** Scaffold is tracked in `docs/verification/runbooks/runtime-linkage.md`.
Full refinement traces are still pending.

## 6. Timeline Guidance (Realistic)

- Phase A + B: **multi‑quarter** (team of 2–4 formal engineers)
- Phase C: **1–4 weeks** (if boundary separation approach)
- Phase D: **multi‑quarter** (systems verification team)
- Phase E: **1–2 months** after all above

---

## Quick Decision Matrix

| Boundary | Can we cross? | Recommended path |
|---|---|---|
| Crypto | Possible but very high cost | Keep modern crypto verified by default; the OIDC `RS256` slices are now closed server-claim exceptions and the remaining broad RSA/ECDSA surface stays compat |
| FFI JSON | Possible with effort | Low* extraction + replacement |
| RNG | Practically no | Move RNG out of formal boundary |
| WASM host | Possible but huge | Consider “verified host” project |

---

## Future Work

- Migrate RS256 verification from the current `aws-lc-rs` intermediate backend
  to a verified HACL* `rsapss` path when the required integration and evidence
  are available.
- Expand the Level 2 refinement-trace pilot from PKCE / DPoP to the full
  authorization-code and token surfaces.

---

## Instruction 2 — Roadmap When Boundary Crossing Is _Not_ Required

This instruction set preserves a defensible “assumption‑qualified” verification
claim without crossing crypto/FFI/RNG/WASM boundaries.

### Objective
- Maintain a realistic verification posture while clearly delimiting the formal boundary.

### Execution Plan
1. Treat the Assumption Register as the authoritative TCB statement.
2. Ensure every `verified` row in the compliance matrix has a formal proof reference.
   - If missing, downgrade the status (`implemented`, `tested`, or `tracking`).
3. Verify all EverParse schemas that are generated and compiled.
4. Document Low*/FFI contracts and add CI checks for drift.
5. Explicitly label the system as “assumption‑qualified” in assurance documents.

### Required Skills
- Compliance matrix operations and evidence hygiene
- F*/Tamarin/EverParse reference management
- Verification documentation and assurance case writing

### Exit Criteria
- All `verified` entries in the compliance matrix have proof references
- The Assumption Register matches the formal TCB exactly
- External review cannot plausibly argue the boundary is ambiguous
