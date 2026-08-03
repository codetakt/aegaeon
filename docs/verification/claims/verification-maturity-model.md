# Verification Maturity Model

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document defines a staged maturity ladder for a **stronger implementation-closure claim**
than the current released assurance case.

It answers a narrower question than
`assurance-case/claim-definition.md`:

> When is it justified to say that the server's security-critical decision kernel
> and state-transition kernel are themselves implemented as formally verified code,
> with the remaining system dependencies reduced to an explicit TCB?

This document is cumulative: each level includes the requirements of all lower levels.

## 1. Relationship to Other Documents

- `assurance-case/claim-definition.md` remains the canonical released formal claim.
- `assumptions/current-register.md` remains the canonical assumption register.
- `../workplans/verification-boundary-roadmap.md` remains the canonical roadmap for closing
  runtime boundaries.
- `../runbooks/runtime-linkage.md` remains the canonical proof-to-runtime traceability map.
- `docs/security/tcb-inventory.md` remains the canonical system TCB inventory.
- `docs/product-positioning.md` remains the canonical outward-facing wording source.

This maturity model does **not** widen the released claim by itself.
Promotion to a higher level requires fresh implementation evidence, CI evidence,
and consistent updates to the documents above.

## 2. Scope

This model applies to the server-side security kernel only.

The target end-state is the following stronger statement:

> The JOSE / PKCE / DPoP / DCR / OIDC security-critical decision kernel, and the
> authorization code / refresh rotation / PAR / replay prevention state-transition
> kernel, are implemented as formally verified code. DB, OS entropy, HTTP fetch,
> KMS, and external stores are explicit TCB elements.

This model does **not** attempt to cover:

- the full HTTP framework
- the full database engine
- the operating system
- deployment and supply-chain integrity
- arbitrary compat-only runtime surfaces

## 3. Terms

### 3.1 Decision Kernel

Code that consumes untrusted protocol input and returns a security-relevant decision,
normalized representation, or rejection result.

Examples:

- JOSE protected-header parsing and validation
- PKCE challenge verification
- DPoP proof verification
- DCR policy validation
- OIDC hash / structure checks

### 3.2 State-Transition Kernel

Code that enforces security-critical protocol state changes and single-use / replay /
rotation / binding invariants.

Examples:

- authorization-code issuance and single-use consumption
- refresh-token rotation and reuse handling
- PAR request storage and single-use consumption
- replay-store check-and-store semantics

### 3.3 Claim-Bearing Path

The runtime implementation path used by the released build for an in-scope feature.
If a fallback path exists and can be used in the released configuration for the same
feature, the fallback is part of the claim-bearing path.

### 3.4 Explicit TCB

A component that is intentionally outside the formal claim, but is named,
bounded, and assigned an interface contract.

Examples:

- DB engine and transaction semantics
- OS entropy source
- HTTP client and network stack
- KMS
- external replay / cache / storage backends

## 4. Evidence Rules

Level assignment must use fresh evidence from:

- implementation code
- current build / verification outputs
- `spec/compliance-matrix.yaml`
- `../runbooks/runtime-linkage.md`
- `docs/security/tcb-inventory.md`

Documentation by itself is not sufficient.

If a feature is gated by a flag, a level may only count that feature when:

1. the claim explicitly names the flag condition, or
2. the released configuration enables the feature and CI exercises that configuration.

## 5. Levels

| Level | Name | Meaning |
|---|---|---|
| 0 | Proof-backed subsystems | Formal proofs exist for important specs or components, but the implementation-closure claim is not yet defendable. |
| 1 | Linked decision kernels | Some verified decision kernels are linked into runtime paths, but optional / fallback / non-verified paths still share the same claim-bearing surface. |
| 2 | Fail-closed decision kernels | All in-scope decision kernels use verified or extracted implementations in the claim-bearing path, or fail closed when unavailable. |
| 3 | Verified state-transition kernels | The in-scope protocol state machines are implemented in verified kernels or have an explicit refinement trace from the authoritative Rust implementation to the verified spec. |
| 4 | Security-kernel closure | The stronger implementation-closure claim is defendable: decision kernels and state-transition kernels are formally verified implementations, and all remaining dependencies are explicit TCB elements. |

## 6. Level Definitions

### Level 0 — Proof-Backed Subsystems

Characteristics:

- Formal models and proofs exist for important protocol requirements.
- The compliance matrix contains verified rows with proof references.
- The runtime may still rely on Rust-only implementations, compatibility code,
  optional verified paths, or parser fallbacks.

Required evidence:

- fresh formal-verification outputs for the claimed subsystems
- `status: verified` rows with proof references in the compliance matrix

Allowed wording:

- "contains formally verified components"
- "assumption-qualified formally verified requirements exist for documented subsystems"

Not yet allowed:

- "the security-critical runtime kernel is implemented as formally verified code"

### Level 1 — Linked Decision Kernels

Characteristics:

- Some decision kernels are actually wired into runtime code paths.
- `runtime_link` evidence exists for those kernels.
- Non-verified fallbacks, optional parsers, or compatibility implementations still
  remain in the same released feature surface.

Required evidence:

- Level 0 evidence
- runtime linkage from proof-bearing modules to concrete Rust entrypoints
- code review showing which verified kernels are live in released builds

Allowed wording:

- "selected runtime decision kernels are backed by formally verified implementations"

Not yet allowed:

- "all in-scope decision kernels are fail-closed verified paths"

### Level 2 — Fail-Closed Decision Kernels

Characteristics:

- Every in-scope decision kernel in the claim-bearing path uses a verified or
  extracted implementation.
- Unavailability of the verified path causes build failure or explicit runtime
  fail-closed behaviour for that claim-bearing feature.
- Compatibility paths may still exist, but they are outside the claim-bearing path.

Required evidence:

- Level 1 evidence
- no claim-bearing parser / verifier fallback to non-verified logic
- CI / build rules that reject missing extracted or verified artefacts for the
  in-scope feature set
- feature / profile configuration that makes the claim-bearing path explicit

Promotion tests:

- prove that `ParserUnavailable`-style paths are unreachable or fail closed for
  the in-scope released configuration
- verify that raw-input handling for in-scope JOSE / DCR / Request Object / ID Token
  surfaces is either verified end-to-end or explicitly outside the claim

Allowed wording:

- "the in-scope security-critical decision kernel is fail-closed on verified implementations"

Not yet allowed:

- "the protocol state machines themselves are implemented as formally verified code"

### Level 3 — Verified State-Transition Kernels

Characteristics:

- The authoritative implementation of the in-scope protocol state machines lives
  in verified kernels, or there is an explicit refinement trace from the Rust
  implementation to the verified model.
- Single-use, replay, rotation, revocation, and binding invariants are enforced by
  the verified implementation boundary rather than only by unverified Rust stateful code.

Required evidence:

- Level 2 evidence
- verified or refinement-backed implementations for:
  - authorization-code issuance / consumption
  - refresh-token rotation / reuse handling
  - PAR store / single-use consumption
  - replay-store check-and-store semantics
- explicit host / storage contracts where state is externalized

Promotion tests:

- refinement traces or equivalent evidence from spec modules to the authoritative
  runtime implementation
- concurrency / atomicity contract review for external replay and persistence backends

Allowed wording:

- "the in-scope authorization and replay-critical state-transition kernels are formally verified implementations or have explicit refinement closure"

Not yet allowed:

- the full Level 4 security-kernel closure statement

### Level 4 — Security-Kernel Closure

Characteristics:

- The server's in-scope decision kernels and state-transition kernels are formally
  verified implementations in the released configuration.
- Remaining non-verified dependencies are explicit TCB elements with named contracts.
- The released claim, compliance matrix, runtime linkage, and product wording are aligned.

Required evidence:

- Level 3 evidence
- explicit TCB inventory for DB, OS entropy, HTTP fetch, KMS, and external stores
- no hidden compatibility or fallback path inside the Level 4 claim-bearing surface
- current released wording updated to match the closed boundary

Permitted stronger wording:

> The JOSE / PKCE / DPoP / DCR / OIDC security-critical decision kernel, and the
> authorization code / refresh rotation / PAR / replay prevention state-transition
> kernel, are implemented as formally verified code. DB, OS entropy, HTTP fetch,
> KMS, and external stores are explicit TCB elements.

Level 4 still does **not** imply:

- proof of computational hardness
- proof of OS / DB / network semantics
- proof of arbitrary compat-only runtime surfaces
- proof of the full web application stack

## 7. Promotion Checklist

Promotion to the next level requires all of the following:

1. Fresh verification evidence for the target scope.
2. Code review showing the claim-bearing runtime path.
3. Compliance-matrix updates for the promoted scope.
4. Runtime-linkage updates for the promoted scope.
5. TCB inventory updates if any non-verified dependency remains in the path.
6. Product-wording review so public claims do not outrun the evidence.

## 8. Current Use

Use this document when:

- deciding whether stronger wording is justified
- planning boundary-closure work
- reviewing whether a verified subsystem has become the authoritative runtime path

Do not use this document by itself to claim a higher verification posture.
It is a staging model, not self-executing evidence.
