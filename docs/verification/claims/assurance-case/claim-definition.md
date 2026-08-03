# Formal Verification Claim Definition

Last updated: 2026-07-24

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split formal verification assurance case.

## Evidence Freshness Baseline

- Released wording in `docs/product-positioning.md` is supported only when the
  claim-supporting verification and security lanes are fresh.
- The current fixed baseline was re-established on **2026-03-10** by a fresh
  rerun of:
  - `nix build .#verify-fstar -L`
  - `nix build .#verify-jose -L`
  - `nix build .#verify-dudect -L`
  - `nix build .#verify-tamarin -L`
  - `nix build .#verify-kani -L`
  - `nix run .#security-suite`
  - `python3 scripts/validation/validate_compliance_matrix.py`
- This freshness rule re-confirms the current claim boundary; it does not
  promote additional compat surfaces into scope.

### Matrix Sufficiency Note

- `spec/compliance-matrix.yaml` is the **authoritative evidence register** for
  the released server claim.
- For the current server-side wording, the matrix is **sufficient when read
  together with** this assurance case,
  `docs/verification/claims/assumptions/current-register.md`, and the freshness
  gates above.
- The key reason is structural: the released claim is intentionally limited to
  requirements whose matrix rows are `status: verified` and which carry formal
  proof references. In that sense, the matrix is not a marketing summary; it is
  the normative map from released wording to proof-bearing requirements.
- The matrix is **not sufficient by itself** for broader claims outside the
  released server boundary. In particular, client / RP release gating,
  publication-org rollout, and admin-console boundary evidence remain tracked by
  their own source-managed policies and reports.

---

## 0. Formal Claim Definition (Official)

This section defines the **exact, assumption‑qualified claim** that Aegaeon can
make, with mathematical precision and explicit scope.

### 0.1 System Definition

Let **S** be the Aegaeon server built from this repository using the pinned
toolchain in `flake.lock`, via `nix build .#server`, and executed under the
documented runtime configuration in `docs/configurations/environment/README.md`.

### 0.2 Claim Scope

The formal claim applies **only** to protocol requirements tracked in
`spec/compliance-matrix.yaml` whose `status: verified` and which have a
corresponding **formal proof reference**.

Define the verified requirement set:

```text
VerifiedReqs = { r ∈ compliance-matrix
               | r.status = verified
               ∧ ∃ p ∈ r.proof : p.type ∈ {fstar, tamarin, kani, everparse, lowstar, hacl} }
```

The six proof types correspond to four verification frameworks (F\*, Tamarin, Kani, EverParse; with `lowstar` and `hacl` as sub-types of F\*):

| Proof type | Framework | Evidence |
|---|---|---|
| `fstar` | F\* type system | `file` points to a verified `.fst`/`.fsti` module |
| `lowstar` | F\* + KaRaMeL extraction (Low\*) | `file` points to a verified Low\* module or extracted C code |
| `hacl` | HACL\* (F\*-verified crypto library) | `file` points to the Aegaeon integration module |
| `tamarin` | Tamarin Prover (symbolic Dolev-Yao) | `file` points to a verified `.spthy` model |
| `kani` | Kani (bounded model checking for Rust) | `file` points to a Kani harness Rust file |
| `everparse` | EverParse (parser verification) | `file` points to a `.3d` schema or generated validator |

A "formal reference" is a `proof[]` entry whose `type` is one of the above and
whose `file` or evidence field identifies the corresponding verified artifact.

> **Note:** `dudect` (constant-time testing) is classified as *empirical*
> evidence, not a formal proof. It does not qualify an entry for
> `status: verified` on its own. See
> [§1.6](verification-scope.md#16-proof-quality-classification).

Anything not marked `verified` (for example `implemented`, `partial`,
`planned`, `in_progress`, `blocked`, or `not_applicable`) is **outside the
formal claim**.

For `aegaeon_jose::raw_json`, the current released claim boundary is
surface-specific. Promoted surfaces begin at raw JSON bytes through the
source-managed `verified-structural-v1` backend and typed per-surface decoders;
the residual `generic-object` surface remains at the duplicate-preserving
top-level object-member interface via `SerdeCompat`. See
`docs/verification/jose/raw-json-boundary.md`.

**Formal boundary note:** In realistic von Neumann systems with I/O, the
following cannot be proven inside the project’s formal system and are treated
as explicit assumptions outside the formal claim: (1) computational hardness
(EUF‑CMA, collision resistance) stated as theorem premises, (2) OS/device
entropy sources modeled as external contracts (e.g., min‑entropy), and (3)
external host/storage behaviour modeled as explicit interface contracts or
TCB boundaries.

### 0.3 Claim Statement (Assumption‑Qualified)

For every requirement **r** in `VerifiedReqs`:

1. **F\***: If r is proven in F\*, then r holds in the F\* logic for the
   corresponding specification module under the stated preconditions.
2. **Tamarin**: If r is proven in Tamarin, then r holds in the symbolic
   Dolev‑Yao model (perfect cryptography, adversarial network).
3. **Kani**: If r is proven by Kani, then r holds for all executions within the
   bounded input domain of the harness.
4. **EverParse**: If r is tied to an EverParse schema, then r holds for the
   generated parser with respect to the `.3d` grammar.
5. **Low\*/HACL\***: If r is proven via Low\* or HACL\*, then r holds in the F\*
   logic and the verification extends to the extracted C implementation (for
   code that is actually linked into the build).
6. **dudect**: If r is checked by dudect, then r passes constant-time testing
   under the documented test parameters. This is an empirical check, not a
   mathematical proof.

These claims are **qualified by the Assumption Register**
(`docs/verification/claims/assumptions/current-register.md`), by the
[Runtime Contract Register](../assumptions/runtime-contract-register.md)
(RC-1 through RC-7), and by the explicit trust boundary listed in §4. The 12 `assume val` declarations in hand-written F\* specification modules
(`fstar/`) are the only unproved axioms: 6 cryptographic hardness boundaries,
2 HACL\* linkage assumptions (verified foreign code), 1 EverParse linkage
assumption, 2 OIDC hash runtime linkage assumptions, and 1 WASM host import.
Test modules (`tests/fstar/`) and generated modules (`generated/`)
are excluded from the assume val count. Generated modules that are referenced by
`VerifiedReqs` entries (e.g., EverParse-generated validators under
`generated/everparse/`) remain within the formal claim.

**Strong-constraint policy:** cryptographic hardness is modeled as honest
theorem premises. Remaining crypto-hardness `assume val` entries are lemmas
only. Function-shaped assumptions are documented linkage contracts to verified
foreign code, generated validators, local C runtime shims, or host boundaries;
they are not claims that the project proves third-party or host behaviour from
first principles.

### 0.4 Configuration Conditions

The claim is conditioned on the following:

- **Runtime policy fields**: Requirements gated by environment policy are only
  in scope when the corresponding active PostgreSQL policy field is enabled:
  - `policy.oidcEnabled` — OIDC Core, Discovery, Logout, Form Post, JAR
  - `policy.jwtAccessTokensEnabled` — RFC 9068 JWT Access Tokens
  - `policy.dpopRequireNonce` — RFC 9449 §5 DPoP Nonce
  When disabled, requirements gated by that policy field are out of scope.
- **Operational configuration**: Policies enforced by the active PostgreSQL
  Environment policy and OAuth profiles are assumed to match the proofs and
  policy documents. Misconfiguration is outside the formal claim. Startup
  `AEGAEON_*` policy toggles are not a supported runtime authority for
  `aegaeon-server`; the process fails closed if they are present.
- **Crypto profile (per instance)**: The strong‑constraint claim applies only
  to IdP/RP/trust‑chain instances configured with the **verified allowlist**
  defined in `docs/verification/claims/crypto-allowlist.md`. Instances using a
  broader compat allowlist are **out of scope** for the formal claim.
  The promoted RS256 slices are in scope for **protocol logic and boundary
  conditions only**; the underlying `aws-lc-rs` RSA PKCS#1 v1.5 SHA-256
  verifier is unverified TCB (RC-7 in the
  [Runtime Contract Register](../assumptions/runtime-contract-register.md)).
- **Boundary-closure exceptions**: If a compat runtime surface must be promoted
  into the formal claim, that exception must be recorded in
  `docs/verification/claims/crypto-allowlist.md`,
  `docs/verification/workplans/verification-boundary-roadmap.md`, and
  `spec/compliance-matrix.yaml`. The OIDC `RS256 Required Slice`
  (`OIDC-1-010`) and `RS256 Interop Slice` (`OIDC-5-002`, `7523-116`, `7523-402`) are the
  currently promoted server-claim exceptions; broad RSA and non-`RS256`
  interoperability remain outside the released claim.
- **Build channel**: Only binaries produced by the pinned Nix build are covered.
  Ad‑hoc builds, alternative toolchains, or patched dependencies are out of scope.

### 0.5 Implementation Refinement Scope

F\* proofs are **specification‑level** unless the verified implementation is
actually used in production:

- **In scope**: Extracted Low\*/EverParse code that is linked and used in the
  runtime path.
- **Out of scope**: Rust‑only implementations that are not proven to refine the
  F\* specification.

See `docs/verification/runbooks/extraction-status.md` for the current extraction
coverage.

Phase E refinement traces are tracked in
`docs/verification/runbooks/runtime-linkage.md`. The current state is a refinement
**stub** for core endpoints (runtime_link evidence only); full proofs are
pending.

### 0.6 Out of Scope (Non‑Goals)

The following items are **explicitly excluded** from the formal claim:

| Exclusion | Reason |
|---|---|
| Requirements not in `VerifiedReqs` | Outside the formal claim by definition (status != `verified` or missing proof reference). |
| Misconfiguration of `AEGAEON_*` policy gates | Formal claims assume documented configuration; operational errors are out of scope. |
| Raw-byte top-level JSON admission for `generic-object` | The residual generic surface remains compat-only at the `aegaeon_jose::raw_json` top-level object-member interface; promoted surfaces are enumerated in `docs/verification/jose/raw-json-boundary.md`. |
| Non‑Nix or unpinned builds | The claim applies only to binaries built via the pinned Nix toolchain. |
| External runtime dependencies | `aws-lc-rs`, `ring`, pure-Rust compat crypto, OS, DB, and networking stack are not formally verified here. |
| Compat-profile crypto surfaces | Algorithms outside the verified allowlist are outside the formal claim unless a narrower promoted slice is explicitly recorded (for example, the OIDC `RS256 Required Slice` or `RS256 Interop Slice`). |
| Supply chain and deployment integrity | CI artifacts, container images, and deployment pipelines are assumed, not proven. |
| Side channels beyond stated scope | Only explicitly verified constant‑time paths are in scope (e.g., dudect‑checked). |
| Client / RP behavior | The released claim covers server‑side protocol handling only. The pre-release client / RP boundary is tracked separately in `docs/verification/claims/client-rp-assurance-case.md`. |
| Admin-console UI behavior | The released claim does not treat the first-party management console as a formally verified UI surface. Instead, the console is constrained by `../aegaeon-admin-console/spec/admin-sdk-boundary.current.json` and `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`, plus hosted and compose-backed evidence. |
| Base64url input validation | F\* models Base64url encode/decode with concrete implementations and proved roundtrip/injectivity lemmas (formerly `assume val`, now proved). The model does NOT verify that the Rust `base64` crate correctly rejects all malformed Base64url strings; runtime rejection is delegated to the Rust layer. |
| Non-ASCII string encoding | `bytes_of_string` is used as a proxy for UTF-8. All callers (PKCE, JWK thumbprint, SD-JWT) operate on ASCII-only inputs per their respective RFCs. This assumption is documented but not enforced by F\* type refinements. |
