# Runtime Linkage — Proof-to-Implementation Traceability

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This document describes how formally verified properties are linked to their
runtime Rust implementations, ensuring that proofs are not just theoretical
artifacts but actively enforce behaviour in production code.

**Formal boundary note:** In realistic von Neumann systems with I/O, the project
cannot formally prove computational hardness (EUF‑CMA/collision resistance)
except as theorem premises, OS/device entropy sources (modeled as external
contracts), or external host/storage behaviour (modeled as explicit interface
contracts or TCB boundaries). These remain outside the formal claim.

---

## 1. Overview

Program posture note (2026-03-09): `runtime_link` traces only the current
**verified** compliance-matrix entries. It must not be read as proof that a
broader runtime capability belongs to the formal claim. Compat crypto surfaces
remain outside the claim unless a narrower promoted slice is explicitly
recorded; the OIDC `RS256 Required Slice` and `RS256 Interop Slice` are the
current promoted exceptions.

Every `status: verified` entry in the
[compliance matrix](../../../spec/compliance-matrix.yaml) carries a
`runtime_link` field that points to the Rust source file where the verified
behaviour is enforced at runtime.

| Field | Purpose | Example |
|-------|---------|---------|
| `module` | Primary source of the requirement (F\* spec, Rust impl, or docs) | `fstar/authcode/AuthCode.Store.fst` |
| `runtime_link` | Rust file that enforces the verified behaviour | `crates/server/src/authcode/store.rs` |

**Invariant:** Every `status: verified` entry has a `runtime_link` pointing
to an existing file. This is enforced by Rule 4 in
`scripts/validation/verify_verified_reqs.py`.

---

## 2. Linkage Categories

Entries are classified by how their `runtime_link` was derived:

| Category | Count | Description |
|----------|-------|-------------|
| **Rust direct** | 148 | `module` already points to a `crates/` file; `runtime_link` = `module` |
| **F\* mapped** | 67 | `module` points to an F\* spec; `runtime_link` derived from FSTAR\_TO\_RUST\_MAP |
| **Docs mapped** | 18 | `module` points to docs; `runtime_link` derived from the entry's test files |

The F\* → Rust mapping is maintained in
`scripts/validation/populate_runtime_link.py` and covers all 42 unique F\*
module paths in the compliance matrix. The verified-entry total is now 233,
including the promoted OIDC `RS256 Required Slice` and `RS256 Interop Slice`
rows.

---

## 3. Runtime Policy Matrix

Several verified behaviours are gated by active PostgreSQL Environment policy
fields. The remaining `AEGAEON_*_EVERPARSE_RUNTIME` entries in this section are
system bootstrap self-checks, not issuer policy authority. Some of those
self-check gates are overridden by the non-default `verified-claim` build
profile described below.

### Opt-in policy surfaces (default off)

| Runtime policy field | Default | Affected Entries | Description |
|------|---------|-----------------|-------------|
| `policy.jwtAccessTokensEnabled` | off | 9068-\* + related (33) | JWT access tokens with `at+jwt` typ, cnf binding |
| `policy.allowedGrantTypes` includes `urn:ietf:params:oauth:grant-type:device_code` | off | 8628-\* + metadata (10) | RFC 8628 Device Authorization Grant |
| `policy.allowedGrantTypes` includes `urn:ietf:params:oauth:grant-type:jwt-bearer` | off | JWT bearer entries (18) | RFC 7523 JWT Bearer grant type |
| `policy.allowedGrantTypes` includes `urn:ietf:params:oauth:grant-type:token-exchange` | off | Token exchange entries (13) | RFC 8693 Token Exchange |

### Database-backed structural self-checks

| Runtime policy field | Default | Affected Entries | Description |
|------|---------|-----------------|-------------|
| `policy.dcrEverparseRuntimeEnabled` | off | 7591-003, v21-004, v21-008 | Canonical-binary EverParse self-check for DCR metadata in the default compatibility profile; `verified-claim` requires the same self-check even when this policy is off |
| `policy.requestObjectEverparseRuntimeEnabled` | off | JAR entries | Canonical-binary EverParse self-check for Request Object claims in the default compatibility profile; `verified-claim` requires the same self-check even when this policy is off |

### Database-backed bounded admission policies

| Runtime policy field | Default | Affected Entries | Description |
|------|---------|-----------------|-------------|
| `policy.joseHeaderMaxLen` | `4096` | JOSE header admission, JAR, PAR, client assertions, JWT bearer | Maximum Base64URL protected-header length accepted by server JOSE contexts (`1..=65536`) |

### Default-on policy surfaces

| Runtime policy field | Default | Affected Entries | Description |
|------|---------|-----------------|-------------|
| `policy.dpopRequireNonce` | on | 9449-011 &ndash; 9449-014 | DPoP nonce enforcement (RFC 9449 &sect;5) |
| `policy.pkceRequired` | on | 9700-\*, v21-034 | PKCE requirement for all flows |
| `policy.dpopStrict` | on | DPoP entries | Strict DPoP proof validation |

### OIDC feature set

| Runtime policy field | Default | Affected Entries | Description |
|------|---------|-----------------|-------------|
| `policy.oidcEnabled` | off | OIDC-1-001, OIDC-3-\*, OIDC-5-\* (7) | Master OIDC toggle from the active PostgreSQL Environment policy |
| `policy.oidcEnableLogout` | off | OIDC-3-001 &ndash; 3-004 | RP-Initiated + Back-Channel Logout |
| `policy.oidcEnableBackchannelLogout` | off | OIDC-3-003, OIDC-3-004 | Back-Channel Logout specifically |
| `policy.oidcEnableUserinfo` | off | OIDC-1-001 | UserInfo endpoint |

### Build-time claim-bearing profile

| Cargo feature | Crates | Current effect |
|------|--------|----------------|
| `verified-claim` | `aegaeon-jose`, `aegaeon-server` | Non-default strict profile that disables JOSE header serde fallback, fails closed on JOSE TLV EverParse entry-validator unavailability, fails closed on OIDC ID Token structure-parser unavailability, routes OIDC hash computation through the source-managed `lowstar_hash` C runtime shim instead of the Rust fallback, and requires canonical EverParse self-checks for DCR / Request Object payloads even when their runtime policies are off. Current runtime hardening rejects duplicate top-level keys/claims before normalization for JOSE headers, DCR metadata, Request Objects, software statements, Required-RS256 ID Token payloads, JWT access tokens, federation entity statements, federation trust marks, the promoted RS256 `private_key_jwt` slice, and JWT bearer assertions; DPoP nonce extraction no longer depends on a separate raw JSON helper surface. `aegaeon_jose::raw_json` is the source-managed posture authority via `PROMOTED_RAW_JSON_SURFACES`, `COMPAT_ONLY_RAW_JSON_SURFACES`, `current_claim_boundary_for_surface(...)`, and `current_claim_posture_for_surface(...)`; `jose-header`, `request-object`, `client-registration`, `software-statement`, `private-key-jwt-payload`, `jwt-bearer-assertion-payload`, `oidc-id-token-payload`, `jwt-access-token-header`, `jwt-access-token-payload`, `federation-entity-statement`, and `federation-trust-mark` are promoted to `raw-bytes` via `verified-structural-v1`. Normal builds have zero compat-only raw JSON surfaces. Test builds keep the legacy `generic-object` surface at `top-level-object-members` so compat-only helper behavior can be regression-tested without appearing in the normal runtime inventory. Software statements are promoted under SSA Profile v1: registered JWT claim shape plus recognized DCR metadata fields decoded through the typed registration parser; unknown SSA extension claims remain outside that promoted profile claim. The remaining broad semantic object-decode helpers are explicitly labeled compat-only (`deserialize_compat_*`) on both the JOSE and server sides, so promoted paths rely on surface-specific typed decoders or minimal member IR instead of a generic semantic decode API. `verify-jose` and `verification.yml` exercise JOSE vector/parity coverage, strict OIDC structure-parser/hash fail-closed tests, strict DCR / Request Object self-check regressions, the `/authorize` JAR RS256 duplicate-claim regression under this profile, and a compile-only smoke build for the opt-in `verified-claim,idtoken_runtime` combination. The extracted `generated/lowstar/oidc/id_token/` runtime is source-managed and compile-checked, but it remains opt-in and outside the current claim, so this is not yet the released default claim-bearing build. |

---

### Crypto profile boundary (per instance)

Cryptographic verification claims apply **only** to IdP/RP/trust‑chain instances
configured with the **verified allowlist** (see
`docs/verification/claims/crypto-allowlist.md`). Instances using a broader compat
allowlist are operationally supported but **out of scope** for strong‑constraint
claims, regardless of feature flags.

## 4. Liveness Evidence

Runtime linkage alone does not prove a behaviour is exercised. The liveness
classification (generated by `scripts/validation/check_runtime_liveness.py`)
categorises each entry:

| Classification | Meaning |
|----------------|---------|
| `live` | File exists, referenced by tests, no opt-in feature flag |
| `live_opt_in` | File exists, referenced by tests, but gated behind an opt-in flag |
| `spec_only` | Module points to F\* spec; Rust counterpart exists but linkage is indirect |
| `untested` | Runtime link exists but no test references found |

The full liveness report is generated on demand:

```bash
python3 scripts/validation/check_runtime_liveness.py
```

### Dead code EverParse schemas

Three of the seven EverParse schemas are not invoked at runtime by default:

| Schema | Status | Activation |
|--------|--------|------------|
| `DcrRegistration.3d` | Opt-in / strict mandatory | `policy.dcrEverparseRuntimeEnabled=true` in the compatibility profile, or `--features verified-claim` |
| `RequestObjectSchema.3d` | Opt-in / strict mandatory | `policy.requestObjectEverparseRuntimeEnabled=true` in the compatibility profile, or `--features verified-claim` |
| `LogoutTokenSchema.3d` | Verified only | No runtime invocation path |

---

## 5. Drift Detection

The drift detection system tracks changes to runtime-linked files:

```bash
# Generate manifest (after updating runtime_link fields)
python3 scripts/validation/check_runtime_drift.py --generate

# Check for drift (CI, warning mode)
python3 scripts/validation/check_runtime_drift.py --check
```

The manifest (`spec/runtime-link-manifest.json`) stores SHA-256 hashes of
all runtime-linked files. When a linked file changes, the drift checker
reports which compliance-matrix entries are affected, helping reviewers
assess whether the proof-to-implementation link is still valid.

**CI integration:** Drift detection runs in warning mode (non-blocking)
as part of the `verify_reqs.sh` CI script.

---

## 6. Cross-references

| Document | What it covers |
|----------|---------------|
| [claim-definition.md](../claims/assurance-case/claim-definition.md) | Verification scope and claim statements |
| [current-register.md](../claims/assumptions/current-register.md) | Assumption Register (12 assume vals across 8 files: 6 crypto, 2 HACL* linkage, 1 EverParse linkage, 2 OIDC hash runtime linkage, 1 WASM host) |
| [claim-index.md](../claims/claim-index.md) | Per-entry quality/strength breakdown + runtime linkage statistics |
| [verification-ops.md](verification-ops.md) | Operational guide for maintaining VerifiedReqs |
| `scripts/validation/populate_runtime_link.py` | Auto-populate tool with FSTAR\_TO\_RUST\_MAP |
| `scripts/validation/check_runtime_liveness.py` | Liveness classification |
| `scripts/validation/check_runtime_drift.py` | Drift detection |
| `spec/runtime-link-manifest.json` | SHA-256 manifest for drift detection |

---

## Phase E scaffold (spec → implementation refinement)

Phase E requires an explicit refinement trace from formal specs to runtime
implementations. The authoritative mapping today is the `runtime_link` field
in `spec/compliance-matrix.yaml` (see `../claims/claim-index.md` for a synthesized view).

Status: The refinement proof layer is pending; this document is the working
location for that trace. New refinement evidence should be added alongside the
existing runtime_link entries, not in a separate document.

### Refinement stub targets (Phase E)

| Endpoint | Spec module(s) | Runtime implementation | Evidence status |
|---|---|---|---|
| `/authorize` | TBD | TBD | Stub (runtime_link only) |
| `/token` | TBD | TBD | Stub (runtime_link only) |
| `/introspect` | TBD | TBD | Stub (runtime_link only) |
| `/revoke` | TBD | TBD | Stub (runtime_link only) |
