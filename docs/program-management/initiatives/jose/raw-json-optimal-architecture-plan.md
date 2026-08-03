# Raw JSON to Greenfield-Optimal Architecture Plan

Last updated: 2026-07-08

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document describes the staged route from the current
`aegaeon_jose::raw_json` posture to the architecture we would prefer in a
greenfield design.

It is intentionally stricter than the short-term migration notes in
`json-tlv/json-tlv-proof-plan.md`: the goal here is not merely to replace the
current `serde_json` byte-level admission step, but to end with a surface-first,
typed, claim-bearing design.

## Target End State

The desired long-term shape is:

```text
raw bytes
  -> verified structural parser
  -> minimal verified object-member / event IR
  -> surface-specific typed decoder
  -> domain object
```

Key properties:

- claim-bearing paths do **not** materialize a broad `serde_json::Value`
  object before surface validation
- claim-bearing paths do **not** rely on `serde_json::from_value(...)`
  for their main semantic decode
- `generic-object` is no longer the architectural center of promoted parsing;
  it remains compat-only, or is replaced by narrower verified subsets
- the code-level claim posture remains surface-specific and is published via
  `aegaeon_jose::raw_json`

## Design Rules

1. **Surface-first semantics**
   - Promote each ingress by building a dedicated decoder for that surface, not
     by widening a single broad "verified JSON object" claim.
2. **Minimal shared IR**
   - The shared verified layer should expose only the smallest reusable
     structure needed by multiple surfaces: ordered members, value kinds,
     lengths, and byte slices / spans.
   - Do not make a broad dynamic JSON AST the main public contract for promoted
     surfaces.
3. **Claim posture follows code**
   - `current_claim_posture_for_surface(...)` remains the authority for whether
     a surface is still `top-level-object-members` or has reached `raw-bytes`.
4. **Compatibility remains explicit**
   - Any remaining broad JSON handling lives on a compat path and is documented
     as such.
5. **Promotion is per surface**
   - No documentation, CI, or roadmap text should imply that all raw JSON
     consumers move together.

## Phase 0: Freeze the Current Boundary

Objective:
- keep the current released claim explicit while the long-horizon target is
  designed

Scope:
- `ALL_RAW_JSON_SURFACES` remains the authoritative inventory
- `SerdeCompat` remains the only active backend
- every current surface remains at `top-level-object-members`

Status (2026-05-18):
- complete as the historical baseline; all concrete claim-bearing surfaces have
  since been promoted to `verified-structural-v1` plus `raw-bytes`, while the
  residual `generic-object` surface stays at `SerdeCompat` plus
  `top-level-object-members`

Exit criteria:
- docs and tests consistently describe the current boundary
- per-surface inventory / env metadata / claim posture remain source-managed

## Phase 1: Introduce a Verified Structural Parser

Objective:
- replace byte-level admission for the first promoted surface without changing
  downstream consumer contracts yet

Deliverables:
- a new raw-byte backend that proves:
  - top-level object shape
  - ordered member preservation
  - duplicate-key preservation at admission
  - complete first-object consumption
  - trailing-byte classification
- adapters from the verified parser output into the current
  duplicate-preserving member representation

Rules:
- do not promote `generic-object`
- do not promise typed semantic decoding yet
- keep the verified parser output smaller than `serde_json::Value`

Exit criteria:
- parity tests show the verified structural parser matches the current helper
  on accepted/rejected top-level object cases
- the new backend can be selected for one surface without affecting the others

Historical note:
- `../../historical/initiatives/jose/raw-json-phase1-structural-parser-plan.md`
  records the completed execution breakdown for this phase.

Status (2026-05-18):
- complete for the scoped `jose-header` landing

## Phase 2: Promote `jose-header` to a Typed Decoder

Objective:
- make JOSE header parsing the first true `raw-bytes` claim-bearing surface

Why first:
- narrow schema
- already has a dedicated Low*/C policy-enforcement path
- does not require broad JSON object materialization

Deliverables:
- direct decode from verified member IR into the JOSE header normalization path
- no broad `serde_json::Value` dependency in the promoted `jose-header` path
- preserved error taxonomy for duplicate keys, trailing bytes, bad key
  encoding, invalid value types, and policy violations

Exit criteria:
- `jose-header` can move to `RawJsonClaimBoundary::RawBytes`
- RFC 7520 vectors, TLV parity, and negative JOSE header tests all pass under
  the promoted backend
- compat and strict builds agree on policy behaviour where both succeed

Status (2026-05-18):
- complete for `jose-header`; the promoted path now decodes verified structural
  IR directly into the typed JOSE header normalization surface and the
  code-level claim posture records `verified-structural-v1` plus `raw-bytes`

## Phase 3: Build Dedicated Typed Decoders for the Narrow Claim Surfaces

Objective:
- promote surfaces whose semantics are still reasonably bounded and whose
  consumers are security-sensitive enough to justify a dedicated decoder

Preferred order:
1. `oidc-id-token-payload`
2. `jwt-access-token-header`
3. `jwt-access-token-payload`
4. `federation-entity-statement`
5. `federation-trust-mark`

Deliverables:
- surface-specific typed decoders operating on the verified member IR
- no `serde_json::from_value(...)` in the promoted paths
- explicit handling for any field that still needs nested JSON semantics

Notes:
- federation may require a bounded verified subtree representation before full
  promotion, depending on the retained extension model

Exit criteria:
- each promoted surface has its own decoder, tests, and claim update
- surface promotion is evidence-backed and independent

Status (2026-05-18):
- complete; `oidc-id-token-payload`, `jwt-access-token-header`,
  `jwt-access-token-payload`, `federation-entity-statement`, and
  `federation-trust-mark` are now promoted to `verified-structural-v1` plus
  `raw-bytes`
- the Required-RS256 verification path now uses a surface-specific typed
  `IdTokenClaims` decoder over structural IR
- JWT access-token verification now uses typed structural decoders for both the
  promoted header (`kid` / `typ`) and payload
  (`iss` / `sub` / `aud` / `exp` / `iat` / `jti`) paths
- federation entity-statement parsing now uses a typed structural decoder that
  extracts `iss` / `sub` / `iat` / `exp` directly and admits nested/open-ended
  JSON only as bounded per-member slices
- federation trust-mark parsing now uses a typed structural decoder for
  `iss` / `sub` / `id` / `iat` / `exp` / `ref_`

## Phase 4: Rework the Broad Surfaces Before Promotion

Objective:
- eliminate the biggest architectural blocker to a truly optimal design:
  broad, generic materialization in `request-object` and `client-registration`

Current blocker:
- these paths still lean on dynamic `Value`-heavy decoding and
  `serde_json::from_value(...)`

Deliverables:
- a typed Request Object decoder over verified member IR
- a typed DCR decoder over verified member IR
- a strategy for nested/open-ended fields:
  - either a verified subtree representation
  - or a narrower claim that explicitly excludes the open-ended portion

Rules:
- do not mark these surfaces `raw-bytes` until the broad `from_value` path is
  out of the promoted decode route
- if some nested field remains intentionally compat-only, document the exact
  boundary

Exit criteria:
- `request-object` and `client-registration` no longer depend on broad dynamic
  JSON materialization in the claim-bearing path

Status (2026-05-18):
- complete; `request-object` and `client-registration` now default to the
  `verified-structural-v1` backend and report the `raw-bytes` claim boundary
- `request-object` decodes `RequestObjectClaims` plus the JWT validation subset
  from admitted top-level members produced by structural IR and retains bounded
  per-member JSON admission for `authorization_details` and additional claims
- `client-registration` decodes `ClientRegistration` from admitted top-level
  members produced by structural IR, rejects alias collisions such as
  `pkce_required` plus `require_pkce` fail-closed, and retains bounded
  per-member JSON admission for `jwks`
- the next architectural blocker is now the remaining `generic-object`
  fan-out used by shared helper surfaces

## Phase 5: Isolate or Retire `generic-object`

Objective:
- make `generic-object` an explicit compatibility facility rather than the
  hidden center of the promoted architecture

Preferred outcome:
- keep `generic-object` outside the promoted claim
- provide dedicated verified surfaces for every claim-bearing consumer that
  currently relies on it

Fallback outcome:
- if a verified generic subset is absolutely required, define it as a separate,
  narrower surface with explicit structural limits and no implicit claim
  inheritance for all generic consumers

Exit criteria:
- software statements, promoted `private_key_jwt`, and JWT bearer assertions no
  longer rely on a broad shared generic claim path, and DPoP nonce handling no
  longer requires a separate raw JSON helper path

Status (2026-05-18):
- complete; `software-statement`, `private-key-jwt-payload`, and
  `jwt-bearer-assertion-payload` now exist as dedicated surfaces instead of
  routing those claim-bearing helpers through the shared `generic-object`
  selector, and DPoP nonce handling now comes directly from the verifier
  result
- follow-up implemented; `software-statement`, `private-key-jwt-payload`, and
  `jwt-bearer-assertion-payload` now share a JOSE-owned RFC 7519
  registered-claims decoder
- `private-key-jwt-payload`, `jwt-bearer-assertion-payload`, and
  `software-statement` were promoted after Phase 6 as JWT-family follow-ups;
  `software-statement` is promoted only under SSA Profile v1, which decodes
  recognized DCR metadata through the typed registration parser and leaves
  unknown SSA extension claims outside the promoted profile claim
- `generic-object` is no longer the shared claim-bearing path for those helper
  flows and remains the conservative residual compat surface

## Phase 6: Simplify the Public Architecture

Objective:
- remove migration-era layering once the promoted surfaces have dedicated typed
  decoders

Deliverables:
- `raw_json` becomes a surface-selection and claim-posture authority, not a
  broad semantic decode API for promoted surfaces
- compat-only helpers are clearly separated from promoted helpers
- docs describe the promoted architecture in surface-first terms, not in terms
  of "a generic JSON helper that also powers everything else"

Exit criteria:
- the main design can be explained without reference to `serde_json::Value`
  on any promoted surface
- the remaining compat surfaces are explicitly named and justified

Status (2026-05-18):
- complete; `raw_json` now exposes explicit `PROMOTED_RAW_JSON_SURFACES` and
  `COMPAT_ONLY_RAW_JSON_SURFACES` inventories so the code-level architecture
  matches the documented surface inventory
- the broad semantic object-deserialization helpers are explicitly labeled
  compat-only and are used only from compat branches; promoted paths keep using
  surface-specific typed decoders or the minimal object-member IR
- the steady-state architecture is now documented and implemented in
  surface-first terms rather than around a generic semantic decode layer

Follow-up status (2026-05-19):
- `private-key-jwt-payload`, `jwt-bearer-assertion-payload`, and
  `software-statement` are promoted to `verified-structural-v1` plus
  `raw-bytes`; the public inventory now has eleven promoted surfaces and one
  compat-only surface
- the remaining compat-only surface is `generic-object`

## Promotion Heuristic

Use this rule for every surface:

- if the surface can be decoded from verified member IR into a typed structure
  without a broad dynamic JSON materialization step, it is a candidate for
  `raw-bytes`
- if the surface still requires broad `Value` decoding or `from_value(...)`, it
  is not yet a candidate for the optimal claim-bearing architecture

## Evidence Requirements

Every phase that changes a surface posture must update:

- code-level posture in `aegaeon_jose::raw_json`
- unit coverage for backend selection / fail-closed behaviour
- surface-specific semantic regressions
- relevant JOSE / OIDC / server integration tests
- `docs/verification/jose/raw-json-boundary.md`
- `docs/verification/runbooks/runtime-linkage.md`
- `docs/verification/claims/verification-maturity-status/gaps-and-promotion-work.md` when the blocker map changes

## What This Plan Optimizes For

This plan optimizes for the end-state architecture we would choose in a
greenfield formal-verification-oriented design:

- small trusted shared core
- typed promoted surfaces
- explicit compat boundaries
- per-surface claim posture

It does **not** optimize for the smallest immediate patch set. That shorter
path is still captured separately in `json-tlv/json-tlv-proof-plan.md`.
