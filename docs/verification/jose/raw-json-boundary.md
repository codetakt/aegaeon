# Raw JSON Claim Boundary

Last updated: 2026-06-18

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This note is the canonical source for the current formal-claim boundary around
`aegaeon_jose::raw_json`.

It applies to the current promoted `raw_json` helper surfaces:

- `jose-header`
- `request-object`
- `client-registration`
- `software-statement`
- `private-key-jwt-payload`
- `jwt-bearer-assertion-payload`
- `oidc-id-token-payload`
- `jwt-access-token-header`
- `jwt-access-token-payload`
- `federation-entity-statement`
- `federation-trust-mark`

The legacy `generic-object` surface is no longer part of the normal public
surface inventory. It is compiled only for `test` and remains outside the
promoted formal claim.

## Current Code-Level Authority

The source-managed authority for the active raw JSON claim posture is the
`aegaeon_jose::raw_json` module:

- `ALL_RAW_JSON_SURFACES`
- `PROMOTED_RAW_JSON_SURFACES`
- `COMPAT_ONLY_RAW_JSON_SURFACES`
- `RawJsonBackend::is_verified()`
- `current_claim_boundary_for_surface(...)`
- `current_claim_posture_for_surface(...)`

As of 2026-06-18:

- `jose-header`, `request-object`, `client-registration`,
  `software-statement`,
  `private-key-jwt-payload`, `jwt-bearer-assertion-payload`,
  `oidc-id-token-payload`, `jwt-access-token-header`, `jwt-access-token-payload`,
  `federation-entity-statement`, and
  `federation-trust-mark`
  default to
  `RawJsonBackend::VerifiedStructuralV1`
- `RawJsonBackend::VerifiedStructuralV1.is_verified()` is `true`
- `jose-header`, `request-object`, `client-registration`,
  `software-statement`,
  `private-key-jwt-payload`, `jwt-bearer-assertion-payload`,
  `oidc-id-token-payload`, `jwt-access-token-header`, `jwt-access-token-payload`,
  `federation-entity-statement`, and
  `federation-trust-mark`
  report
  `RawJsonClaimBoundary::RawBytes`
- normal builds have no compat-only raw JSON surface in
  `COMPAT_ONLY_RAW_JSON_SURFACES`; the legacy `generic-object` surface appears
  only under `test`, where it remains
  `RawJsonBackend::SerdeCompat` plus
  `RawJsonClaimBoundary::TopLevelObjectMembers`

The surface list in this note is a human-readable mirror of
`ALL_RAW_JSON_SURFACES`; when they ever diverge, treat the code-level inventory
as authoritative and update this document in the same change.

The broad semantic object decode helpers now also follow the same boundary:
their explicit `deserialize_compat_*` naming is the source-managed signal that
those helpers remain compat-only and are not part of the promoted raw-byte
claim for any surface.

The remaining implicit `generic-object` convenience wrappers are gated behind
`test` and are deprecated as legacy compat-only APIs. Claim-bearing or
policy-sensitive code must call the `*_for_surface(...)` entry points
explicitly and select a promoted surface.

## Interpretation

The current released claim is now surface-specific.

For `jose-header`, the claim starts at raw JSON bytes and flows through the
source-managed `verified-structural-v1` backend into a typed
`key + (string | null)` decoder before the Low*/C normalization boundary.

For `request-object`, the claim starts at raw JSON bytes and flows through the
same source-managed `verified-structural-v1` backend into a typed
`RequestObjectClaims` plus `JwtClaims` decoder. The promoted path extracts the
JWT validation subset directly from admitted top-level members and admits
open-ended fields such as `authorization_details` only as bounded per-member
JSON values.

For `client-registration`, the claim starts at raw JSON bytes and flows
through the same source-managed `verified-structural-v1` backend into a typed
`ClientRegistration` decoder. The promoted path extracts recognized metadata
directly from admitted top-level members, rejects alias collisions fail-closed,
and admits `jwks` only as a bounded per-member JSON value.

For `private-key-jwt-payload`, the claim starts at raw JSON bytes and flows
through the same source-managed `verified-structural-v1` backend into the
registered-claims decoder used by the promoted RS256 `private_key_jwt` slice.
This promotes raw JSON admission and claim-shape checking for that payload
surface; it does not widen the broader RSA or client-authentication proof
claim.

For `jwt-bearer-assertion-payload`, the claim starts at raw JSON bytes and
flows through the same source-managed `verified-structural-v1` backend into
the registered-claims decoder used by the JWT bearer grant assertion path.
This promotes raw JSON admission and claim-shape checking for that payload
surface; subject/audience policy and replay protection remain separate server
validation claims.

For `oidc-id-token-payload`, the claim starts at raw JSON bytes and flows
through the same source-managed `verified-structural-v1` backend into the
Required-RS256 typed `IdTokenClaims` decoder. Known claims are decoded directly
from structural IR and open-ended additional claims are admitted only as
bounded per-member JSON values.

For `jwt-access-token-header`, the claim starts at raw JSON bytes and flows
through the same source-managed `verified-structural-v1` backend into the
access-token validator's typed header decoder. The promoted path extracts the
security-relevant `kid` and `typ` fields directly from structural IR before
signature and token-type checks run.

For `jwt-access-token-payload`, the claim starts at raw JSON bytes and flows
through the same source-managed `verified-structural-v1` backend into the
access-token validator's typed payload decoder. The promoted path extracts the
security-relevant `iss`, `sub`, `aud`, `exp`, `iat`, and `jti` fields directly
from structural IR before issuer, lifetime, and audience policy checks run.

For `federation-entity-statement`, the claim starts at raw JSON bytes and
flows through the same source-managed `verified-structural-v1` backend into a
typed `EntityStatement` decoder. The promoted path extracts
`iss` / `sub` / `iat` / `exp` directly from structural IR and admits
`jwks`, `metadata`, `metadata_policy`, `constraints`, `trust_marks`,
`authority_hints`, and `source_endpoint` only as bounded per-member JSON
values.

For `federation-trust-mark`, the claim starts at raw JSON bytes and flows
through the same source-managed `verified-structural-v1` backend into a typed
`TrustMarkClaims` decoder. The promoted path extracts
`iss` / `sub` / `id` / `iat` / `exp` / `ref_` directly from structural IR
before trust-mark validation runs.

For `software-statement`, the claim starts at raw JSON bytes and flows through
the same source-managed `verified-structural-v1` backend into SSA Profile v1.
The profile covers registered JWT claim shape plus recognized DCR metadata
fields decoded through the typed `ClientRegistration` field parser. Unknown
SSA extension claims remain preserved in the custom claim bag, but they are
outside the promoted profile claim. Nested `software_statement` metadata and
DCR metadata alias collisions fail closed.

For legacy `generic-object` builds, the strongest boundary remains the
duplicate-preserving top-level object-member interface exported by
`aegaeon_jose::raw_json`. Its path uses the `SerdeCompat` backend and remains
outside the current formal claim. It is no longer compiled into normal builds
and is no longer the shared claim-bearing path for software statements,
promoted `private_key_jwt`, JWT bearer assertions, or DPoP nonce extraction.

In practice this means:

- do describe `jose-header`, `oidc-id-token-payload`,
  `request-object`, `client-registration`, `software-statement`,
  `private-key-jwt-payload`,
  `jwt-bearer-assertion-payload`, `jwt-access-token-header`,
  `jwt-access-token-payload`,
  `federation-entity-statement`, and `federation-trust-mark` as promoted
  `raw-bytes` surfaces
- do not describe raw-byte parsing for legacy `generic-object` as formally
  verified
- do describe that legacy test-only surface as `top-level-object-members`
  when tests intentionally exercise it
- keep the helper's source-managed posture aligned with verification docs and
  runtime-linkage notes

## Current Surface Posture

| Surface | Backend | Verified backend? | Claim boundary |
| --- | --- | --- | --- |
| `jose-header` | `verified-structural-v1` | yes | `raw-bytes` |
| `request-object` | `verified-structural-v1` | yes | `raw-bytes` |
| `client-registration` | `verified-structural-v1` | yes | `raw-bytes` |
| `software-statement` | `verified-structural-v1` | yes | `raw-bytes` |
| `private-key-jwt-payload` | `verified-structural-v1` | yes | `raw-bytes` |
| `jwt-bearer-assertion-payload` | `verified-structural-v1` | yes | `raw-bytes` |
| `oidc-id-token-payload` | `verified-structural-v1` | yes | `raw-bytes` |
| `jwt-access-token-header` | `verified-structural-v1` | yes | `raw-bytes` |
| `jwt-access-token-payload` | `verified-structural-v1` | yes | `raw-bytes` |
| `federation-entity-statement` | `verified-structural-v1` | yes | `raw-bytes` |
| `federation-trust-mark` | `verified-structural-v1` | yes | `raw-bytes` |

Legacy/test-only posture:

| Surface | Backend | Verified backend? | Claim boundary |
| --- | --- | --- | --- |
| `generic-object` | `serde-compat` | no | `top-level-object-members` |

The shared server-side claim-bearing helpers no longer reuse
`generic-object`. Software statement claim parsing binds to its dedicated
promoted surface and then applies SSA Profile v1 typed metadata admission.
Promoted `private_key_jwt` and JWT bearer assertion claim parsing bind to their
dedicated promoted surfaces. All three paths fail closed if their per-surface
raw JSON backend policy is misconfigured.

## Promotion Rule

Moving any additional surface from `top-level-object-members` to `raw-bytes`
requires one coordinated change set for that specific surface:

1. land a verified raw-byte parser backend for the promoted surface
2. update `aegaeon_jose::raw_json` so the code-level posture for that surface
   reflects the new backend and boundary
3. refresh the surface-specific regression evidence
4. update the assurance case, runtime linkage, roadmap, and outward-facing
   wording together

The current helper is surface-aware, so future parser work should target
explicit promoted surfaces. The legacy `generic-object` test surface is a
compatibility fixture only, not a promotion candidate for normal server runtime
code.

Do not widen the released claim by documentation edits alone or by treating a
runtime override as a claim change without the corresponding code-level posture
and evidence updates.
