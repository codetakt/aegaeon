# Future Program Backlog

Last updated: 2026-07-07

Status: future plan

Owner: Program Management

Audience: maintainers, planning contributors

This backlog covers future, deferred, or not-yet-claim-bearing work. It intentionally omits
completed implementation phases; use `docs/specs/` for current behaviour and
`docs/program-management/historical/roadmaps/` for delivery records.

Items move from this file into `../active/current-execution-plan.md` only when ownership, sequencing, evidence
requirements, and exit criteria are clear.

## 1. Management-Platform Publication And Hosted Evidence

The backend, local-IAM, broker/federation, SDK, and admin-console baselines are implemented. The
remaining work is publication and claim activation, not first implementation.

Future work:

1. apply branch-protection, repository-settings, and release-custody contracts in the real
   publication organization
2. provision managed commercial-provider tenants and capture hosted evidence
3. feed managed-provider and admin-SDK evidence into client-claim promotion gates
4. publish SDK packages with provenance, SBOM, release attestation, and retained claim reports
5. keep regulated-environment evidence retention and drift-response runbooks current

Canonical execution detail: `../active/management-platform-follow-on-plan.md`.

## 2. External Conformance Expansion

The minimum publication baseline is complete. Future work expands plan coverage and archival.

Priority targets:

- OIDC Basic plan: resolve manual evidence modules and re-export accepted results
- OAuth code + PKCE plan: archive machine-readable suite exports
- DPoP plan: validate nonce, `cnf.jkt`, and DPoP token-type behaviour
- PAR and JAR plans: validate pushed and signed request handling
- Token Exchange and Device Authorization plans: run when suite support is available
- release indexing: link accepted exports from `docs/releases/`

OIDF certification application remains optional until adoption or customer demand justifies fee and
legal overhead.

## 3. Verification And Extraction Backlog

The current claim has zero `admit()` and documented trust boundaries. Future work should reduce
remaining proof debt only where it improves maintainability or claim clarity.

Tracked items:

- `Jose.HeaderParser.read_u8_safe`: deferred F\* proof candidate requiring Tot/Stack effect work
- JOSE/TLV extraction hardening: EverParse / Low* integration, warning reduction, and CI posture
- named-lemma cleanup for remaining ad-hoc proof scaffolding
- periodic full-refresh evidence updates for F\*, Tamarin, Kani, dudect, JOSE vectors, and the
  security suite
- trust-boundary upkeep for FFI, crypto primitives, RNG, and WASM host imports
- ES512 / P-521 research only if a verified or auditable P-521 backend and product need are both
  established

Canonical proof detail: `../active/proofs-roadmap.md` and `docs/verification/`.

## 4. Future Protocol And Product Surfaces

Potential future additions must preserve fail-closed defaults and must not overstate the verified
claim.

Candidates:

- FAPI Baseline validation using current PAR, DPoP/mTLS, PKCE, issuer binding, and confidential
  client enforcement
- FAPI Advanced enforcement for signed PAR/JAR combinations, additional hash claims, and stricter
  error handling
- JARM response signing and `response_mode` variants such as `jwt`, `query.jwt`, and
  `form_post.jwt`
- optional OIDC `claims` parameter support
- signed or encrypted UserInfo responses
- WebFinger only if a concrete interoperability requirement appears
- broader verified OIDC server/client claim positions after source, hosted evidence, and public
  wording gates close

OIDC Session Management 1.0 and Front-Channel Logout remain intentionally unsupported unless the
browser ecosystem changes enough to make those mechanisms reliable and security-aligned.

## 5. Claim Upgrade Tracks

Future public wording upgrades remain gated by evidence, not implementation optimism.

Open tracks:

- enterprise-ready claim activation after real tenant evidence and publication-org blockers close
- formal OIDF certification after selected plans pass with acceptable external evidence
- bounded verified-UI wording only after hosted admin-console evidence and claim-boundary review
- released-client claim activation only after package publication, provenance, custody, and hosted
  evidence gates pass

Canonical claim detail: `../active/enterprise-readiness-certification-ui-claim-plan.md` and
`../active/verified-server-client-formal-claim-roadmap.md`.

## 6. Promotion Rule

Before promoting any item to active execution:

- define owner, scope, non-goals, and exit criteria
- identify compliance-matrix rows and proof/test evidence
- state whether the result affects product wording, formal claim wording, or neither
- update specs or operations docs for durable behaviour
- keep completed delivery records out of this backlog
