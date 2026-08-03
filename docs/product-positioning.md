# Product Positioning

Last updated: 2026-07-23

Status: current implementation baseline

Owner: Documentation

Audience: contributors, maintainers

## Purpose

This document is the canonical source for outward-facing product wording for Aegaeon.
It translates the formal claim, security evidence, and active roadmaps into safe
release / marketing language.

If this document conflicts with
`docs/verification/claims/assurance-case/claim-definition.md`,
`docs/verification/claims/assumptions/current-register.md`,
`docs/verification/claims/assumptions/runtime-contract-register.md`,
`docs/verification/claims/crypto-allowlist.md`, or `spec/compliance-matrix.yaml`,
those documents win.

## Scope

- current claimable server positioning
- statements that are still too strong today
- next target positions gated on explicit verification-boundary closure
- separation between the current server product and the planned client / SDK track

## Claimable Today

- **Primary statement**: Aegaeon is an assumption-qualified formally verified and
  security-tested OIDC 1.0 / OAuth 2.0/2.1 identity-provider server, with OpenID Connect Federation runtime support.
- **OIDC nuance**: that server claim is now supported by the promoted OIDC
  `RS256 Required Slice` and `RS256 Interop Slice`; broader RSA remains compat.
- **Input-boundary nuance**: claim-bearing raw JSON surfaces are promoted
  surface-by-surface. Current promoted surfaces are enumerated in
  `docs/verification/jose/raw-json-boundary.md`; the residual `generic-object`
  surface remains compat-only.
- **Server-side RP nuance**: Aegaeon includes server-side OIDC RP / brokering runtime
  capability, but that does not create a formally verified standalone client / RP product claim.
- **Verified Core nuance**: Verified Core extraction and WASM distribution support a future
  SDK / client track, but the current released formal claim remains server-side.
- **Admin-console nuance**: the first-party management console is currently positioned as a
  control-plane UI constrained by `@aegaeon/management-client`, the admin SDK boundary,
  and the source-managed management-session auth boundary; it is not itself part of the
  released formal verification claim. A bounded admin control-plane security-boundary assurance
  case and checked model now exist for future claim activation, but hosted runtime evidence and
  Phase 4 activation remain incomplete.

## Current Evidence Baseline

- **Freshness status (2026-03-10)**: the current released server claim has been
  re-established against a fresh claim-supporting verification / security baseline.
- **Claim-supporting lanes re-run fresh**:
  - `nix build .#verify-fstar -L`
  - `nix build .#verify-jose -L`
  - `nix build .#verify-dudect -L`
  - `nix build .#verify-tamarin -L`
  - `nix build .#verify-kani -L`
  - `nix run .#security-suite`
  - `python3 scripts/validation/validate_compliance_matrix.py`
- **Interpretation**: this re-confirms the existing assumption-qualified,
  server-side claim. It does not widen the claim to cover client / SDK surfaces
  or broad RSA beyond the promoted OIDC `RS256` slices.

## Statements To Avoid Today

| Statement | Why it is too strong today | What must happen first |
|---|---|---|
| `formally verified OIDC/OAuth server and client` | The current assurance case explicitly scopes the released formal claim to server-side protocol handling only, and the new combined server/client claim gate is inactive. | Complete `spec/server-client-formal-assurance-claim.current.json`, activate the released-client claim, close hosted / publication evidence, and keep TCB-qualified wording adjacent to any broad shorthand. |
| `formally verified client SDK` | Client SDK / WASM / runtime-adapter work is still draft / roadmap material. | Ship the SDK track with its own verification boundary and release evidence. |
| `formally verified admin console` | The admin console is currently justified as a first-party control-plane UI constrained by SDK and auth-boundary audits, not as a formally verified UI surface. | Keep the current admin boundary posture, or define a separate formal/admin assurance claim if stronger wording is required. |
| `verified OIDC interoperability` | This wording implies a broader interoperability claim than the promoted `RS256` Request Object / `request_uri` / `private_key_jwt` slices and would blur unsupported or compat-only OIDC surfaces. | Define and verify the broader interoperability surface you want to claim. |
| `OAuth 2.1 / OIDC 1.0 Core is fully verified` | MUST-level verified coverage is partial; see the MUST-Level Coverage section of the verification scope for current counts. | Bring every MUST-level entry for the claimed specification to `verified`. |
| `each OIDC Core requirement is individually verified` | The `openid_core` matrix uses roll-up entries rather than one ID per discrete OIDC Core requirement. | Disaggregate the OIDC Core roll-ups and verify every resulting requirement entry. |
| `completely security-proven OIDC/OAuth implementation` | This implies the project proves OS entropy, external hosts/storage, third-party dependencies, deployment integrity, and cryptographic hardness from first principles. Those are explicit assumptions or TCB boundaries. | Use assumption-qualified / boundary-explicit wording tied to the assurance case and assumption register. |

## Target Position Ladder

1. **Current released position**
   - assumption-qualified formally verified and security-tested OIDC 1.0 / OAuth 2.1 server, with OIDC Federation runtime support
2. **After separate SDK / client assurance work**
   - released client / SDK wording, but only under a separately documented released-client policy and evidence report
3. **After combined server/client formal-assurance closure**
   - assumption-qualified formally verified server plus verified client/RP core wording, only under `spec/server-client-formal-assurance-claim.current.json` and with explicit runtime-adapter / external-dependency TCB disclosure
4. **After enterprise-readiness closure**
   - enterprise-ready identity platform wording, only after the source-managed enterprise-readiness gate is active and backed by publication-org, managed-provider, KMS/HSM, regulated-runbook, hardened-deployment, release-custody, and SLO evidence
5. **After named certification closure**
   - certified wording only for the exact certification target whose gate is active; do not use `fully certified` without naming the OIDF/OAuth/FAPI/SOC2/ISO target and linking archived evidence or public listing
6. **After bounded admin-UI assurance closure**
   - bounded admin control-plane security-boundary assurance wording, only after a separate admin UI assurance case, checked model, contract drift gates, and hosted runtime evidence exist

## Future-Gated Claim Targets

These are not claimable today. They are source-managed target contracts for
future release reviews.

| Future phrase | Required gate | Safe target wording after closure |
|---|---|---|
| `fully enterprise-ready` | `spec/enterprise-readiness-claim.current.json` must set `claim_active: true` with all required evidence complete. | `Enterprise-ready identity platform with audited release custody, regulated-operation runbooks, hardened deployment guidance, real managed-provider evidence, and KMS/HSM deployment classification.` |
| `fully certified` | `spec/certification-claim.current.json` must set `claim_active: true` for a named certification scope. | `Certified for <named scope>`; examples: `OIDF Certified OP for <plan set>` or `FAPI <profile> conformance certified`. |
| `formally verified server and client` | `spec/server-client-formal-assurance-claim.current.json` must set `claim_active: true`, and the released-client claim plus publication / hosted evidence gates must be active or complete as required. | `Assumption-qualified formally verified OIDC/OAuth server with a released client/RP SDK containing a verified client core and explicit runtime-adapter and external-dependency TCB boundaries.` |
| `formally verified UI included` | `spec/admin-ui-assurance-claim.current.json` must set `claim_active: true` for the bounded admin security boundary. | `Admin control-plane security boundary with formally specified and mechanically checked authorization/session state-machine invariants.` |

Do not use the broad literal wording if the active gate is narrower. In
particular, a bounded admin UI assurance claim must not imply that React,
browser rendering, CSS, browser extensions, OS UI behaviour, or every possible
visual interaction is formally verified.

## Japanese Wording Examples (Non-Normative)

These examples are convenience translations only. The canonical claim boundary
still lives in the English documents referenced above.

- **Current safe server wording**
  - `Aegaeon は、前提仮定付きの形式検証済み・セキュリティ検査済み OIDC 1.0 / OAuth 2.0/2.1 アイデンティティプロバイダサーバであり、OpenID Connect Federation のランタイムサポートを備える。`
- **Current safe SDK wording**
  - `Aegaeon SDK は、検証済みサーバ / コア境界を前提とした pre-release SDK 実装であり、released client claim はまだ有効化していない。`
- **Current safe admin-console wording**
  - `Aegaeon Admin Console は、@aegaeon/management-client と management-session 境界に拘束された first-party control-plane UI であり、UI 自体を形式検証済みとは主張しない。`
- **Future wording after publication-org blockers close**
  - `Aegaeon は、前提仮定付きの形式検証済み・セキュリティ検査済みサーバ実装を中核に持ち、released-client policy に従う SDK / client 実装を提供する。`
- **Future bounded server/client formal-assurance wording**
  - `Aegaeon は、前提仮定付きの形式検証済み OIDC/OAuth サーバと、検証済み client core を含む released client/RP SDK を提供する。ただし runtime adapter と外部依存は明示された TCB 境界に従う。`

## Short Public Copy (Non-Normative)

Use these only as short-form copies of the canonical wording above.

### English

- **Website / landing page**
  - `Assumption-qualified formally verified and security-tested OIDC 1.0 / OAuth 2.0/2.1 server, with OpenID Connect Federation runtime support.`
- **SDK status**
  - `Aegaeon SDK is a pre-release SDK track with a source-managed client boundary and hosted readiness gates; a released client claim is not enabled yet.`
- **Admin-console status**
  - `Aegaeon Admin Console is a first-party control-plane UI constrained by SDK and management-session boundary audits; it is not claimed as a formally verified UI surface.`

### Japanese

- **Website / landing page**
  - `Aegaeon は、前提仮定付きの形式検証済み・セキュリティ検査済み OIDC 1.0 / OAuth 2.0/2.1 サーバであり、OpenID Connect Federation のランタイムサポートを備える。`
- **SDK status**
  - `Aegaeon SDK は、source-managed な client boundary と hosted readiness gate を備える pre-release SDK track であり、released client claim はまだ有効化していない。`
- **Admin-console status**
  - `Aegaeon Admin Console は、SDK 境界と management-session 境界監査に拘束された first-party control-plane UI であり、形式検証済み UI とは主張しない。`

## Source Documents

- **Formal claim / boundary**: `docs/verification/claims/assurance-case/claim-definition.md`, `docs/verification/claims/assumptions/current-register.md`, `docs/verification/claims/crypto-allowlist.md`
- **Implementation-closure ladder**: `docs/verification/claims/verification-maturity-model.md`
- **Boundary-closure plans**: `docs/verification/workplans/verification-boundary-roadmap.md`, `docs/program-management/roadmaps/active/current-execution-plan.md`, `docs/program-management/roadmaps/active/oidc-spec-coverage-roadmap.md`
- **Runtime / security evidence**: `docs/security/security-review/README.md`, `docs/releases/evidence/beta-conformance.md`, and fresh artefacts under `artifacts/`
- **Future client / SDK track**: `docs/verification/claims/client-rp-assurance-case.md`, `docs/program-management/initiatives/sdk/client-sdk-architecture.md`, `docs/specs/verified-core-wasm.md`, `docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`
- **Future server/client formal-assurance track**: `docs/program-management/roadmaps/active/verified-server-client-formal-claim-roadmap.md`, `spec/server-client-formal-assurance-claim.current.json`
- **Admin-console control-plane boundary**: `../aegaeon-admin-console/spec/admin-sdk-boundary.current.json`, `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`
- **Admin UI assurance boundary**: `docs/verification/claims/admin-ui-assurance-case.md`, `spec/admin-ui-security-state-machine.current.json`, `docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json`
- **Future claim gates**: `spec/enterprise-readiness-claim.current.json`, `spec/certification-claim.current.json`, `spec/admin-ui-assurance-claim.current.json`, `spec/server-client-formal-assurance-claim.current.json`

## Update Rule

When a new outward-facing phrase is needed, update this document and ensure the
supporting boundary / evidence documents already justify it. Roadmaps and draft
specs may describe future capability, but they do not change the current released
product statement by themselves.
