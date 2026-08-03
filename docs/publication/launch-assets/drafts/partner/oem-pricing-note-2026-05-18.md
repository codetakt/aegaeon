# OEM Partner Pricing Note (2026-05-18)

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This note records the current commercial recommendation for a likely OEM /
reseller-style identity-platform deal so future agent sessions do not need to
reconstruct the business context from chat history alone.

## Context

- prospective partner sells accounting-document software to SMB customers
- current growth signal: more than 600 additional customer companies per month
- partner appears strong in sales and is expected to expand into adjacent
  products such as attendance management and workflow
- goal: keep the identity-only entry price low enough for SMB packaging while
  preserving margin through identity-as-a-service add-ons
- commercial target: recover more than JPY 30M in year 1 or, at worst, within
  the first two contract years

## Recommended Commercial Shape

Prefer **Managed Cloud** as the default offer.

Why:

- it keeps deployment / upgrade / support custody on the Aegaeon side
- it is easier to price as a platform minimum plus downstream usage and
  optional packs
- it avoids turning the whole deal into a one-time support-license negotiation

Recommended structure:

1. `Core Identity Platform`
   - annual minimum guarantee: **JPY 15M**
   - includes baseline tenant / directory / login / session / user lifecycle
     platform capability for the partner's SMB package
2. `Onboarding / Migration`
   - one-time: **JPY 6M**
   - covers initial setup, packaging alignment, launch support, and migration
3. `Enterprise Access Pack`
   - **JPY 30k / enterprise connection / month**
   - intended for SSO / directory sync / stronger workforce-style federation
     needs at the downstream customer layer
4. `Governance Pack`
   - **JPY 3M / year**
   - admin-grade identity-as-a-service controls, policy, audit, stronger lifecycle / access
     governance features
5. `Additional Product Pack`
   - **JPY 2M / product / year**
   - for attendance, workflow, and future adjacent product lines sharing the
     same identity platform
6. `Premium Support / TAM`
   - optional: **JPY 3M-5M / year**

## Negotiation Guidance

- Preferred anchor:
  - annual minimum `JPY 15M`
  - onboarding `JPY 6M`
  - enterprise access `JPY 30k / connection / month`
  - governance `JPY 3M / year`
  - additional product `JPY 2M / product / year`
  - term: **2 years**, annual billing, quarterly true-up
- Walk-away floor:
  - annual minimum should not drift materially below **JPY 12M**
  - onboarding should not drift materially below **JPY 5M**
- Upside case:
  - annual minimum `JPY 18M`
  - onboarding `JPY 8M`
  - premium support attached

## Revenue Logic

This structure keeps the identity base affordable for SMB packaging while
moving the real monetization to the places where the partner's strong sales
motion is most likely to expand:

- enterprise federation / SSO connectivity
- governance and operational-control needs
- cross-sell into additional applications on the same identity platform

That is the intended route to a `JPY 30M+` recovery profile without making the
core identity SKU too expensive to embed into the partner's base package.
