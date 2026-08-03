# Aegaeon v0.1.0 Landing Page Structure

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This document defines the intended information architecture for the first public Aegaeon landing
page. Pair it with `aegaeon-v0.1.0-landing-page-copy.md`, which holds the working copy draft.

## Page objective

The first-launch LP should do three things in this order:

1. explain what Aegaeon is without widening the current claim
2. show why it is different from a generic OAuth/OIDC implementation
3. convert qualified interest into preview / PoC requests

## Primary audience

- engineering leaders evaluating an identity foundation
- security architects comparing build-vs-buy or replace decisions
- product/platform teams that need OAuth/OIDC but do not want to carry long-term operational debt

## Conversion goal

Primary conversion:

- preview / PoC inquiry

Secondary conversions:

- whitepaper download
- Spec Sheet download
- GitHub repository visit

## Recommended page flow

### 1. Hero

Goal:

- establish category, value, and release scope in one viewport

Must communicate:

- Aegaeon is an OAuth/OIDC platform
- the product is differentiated by high-assurance server core plus operational controls
- the initial release is OSS / Self-hosted

Recommended modules:

- eyebrow
- headline
- subheadline
- primary CTA
- secondary CTA
- support line

### 2. Problem framing

Goal:

- move the reader from "we need OAuth/OIDC" to "we need a platform that survives operations"

Must communicate:

- protocol implementation alone does not solve operational breakage
- exceptions, key handling, change control, and auditability are recurring sources of failure

### 3. Three-pillar value section

Goal:

- define the product thesis in a memorable structure

Recommended order:

1. Secure Defaults
2. Verified Core
3. Operational Controls

Reason:

- this mirrors the current program narrative and booth message

### 4. What ships now

Goal:

- avoid ambiguity about what is actually available in v0.1.0

Must communicate:

- server
- admin console
- self-hosted evaluation path

Must not imply:

- released SDK / WASM
- formally verified UI

### 5. Trust / evidence section

Goal:

- give technically literate readers enough confidence to keep engaging

Recommended treatment:

- a short claim-safe summary
- links to the assurance boundary and evidence
- no deep proof details on the main scroll path

### 6. Use cases

Goal:

- help the reader map Aegaeon to their environment quickly

Recommended use cases:

- embedded identity foundation for an existing product
- shared authentication / API protection layer across services
- identity control plane with stricter auditability and change control

### 7. FAQ

Goal:

- resolve boundary-sensitive questions before the reader bounces

Must include:

- what is included in the first release
- what is and is not inside the current formal claim
- OSS / Self-hosted posture

### 8. Final CTA

Goal:

- end the page with a concrete next step

Recommended hierarchy:

1. preview / PoC inquiry
2. whitepaper
3. Spec Sheet

## Recommended section order for desktop and mobile

1. Hero
2. Problem framing
3. Three-pillar section
4. What ships now
5. Use cases
6. Trust / evidence
7. FAQ
8. Final CTA

Note:

- On mobile, the trust / evidence section may move below the use cases if that improves readability.
- Keep the first CTA above the fold and repeat it after the final CTA block.

## Copy direction by section

### Hero copy style

- short, declarative, product-category-first
- do not lead with protocol acronyms only
- do not lead with formal methods jargon

Preferred:

- `認証認可を、実装だけでなく運用まで壊れにくくする`

Alternative:

- `OAuth/OIDC を、導入後も運用で崩れにくい基盤にする`
- `高保証コアと運用統制で、認証認可の運用負債を抑えやすくする`

### Problem framing style

- describe familiar operational pain, not abstract security theory
- keep the tone practical

Preferred opening:

- `OAuth/OIDC の課題は、実装したあとに本番運用で顕在化しやすい`

### Pillar section style

- each pillar should be one promise and one operational consequence
- avoid proof-jargon-heavy descriptions

### Trust section style

- calm and explicit
- qualify the claim without sounding defensive

Preferred phrasing:

- `現時点の対外表現は、サーバ側の security-critical な OAuth/OIDC コアに関する主張に基づきます。`

Avoid:

- `全体を完全に形式検証`
- `すべての機能を証明済み`

## Suggested wireframe notes

### Hero right-side visual

- architecture or control-plane visual
- not a cryptography diagram

### Three-pillar section

- 3 cards or 3-column layout on desktop
- stacked cards on mobile

### What ships now

- simple inclusion list with one boundary note

### Trust section

- 3 to 4 evidence links
- one short boundary disclaimer

## CTA strategy

### Primary CTA label options

- `プレビュー版を申し込む`
- `PoC を相談する`
- `評価について相談する`

Recommendation:

- use `プレビュー版を申し込む` on the public LP
- route enterprise-intent users inside the form

### Secondary CTA label options

- `ホワイトペーパーを読む`
- `Spec Sheet を見る`
- `GitHub を確認する`

Recommendation:

- keep the secondary CTA as a document download, not GitHub
- place GitHub as a lower-friction tertiary path in the trust or footer area

## Proof-boundary guardrails for LP copy

- say `server-side` when referring to the high-assurance / formally verified claim
- describe the admin console as a first-party control-plane UI
- do not say or imply that the UI itself is formally verified
- do not mix SDK / WASM launch language into the first LP
- do not let `Verified Core` visually expand to every product surface

## Evidence link block recommendation

The LP should link only to a small curated set:

- product positioning
- assurance case
- assumptions
- compliance matrix

Do not expose too many deep links in the main body.
Keep detailed verification references in a footer or "Learn more" area.

## Open production tasks

- choose final hero headline from the preferred / alternative set
- decide whether the primary CTA should be preview-led or PoC-led
- produce the hero visual and one architecture diagram
- capture 2 to 3 admin-console screenshots with stable sample data
- implement the CTA path and document-download behavior
