# Aegaeon v0.1.0 Whitepaper Outline

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

## Working title

認証認可を事故らせないために:
高保証な中核実装と運用統制で、実装リスクと運用負債の低減を支援

## Purpose

This whitepaper should bridge technical credibility and business relevance.
It should explain why Aegaeon exists, what problem it addresses, what is claim-safe today,
and why that matters for teams evaluating an identity platform.

## Target audience

- product / platform engineering leaders
- security architects
- enterprise architects
- teams evaluating an OAuth/OIDC foundation for an existing service

## Executive summary draft

OAuth/OIDC の導入では、プロトコル実装だけでなく、その後の運用統制が品質を左右します。
危険な例外設定の固定化、鍵運用の属人化、設定変更の事故、監査不備といった問題は、
導入後に顕在化しやすい代表例です。Aegaeon は、サーバ側の security-critical な
OAuth/OIDC コアに高保証アプローチを適用しつつ、Secure Defaults と運用統制を
組み合わせることで、認証認可を長期運用で壊れにくくすることを目指します。

## Suggested structure

### 1. Why identity breaks in operations

- implementation quality alone is not enough
- examples of operational failure modes
- why exceptions, key handling, and change control matter

### 2. What Aegaeon is

- product definition
- intended deployment patterns
- current shipped surfaces: server + admin console
- first release scope

### 3. Aegaeon's design principles

- Secure Defaults
- Verified Core
- Operational Controls

### 4. What "high-assurance" means here

- current claim-safe wording
- explicit assumptions / trust boundary
- what is inside the current server claim
- what is intentionally outside the claim

### 5. Operational model

- configuration changes under control
- control plane vs data plane split
- auditability and key/secret lifecycle handling

### 6. Evaluation scenarios

- embedded identity foundation for an existing product
- shared enterprise authentication / API protection core
- teams replacing ad hoc identity operations with governed changes

### 7. How to start

- preview / PoC request
- self-hosted evaluation path
- GitHub and documentation entrypoints

## Figures / visuals needed

- one architecture diagram: data plane vs control plane
- one 3-pillar diagram: Secure Defaults / Verified Core / Operational Controls
- one screenshot: Admin Console
- one trust-boundary figure: current server claim vs surrounding TCB / assumptions

## Source inputs to cite or adapt

- `docs/product-positioning.md`
- `docs/development/current-delivery-context.md`
- `docs/verification/claims/assurance-case/README.md`
- `spec/compliance-matrix.yaml`
- `README.md`

## Writing guardrails

- explain formal assurance in plain Japanese
- avoid implying the entire product, including UI, is formally verified
- avoid promising SDK / WASM release in the first launch paper
- keep the tone explanatory rather than academic

## CTA

- download the Spec Sheet
- request a preview / PoC discussion
- visit the public GitHub repository
