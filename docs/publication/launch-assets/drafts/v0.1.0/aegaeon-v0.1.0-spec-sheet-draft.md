# Aegaeon v0.1.0 Spec Sheet Draft

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This is a content draft for a one-page Spec Sheet.
Keep it concise and suitable for PDF layout.

## Document header

- Product name: `Aegaeon v0.1.0`
- Tagline: `High-assurance OAuth/OIDC platform for services and enterprise identity infrastructure`
- Release form: `OSS / Self-hosted`

## Short description

Aegaeon は、既存サービスやエンタープライズ基盤に組み込める OAuth/OIDC 基盤です。
サーバ側の高保証コア、Secure Defaults、運用統制を一体で整備し、
認証認可の実装リスクと運用リスクの低減を支援します。

## Highlights

- OAuth 2.0 / OAuth 2.1 server
- OpenID Connect 1.0 provider
- OpenID Connect Federation runtime support
- Secure Defaults for risky protocol / policy areas
- Admin Console for control-plane operations
- Auditability, RBAC, and key / secret lifecycle controls

## Current release boundary

- Current claim-bearing surface:
  - server-side OAuth/OIDC core
- Current non-claim-bearing but included surface:
  - Aegaeon Admin Console as a first-party control-plane UI
- Not part of the initial release claim:
  - formally verified UI wording
  - released SDK / WASM client claim

## Standards / runtime coverage

- OAuth 2.0 / 2.1
- OpenID Connect 1.0
- PKCE (S256)
- PAR
- DPoP
- Dynamic Client Registration / Management
- Revocation / Introspection
- OpenID Connect Federation runtime support

## Security and assurance posture

- Assumption-qualified formally verified and security-tested server claim
- Security BCP-oriented default posture
- Formal methods and security testing maintained alongside the Rust implementation
- Explicit assumptions and compatibility boundaries documented

## Operational controls

- configuration changes under management-plane control
- audit trail and role-based control paths
- key and secret lifecycle handling
- control-plane operations through Aegaeon Admin Console

## Target use cases

- embedding an OAuth/OIDC foundation into an existing service
- standardizing shared authentication and API protection across multiple services
- tightening change control and auditability for identity infrastructure

## Deployment / evaluation

- Delivery model: `OSS / Self-hosted`
- Evaluation path: `Preview / PoC consultation`
- Recommended companion materials:
  - Whitepaper
  - Product page
  - Preview request form

## Footer block

- Website URL
- GitHub URL
- Contact / preview request URL
- Version / date
