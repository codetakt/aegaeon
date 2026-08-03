# Aegaeon Event One-Page Handout

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This file is the content draft for a one-page printed handout or downloadable event leave-behind.
It is designed for a single A4 page, portrait or landscape.

## Primary objective

- help visitors remember what Aegaeon is after leaving the booth
- make it easy to share internally with engineering / security stakeholders
- drive readers to the whitepaper and preview / PoC request

## Layout recommendation

Use a simple 5-block structure:

1. headline and one-line definition
2. three pillars
3. what ships now
4. use cases
5. QR codes and CTA

## Draft content

### Header

#### Product name

Aegaeon

#### Tagline

高保証コアと運用統制を備えた OAuth/OIDC 基盤

#### One-line definition

既存サービスやエンタープライズ基盤に組み込める OAuth/OIDC サーバと、
それを支える control-plane を一体で整備するためのプラットフォームです。

### Three pillars

#### Secure Defaults

危険な構成を避けやすい既定値と、例外設定を統制下で扱う運用を支援します。

#### Verified Core

PKCE、DPoP、JOSE など、サーバ側の security-critical な OAuth/OIDC コア領域に
高保証アプローチを適用します。

#### Operational Controls

変更管理、監査、RBAC、鍵・秘密情報のライフサイクル管理を、
運用者が追跡しやすい形で扱えるようにします。

### What ships now

- OAuth 2.0 / OAuth 2.1 server
- OpenID Connect 1.0 provider
- OpenID Connect Federation runtime support
- Aegaeon Admin Console による control-plane 操作
- OSS / Self-hosted evaluation path

### Use cases

- 既存プロダクトへの認証基盤の組み込み
- 複数サービスにまたがる共通認証・API 保護基盤の整備
- 鍵運用、監査、設定変更まで含めた運用統制の強化

### Boundary note

現時点の高保証に関する対外表現は、サーバ側の security-critical な OAuth/OIDC コアを
対象としたものです。Aegaeon Admin Console は first-party control-plane UI ですが、
UI 自体を形式検証済みとは表現しません。

### CTA block

資料と評価導線:

- ホワイトペーパー
- Spec Sheet
- プレビュー版 / PoC 相談

### QR labels

- `Whitepaper`
- `Spec Sheet`
- `Preview / PoC`

## Design notes

- keep the page easy to scan in under 30 seconds
- avoid long standards lists
- use one diagram at most
- prioritize one QR for conversion and one QR for content

## Optional back-side content

If a two-sided version is needed, add:

- simple architecture diagram
- short demo flow
- contact or meeting-booking URL
