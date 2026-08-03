# Aegaeon v0.1.0 Landing Page Copy Draft

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This draft is for the first public product page / launch LP.
The copy intentionally stays inside the current server-side claim boundary.

For the page-level information architecture and CTA design, see
`aegaeon-v0.1.0-landing-page-structure.md`.

## Page goal

- Explain what Aegaeon is in one screen
- Show why it is different from a generic OAuth/OIDC server
- Convert interest into preview / PoC inquiries

## Hero

### Eyebrow

High-assurance OAuth/OIDC platform

### Headline

認証認可を、実装だけでなく運用まで壊れにくくする

### Subheadline

Aegaeon は、既存サービスやエンタープライズ基盤に組み込める OAuth/OIDC 基盤です。
サーバ側の高保証コア、Secure Defaults、運用統制を一体で整備し、導入時の実装リスクと
運用で起こる事故の両方を抑えやすくします。

### Primary CTA

プレビュー版を申し込む

### Secondary CTA

ホワイトペーパーを読む

### Support copy

OSS / Self-hosted で提供予定。
初期リリースでは、Aegaeon Server と Aegaeon Admin Console を中心に公開します。

## Section 1: Why Aegaeon

### Heading

OAuth/OIDC は、実装できても運用で崩れやすい

### Body

認証認可の問題は、プロトコルを実装した時点では終わりません。
危険な設定の例外化、鍵運用の属人化、変更時の事故、監査不備など、
本番環境では運用由来のリスクが積み上がります。

Aegaeon は、OAuth/OIDC の実装と運用統制を切り離さずに扱うことで、
長期運用に耐える認証認可基盤を目指しています。

## Section 2: Three pillars

### Heading

3つの柱で、壊れにくい認証認可基盤へ

### Pillar 1

#### Title

Secure Defaults

#### Description

危険な構成を避ける既定値を採用し、例外設定も統制下で扱いやすくします。

### Pillar 2

#### Title

Verified Core

#### Description

PKCE、DPoP、JOSE など、サーバ側の security-critical な OAuth/OIDC コア領域に
高保証アプローチを適用しています。

### Pillar 3

#### Title

Operational Controls

#### Description

設定変更、監査、RBAC、鍵・秘密情報のライフサイクル管理を、
運用者が追跡しやすい形でまとめて扱えます。

## Section 3: What ships in v0.1.0

### Heading

初回公開で提供するもの

### Body

- OAuth 2.0 / OAuth 2.1 対応サーバ
- OpenID Connect 1.0 対応サーバ
- OpenID Connect Federation runtime support
- Aegaeon Admin Console による control-plane 操作
- Self-hosted を前提にした導入・評価フロー

### Note

Aegaeon Admin Console は first-party control-plane UI ですが、
UI 自体を形式検証済みとは位置付けません。
形式的な主張の中心はサーバ側にあります。

## Section 4: Evidence / trust section

### Heading

公開時点の主張と根拠

### Body

Aegaeon の現時点の対外表現は、
「前提仮定付きの形式検証済み・セキュリティ検査済み OIDC 1.0 / OAuth 2.0/2.1
アイデンティティプロバイダサーバ」
というサーバ側の主張に基づきます。

この表現は、F*、Tamarin、Kani、JOSE / conformance / security-suite などの
検証・試験成果と、明示的な前提条件の上で成り立っています。

### Evidence links

- Assumption Register
- Assurance Case
- Compliance Matrix
- Security review summary

## Section 5: Use cases

### Heading

想定する導入シーン

### Use case 1

既存プロダクトに認証基盤を組み込みたい

### Use case 2

複数サービスの共通認証・API 保護基盤を統一したい

### Use case 3

鍵運用、監査、変更管理まで含めて統制を確立したい

## Section 6: Call to action

### Heading

まずは評価用の資料をご確認ください

### Body

ホワイトペーパーと Spec Sheet を公開しています。
プレビュー版や PoC の相談も受け付けています。

### CTA buttons

- ホワイトペーパーをダウンロード
- Spec Sheet をダウンロード
- プレビュー版を申し込む

## FAQ draft

### Q. Aegaeon は何を公開しますか

Aegaeon Server と、これを運用するための Aegaeon Admin Console を中心に公開します。

### Q. 形式検証済みなのは製品全体ですか

現時点の主張はサーバ側の security-critical な OAuth/OIDC コアに関するものです。
Admin Console は first-party control-plane UI ですが、UI 自体を形式検証済みとは
表現しません。

### Q. SaaS ですか、Self-hosted ですか

初回公開では OSS / Self-hosted を前提とした評価導線を中心に案内します。

## Copy to avoid

- 「製品全体が形式検証済み」
- 「管理UIも形式検証済み」
- 「SDK / WASM も同時リリース済み」
- 「すべての暗号・すべてのクライアント面まで検証済み」
