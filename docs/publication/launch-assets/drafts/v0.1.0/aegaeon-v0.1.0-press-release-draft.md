# Aegaeon v0.1.0 Press Release Draft

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This file pulls the first-launch press release into a standalone working draft.
Use `docs/product-positioning.md` as the boundary authority before publication.

## Headline

Aegaeon、既存サービスに組み込める OAuth/OIDC 基盤「Aegaeon v0.1.0」を公開

## Subheadline

サーバ側の高保証コアと運用統制により、認証認可の実装・運用リスクの低減を支援

## Lead

Aegaeon は、既存サービスやエンタープライズ基盤に組み込んで利用できる
OAuth 2.0 / OpenID Connect 対応プラットフォーム「Aegaeon v0.1.0」を公開しました。
サーバ側のセキュリティ上重要なコア領域に高保証アプローチを適用するとともに、
自社提供の Aegaeon Admin Console により、設定変更、監査、鍵運用を一元的に扱える
運用基盤を提供します。これにより、例外設定の固定化、鍵運用の属人化、設定変更時の
事故、監査不備といった運用起因のリスクの低減を支援します。

## Body

Aegaeon は、OAuth/OIDC を導入するためのソフトウェアにとどまらず、
安全に運用し続けるための基盤として提供します。主な特長は以下の通りです。

### 1. Secure Defaults

危険な構成を避ける既定値を採用し、例外設定も統制の下で管理できるようにします。

### 2. Verified Core

PKCE、DPoP、JOSE など、サーバ側のセキュリティ上重要な OAuth/OIDC 領域に
高保証アプローチを適用します。

### 3. Operational Controls

自社提供の Aegaeon Admin Console を通じて、変更管理トランザクション、監査、
RBAC、鍵・秘密情報のライフサイクル管理を一貫して扱えるようにします。

### 4. 想定ユースケース

既存製品への認証基盤の組み込みや、エンタープライズにおける共通認証・API 保護基盤
としての導入を想定しています。

## Quote template

「認証認可の課題は、実装時だけでなく運用段階でも生まれます。Aegaeon は、
サーバ側の中核部分と運用統制を切り分けて整備することで、導入時の実装リスクだけで
なく、運用のなかで起きる事故や負債の抑制も支援します。」

— `[代表者名・役職]`

## Availability block

- 提供形態: `OSS / Self-hosted`
- 評価: `PoC 相談受付開始`
- 資料: `ホワイトペーパー`, `Spec Sheet`

## CTA

ホワイトペーパーと Spec Sheet は公開ページから入手できます。
評価・導入相談を受け付けています。

## Boilerplate placeholders

- 会社概要
- 代表者名
- 問い合わせ先
- 会社URL

## Publication guardrails

- `Verified Core` はサーバ側の security-critical な OAuth/OIDC コアを指す
- `Aegaeon Admin Console` を形式検証済み UI と表現しない
- SDK / WASM / released client claim を本稿に混在させない
