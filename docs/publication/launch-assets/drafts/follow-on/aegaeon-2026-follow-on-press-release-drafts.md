# Aegaeon 2026 Follow-on Press Release Drafts

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this
> as approved release wording, and check `docs/product-positioning.md` before reuse.

This file keeps follow-on announcement copy outside the active launch schedule.
Do not assign publication dates here; use the active launch package and release
evidence gates before promoting any block.

## Aegaeon SDK v0.1.0

### Headline

Aegaeon、Verified Core の WASM と公式 SDK を公開

### Subheadline

フロントエンド統合の実装リスクを削減し、安全な導入を加速

### Lead

Aegaeon は、Verified Core を WASM として提供し、TypeScript / Rust SDK を公開しました。
トークン検証、DPoP など実装差分が事故につながりやすい領域を共通化し、統合実装のばらつきを抑制します。

### Body

- Verified Core を WASM として提供し、統合側の実装差分を減らします
- 公式 SDK により、推奨の統合パターンと安全なデフォルトを標準化します
- 既存システムへの組み込みを短期間で進めやすくし、導入の再現性を高めます
- 管理 API クライアントにより、運用統制をアプリケーション側から一貫して扱えるようにします

### Quote template

「導入の成否は、統合実装の品質と再現性で決まります。WASM と SDK で危険な再発明を減らし、
運用統制まで含めて導入を加速します。」

— `[代表者名・役職]`

### Availability block

- SDK: `TypeScript / Rust`
- Verified Core: `WASM 提供`
- 資料: `統合ガイド`, `更新版 Spec Sheet`

### CTA

統合ガイドと更新版 Spec Sheet は公開ページから入手できます。評価・導入相談を受け付けています。

### Whitepaper title

フロント統合を事故らせない：Verified Core WASM と SDK で OAuth/OIDC 実装リスクを削減

## Aegaeon v0.2.0 Education Ready

### Headline

Aegaeon、LTI 1.3 準拠の Education Ready を提供開始

### Subheadline

教育機関向けの導入手順と運用統制を標準化

### Lead

Aegaeon は、LTI 1.3 準拠の Education Ready を提供開始しました。教育機関・教育サービス
事業者が求める導入容易性と、監査、鍵運用、RBAC、設定変更管理などの運用統制を一体で提供します。

### Body

- LTI 1.3 準拠により、教育機関での利用をスムーズに開始できます
- 鍵運用、監査、RBAC、設定変更管理を標準装備し、長期運用を支援します
- 既存 LMS・教育サービスとの統合を前提に、導入の再現性を高めます
- セキュリティ既定値を維持しながら、教育現場の要件に合わせた運用を可能にします

### Quote template

「教育は運用期間が長く、統制と監査が重要です。Aegaeon は導入のしやすさと、事故らない
運用を同時に提供します。」

— `[代表者名・役職]`

### Availability block

- `Education Ready パッケージ`
- `教育向け統合ガイド`
- `更新版 Spec Sheet`

### CTA

教育向け統合ガイドと更新版 Spec Sheet は公開ページから入手できます。評価・導入相談を受け付けています。

### Whitepaper title

教育機関がすぐ使える LTI 1.3：導入と運用統制を標準化した認証認可基盤

## Aegaeon SAML Facade v0.1.0

### Headline

Aegaeon、SAML Facade と監査可能な属性マッピング機構を提供開始

### Subheadline

OIDC を中核に据えたまま、レガシーエンタープライズ統合を実現

### Lead

Aegaeon は、SAML Facade と属性マッピング機構を提供開始しました。OIDC を中核に据えながら、
SAML を必要とする既存環境との統合を境界化し、属性変換や個別要件を監査・変更管理の対象として
統制下で扱えるようにします。

### Body

- OIDC を中核に維持しながら、SAML 統合を明示的な境界として吸収します
- 属性マッピングを監査・変更管理の対象とし、例外設定の恒久化を抑えます
- 組織固有の要件に対応しつつ、統合運用の再現性と統制を確立します
- 既存システムからの段階移行を進めやすくし、移行時の運用負債を抑制します

### Quote template

「統合の難しさは技術そのものより、例外をどう運用し続けるかにあります。Aegaeon は SAML と
属性マッピングを統制下に置くことで、移行と長期運用を両立させます。」

— `[代表者名・役職]`

### Availability block

- `SAML Facade`
- `属性マッピング機構`
- `エンタープライズ統合ガイド`
- `更新版 Spec Sheet`

### CTA

エンタープライズ統合ガイドと更新版 Spec Sheet は公開ページから入手できます。評価・導入相談を受け付けています。

### Whitepaper title

OIDC を中核に、レガシー統合を吸収する：SAML Facade と監査可能な属性マッピング
