# Management UI & TypeScript SDK Delivery Record

Last updated: 2026-05-14

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

> **Status note (2026-05-14):** This historical record captures the backend-side coordination
> assumptions for the initial SDK / control-plane implementation track. The sibling
> `../aegaeon-sdk` and `../aegaeon-admin-console` repositories now carry the active SDK /
> control-plane implementation and hosted workflow inventory. The remaining cross-repository
> execution sequence is tracked in `../../roadmaps/active/management-platform-follow-on-plan.md`, and the
> shared quality baseline / drift policy are tracked in
> `../../../policies/management-platform-quality-profile.md`. This record does not redefine the
> released product statement or formal claim; use `../../../product-positioning.md` and
> `../../../verification/claims/assurance-case.md` for those.
> **Implementation snapshot (2026-05-14):**
>
> - `../aegaeon-sdk` now carries the package workspaces for `@aegaeon/verified-core`, `@aegaeon/runtime-node`, `@aegaeon/runtime-web`, `@aegaeon/management-client`, `@aegaeon/issuer-spa`, and `@aegaeon/rp-core`.
> - `../aegaeon-sdk/.github/workflows/` currently carries `verify-core.yml`, `ci.yml`, `lint.yml`, `playwright.yml`, `managed-provider-evidence.yml`, `client-claim-promotion.yml`, `released-client-readiness.yml`, and `publish.yml`.
> - `../aegaeon-sdk/sdk/spec/` now carries the source-managed workflow / evidence / custody / claim contracts needed for hosted promotion and readiness gates.
> - `../aegaeon-admin-console` now consumes `@aegaeon/management-client` as its only SDK dependency, source-manages the current SDK/auth boundary in `spec/admin-sdk-boundary.current.json` and `spec/admin-auth-boundary.current.json`, and currently carries hosted workflows `ci.yml`, `lint.yml`, and `stack-e2e.yml`.
> - The compose-backed admin-console lane and hosted stack lane exist; what remains is not “build the first UI/SDK surface” but “promote the existing surfaces through publication custody, hosted evidence, and final operational hardening”.

## 0. Current execution delta

The original sequence in this document assumed the backend repository would first emit a reference
scaffold and that the actual SDK / UI work would happen later. That assumption is now outdated.

What is already materially present in sibling repositories:

- `@aegaeon/management-client` exists and is the enforced dependency boundary for the admin console.
- `@aegaeon/issuer-spa` and `@aegaeon/rp-core` alpha packages exist in the SDK repository.
- Hosted workflow inventories and source-managed evidence contracts exist in both the SDK and
  admin-console repositories.
- The admin console already has a stack-backed browser lane that drives a sibling backend and SDK
  workspace together.

Therefore the active remaining work for the broad management-platform track is:

1. apply the source-managed branch-protection / repository-settings / release-custody contracts in
   the real publication organization
2. run the managed-provider evidence lane against provisioned commercial tenants and feed those
   artifacts into the hosted promotion/readiness gates
3. publish the SDK packages and activate the released client claim only after the hosted evidence
   and custody gates are satisfied
4. complete regulated-environment operational runbooks and the remaining KMS/HSM-backed OIDC
   signing-key work on the backend side

## 1. 背景と目的

- OAuth/OIDC の server-side Sprint (OAuth 0–7, OIDC-1…5) は完了済み。
- Management Console と SDK 実装は別リポジトリで進行しており、alpha の package/workflow
  baseline はすでに存在する。現在の焦点は初期実装そのものではなく、境界固定、
  hosted evidence、release custody、公開準備である。
- Verified Core (EverCrypt/HACL\* 基盤) を WASM として公開し、管理 UI・外部 SPA
  クライアント・RP 用 SDK が共通基盤を利用できるようにする。
- 将来的に FIPS 対応も選択肢になるが、現時点では EverCrypt/HACL\* を前提とし、FIPS は後続課題として記録する。

## 2. 依存関係（論理順序）

```text
Verified Core (F*/Low*/KaRaMeL → WASM)
        │
        ▼
Runtime Adapters (TypeScript Web/Node, Rust FFI)
        │
        ├── Management API Client SDK (@aegaeon/management-client)
        ├── Issuer SPA SDK (@aegaeon/issuer-spa)
        └── RP/外部クライアント SDK (@aegaeon/rp-core)
             │
             ▼
      Management UI 実装 (別リポジトリ)
```

- 注記（リポジトリ分割）:
  - TypeScript SDK / Management UI の実装は別リポジトリ（`aegaeon-sdk` 等）を正本とする。
  - 本リポジトリは Verified Core の抽出 artefact（例: `artifacts/verified-core/`）とサーバ実装を提供し、
    SDK 側はそれを fetch して利用する。
  - 本ドキュメント内の `pnpm ...` は SDK リポジトリ側での実行を指す（本リポジトリの `package.json` は SDK 開発用ではない）。

- すべての SDK は Verified Core を利用する。現在は artifact/handoff と package boundary
  が揃っており、残る論点は公開用 custody と hosted evidence の昇格である。
- Management UI の MVP には `@aegaeon/management-client` が必須。同時に SPA 認証フロー（PKCE/DPoP/state/nonce）が Verified Core 経由で提供される必要がある。

### Definition of Ready (横断)

各スプリントの開始条件として、以下を満たしていることを確認する:

1. `docs/specs/management-plane-phase1.md` と `docs/program-management/initiatives/sdk/client-sdk-architecture.md` が最新の決定事項（EverCrypt/HACL\* 暗号ポリシー、FIPS 検討課題、フェデレーション要件）を反映している。
2. 該当スプリントで触れる F\*/Rust/TypeScript モジュールがメインブランチでビルド・テスト可能であり、未解決のブロッカー Issue が無い（Zulip/Issue tracker にて確認）。
3. 依存するアーティファクト (WASM, npm/crates package, OpenAPI スキーマ) の生成方法が `docs/` もしくは `scripts/` に明文化され、`nix flake check` が現状グリーンである。
4. セキュリティ・プロダクト観点のレビュー担当（security architect / product owner）がキックオフ前に Definition of Ready checklist を承認している。

## 3. 予定スプリントと成果物（依存順）

### Sprint A — Verified Core Extraction & WASM 基盤

Current status (2026-05-12):

- backend-side extraction / packaging baseline is present
- sibling SDK repository now consumes the resulting verified-core artifact shape
- remaining work is publication custody and final released-package rollout, not initial scaffolding

#### Definition of Ready

- Verified Core に含める F\* モジュールの一覧と依存グラフが `docs/specs/verified-core-wasm.md` に記載済みで、`fstar --verify_all` がローカルで緑。
- `scripts/extraction/run_verified_core_lowstar.sh` の雛形が存在し、EverCrypt/HACL\* のソース取得経路が `nix develop` から確認済み。
- `docs/program-management/initiatives/sdk/sdk-repository-plan.md` に SDK リポジトリ構成案（fetch 手順、CI 方針）がまとまっている。
- SDK CI 方針が `docs/program-management/initiatives/sdk/sdk-ci-plan.md` に整理されている。
- SDK 実装の詳細手順が `docs/program-management/initiatives/sdk/sdk-implementation-guide.md` にまとまっている。

**Goal**: F\* Verified Core を wasm32-wasi として抽出し、署名付き artefact を提供する。

Scope:

- F\* モジュールの整理（PKCE、DPoP、nonce/state、JWK/JWT 検証、リクエスト正規化）。
- KaRaMeL → C → wasm32-wasi ビルドパイプライン (`scripts/extraction/run_verified_core_lowstar.sh` + `scripts/extraction/package_verified_core.sh`)。
  - 現状: packaging スクリプトで `verified_core.wasm`／`*.sha256`／`*.sri`／`manifest.json` を `artifacts/verified-core/` に配置。
  - 次段階: WASM artefact の署名 (Ed25519)・SBOM 生成と C ABI (thin wrapper) + smoke testsを追加。
- Verified Core artefact は本リポジトリで管理し、上位層（Runtime Adapter / Domain SDK）は専用リポジトリ `aegaeon-sdk` へ切り出す方針を文書化。
- `docs/program-management/initiatives/sdk/client-sdk-architecture.md` に 3 層（Core Loader → Runtime Adapter → Domain SDK）構成とリポジトリ分割ルールを反映。
- `scripts/extraction/run_verified_core_lowstar.sh` を実装し、PKCE/DPoP/JWT モジュールの `.krml` 生成まで自動化。

DoD:

1. `scripts/extraction/package_verified_core.sh` が `nix develop` 環境で緑になり、artefact にハッシュ/manifest が添付されている。
2. Rust: `cargo test -p aegaeon-core`（Rust FFI smoke）が緑。TypeScript: SDK リポジトリで WASM ロード smoke が緑（例: `pnpm test --filter @aegaeon/verified-core`）。
3. `docs/program-management/initiatives/sdk/client-sdk-architecture.md` と `docs/specs/verified-core-wasm.md` にビルド手順／署名・SBOM方針／リポジトリ分割が追記されている。
4. Artefact (WASM, hash manifest, sig) が `artifacts/verified-core/` に保存され、SDK リポジトリ向けに fetch 手順が提示されている（例: `pnpm run fetch-core`）。

> **現状 (2026-02-17)**
> WASM extraction pipeline functional: `package_verified_core.sh` generates `verified_core.wasm` + hash/manifest in `artifacts/verified-core/`.
> Phase 9 Sprint A 進行中:
>
> - C ABI thin wrapper (`verified_core_shim.c`) 実装中 — KaRaMeL 出力に対する FFI エントリポイント定義。
> - WASM smoke tests 作成中 — PKCE challenge generate/verify, DPoP header 生成の往復テスト。
> - Artifact manifest (`manifest.json`) 完成・署名フロー整備中 — Ed25519 署名 + SBOM 生成。
> - 残タスク: Low\* Warning 15 の解消方針策定、Token/PkJWT モジュールの抽出確認、Rust/TypeScript smoke tests、署名・SBOM・配信フロー整備。

### Sprint B — Runtime Adapters (TS/Rust)

Current status (2026-05-12):

- sibling SDK repository now carries active `runtime-node` / `runtime-web` packages and hosted
  browser lanes
- remaining work is package publication, provenance/custody promotion, and post-TypeScript
  language rollout

#### Definition of Ready

- Sprint A の artefact (`verified_core.wasm` + hash/manifest、署名・SBOMは後続) が `artifacts/verified-core/` にコミットされ、検証手順書が存在する。
- TypeScript/Rust それぞれのリポジトリに npm/crates publishing トークンの準備状況が確認され、内部レジストリ/ crates.io への publish フローが整っている。
- Web/Node/Rust 向けの例示 API 仕様が `docs/program-management/initiatives/sdk/client-sdk-architecture.md` に反映済みで、セキュリティレビュー（CSP, SecureContext 前提）が完了している。

**Goal**: WASM Core を呼び出す TypeScript (Web/Node) と Rust FFI の薄いアダプタを提供。

Scope:

- `@aegaeon/verified-core` パッケージ: WASM ローダ、JSON Schema Validation、Web/Node 双方サポート。
- `aegaeon-core` Rust crate: `no_std` 対応、`zeroize` ベースの秘密管理。
- SecureContext チェック、SRI/integrity 検証、エラー伝播 (`Result`, `ErrorCode`) の統一。
- ブラウザ/E2E smoke: PKCE チャレンジ生成→検証、DPoP header 生成、JWK 署名検証の往復テスト。

DoD:

1. SDK リポジトリで TypeScript パッケージが npm private registry に publish 可能 (`pnpm publish --dry-run` 緑)。
2. Rust crate `cargo publish --dry-run` 緑、`cargo audit` クリア。
3. Runtime adapter の API が `docs/program-management/initiatives/sdk/client-sdk-architecture.md` と API Reference (README) に記載。
4. ブラウザ (Playwright)／Node (Vitest)／Rust (unit test) の CI ジョブが緑。

### Sprint C — Management API Client SDK

Current status (2026-05-12):

- sibling SDK repository now carries an active alpha `@aegaeon/management-client`
- sibling admin-console repository now consumes that package as its only SDK dependency and audits
  the boundary fail-closed
- remaining work is publication hardening, not first implementation

#### Definition of Ready

- OpenAPI v1 スキーマ (`generated/openapi/aegaeon-management-api.v1.json`) が最新で、Version bump 方針が product/security で承認済み。
- セッション管理・CSRF ポリシーが `docs/specs/management-plane-phase1.md` に定義され、バックエンド実装が最低限 API スタブを提供している。
- 管理 UI リポジトリが SDK のベータ版を取り込むための feature flag / DI 構造を用意し、共同開発体制が整っている。

**Goal**: 管理 UI が使う REST クライアント (`@aegaeon/management-client`) を提供。

Scope:

- OpenAPI (管理 API v1) からの型生成 + runtime validation (`zod` or `valibot`)。
- CSRF トークン／Origin チェック／teamId 付与の共通ヘルパー。
- サーバー側 cookie セッション連携（SameSite=Lax, double-submit token）。
- `ManagementSession` ラッパーとローテーション対応。
- Error handling (`errorCode`, retry policy) と監査ログ連携。

DoD:

1. SDK リポジトリで自動生成コード + ハンドラの `pnpm lint && pnpm test` が緑。
2. `examples/management-console` (mock server) での end-to-end smoke が CI で走る。
3. README に統合手順（Bootstrapping → Login → API 呼び出し）が記載。
4. OSS/Enterprise いずれでも利用可能な設定フラグが documented。

### Sprint D — SPA / Issuer SDK

Current status (2026-05-12):

- sibling SDK repository now carries an active alpha `@aegaeon/issuer-spa`
- local mock-upstream, local Aegaeon-provider, Dex, Keycloak, and optional managed-provider lanes
  are represented in the current repository/workflow layout
- remaining work is hosted managed-provider evidence, released wording activation, and publication

#### Definition of Ready

- Sprint B で提供された Web Adapter が Playwright smoke を通過し、CSP/Trusted Types 前提のエラーパターンが洗い出されている。
- SPA の要件（認証 UX、セッション保持、DPoP ヘッダ生成）が `docs/program-management/initiatives/sdk/client-sdk-architecture.md` に明文化され、UI チームと合意されている。
- 管理プレーン `/authorize` → `/token` の E2E モック環境が立ち上げられ、SDK から利用可能な状態である。

**Goal**: SPA 向けの Auth クライアント (`@aegaeon/issuer-spa`) を Verified Core 上に構築。

Scope:

- PKCE/DPoP/State/Nonce の発行・検証を Core 経由で提供。
- Redirect handling, session storage (Web Crypto + Credential Management API)。
- Error boundary、CSP/Trusted Types を前提にしたフック/コンポーネント。
- Example: Next.js/React での統合サンプル。

DoD:

1. ブラウザ E2E (Playwright) で Auth Code フロー往復が緑。
2. Token/refresh handling, Storage fallback (IndexedDB/localStorage guarded) のテスト完備。
3. `docs/program-management/initiatives/sdk/client-sdk-architecture.md` の対応セクション更新。

### Sprint E — RP Core SDK & Federation Wiring

Current status (2026-05-12):

- sibling SDK repository now carries an active alpha `@aegaeon/rp-core`
- higher-level federated login orchestration exists at the package/layout level
- remaining work is promotion from alpha/runtime-readiness into published/released status, plus
  any additional backend KMS/HSM integration needed for the broader management-platform story

#### Definition of Ready

- 外部 IdP (Google Workspace 等) のテストアカウントと mock IdP が準備され、JWKS キャッシュ/属性マッピング仕様が `docs/program-management/initiatives/sdk/client-sdk-architecture.md` に確定している。
- フェデレーション設定 (`federation` ブロック) の DB Schema / Migration 草案が `docs/specs/management-plane-phase1.md` に追記されている。
- セキュリティチームが Federation Threat Model (STRIDE) の下書きを用意し、主要リスクへの対策案が合意されている。

**Goal**: 外部 IdP (例: Google Workplace) への RP フローを支える `@aegaeon/rp-core` とサーバー設定を提供。

Scope:

- Authorization Code + PKCE, ID Token/JWK 検証、属性マッピング DSL (WASM sandbox)。
- Management API での `federation` ブロック CRUD、監査イベント整備。
- サーバー側 RP モード path のドキュメント更新、monitoring (metrics/logging)。
- Example integration test with mock IdP (conformance-like harness)。

DoD:

1. フェデレーション設定変更 → RP フロー → session 発行までの自動テストが緑。
2. Management UI 側で設定フォームが動作、監査イベントが記録される。
3. `spec/compliance-matrix.yaml` の該当行が `planned` → `verified` に更新。

## 4. Definition of Done (横断)

各スプリントで共通に満たすべき条件:

1. `nix flake check --print-build-logs` 緑。
2. テスト/リンター（Rust: `cargo test`, `cargo clippy`; TypeScript: SDK リポジトリで `pnpm lint`, `pnpm test`）緑。
3. ドキュメント更新: `docs/program-management/initiatives/sdk/client-sdk-architecture.md`, `docs/program-management/roadmaps/...` にステータス反映。
4. SBOM と署名 artefact (`cosign`, `sbom.json`) が生成され、`artifacts/` に保存。
5. セキュリティ姿勢: 新たな fail-open を作らず、Secrets は SecureContext / keystore を通して扱う。

## 5. リスクと対策

| リスク                                 | 対策                                                                                                                         |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Verified Core WASM が SPA で動作しない | 早期に Web/Node 双方で smoke test を実装。                                                                                   |
| フロントエンド着手が遅延               | Sprint B 完了後に管理 UI チームが `@aegaeon/management-client` α版を取り込み、並行開発。                                     |
| サードパーティ IdP の仕様差異          | Mock IdP + 実 IdP（Google/TBD）での nightly テストを追加。                                                                   |
| FIPS 要件発生                          | 暗号プロバイダ抽象化を Sprint B で設計。FIPS は `docs/program-management/initiatives/sdk/client-sdk-architecture.md` 8.1 に記載の通り将来課題として記録。 |

## 6. 参考

- `docs/program-management/initiatives/sdk/client-sdk-architecture.md`
- `docs/specs/management-plane-phase1.md`
- `docs/program-management/roadmaps/active/current-execution-plan.md`
- `spec/compliance-matrix.yaml`

本記録は初期 SDK / UI delivery の履歴であり、現在の残作業は
`docs/program-management/roadmaps/active/management-platform-follow-on-plan.md` に集約する。
