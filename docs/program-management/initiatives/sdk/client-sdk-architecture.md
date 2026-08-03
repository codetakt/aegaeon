# Aegaeon Client & Federation Architecture (Draft)

Last updated: 2026-07-08

Status: draft

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-07-08):** Draft client architecture; it does not activate released client wording or formal claim scope.

## Status

- **Author**: Codex (assistant)
- **Date**: 2026-03-10
- **Version**: 0.2 (draft)
- **Scope**: Verified-core ベースのクライアント SDK、WASM 化、フェデレーション RP 機能を含む。
  サーバ実装は **同一の KaRaMeL 抽出 C をネイティブでリンク**し、WASM はクライアント配布専用とする。
- **Security posture**: 機密性・完全性最優先。フェイルクローズと検証可能性を前提。
- **Claim boundary**: This draft describes future client-side packaging and runtime surfaces. It must not be read as a released client-product claim; use `../../../product-positioning.md` and `../../../verification/claims/assurance-case/README.md` for the current claim boundary.
- **Implementation snapshot (2026-03-13)**: this repository now contains a Node reference adapter at `scripts/sdk/runtime_node_reference.ts`, a browser reference adapter at `scripts/sdk/runtime_web_reference.ts`, focused Node/WebCrypto tests at `tests/verified_core_wasm/runtime_{node,web}_reference_test.ts`, and a browser smoke harness at `tests/verified_core_wasm/runtime_web_reference.html`. The current client-core baseline supports PKCE plus JWT / DPoP compact and claims flows; EdDSA remains inside the current WASM verification path, while `RS256` / `ES256` are presently handled by adapter-side preverification before Verified Core enforces claims / time / replay semantics. The current SDK scaffold also emits alpha `@aegaeon/management-client`, `@aegaeon/issuer-spa`, and `@aegaeon/rp-core` packages: `management-client` covers selected OpenAPI-backed control-plane operations plus session / CSRF / Origin / `teamId` helpers, including oauth-profile CRUD, connection CRUD, environment/team-audit JSON/CSV export, and query-string-backed audit filters, `issuer-spa` now covers browser transaction persistence, browser-native session persistence, discovery-driven callback completion, and logout orchestration, and `rp-core` now covers both low-level Authorization Code + PKCE helpers and higher-level federated-login orchestration via in-memory transaction/session stores plus issuer metadata / discovery helpers and `startFederatedLogin` / `finishFederatedLogin`. The sibling `../aegaeon-admin-console` now uses `@aegaeon/management-client` as its only SDK dependency, emits `.artifacts/admin-sdk/admin-sdk-evidence.json` against `spec/admin-sdk-evidence.schema.json`, and now has both a compose-backed local browser lane and a hosted `Admin Console Stack E2E / Stack E2E` workflow that exercise bootstrap, login, dashboard rendering, create team/tenant/environment, list/create/update/delete oauth profiles, list/create/update/delete connections, update environment policy, create/activate configuration version, rotate/activate-next/revoke signing key, update key store, list/block/unblock users, invalidate user sessions, revoke user refresh tokens, environment/team audit reads, query-string-backed audit filtering, environment/team-audit JSON/CSV export, audit-event detail, create/update/delete client, issue/revoke/revoke-all client secrets, and logout against a sibling `../aegaeon` stack, while uploading admin evidence and Playwright diagnostics as CI artifacts; the hosted workflow name, lane name, and artifact names are now source-managed in `../aegaeon-admin-console/spec/workflow-inventory.current.json` and audited fail-closed by the console repo itself. Published `@aegaeon/runtime-node` / `@aegaeon/runtime-web` packages remain future deliverables in the separate SDK repository.

## 1. 目的と背景

- Aegaeon は OAuth/OIDC サーバ実装のうち VerifiedReqs 範囲を仮定限定付きで形式検証しており（F\*/Low\*/KaRaMeL。境界は `../../../verification/claims/assurance-case/claim-definition.md` を参照）、データプレーンに高い保証を提供する。
- 次段階として、Aegaeon 自身が安全な **クライアント SDK** を提供し、さらに **既存 IdP（例: Google Workspace）とフェデレーション** する RP 機能を追加する。
- 設計目標:
  - Verified Core を WASM として共通化し、まず TypeScript SDK を整え、その後 **Rust → Ruby → PHP** の順で言語展開する SDK 基盤にする。
  - サーバー側は Environment 単位でフェデレーション設定を管理し、外部 IdP と安全に連携する。
  - 秘密値・セッション・属性変換は最小限の境界で処理し、常にフェイルクローズする。

## 2. アーキテクチャ構成

> 詳細なリポジトリ構成と CI フローは `sdk-repository-plan.md` を参照。
> 実装手順については `sdk-implementation-guide.md` を参照。

### 2.1 Verified Core (WASM)

- **実装**: F\* → KaRaMeL → C → wasm32-wasi。
- **責務**:
  - PKCE（S256）、DPoP、State/Nonce 正規化、Redirect URI 正規化。
  - Authorization Code フロー検証（at_hash、c_hash、nonce）。
  - JWK/JWT 検証（署名、iss/aud/exp）と Replay 防止。
  - 状態機械は純粋関数として実装、入出力はシリアライズ済みバッファのみ。
- **制約**:
  - 動的メモリアロケーション禁止（固定アリーナ or caller提供バッファ）。
  - `wasi_snapshot_preview1` のみ。I/O capability なし。
  - エラーは `Result<Success, ErrorCode>` のみ（例: `INVALID_TOKEN`, `PKCE_MISMATCH`, `SECURITY_LEDGER_CONFLICT` 等）。

### 2.2 ランタイムアダプタ

| 層 | npm/crate 名 | 役割 | 主な制約 |
|----|-------------|------|-----------|
| **Core Loader** | `@aegaeon/verified-core` / `aegaeon-core` | WASM artefact 取得、署名検証、core エントリポイントの抽象化。 | Web: SecureContext + SRI + streaming instantiate。Node/Rust: Ed25519 署名検証後に `wasmtime` / `wasmer` / `wasm3` backend を選択式にロード。 |
| **Runtime Adapter** | `@aegaeon/runtime-web` / `@aegaeon/runtime-node` | Core とのバイナリ境界を型安全にする薄い層。入力/出力検証、バッファ管理、同期待ち。 | WASM メモリ再割当て禁止。すべての API が `AbortSignal` でキャンセル可能。 |
| **Domain SDK** | `@aegaeon/management-client`, `@aegaeon/issuer-spa`, `@aegaeon/rp-core` | 管理 API、Issuer SPA、外部 RP の業務ロジック。 | プロトコル状態機械は Core に委譲。UI/HTTP はここで実装。 |
| **Integration Helpers** | (別リポ: `@aegaeon/next`, `@aegaeon/remix`) | フレームワーク統合、DI、React hooks。 | optional。Core/API SDK の wrapper のみ。 |

- Layered distribution (3 層構成) を基本とし、Integration Helpers を加えれば 4 層。最下層は常に WASM Core。
- アダプタは WASM との境界を薄く保ち、状態機械や署名検証を再実装しない。
- Package boundary normalization:
  - `@aegaeon/management-client` is the canonical management-plane package for admin UIs and automation.
  - `@aegaeon/issuer-spa` and `@aegaeon/rp-core` are the canonical OIDC client / RP packages.
  - Admin consoles should depend on `@aegaeon/management-client` only unless the management-plane login flow itself moves onto OIDC.
  - The sibling `../aegaeon-admin-console` now source-manages that rule in `spec/admin-sdk-boundary.current.json` and audits it with `pnpm test:repo`.
  - The sibling `../aegaeon-admin-console` also source-manages the current management-auth posture in `spec/admin-auth-boundary.current.json`: admin login stays on the cookie-based management-session flow, and app sources must not hand-roll cookie / CSRF / bearer-token auth logic.
- 初期化フロー:
  1. Core Loader が `verified_core.wasm` + `manifest.json` を取得し、署名/SRI/ハッシュを検証。
  2. Runtime Adapter が JSON Schema で入出力を検査 (`zod` / `serde_with`).
  3. Domain SDK が HTTP/Storage/UI ロジックを実装。

### 2.2.2 Post-TypeScript language rollout

Post-TypeScript language expansion is planned in this order:

1. **Rust**
2. **Ruby**
3. **PHP**

- Rust comes first because it is the closest follow-on to the current WASM/runtime boundary and release-attestation flow.
- Ruby starts only after the Rust package boundary and release discipline are stable.
- PHP starts only after the Ruby package boundary and release discipline are stable.
- Adding a new language track does **not** widen the current formal claim boundary by itself; any claim change still requires explicit evidence and policy promotion.

### 2.3 SDK 層

1. `@aegaeon/verified-core` (WASM + TypeScript bindings)
   - WASM モジュールおよび `initCore()` ヘルパー。
   - Core への入力/出力を JSON Schema で検証。
   - `packages/verified-core/` には以下を含める:
     - `dist/verified_core.wasm` (SRI 対象)
     - `dist/verified_core.manifest.json`（sha256, sha512, サイズ, ビルド番号）
     - `dist/verified_core.wasm.sig`（Ed25519）
     - `loader.ts`（署名検証と `WebAssembly.instantiateStreaming` 呼び出し）
   - `npm install` 時に postinstall フックでマニフェスト照合、`NODE_ENV=production` ではハッシュ不一致を致命エラー扱い。
2. `@aegaeon/management-client`
   - Alpha 現況: Aegaeon 管理 API の現行 admin-console surface をカバーする control-plane package。
   - 現在の helper は CSRF / Origin / teamId を自動挿入し、Node/browser 両方で扱える in-memory session / cookie surface を提供。
   - 現行 alpha は単一 package に `core` / `auth` 相当の surface をまとめており、React hooks は未実装。
   - 将来: `react/` (hooks/UI 統合)、E2EE オプション（環境スナップショット、監査ログ）、より広い OpenAPI codegen を追加。
3. `@aegaeon/issuer-spa`
   - 認証 UI、session 管理、PKCE/DPoP は Core へ委譲。
   - XSS 対応（CSP, Trusted Types）を強制。
   - Alpha 現況: browser transaction/session store と callback-driven completion を備える。
   - `runtime-web` の上に構築し、Next.js/Remix など各フレーム��ークは Integration Helpers で対応。
4. `@aegaeon/rp-core` (外部 IdP RP 用)
   - Authorization Code + PKCE 交換、ID Token/JWK 検証を Core へ委譲。
   - 属性マッピング DSL、SAML/OIDC イベントハンドリングをサポート。
   - Alpha 現況: low-level PKCE/callback helpersに加え、in-memory transaction/session store と `startFederatedLogin` / `finishFederatedLogin` を備える。
   - Federation 設定の live reload をサポート（Management API Webhook → SDK Cache 無効化）。

Post-TypeScript language expansion is planned in this order:

- **Rust**: `aegaeon-management`（OpenAPI ラップ）と `aegaeon-core`（WASM FFI）
- **Ruby**: RubyGems 配布の wrappers
- **PHP**: Composer / Packagist 配布の wrappers

### 2.4 パッケージ構成とビルド戦略

```text
packages/
  verified-core/          # npm 基盤パッケージ（WASM + loader）
  runtime-web/            # Core Loader をブラウザ向けにラップ
  runtime-node/           # Node/Edge (Deno, Bun) 向け
  management-client/      # 管理 API SDK（core/auth/react）
  issuer-spa/             # 認証 UI SDK
  rp-core/                # フェデレーション RP SDK
  next/                   # Next.js 用 helper（optional）
crates/
  aegaeon-core/           # Rust Loader + FFI
  aegaeon-management/     # OpenAPI クライアント
gems/                     # Ruby language track (planned)
php/                      # PHP language track (planned)
```

- `pnpm` の workspaces を採用。`pnpm recursive run build` で全パッケージをビルド。
- WASM artefact は git に追跡せず、`pnpm run fetch-core` が `artifacts/verified-core/` から取得して `dist/` に配置。
  - 参考: 本リポの `scripts/sdk/fetch_core_artifact.js` が CLI 雛形（Node 22+ / Ed25519 検証）。
- CI:
  - Step1: `scripts/extraction/package_verified_core.sh` を走らせ artefact を生成。
  - Step2: `pnpm run fetch-core && pnpm run lint && pnpm run test`.
  - Step3: `pnpm publish --dry-run` / `cargo publish --dry-run` でリーンチェック。
- Browser bundle: `verified_core.wasm` は dynamic import (ESM) で読み込み、`vite/webpack` の `asset/inline` 無効化で integrity チェックを保持。
- Node: `runtime-node` は `fs/promises` から WASM を読み込み、manifest でハッシュ検証後 `WebAssembly.instantiate`。環境変数 `AEGAEON_CORE_WASM_PATH` で上書き可能（テスト用）。

### 2.5 リポジトリ分割方針

- **このリポジトリ (aegaeon)**: Verified Core (F*/C/WASM)、`scripts/extraction/*`、`artifacts/verified-core/`、core 仕様ドキュメント。
- **新規リポジトリ (仮称: aegaeon-sdk)**: `packages/` / `crates/` など上位レイヤーを含む pnpm workspace。Core artefact は GitHub release もしくは内部 S3 から取得し、`pnpm run fetch-core` で同期。
- Core 更新フロー:
  1. 本リポで `package_verified_core.sh` → artefact 発行 → release tag。
  2. SDK リポが manifest を参照してハッシュ/署名を検証しつつ取り込み (`pnpm update-core --version <tag>` を想定)。
  3. SDK CI が lint/test/publish。
- この切り分けにより、Verified Core の証明 artefact とフロントエンド SDK の配布サイクルを独立させ、監査トレイルと supply-chain 制御を明確化する。

## 3. フェデレーション（RP）機能

### 3.1 Environment スナップショット拡張

`configurationDocument` に `federation` ブロックを追加:

```json
"federation": {
  "upstreamIssuer": "https://accounts.google.com",
  "clientId": "uuid",
  "redirectUri": "https://env.example/oauth2/callback",
  "jwksCache": {
    "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
    "maxAgeSeconds": 3600
  },
  "attributeMapping": [
    { "from": "google.groups", "to": "aegaeon.roles", "rule": "mapGroups" }
  ],
  "logout": {
    "backChannel": true,
    "sessionHintClaim": "sid"
  }
}
```

- 秘密は含めない。外部 IdP の client secret/private key は keystore 経由で参照 ID のみ保持。
- Config Transaction で変更し、監査ログを必須化。

### 3.2 フロー概略

1. Aegaeon `/authorize` で prompt=login ⇒ RP モードへ遷移。
2. Verified Core が生成した `state`/`nonce`/PKCE を外部 IdP に付与。
3. 外部 IdP から戻った code を Core が検証（PKCE、nonce、署名、alg）。
4. 属性マッピングは sandboxed DSL (WASM) で実行。エラーは `invalid_token`。
5. 成功時は Environment 内の session を発行し、監査イベント `FEDERATION.LOGIN.SUCCEEDED.v1` を記録。

### 3.3 セキュリティコントロール

- 外部 IdP の JWK フェッチ: TLS pinning + ETag + max-age 監視。失敗時は last-known-good + アラート。
- 属性マッピング: DSL は宣言的。実行は WebAssembly sandbox 内で行い、ネットワーク能力なし。
- セッション連携: 外部 IdP の cookie はサーバーで扱わず front-channel のみ。Back-channel ログアウトは webhook 経由で session store を失効。
- 監査: 成功/失敗を `management.federation.*` / `security.federation.*` イベントとして記録。requestId/traceId を含める。

## 4. セキュリティ設計

### 4.1 フェイルクローズと重複防止

- Verified Core はエラーを `SECURITY_LEDGER_CONFLICT`, `PKCE_MISMATCH`, `TOKEN_VALIDATION_FAILED` など明示的コードで返す。
- JavaScript/Rust 側はこれをラップせず、呼び出し側に伝播。
- ブラウザ SDK は HTTP 以外 (file://) での動作を禁止。Node SDK は `NODE_ENV=production` でのみ keystore 解凍を許可。

### 4.2 秘密値管理

- TypeScript: Web Crypto API の `CryptoKey`/`PasswordCredential` を利用。console.log 禁止。
- Rust: `secrecy::Secret` + `zeroize`。panic path でも drop でゼロ化。
- サーバー: 外部 IdP の client secret は HSM/KMS (keystore) で保管。Configuration Document は参照 ID のみ。

### 4.3 WASM 配布と署名

- WASM バイナリは Ed25519 で署名し、リリース artefact に署名ファイルを添付。
- ブラウザ版は `<script type="module">` で SRI (integrity) を必須化。Node/Rust 版も署名検証を通らなければ起動しない。
- Supply chain: `cosign attest --predicate sbom.json` で SBOM を添付。

### 4.4 Hardening

- CSP (`default-src 'none'`, `script-src 'self' 'wasm-unsafe-eval'`) と Trusted Types を前提にラインタイムを設計。
- SDK 内の fetch は `same-origin` または明示ホワイトリスト。XSRF 対策: cookie + header double submit。
- ランタイム例外はすべて構造化ログ (`SECURITY.*`) として記録し、PII は含めない。

## 5. テストと検証

| 分類 | 内容 |
|------|------|
| F\* | RP フロー、PKCE、nonce、DPoP、JWK 署名検証、属性マッピング DSL の安全性。 |
| WASM | `wasm-bindgen-test` + fuzz (`cargo fuzz`)。dudect で side-channel 検出。 |
| SDK | Playwright (ブラウザ) / Vitest (Node) で CSP/XSS/Token 漏洩テスト。Rust は `cargo kani` でハーネス準備。 |
| プロトコル | OIDC Conformance (RP), Google Workspace 実証、OIDF RP certification。 |
| 監査 | STRIDE モデル、Red Team ガイドラインを docs/security に記載。 |

## 6. デプロイと配布

- npm: `@aegaeon/verified-core`, `@aegaeon/management-client`, `@aegaeon/issuer-spa`, `@aegaeon/rp-core`。SLSA Level 2 provenance。
- crates.io: `aegaeon-core` (WASM FFI), `aegaeon-management` (API client)。
- RubyGems: Ruby wrappers (planned after Rust)。
- Packagist / Composer: PHP wrappers (planned after Ruby)。
- OSS と SaaS のコードベースは同一。機能制御は feature flag による。
- WASM バイナリは CDN 配布せず、署名付き tarball を提供。ブラウザ SDK は integrity チェック必須。

## 7. ロードマップ

1. Verified Core の F\* 証明拡張と WASM ビルドパイプライン整備（dudect, KaRaMeL extraction）。
2. TypeScript adapter 実装とセキュアな初期化経路。
3. フェデレーション設定 (`federation` ブロック) を Environment スナップショットへ追加し、Management API/UI を対応。
4. SDK (management/issuer/rp) を段階的にリリースし、実環境で RP E2E テスト → beta → GA。
5. Post-TypeScript language expansion を **Rust → Ruby → PHP** の順で進める。
6. 外部監査（Cure53 など）と security review を実施、リリース前に脆弱性評価。

The management-plane follow-on work for these two deployment postures is tracked separately:

- primary-authority local IAM: `../../../specs/primary-authority-user-management.md`
- upstream-authority broker / downstream-IdP: `../../../specs/oidc-rp-brokering-spec.md`

## 8. リスクと対応

| リスク | 緩和策 |
|--------|--------|
| WASM バイナリ改ざん | Ed25519 署名 + SRI + Node/Rust での署名検証。 |
| 属性マッピングの誤実装 | DSL を Verified Core で実装し，サンドボックス実行。UI はバリデーションと dry-run 機能を提供。 |
| 外部 IdP JWK 変更 | `jwksCache` の期限監視とラストナウングッド参照、異常時は fail-close + アラート。 |
| SDK 利用時の秘密漏洩 | SecureContext 依存、`secrecy::Secret`、ログ禁止、例外時のゼロ化。 |
| サプライチェーン攻撃 | SBOM + sigstore/cosign + reproducible builds。 |

### 8.1 FIPS 対応に関する検討（将来課題）

- 現時点（Phase 1〜2）では EverCrypt/HACL\* を暗号基盤の前提とし、FIPS 認証は取得していない。
- 2026-xx 時点で FIPS 140-3 認証が必要になった場合は、以下を検討する:
  1. 暗号プロバイダ抽象層を導入し、FIPS モード時には OpenSSL FIPS Provider や AWS-LC FIPS ビルドへ切り替える。
  2. FIPS モード開始時に自己テスト（KAT）・DRBG 初期化・禁止アルゴリズム無効化を実装する。
  3. Verified Core (EverCrypt) と FIPS モードの共存方針を整理し、非 FIPS モードでは従来の Verified Core を継続利用する。
- この方針は管理プレーン仕様の「Cryptography posture and future FIPS track」と同期させ、将来課題として
  `../../roadmaps/future/future-projects.md` で追跡する。
- これらは将来の要件に応じて再評価する。現段階では EverCrypt/HACL\* を前提とし、FIPS 対応はロードマップ候補として記録するに留める。

---

本ドキュメントは draft として位置づけられ、後続の仕様書/実装に合わせて更新する。レビューは security/architecture チャネルで行い、承認後にバージョンを確定させる。
