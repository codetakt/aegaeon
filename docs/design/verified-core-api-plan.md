# Verified Core API Export Plan

Last updated: 2026-07-07

Status: future plan

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-07-07):** The Phase 1 claims runtime baseline described below is implemented in this repository. Read this document as a follow-up plan for deferred compact-path, SDK-packaging, and compat-algorithm work; it does not widen the current verified allowlist.

## 背景

TypeScript/Node ランタイムは `VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1` といった
エクスポートを期待しているが、現行の Low*/KaRaMeL 抽出では
`Dpop_Validation_verify_dpop` や `Pkce_verify_pkce` 等の内部関数のみが公開されており、
ホスト側から直接利用するには

1. DPoP/JWT の構文解析（JOSE Header, Payload, Signature）
2. 署名検証のアルゴリズム選択やクレーム検証
3. `FStar_Bytes_bytes`／`Prims_string` など Low* 型への変換

をホスト側で再実装する必要がある。これでは Verified Core を「プロトコル実装の単一ソース」として
使う価値が薄れるため、Verified Core 側でホストフレンドリーな ABI を提供する。

## 現状の実装状態

### Compact パス（`*_verify_v1`）
- `c/verified-core/verified_core_exports.c` で `VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1` を導入済み。
- 現在の Compact パスは `Host_parse_dpop_compact` / `Host_parse_jwt_compact` を介して機能しており、current verified WASM path では **EdDSA** の DPoP/JWT 検証を返せる。
- `ES256` / `RS256` は引き続き verified WASM path では `UNSUPPORTED` で、別の promotion task として扱う。

### Claims パス（`*_verify_claims_v1`）— **Phase 1 完了**
- `fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst` で F* 実装済み。
- KaRaMeL 抽出で C コード生成: `generated/lowstar/verified-core/c/VerifiedCore_Api_Claims_Runtime.{c,h}`
- `c/verified-core/verified_core_exports.c` から F* 実装を呼び出すブリッジコード完成。
- このリポジトリには reference Node adapter (`scripts/sdk/runtime_node_reference.mjs`) と reference browser adapter (`scripts/sdk/runtime_web_reference.mjs`) があり、`dpopVerify` / `dpopVerifyClaims` / `jwtVerify` / `jwtVerifyClaims` を提供する。
- Node smoke tests は `tests/verified_core_wasm/runtime_node_reference_test.mjs`、browser-facing adapter tests は `tests/verified_core_wasm/runtime_web_reference_test.mjs` で検証済み。

Claims パスは Base64/JSON パースをホスト側に委譲し、Verified Core は事前パース済みのバイト列のみを受け取る。
これにより TCB (Trusted Computing Base) を縮小しつつ、完全な検証機能を提供する。

## 目標

以下の C シンボルを `verified_core.wasm` から直接エクスポートする。

```c
uint32_t VerifiedCore_dpop_verify_v1(
  const struct DpopVerificationInputV1 *input,
  struct DpopVerificationOutputV1 *output);

uint32_t VerifiedCore_jwt_verify_v1(
  const struct JwtVerificationInputV1 *input,
  struct JwtVerificationOutputV1 *output);
```

ABI の構造体定義は `scripts/sdk/generate_verified_core_abi.js` に合わせる。
戻り値は `VerifiedCoreStatusCode`（0: OK, それ以外はエラーコード）。

## 実装方針

### 1. F*/Low* module (`fstar/verifiedcore/VerifiedCore.Api.fst`)

- `val dpop_verify_v1 : input -> ST output (requires ...) (ensures ...)`
- `val jwt_verify_v1  : input -> ST output (requires ...) (ensures ...)`
- 既存の `Dpop_Validation.verify_dpop`・`Jose.*` モジュールを呼び出してベースロジックを再利用する。
- 入力型は ABI に合わせた `bytes` / `string` / `uint32` / `uint64` のタプルとして定義し、
  Low* 抽出時に `struct` 化されるよう `[@@@extract]` 属性を付与する。
- エラーは `VerifiedCoreStatusCode` 相当の整数に正規化する（`Prims_native` を使わず `C_Enums` で固定）。
- DPoP リプレイストアは抽象インターフェース `module type ReplayStore` を定義し、
  既存の `Dpop.Replay` を通じてキー生成（ハッシュ）を行う。

### 2. KaRaMeL bundle

- `run_verified_core_lowstar.sh` の `MODULE_DIRS` に `verifiedcore`（新規ディレクトリ）を追加。
- 抽出順序: `verifiedcore/VerifiedCore.Api.fst` は最後に配置し、依存する `Dpop`/`Jose` モジュールを事前に `--bundle` する。
- KaRaMeL の `-bundle` オプションで `VerifiedCore.Api=Prims,FStar,...` とまとめ、不要なシンボルが C に出ないようにする。
- Warning 15 を抑止するため、`FStar.UInt32.*` 等の関数は `compat.h` を明示的に取り込むか、Low* 側で `UInt32.t` を利用するようリファクタする。

### 3. C Shim (`c/verified_core/verified_core.c`)

- F* から抽出されたモジュールを直接エクスポートするため、KaRaMeL 出力に加えて
  手書きの C ファイルで以下を担当する。
  - ABI 構造体（`DpopVerificationInputV1` など）の定義と `static_assert` によるサイズチェック。
  - UTF-8 文字列を `Prims_string`（`char *`）に変換。
  - バイナリ列を `FStar_Bytes_of_buffer(len, ptr)` でラップ。
  - `VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1` を実装し、F*/Low* 関数を呼び出して戻り値を構造体にパック。
- この C ファイルを `run_verified_core_lowstar.sh` で KaRaMeL 出力にコピーし、ビルド対象に含める。

### 4. テスト

- `tests/verified_core_wasm` に `wasmtime` ベースの smoke テストを追加。
  - 正常系: 有効な DPoP/JWT ベクトルで `status=0` を確認。
  - エラー系: リプレイ検知（`REPLAY`）、署名不一致（`INVALID_SIGNATURE`）などのコードを確認。
- SDK ランタイムから `pnpm test` を通じて Node/Web の統合テストを実装。

## 残作業

1. Compact path (`*_verify_v1`) の再整理を、claims path の ABI と同じエラー分類で進める。
2. Publishable SDK packages 側の runtime-node / runtime-web examples and tests に claims path を反映する。
3. `ES256` / `RS256` は、別の boundary-promotion record が閉じるまで compat/runtime target として扱う。

## Phase 1: Claims 実行モデル

### アーキテクチャ

```text
┌─────────────────┐     ┌─────────────────────────────────────────┐
│  Application    │     │              Host Runtime               │
│                 │     │  (Node.js / Browser)                    │
│  - DPoP proof   │────▶│                                         │
│  - JWT token    │     │  1. Parse JWS (split by '.')            │
└─────────────────┘     │  2. Decode Base64url segments           │
                        │  3. Extract claims from payload JSON    │
                        │  4. Create bytes handles                │
                        │                                         │
                        │     ┌─────────────────────────────┐     │
                        │     │     Verified Core WASM      │     │
                        │     │                             │     │
                        │     │  dpop_verify_claims_impl    │     │
                        │     │  jwt_verify_claims_impl     │     │
                        │     │                             │     │
                        │     │  - Validate claims          │     │
                        │     │  - Check iat window         │     │
                        │     │  - Verify Ed25519 in-WASM   │     │
                        │     │  - Call replay store        │     │
                        │     └─────────────────────────────┘     │
                        │                                         │
                        │  Host callbacks (current 7 imports):   │
                        │  - replay store check-and-store         │
                        │  - register/release byte handles        │
                        │  - parse compact DPoP/JWT               │
                        │  - resolve handle -> (ptr, len)         │
                        └─────────────────────────────────────────┘
```

### 実装ファイル

| ファイル | 役割 |
|---------|------|
| `fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst` | F* 検証ロジック本体 |
| `generated/lowstar/verified-core/c/VerifiedCore_Api_Claims_Runtime.{c,h}` | KaRaMeL 抽出 C コード |
| `c/verified-core/verified_core_exports.{c,h}` | C ブリッジ (ABI 構造体定義含む) |
| `scripts/sdk/runtime_node_reference.mjs` | Reference Node adapter / host imports / packaging-aware loader |
| `scripts/sdk/runtime_web_reference.mjs` | Reference browser adapter / secure-context loader / WebCrypto-based artefact verification |
| `tests/verified_core_wasm/runtime_node_reference_test.mjs` | Node smoke tests |
| `tests/verified_core_wasm/runtime_web_reference_test.mjs` | Web-facing adapter tests on Node WebCrypto |
| `tests/verified_core_wasm/runtime_web_reference.html` | Browser smoke harness for the reference web adapter |
| `tests/verified_core_wasm/package_dist_test.mjs` | sign → package → fetch verification smoke |

### 検証済み項目

- DPoP iat ウィンドウ検証 (max age / future skew)
- current verified-signature path: EdDSA (`ES256` / `RS256` remain unsupported in the verified WASM path)
- リプレイ検出 (TTL 付きストア)
- ステータスコードマッピング (F* → C → TypeScript)

## 参考

- `fstar/dpop/Dpop.Validation.fst` – 現行の署名検証・クレームチェック。
- `fstar/jose/Jose.Jwt_validation.fst` – JWT claim 検証ロジック。
- `scripts/sdk/generate_verified_core_abi.js` – ABI JSON の正本。
- `docs/design/runtime-adapter-design.md` – ランタイムが依存する API 仕様。
- `docs/design/verified-core-claims-runtime-plan.md` – Phase 1 実装計画。
