# Verified Core ABI Snapshot（v1）

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

> **Status note (2026-03-09):** This ABI snapshot documents a host/runtime surface, not the current strong-constraint claim boundary. Mentions of `RS256` / `ES256` here describe compatibility targets unless and until a separate boundary-closure decision promotes them. Current Verified Core WASM claims verification is functional for `EdDSA`; `iss` / `aud` checks and DPoP `ath` binding are now handled inside the C exports layer rather than as dedicated host callbacks.

最終更新日: 2026-03-09

Verified Core の WebAssembly モジュールが公開する import/export と
データレイアウトの正本は
`generated/lowstar/verified-core/verified_core.abi.json`
に保持されます。この JSON は手動管理のテンプレートに基づき
`scripts/sdk/generate_verified_core_abi.js` で生成します。

```bash
node scripts/sdk/generate_verified_core_abi.js
```

スクリプトはテンプレートへ `generatedAt` を付与して JSON を書き出すだけです。
KaRaMeL のヘッダ構造に依存しないため、WASM とホストの境界仕様を意図どおりに
固定できます。

## 主要コンベンション

- **バイト列**: `bytes_handle (u32)` をホストが管理します。呼び出し中は必ず有効でなければならず、完了後に解放して構いません。大量コピーは `FStar_Bytes_read` を使用します。
- **時刻**: `u64`（Unix 秒）。JavaScript からは `BigInt` で受け渡しします。
- **整数**: 長さ・インデックスは `u32`。エラーコードは `VerifiedCoreStatusCode (u32)`。
- **ES256 署名形式**: ABI は JOSE/P1363 (`r || s` の 64 バイト) を正とします。将来 compat/runtime adapter が `ES256` を受ける場合、DER ↔︎ P1363 変換は verified WASM 境界の外側で吸収してください。
- **Replay Store**: `ReplayStore_check_and_store` は Redis の `SET key 1 NX PX ttl` に相当し、`UNAVAILABLE` は fail-close として扱います。

## 代表的な構造体

| 構造体 | 役割 |
|--------|------|
| `DpopVerificationInputV1` | HTTP メソッド/URI/DPoP JWS 等の入力と検証ウィンドウ (`maxAgeSeconds`, `maxFutureSkewSeconds`)、`allowedAlgorithmsBitmask` を保持。|
| `DpopVerificationOutputV1` | `jktHash`、`replayKeyHash`、`statusCode` などを返却。|
| `JwtVerificationInputV1` | JWT Compact、期待する `iss`/`aud`、公開鍵（JWK/SPKI/RAW）を渡すためのハンドル群。|
| `JwtVerificationOutputV1` | `payloadHash`, `kidHash`, `statusCode` 等を返却。|
| `DpopClaimsInputV1` | **Claims パス**: 事前パース済みの署名入力、署名バイト、公開鍵、HTTP メソッド/URI、iat/jti 等を渡す (72 bytes)。|
| `JwtClaimsInputV1` | **Claims パス**: 事前パース済みの署名入力、署名バイト、公開鍵、iss/aud/exp/nbf/iat 等を渡す (72 bytes)。|

いずれも `repr(C)` / 8 バイトアラインを採用し、互換性維持のため予約フィールドを確保しています。

## Claims ベース検証パス

従来の Compact 形式入力（`*_verify_v1`）に加え、**Claims ベースの検証パス**（`*_verify_claims_v1`）を提供します。
Claims パスでは Base64/JSON パースをホスト側で行い、Verified Core には事前解析済みのバイト列のみを渡します。

### メリット

- **TCB の縮小**: Verified Core 内で Base64/JSON パーサを動かす必要がなく、検証対象コードが削減される。
- **柔軟性**: ホストが独自の JWS パーサやキャッシュ戦略を実装可能。
- **互換性**: 既存の Compact パスと同じ Output 構造を使用。

### DpopClaimsInputV1 レイアウト (72 bytes)

| オフセット | サイズ | フィールド名 | 型 | 説明 |
|-----------|--------|-------------|-----|------|
| 0 | 4 | `httpMethodBytesHandle` | u32 | HTTP メソッド (大文字) |
| 4 | 4 | `httpUriBytesHandle` | u32 | HTTP Target URI |
| 8 | 4 | `signingInputHandle` | u32 | JWS 署名入力 (header.payload) |
| 12 | 4 | `signatureBytesHandle` | u32 | 署名バイト |
| 16 | 4 | `publicKeyBytesHandle` | u32 | 公開鍵バイト |
| 20 | 4 | `publicKeyFormat` | u32 | 鍵形式 (0=JWK, 1=SPKI, 2=RAW) |
| 24 | 4 | `replayNamespaceHandle` | u32 | リプレイ名前空間 |
| 28 | 4 | `accessTokenHashHandle` | u32 | ath 値 (オプション) |
| 32 | 4 | `jtiBytesHandle` | u32 | jti 値 (オプション) |
| 36 | 4 | `allowedAlgorithmsBitmask` | u32 | 許可アルゴリズム |
| 40 | 4 | `flags` | u32 | 検証フラグ |
| 44 | 4 | `reserved0` | u32 | 予約 |
| 48 | 8 | `iatSeconds` | u64 | iat クレーム値 |
| 56 | 8 | `nowUnixTimeSeconds` | u64 | 現在時刻 |
| 64 | 4 | `maxAgeSeconds` | u32 | 最大経過時間 |
| 68 | 4 | `maxFutureSkewSeconds` | u32 | 最大未来スキュー |

### JwtClaimsInputV1 レイアウト (72 bytes)

| オフセット | サイズ | フィールド名 | 型 | 説明 |
|-----------|--------|-------------|-----|------|
| 0 | 4 | `signingInputHandle` | u32 | JWS 署名入力 |
| 4 | 4 | `signatureBytesHandle` | u32 | 署名バイト |
| 8 | 4 | `publicKeyBytesHandle` | u32 | 公開鍵バイト |
| 12 | 4 | `publicKeyFormat` | u32 | 鍵形式 |
| 16 | 4 | `claimsIssuerHandle` | u32 | iss 値 (オプション) |
| 20 | 4 | `claimsAudienceHandle` | u32 | aud 値 (オプション) |
| 24 | 4 | `allowedAlgorithmsBitmask` | u32 | 許可アルゴリズム |
| 28 | 4 | `flags` | u32 | 検証フラグ |
| 32 | 4 | `expectedIssuerHandle` | u32 | 期待する iss 値 (オプション、0 で無効) |
| 36 | 4 | `expectedAudienceHandle` | u32 | 期待する aud 値 (オプション、0 で無効) |
| 40 | 8 | `expSeconds` | u64 | exp クレーム値 |
| 48 | 8 | `nbfSeconds` | u64 | nbf クレーム値 |
| 56 | 8 | `iatSeconds` | u64 | iat クレーム値 |
| 64 | 8 | `nowUnixTimeSeconds` | u64 | 現在時刻 |

## Import/Export 一覧（要点）

### Imports
- `VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store` – Redis など外部ストアを呼び、再利用 (replay) 判定と TTL 付き登録を同時に実行します。
- `vc_host_register_bytes` / `vc_host_release_handle` – wasm 線形メモリ上の生バイト列を host-managed handle に昇格・解放します。
- `Host_parse_dpop_compact` / `Host_parse_jwt_compact` – Compact JWS を事前パースし、claims / signing input / signature / key handles を返します。
- `Host_handle_data_ptr / Host_handle_data_len` – bytes handle を WASM 線形メモリ上の `(ptr, len)` に解決します。

### Claims パス用 Imports
Claims ベース検証パスで残る**機能的な検証依存**は **replay store** のみです。
- `VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store` – リプレイ検出

`iss` / `aud` の照合、`ath` binding、SHA-256、Ed25519 署名検証、および Low* compat/math shim は current verified WASM path では host callback を使わず、WASM + C exports layer 側で処理します。

フラグ用グローバル定数:
- `VerifiedCore_Api_Claims_Runtime_dpop_flag_require_ath` (= 1)
- `VerifiedCore_Api_Claims_Runtime_dpop_flag_require_jti` (= 2)
- `VerifiedCore_Api_Claims_Runtime_jwt_flag_require_exp` (= 1)
- `VerifiedCore_Api_Claims_Runtime_jwt_flag_require_iat` (= 2)
- `VerifiedCore_Api_Claims_Runtime_jwt_flag_require_nbf` (= 4)

### Exports
- `VerifiedCore_dpop_verify_v1` – DPoP 検証（Compact 形式入力、host parser 経由）。current verified WASM path では EdDSA 署名検証と replay semantics を返します。
- `VerifiedCore_jwt_verify_v1` – JWT 検証（Compact 形式入力、host parser 経由）。current verified WASM path では EdDSA 署名検証と optional issuer/audience checks を返します。
- `VerifiedCore_dpop_verify_claims_v1` – **Claims パス**: 事前パース済み入力での DPoP 検証。
- `VerifiedCore_jwt_verify_claims_v1` – **Claims パス**: 事前パース済み入力での JWT 検証。

## 運用ポリシー

- JSON が**唯一の正本**です。ドキュメントは補足説明（背景・注意点）に留め、JSON の差分が出た場合は生成スクリプトを更新して再生成してください。
- ABI の破壊的変更（フィールド位置変更、列挙値の変更など）は `abiVersion` のメジャーバンプが必要です。
- Verified Core の実装や SDK 側で import/export を追加する際は、まずこのテンプレートを更新してからスクリプトを再実行し、差分チェックを行ってください。

## Host 実装者向けチェックリスト

1. `vc_host_register_bytes` / `vc_host_release_handle` を実装し、呼び出し中はハンドルが生きていることを保証する。
2. `Host_parse_*` と `Host_handle_data_*` を fail-closed で実装し、invalid handle / parse error を成功扱いにしない。
3. `ReplayStore_check_and_store` は Redis 等の SET NX PX にマッピングし、`UNAVAILABLE` を fail-close で呼び出し元へ返す。
4. `dpopVerify` / `jwtVerify` 実装では `allowedAlgorithmsBitmask` を尊重し、無効化されたアルゴリズムを使わない。
5. 生成物 (`verified_core.abi.json`) を CI でバリデートし、SDK/ランタイム側と常に整合するようにする。
