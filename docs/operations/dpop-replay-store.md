# DPoP リプレイストア運用ガイド

Last updated: 2026-07-01

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

本ドキュメントは DPoP 送信者制約のリプレイ対策を Redis で運用するための手順と推奨設定をまとめたものです。Verified Core（F*/Low*/WASM）は `replay_ticket` を返すだけでストレージは扱わないため、アプリケーションが確実に fail-close するようホスト側で制御します。

## 1. 環境変数

| 変数 | 目的 | 既定値 | 備考 |
|------|------|--------|------|
| `AEGAEON_DPOP_REDIS_URL` | リプレイストアとして利用する Redis への接続 URL (`rediss://`。loopback 開発 endpoint のみ `redis://` も可) | DPoP runtime 有効時の server 起動では必須 | インメモリ実装は直接 unit test / fuzz / protocol harness 用であり、`aegaeon-server` の supported startup posture ではない。 |
| `AEGAEON_DPOP_NONCE_REDIS_URL` | DPoP nonce store として利用する Redis への接続 URL | nonce enforcement 有効時の server 起動では必須 | `AEGAEON_DPOP_REDIS_URL` への fallback はない。 |

`iat` 許容ウィンドウ、JWT leeway、DPoP nonce TTL は startup 環境変数ではなく、active
configuration document の `policy.dpopIatWindowSeconds`、`policy.jwtLeewaySeconds`,
`policy.dpopNonceTtlSeconds` が authoritative です。Redis key namespace は management
database の Environment ID から導出され、operator が process env で上書きするものでは
ありません。

Redis に接続できない場合、アプリケーションは **503 (temporarily_unavailable)** を返却し fail-close するよう実装しています。障害時に fail-open しないことを確認するため、監視・通知を合わせて整備してください。

## 2. キー設計と TTL

1. Verified Core は `method`/`uri`/`jti`/`jkt`/`ath` などを含む `replay_ticket` を返す。
2. Rust ミドルウェアが以下を連結し SHA-256 でハッシュ化、base64url エンコードした値をキーに使用します。
   ```text
   dpop:v1:{namespace}:{base64url(SHA256(method || uri || jti || jkt || ath-or-'-'))}
   ```
3. TTL は active policy の `dpopIatWindowSeconds + jwtLeewaySeconds`（既定で 360 秒）。`SET <key> 1 NX PX <ttl_ms>` で保存し、既存キーがあればリプレイとして拒否します。

## 3. Redis 推奨設定

- 専用インスタンスまたは専用 DB（DB 番号）を割り当て、他用途と分離する。
- `maxmemory-policy noeviction` を強制：エビクションによってリプレイ保護が崩れないようにする。
- TLS/認証を有効化し、接続情報は Secret Manager 等で管理する。非 loopback endpoint は `rediss://` で設定し、平文 `redis://` は local loopback 検証に限定する。
- 運用監視:
  - 接続エラー／タイムアウトをメトリクス/ログで検知。
  - `keyspace_misses` や `used_memory` を監視し、容量逼迫時にアラート。

## 4. 障害時の挙動

- Redis への `SET ... NX PX` が失敗した場合、`DpopError::BackendUnavailable` として 503 を返却し、クライアントには「DPoP replay backend unavailable」を通知。
- 障害イベントは監査ログ/監視に残るようアプリケーション側でログ出力 (`tracing::error!`) を実装することを推奨。

## 5. テストと検証

### ローカル検証手順

1. インメモリ実装の確認は、server startup ではなく直接 store / middleware の unit test または fuzz/protocol harness に限定する。
2. Docker などで Redis を立ち上げ、`AEGAEON_DPOP_REDIS_URL=redis://127.0.0.1:6379` を指定して以下を実行:
   ```bash
   AEGAEON_DPOP_REDIS_URL=redis://127.0.0.1:6379 \
   cargo test -p aegaeon-server dpop_middleware_integration_test::test_protected_endpoint_detects_replay
   ```
   同じ JTI が 2 度送信された場合に 401/invalid_token になることを確認します。
3. Redis を停止 → 同テスト実行で 503 / temporarily_unavailable が返ることを確認し、fail-close を検証。

### CI への組み込み例

- `docker compose` で Redis を起動し、`AEGAEON_DPOP_REDIS_URL` を設定した状態で `cargo test -p aegaeon-server dpop_*` ターゲットを追加。
- server process を起動する regression では、loopback `redis://` または `rediss://` の `AEGAEON_TEST_REDIS_URL`、または完全な `AEGAEON_*_REDIS_URL` runtime-store env を与える。legacy `REDIS_URL` は supported server posture から外す。未設定時に process-local store へ落とすテストも supported server posture から外す。

## 6. 今後の拡張メモ

- Redis 障害の詳細をメトリクス化（成功/リプレイ/失敗など）し、ダッシュボードでトレンド監視。
- 将来的に `AEGAEON_DPOP_REDIS_URL` を複数指定してレプリカ冗長化（Redis Cluster/Active-Active）する場合は、Lua スクリプト等でアトミックな multi-write を検討する。
- クロスリージョン冗長化を行う場合、名前空間(`namespace`)にリージョン情報を含め、リージョンごとにハッシュが衝突しないようにする。

---

以上が現在の DPoP リプレイストア運用手順です。server 運用では Redis を必須とし、fail-close・監視・アラートを一貫して構築してください。インメモリ実装は直接 unit test / fuzz / protocol harness 用の補助境界としてのみ扱います。
