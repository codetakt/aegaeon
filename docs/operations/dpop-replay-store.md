# DPoP リプレイストア運用ガイド

Last updated: 2026-10-01

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

本ドキュメントは DPoP 送信者制約のリプレイ対策を Redis で運用するための手順と推奨設定をまとめたものです。Rust FFI は署名と freshness 等を検査して `jti` と任意の nonce を返します。リプレイ記録と nonce policy は Rust middleware が適用し、保存失敗時は fail-closed にします。

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

1. FFI の proof 検証後、Rust middleware が nonce policy を適用します。FFI 自体は `jti` の再利用を検査しません。
2. リプレイキーは既存の environment namespace と、長さ付きで連結した `jkt` / `jti` から導出します。共有 Redis の namespace・キー形式は変更しません。
3. 成功した proof の保存直前に、TTL を次の最大値まで引き上げます。
   - `2 * MAX_DPOP_IAT_WINDOW_SECS + 1` 秒（現在は `2 * 300 + 1 = 601` 秒）
   - 直接構築された middleware の window に対する `2 * iat_window_secs + 1` 秒
   - 呼び出し元が指定した、より長い保存期間
4. `SET <key> 1 NX PX <ttl_ms>` で原子的に保存し、既存キーがあればリプレイとして拒否します。算術 overflow や保存失敗は受理前に拒否し、TTL を切り詰めません。

freshness は整数秒で `abs(now - iat) <= window` と判定します。未来側の端で受理した proof は
最大で window の 2 倍先まで有効なため、片側 window と JWT leeway の加算では不足します。
DPoP freshness に JWT leeway は加算されません。追加の 1 秒は包含する最終秒と保存時刻の端数を
覆い、production の最大 window を使う下限は、共有ストアを使う instance 間の対応範囲内の
window 拡大にも備えます。NumericDate の意味を変更する場合はこの導出を再評価します。

nonce enforcement の有効・無効にかかわらず同じ TTL 下限を適用します。nonce の短い有効期間へ
リプレイ TTL を縮めず、nonce が一回限りとは仮定しません。production は nonce が有効でも
`iat` freshness を検査します。これは RFC 9449 sections 4.3 / 11.1 に対する Aegaeon の
single-use policy であり、全 DPoP 配置に無条件の replay-store MUST があるという主張ではありません。

継続して受理する一意な proof のレートを毎秒 R 件とすると、下限で保持するキー数の目安は
`601 * R` です（期限切れ処理・メモリ overhead は別）。従来の既定 360 秒から保存量が増えるため、
既存の no-eviction 要件を満たす容量を確保します。全 replica が同じ共有ストアを使い、受理期間内に
記録が失われないこと、および時計が信頼できることが前提です。有限の相対 TTL は任意の後方時計変更を
解決せず、本修正はこれらの前提を証明するものではありません。

### 更新時の admission 停止と待機

旧 instance が受理した proof の短い記録は、新 instance から復元・延長できません。
継続的な厳密リプレイ排除が必要な運用では、最後の旧 instance を停止する前に DPoP admission を停止し、
旧 instance による最後の受理から最大の従来 acceptance horizon が経過してから、修正済み instance
だけで再開します。現在の supported maximum では、上記の時計前提の下で 601 秒待機します。
既存 namespace の維持により残存記録は引き継ぎますが、期限切れの記録は復活しません。
rolling deployment だけで過去の replay history が直ちに更新されるとは扱いません。
新しい設定や storage schema は不要です。

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
