# Management Plane Follow-up Items

Last updated: 2026-07-08

Status: future plan

Owner: Product / Engineering

Audience: implementers, reviewers

## Remaining open decisions (track in Phase 1)

The core invariants are fixed above (SoT model, rollback safety gates, CSRF, disclosure policy,
issuer immutability). The items below must be resolved before implementation reaches production:

- Configuration snapshot canonicalization:
  - define canonicalization + `configurationHash` computation rules for `schemaVersion = 1`.
- Security downgrade detection:
  - specify exact downgrade rules (fail-closed) for TTL increases, allowlist widening, and policy
    relaxation.
- Revocation ledger storage:
  - define where `revokedSigningKeyIds` / `revokedClientSecretIds` live (separate table vs derived),
  - define “usable” states precisely (e.g. JWKS membership for `RETIRING` vs `REVOKED`).
- Session hardening details (Phase 1):
  - session cookie name, lifetime/idle timeout, rotation policy,
  - CSRF token issuance path and refresh rules.

## Cryptography posture and future FIPS track (Phase 1 guidance)

- Phase 1 の管理プレーンおよびデータプレーンは、既存の Verified Core と同じく EverCrypt/HACL\* を暗号基盤として採用する。実装は F\*/Low\*/KaRaMeL から抽出されたコンポーネントと EverCrypt の C 実装を前提とし、TLS/ハードウェア境界については運用レイヤーで制御する。
- 実装上の暗号プロバイダ差し替えは抽象化レイヤーを通して設計しておくこと（例: keystore プラグインで OpenSSL FIPS Provider や AWS-LC FIPS ビルドに切り替えられるようにする）。
- 現段階では FIPS 140-3 認証を取得していないため、FIPS が契約要件になった場合に備えて以下を検討課題として記録する:
  1. FIPS モード用の暗号プロバイダ実装（OpenSSL FIPS Provider / AWS-LC FIPS 等）の評価と、EverCrypt からの切り替え条件整理。
  2. 自己テスト (KAT)、ランダム生成器の初期化、禁止アルゴリズムの無効化など FIPS 動作要件を満たす初期化フローの追加。
  3. FIPS モードをオンにした場合の Verified Core との整合性（証明済みコードが FIPS プロバイダをラップできるか、あるいは FIPS 時のみ別コードパスを使用するか）の検証。
- これらの検討結果は `docs/program-management/initiatives/sdk/client-sdk-architecture.md` に反映し、FIPS 対応を将来課題として
  `docs/program-management/roadmaps/future/future-projects.md` で追跡する。
