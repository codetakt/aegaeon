# Verified Core WASM Extraction

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

> **Status (2026-03-10)**
> `scripts/extraction/package_verified_core.sh` を実行すると、`VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1` に加えて **claims 入力版**（`VerifiedCore_dpop_verify_claims_v1`, `VerifiedCore_jwt_verify_claims_v1`）もエクスポートする `verified_core.wasm` が生成される。claims exports はもはや一律スタブではなく、Verified WASM path では **EdDSA** に対して意味のある status を返し、`jwt_verify_claims_v1` は optional な expected `iss` / `aud` 制約も処理する。`ES256` / `RS256` は引き続き **WASM 内部署名検証**としては unsupported だが、`SIGNATURE_PREVERIFIED` flags を通じて Node/Web reference adapters が host crypto で署名を事前検証し、その後の claims / time / replay enforcement を Verified Core claims exports に委譲できるようになった。`tests/verified_core_wasm/test_instantiate.mjs` は preverified `RS256` accept と non-preverified reject の両方を検証し、`runtime_{node,web}_reference_test.mjs` は adapter-side `RS256` / `ES256` coverage を提供する。
> 2026-03-09 時点で `aud` membership は `c/verified-core/verified_core_exports.c` 内に内製化され、`Dpop.Htm_validation` も `FStar_String_uppercase` を要求しなくなった。さらに minimal runtime shim と HMAC 非依存 build を入れたことで、default fixture の import table は 67 → 64 → 7 に減った。残る host/runtime imports は replay store、`vc_host_register_bytes` / `vc_host_release_handle`、compact parser、handle resolution のみである。`scripts/sdk/runtime_node_reference.mjs` はこの 7-import boundary を直接消費する reference Node adapter であり、`tests/verified_core_wasm/runtime_node_reference_test.mjs` が compact / claims 両経路の Node smoke coverage を提供する。
> `WASI_CLANG` / `WASI_SYSROOT` は自動検出に対応済みだが、未検出の場合は従来通り環境変数で上書きする。
> Low* Warning 15（GC 型／整数）は extraction 時の注意点として残るが、default fixture では `Prims_*` / `__multi3` / allocator shims はもはや host import ではない。
> `scripts/sdk/package_verified_core_dist.js` と `scripts/sdk/sign_core_artifact.js` により、dev/test 用の Ed25519 署名、CycloneDX SBOM、hash helper files、TypeScript bindings を含む packaged distribution は生成可能になった。`tests/verified_core_wasm/package_dist_test.mjs` が sign → package → fetch verification を通す。`scripts/sdk/runtime_web_reference.mjs` と `tests/verified_core_wasm/runtime_web_reference_test.mjs` は browser-facing runtime adapter surface を Node/WebCrypto 上で検証し、`tests/verified_core_wasm/runtime_web_reference.html` / `runtime_web_reference_server.mjs` は secure-context browser smoke harness を提供する。残る課題は production key custody、CI attestations、公開 release 向けの運用固定化、および dedicated browser CI である。
> **Positioning note (2026-03-09)**
> This plan supports the future client / SDK distribution track. It does **not** by itself create a claimable "formally verified client" product statement. Use `../product-positioning.md` for current outward-facing wording and `../verification/claims/assurance-case/claim-definition.md` for the formal boundary.

## 1. Purpose

Provide a reproducible pipeline that extracts the Verified Core (F*/Low*/KaRaMeL) into a `wasm32-wasi`
artifact, signs it, and exposes a minimal C ABI for higher-level adapters. The **same extracted C**
is also built as a **native library** for the server; the WASM artifact is for **client distribution**.
Verified Core artefacts stay in this repository; the Runtime Adapter / Domain SDK 層は別リポジトリ
(`aegaeon-sdk`) で管理される。
This work supports the TypeScript/Rust SDK publication track captured in
`docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`.

## 2. Scope

- **Input modules (initial set)**
  - Phase 1 (prototype): PKCE core (`Pkce`, `Pkce.Challenge`, `Pkce.Verifier`, `Pkce.Method_selection`, `Pkce.Verification`) と DPoP core (`Dpop.*`).
  - AuthCode/Token store モジュールは KaRaMeL 変換時に `Failure("nth")` が発生するため、一時的に除外。原因は KaRaMeL `Simplify.remove_unused_parameters` の既知不具合で、最小再現（`AuthCode.Flow`＋`AuthCode.Store`＋`AuthCode.Types`）でも再発する。修正方針を追跡し、回避策が確立次第に再追加する。
  - 共通ユーティリティ（`ConstTime` / `EverCrypt.*` 等）は対応モジュールの取り込み時に再接続する。
- **Outputs**
  - `artifacts/verified-core/verified_core.wasm` (wasm32-wasi, stripped).
  - `artifacts/verified-core/verified_core.wasm.sha256` / `.sri` / `manifest.json` (hash & metadata).
  - **Native server library** (built from the same extracted C and linked via `crates/ffi`).
- `artifacts/verified-core/verified_core.wasm.sig` (Ed25519 signature; future work).
- `artifacts/verified-core/sbom.json` (CycloneDX; future work).
- `include/verified_core.h` (generated C ABI header; future work).
- `../program-management/initiatives/sdk/client-sdk-architecture.md` updated with build + trust notes and repository split.
- `crates/aegaeon-core` (Rust helper crate) embeds the artefact to provide integrity checks; `aegaeon-sdk/packages/verified-core` supplies the matching pnpm test harness.
- **Out of scope (Sprint A)**
  - TypeScript/Rust runtime adapters (handled in Sprint B).
  - Browser packaging, bundler integration, CDN decisions.
  - FIPS 140 evaluation (recorded as future work in
    `../program-management/initiatives/sdk/client-sdk-architecture.md` §8.1).

## 3. Build Pipeline (proposed)

1. **F-star verification**
   - `nix develop .#verification --command make -C fstar verify-core` (new target).
   - Uses cached `.checked` files (`fstar/.cache`) for deterministic runs.
2. **KaRaMeL extraction**
   - `nix develop .#verification --command scripts/extraction/run_verified_core_lowstar.sh` (new script).
   - Outputs C sources under `generated/lowstar/verified-core/`.
3. **WASM compilation / staging**
   - `scripts/extraction/package_verified_core.sh`（`nix develop .#verification` 内での実行を推奨）。
     - `WASI_CLANG` / `WASI_SYSROOT` が未指定の場合でも、`wasm32-unknown-wasi-clang` と `*-wasi-sysroot` を `/nix/store` から自動検出するように更新済み。
     - 自動検出に失敗した場合は環境変数を明示する。
   - 内部で `run_verified_core_lowstar.sh` を `WITH_WASM_BUILD=1` 付きで呼び出し、`verified_core.wasm` とハッシュ artefact を `artifacts/verified-core/` にコピーする。
   - コンパイルは `wasm32-unknown-wasi` clang ラッパー、KaRaMeL headers (`lib/krml/{c,dist}`)、`assert.h` 不在時のスタブ (`c/wasi-stubs/`) を利用して実施。
   - Exported functions follow naming convention `vc_*`.
4. **Signing & SBOM**
   - Signing key managed via `./keys/verified-core-dev.key` (dev) and Secrets Manager in CI.
   - `cosign sign-blob verified_core.wasm --key ... > verified_core.wasm.sig`.
   - `nix run .#security-sbom -- verified_core.wasm`.
5. **Smoke tests**
   - `tests/verified_core_wasm/` with `wasmtime` harness verifying PKCE round-trip, DPoP proof validation, JWT signature check using known vectors.

## 4. C ABI (initial sketch)

```c
typedef struct {
    const uint8_t *ptr;
    size_t len;
} vc_slice;

typedef struct {
    uint32_t code;      // 0 = success, non-zero = error
    vc_slice output;    // caller-owned buffer on success
} vc_result;

// PKCE
vc_result vc_pkce_challenge_generate(vc_slice verifier);
vc_result vc_pkce_verify(vc_slice verifier, vc_slice challenge);

// DPoP
vc_result vc_dpop_verify(vc_slice jwt, vc_slice jwk, uint64_t now_seconds);

// JWT/JWS
vc_result vc_jwt_verify(vc_slice jwt, vc_slice jwks_json, vc_slice expected_claims_json);

void vc_free_slice(vc_slice slice);
```

> Note: exact signatures will depend on KaRaMeL extraction; the above guides the shim implementation.

## 5. Definition of Done (Sprint A)

1. `scripts/extraction/package_verified_core.sh` succeeds (CI + local `nix develop`).
2. `cargo test -p aegaeon-core` and `pnpm test --filter @aegaeon/verified-core` pass, invoking the WASM artifact through host shims (future work).
3. Artefacts (`verified_core.wasm`, `*.sha256`, `*.sri`, `manifest.json`) are stored under `artifacts/verified-core/` with regeneration instructions.
4. Documentation updated:
   - `docs/program-management/initiatives/sdk/client-sdk-architecture.md` (build + trust model).
   - `docs/program-management/roadmaps/active/management-platform-follow-on-plan.md` (publication and
     hosted-evidence status).
   - This file reflects final module list and command reference.
5. No new fail-open paths; secrets (signing keys) are managed outside git (CI secrets/SSM).

## 6. Open Questions

- Exact list of modules to include in initial WASM (state/nonce helpers may live in `fstar/auth` or `fstar/authcode`; survey in progress).
- Whether to expose streaming APIs (for large payloads) or keep slice-based API.
- Integration with existing EverCrypt C stubs—some routines may already exist as native C; duplication must be avoided.

### 6.1 Candidate module inventory (WIP)

| Capability | Primary modules | Notes |
|------------|-----------------|-------|
| PKCE | `fstar/pkce/Pkce.fst`, `Pkce.Challenge.fst`, `Pkce.Verifier.fst`, `Pkce.Method_selection.fst` | Requires `ConstTime`, `Result`. |
| DPoP | `fstar/dpop/Dpop.fst`, `Dpop.Validation.fst`, `Dpop.Signature.fst`, `Dpop.Replay.fst`, `Dpop.Claims.fst` | Depends on JOSE signature helpers + replay store lemmas. |
| JWT/JWS | `fstar/jose/Jose.Jwt_validation.fst`, `Jose.Jws_signature.fst`, `Jose.Jwk_structure.fst`, `Jose.Alg_policy.fst` | Relies on EverCrypt HMAC/Ed25519 wrappers and TLV parsers. |
| Nonce/State | _(Deferred)_ `fstar/authcode/AuthCode.Store.fst`, `AuthCode.Types.fst` | KaRaMeL `Failure("nth")` のため現状は除外。回避策確立後に再評価。 |
| Utilities | `fstar/ConstTime.fst`, `fstar/result/Result.fst`, `fstar/EverCrypt.HMAC.fst`, `fstar/EverCrypt.Chacha20Poly1305.fst` | Provide constant-time primitives and crypto facades. |

> Action: confirm `authcode` module structure and extend the table before extraction scripting.

## 7. Next Steps

1. Low* warnings整理：Warning 15（GC 型／整数）を発生させている関数群を列挙し、`compat.h` 追加やストア実装リファクタで解消するか、`noextract`/`bundle` 方針を決定する。
2. Token/PkJWT 再統合: `empty_store` 関数化後に KaRaMeL 抽出を再試行し、`Failure("nth")` が解消されたか確認。必要に応じて upstream fix を追従。
3. ABI + Shim: `c/verified_core.c` と `include/verified_core.h` を実装し、`vc_*` エントリポイントを定義。
4. Smoke tests: `cargo test -p aegaeon-core`（wasmtime）と `pnpm test --filter @aegaeon/verified-core`（Node/Web）を実装。
5. 署名/SBOM: `cosign` による `verified_core.wasm.sig` と `nix run .#security-sbom` による CycloneDX を生成、CI に組み込む。
6. Artefact 配信: SDK リポジトリが `pnpm run fetch-core` 経由で取得できるよう、GitHub Release/S3 配信とバージョン管理フローを整備。

---

_This document will be updated as Sprint A progresses._
