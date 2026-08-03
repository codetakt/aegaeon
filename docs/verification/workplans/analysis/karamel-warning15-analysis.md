# KaRaMeL Warning 15 (2026-01-14 時点) 分析メモ

Last updated: 2026-07-07

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

Verified Core (`scripts/extraction/package_verified_core.sh`) の実行時に出力される Warning 15 を整理し、対処方針を共有します。Warning 15 は「Low* に安全に落としきれていない（GC 型や数学的整数が残っている）」場合に発生します。

## 1. 現在発生している Warning 15 一覧

| 対象 | 内容 | 原因 |
|------|------|------|
| `ConstTime.ct_bytes_eq` | 数学的整数とランタイムチェック | `FStar.Seq` ベースの比較が残っている |
| `Dpop.Validation.verify_dpop` | 数学的整数 | `int` ベースの時間差計算・List操作 |
| `Dpop.Htm_validation.validate_htm` | `FStar_String_uppercase` による `string` (GC 型) | メソッド比較を大小文字変換で行っている |
| `Dpop.Iat_validation.validate_iat` | 数学的整数 | `now - iat` の絶対値計算、`int` 判定 |
| `Dpop.Claims.claims` | 数学的整数 | `iat : int` のまま構造体に残っている |
| `Dpop.verify_dpop` / `Dpop.window_ok` | 数学的整数 | Policy predicate が `int` を返している |
| `Pkce.verifier_ok`, `Pkce.strlen` | 数学的整数 | `nat`/`int` ベースの長さチェック |
| `Prims` 系演算子 (`op_GreaterThanOrEqual`, `op_LessThanOrEqual`, `op_Addition`, `op_Subtraction`) | 数学的整数 | 上記モジュールから呼び出され、警告に連鎖 |
| `FStar.UInt32.uint_to_t`, `FStar.UInt32.v` | 数学的整数 | `int` から `u32` への変換が Low* で特別扱い |

## 2. 優先度と対処方針

1. **DPoP 一式**（`Dpop.*`）
   - `iat`/`now`/`window` を `u64` (`UInt64`) に切り替え、差分は飽和演算で処理する。
   - `htm` 正規化は大文字変換 (`String.uppercase`) を避け、事前に大文字化して入力する or 手書き比較に差し替える。
   - `claims` の `iat` を `UInt64.t` にし、`validate_iat` でも整数変換を行わない。
   - `replay_ticket` の生成に合わせて `list` を使わない設計になっているため、残るは整数系のリファクタで解消可能。

2. **PKCE** (`Pkce.*`)
   - 長さチェックを `LowStar.Buffer`/`UInt32` のみで表現し、`nat` を使わないようにする。
   - 文字列長は `u32` にキャスト済み（F* で `len : UInt32.t` を返す helper）を用意する。

3. **共通ユーティリティ** (`ConstTime`)
   - HACL*/EverCrypt の定数時間比較（`Hacl.Hash` 等）への差し替えを検討。
   - 既に Rust 側で `evercrypt` を利用しているため、F* 側も同等の API に寄せる。

## 3. 対応ステップ（提案）

1. `fstar/dpop/Iat_validation.fst` / `Dpop.Validation.fst` に対して、`iat` 型を `UInt64.t` に統一し、差分計算を `if now >= iat then now - iat else ...` 方式に書き換える。
2. `fstar/dpop/Htm_validation.fst` で `String.uppercase` 依存を除去し、許容メソッド（`"GET"`, `"POST"` 等）を列挙して比較する。
3. `fstar/pkce` 系で `nat` ベースの API を `UInt32` ベースにリファクタ。
4. 以上が完了したら再度 `package_verified_core.sh` を実行し、Warning 15 が解消したか確認。残る場合は `compat.h` 追加 or `noextract` などの代替策を検討。

## 4. 参考

- KaRaMeL Warning 15 の詳細解説: <https://github.com/FStarLang/karamel/wiki/Warnings>
- EverCrypt/HACL\* の Low\* 対応ガイドライン: <https://github.com/mitls/mitls-fstar/wiki/LowStar>
- 既存出力ログ: 2026-01-14 時点の `scripts/extraction/package_verified_core.sh` 実行結果。

このメモは継続的に更新し、Warning 15 が解消されたタイミングでアーカイブしてください。
