# KaRaMeL Warning 15 Analysis Memo (as of 2026-01-14)

Last updated: 2026-07-07

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This memo inventories Warning 15 messages emitted when running Verified Core (`scripts/extraction/package_verified_core.sh`) and shares the approach to addressing them. Warning 15 occurs when code has not been fully lowered safely to Low* (GC types or mathematical integers remain).

## 1. Current Warning 15 Inventory

| Target | Description | Cause |
|------|------|------|
| `ConstTime.ct_bytes_eq` | Mathematical integers and runtime checks | `FStar.Seq`-based comparisons remain |
| `Dpop.Validation.verify_dpop` | Mathematical integers | `int`-based time difference calculations and List operations |
| `Dpop.Htm_validation.validate_htm` | `string` (GC type) from `FStar_String_uppercase` | Method comparison uses case conversion |
| `Dpop.Iat_validation.validate_iat` | Mathematical integers | Absolute-value calculation for `now - iat` and `int` checks |
| `Dpop.Claims.claims` | Mathematical integers | `iat : int` remains in the structure |
| `Dpop.verify_dpop` / `Dpop.window_ok` | Mathematical integers | Policy predicates return `int` |
| `Pkce.verifier_ok`, `Pkce.strlen` | Mathematical integers | `nat`/`int`-based length checks |
| `Prims` operators (`op_GreaterThanOrEqual`, `op_LessThanOrEqual`, `op_Addition`, `op_Subtraction`) | Mathematical integers | Calls from the modules above propagate warnings |
| `FStar.UInt32.uint_to_t`, `FStar.UInt32.v` | Mathematical integers | Conversions from `int` to `u32` receive special treatment in Low* |

## 2. Priorities and Approach

1. **DPoP modules** (`Dpop.*`)
   - Switch `iat`/`now`/`window` to `u64` (`UInt64`) and use saturating arithmetic for differences.
   - Avoid uppercase conversion (`String.uppercase`) for `htm` normalization; supply already uppercased input or replace it with a handwritten comparison.
   - Change `iat` in `claims` to `UInt64.t` and avoid integer conversions in `validate_iat` as well.
   - The design already avoids `list` in conjunction with `replay_ticket` generation, so refactoring the remaining integer operations can resolve the warnings.

2. **PKCE** (`Pkce.*`)
   - Express length checks using only `LowStar.Buffer`/`UInt32`, avoiding `nat`.
   - Provide string lengths already cast to `u32` (an F* helper returning `len : UInt32.t`).

3. **Shared utilities** (`ConstTime`)
   - Consider replacing comparisons with constant-time comparisons from HACL*/EverCrypt (such as `Hacl.Hash`).
   - Rust already uses `evercrypt`, so align the F* side with equivalent APIs.

## 3. Proposed Steps

1. In `fstar/dpop/Iat_validation.fst` / `Dpop.Validation.fst`, standardize the `iat` type on `UInt64.t` and rewrite difference calculations in the form `if now >= iat then now - iat else ...`.
2. Remove the `String.uppercase` dependency in `fstar/dpop/Htm_validation.fst` and compare against an enumeration of allowed methods (`"GET"`, `"POST"`, etc.).
3. Refactor the `nat`-based APIs in `fstar/pkce` to use `UInt32`.
4. Once these steps are complete, run `package_verified_core.sh` again and check whether Warning 15 has been resolved. If it remains, consider alternatives such as adding `compat.h` or using `noextract`.

## 4. References

- Detailed explanation of KaRaMeL Warning 15: <https://github.com/FStarLang/karamel/wiki/Warnings>
- EverCrypt/HACL\* Low\* guidelines: <https://github.com/mitls/mitls-fstar/wiki/LowStar>
- Existing output logs: results of running `scripts/extraction/package_verified_core.sh` as of 2026-01-14.

Keep this memo updated and archive it once Warning 15 has been resolved.
