# RS256 Verified Backend Feasibility Study

Last updated: 2026-07-27

Status: draft

Owner: Verification

Audience: verification contributors, maintainers

> **Status note (2026-07-27):** Draft investigation for RS256 verified backend
> feasibility. This document is not an implementation plan or claim change.

This investigation evaluates whether the promoted RS256 verifier can move from
the current `aws-lc-rs` runtime contract to a verified backend. It does not
change code or claims.

## Recommendation

The pinned HACL\* tree contains verified RSA-PSS (`Hacl.RSAPSS`) and verified
bignum exponentiation support, but local inspection found no PKCS#1 v1.5 /
EMSA-PKCS1-v1_5 signature verification module. Path A is therefore feasible
only as new verification and extraction work: reuse HACL\* bignum modular
exponentiation, then specify and prove the RS256 EMSA-PKCS1-v1_5 encoding and
comparison layer.

Near term, Path B is the lower-risk verified-RSA route: provide and recommend
PS256 via extracted HACL\* RSAPSS while keeping RS256 as an explicit compatibility
boundary exception. Path C is operationally cheapest but leaves RC-7 permanent
and is weaker for external audit.

## Inputs and Local Evidence

Current RS256 verification is routed through
`aegaeon_crypto::signature::verify_rsa_pkcs1_sha256`, which uses
`signature::RSA_PKCS1_2048_8192_SHA256` from `aws-lc-rs`. PS256 similarly uses
`signature::RSA_PSS_2048_8192_SHA256`. RC-7 records this as unverified but
FIPS-lineage TCB for promoted RS256 slices.

Repository wiring for HACL\* RSAPSS or Bignum was not found in `flake.nix`,
`nix/`, `scripts/extraction/`, `c/`, `crates/ffi/build.rs`, or the Rust JOSE
verification path. The only current Rust RS256 and PS256 verification path is
`aegaeon_crypto::signature`.

## Pinned HACL\* and KaRaMeL Inventory

The repository pins HACL\* through `nix/hacl-star/default.nix`, not as a flake
input:

| Package | Version | Rev |
|---|---:|---|
| HACL\* | `2024.08.26` | `531820c1af15cafc2437068fb565fa0b8b431e73` |
| KaRaMeL | `2025-10-08` | `254e099bd586b17461845f6b0cab44c3ef5080e9` |

The dev shell exposes
`HACL_FSTAR_PATH=/nix/store/lf1yfcf0w1wq3nj42jpc3xzg1q2gw13z-hacl-star-2024.08.26/share/hacl-star/fstar`
and
`EVERCRYPT_SRC_DIR=/nix/store/4apm80wg0j294hycqisbsi5iryd3xxxa-evercrypt-source-2024.08.26/share/evercrypt`.

Modules present in the pinned HACL\* F\* tree include:

- `Spec.RSAPSS.fst`
- `rsapss/Hacl.RSAPSS.fst`
- `rsapss/Hacl.Impl.RSAPSS.fst`
- `rsapss/Hacl.Impl.RSAPSS.Keys.fst`
- `rsapss/Hacl.Impl.RSAPSS.MGF.fst`
- `rsapss/Hacl.Impl.RSAPSS.Padding.fst`
- `rsapss/Hacl.Spec.RSAPSS.fst`
- `bignum/Hacl.Bignum.Exponentiation.fst`
- `bignum/Hacl.Bignum.Exponentiation.fsti`
- `bignum/Hacl.Spec.Bignum.Exponentiation.fst`
- `bignum/Hacl.Spec.Bignum.Exponentiation.fsti`

`Hacl.RSAPSS.fst` exposes `rsapss_verify`, `rsapss_pkey_verify`, and
`new_rsapss_load_pkey`. The generated EverCrypt headers expose the matching C
functions `Hacl_RSAPSS_rsapss_verify`,
`Hacl_RSAPSS_new_rsapss_load_pkey`, and
`Hacl_RSAPSS_rsapss_pkey_verify`.

Local search for `PKCS1`, `PKCS_1`, `PKCS#1`, `PKCS`, `EMSA`, `emsa`,
`DigestInfo`, `v1_5`, `v1.5`, and `rsassa` over the pinned HACL\* F\* files found
no PKCS#1 v1.5 / EMSA-PKCS1-v1_5 verification implementation. Matches in
generated EverCrypt C for `v1_5` were local variable names, not PKCS#1 v1.5
logic.

## Path A: Verified Bignum Modexp Plus New EMSA-PKCS1-v1_5

Path A would build a verified RS256 verifier from HACL\* modular exponentiation
and new project-local F\* for RSASSA-PKCS1-v1_5 with SHA-256 fixed.

Required F\* work:

- Define an RSA public-key admission layer for modulus and exponent bytes,
  reusing HACL\* RSAPSS key loading or HACL\* Bignum predicates where possible.
- Define an RSAVP1/modexp wrapper for the public exponent path.
- Define `emsa_pkcs1_v1_5_sha256_encode` or an equivalent verifier predicate.
- Model exact encoding:
  `0x00 || 0x01 || PS(0xff...) || 0x00 || DigestInfo(SHA256(message))`.
- Prove `PS` length is at least 8 bytes and `k >= tLen + 11`.
- Prove signature length equals modulus length, and that the modexp result is
  serialized to exactly `k` bytes.
- Prove the extracted comparison checks the entire encoded message.
- Preserve leading-zero trimming compatibility with the current JWK/SPKI path.

The SHA-256 DigestInfo DER prefix to use is expected to be
`3031300d060960864801650304020105000420`, but this investigation did not
re-derive it from a standard. Treat that constant as `不明` until the proof task
pins a normative source or derives the DER structure.

Expected extraction and wiring:

- Add a new F\* module under `fstar/jose/` or `fstar/crypto/`.
- Add KaRaMeL extraction scripts and generated C artifacts.
- Extend `crates/ffi/build.rs` or the existing generated-C build path.
- Add a Rust FFI wrapper in `crates/ffi` or `crates/crypto`.
- Route `crates/jose/src/jws.rs` RS256 verification through the wrapper.
- Keep Wycheproof invalid/valid tests and existing RS256 edge-case tests.

Likely assumptions and TCB:

- HACL\* Bignum correctness and generated C memory safety for the selected API.
- SHA-256 computational assumptions already used by the claim boundary.
- C ABI, buffer length, and build/linkage contracts at the Rust FFI boundary.
- Whether HACL\* RSAPSS key loading can be reused without extracting private
  implementation internals is `不明` until a prototype.

Effort is high: multi-week to multi-month. The main risk is proof and extraction
scope, not the encoding algorithm itself.

## Path B: PSS-First Verified RSA

Path B leaves RS256 on `aws-lc-rs` but promotes PS256 as the verified RSA
signature path by wiring extracted HACL\* RSAPSS into the runtime. This aligns
with the pinned HACL\* module inventory and avoids proving PKCS#1 v1.5 padding.

Required work:

- Compile/link `Hacl_RSAPSS.c` and its dependencies through the FFI build.
- Add Rust wrappers for `Hacl_RSAPSS_rsapss_pkey_verify` or
  `Hacl_RSAPSS_rsapss_verify`.
- Map JWK modulus/exponent bytes, modulus bit length, exponent bit length,
  salt length, signature bytes, and message bytes into the HACL\* API.
- Replace or dual-route the current PS256 `aws-lc-rs` verifier.
- Add Wycheproof and JOSE interop tests for PS256.
- Update [crypto-allowlist.md](../claims/crypto-allowlist.md) and verification
  profile wording to recommend PS256 where clients can use it.

This path does not eliminate RC-7 for OIDC mandatory RS256. It improves the
available verified RSA surface and makes claim wording stronger for PS256, but
RS256 remains an explicit compatibility exception.

Effort is medium. The main risks are FFI packaging, API parameter correctness,
and CI portability.

## Path C: Status Quo

Path C keeps RS256 verification on `aws-lc-rs` and keeps RC-7 permanent. This
has low engineering cost and preserves current interoperability, including OIDC
mandatory RS256 ID Token support.

The external-audit explanation is acceptable only if kept explicit: protocol
logic and boundary conditions are modeled, but RSA PKCS#1 v1.5 + SHA-256
verification is unverified runtime TCB. Wycheproof coverage and the crypto
allowlist reduce regression risk but do not close the formal claim gap.

Risk is medium because the unverified primitive sits on a promoted mandatory
OIDC surface.

## Comparison

| Path | Go/no-go view | Effort | Risk | RC-7 effect | Claim wording impact |
|---|---|---:|---|---|---|
| A: HACL\* Bignum + new EMSA-PKCS1-v1_5 | Go only if release criteria require removing RS256 RC-7 | High | High | Could eliminate RC-7 after proof, extraction, and FFI validation | RS256 can move from compatibility TCB to verified backend, subject to residual FFI contracts |
| B: PSS-first | Go for near-term verified RSA progress | Medium | Medium | RS256 RC-7 remains | PS256 can be documented as the recommended verified RSA path; RS256 remains a promoted exception |
| C: status quo | Go only if RC-7 is acceptable as a release boundary | Low | Medium | Permanent | Claim remains assumption-qualified for promoted RS256 |

## Claim and Documentation Impact

Path A would update RC-7 from a live runtime contract to a closed or narrowed
historical risk, assuming the new verifier and FFI boundary are validated.
[claim-definition.md](../claims/assurance-case/claim-definition.md),
[crypto-allowlist.md](../claims/crypto-allowlist.md),
[tcb-inventory.md](../../security/tcb-inventory.md), and the RS256 slice
documents would need to state the verified backend and its residual FFI
assumptions.

Path B would not change RS256 status. It would add a verified PS256 backend to
the allowlist and product positioning, while retaining RC-7 for OIDC mandatory
RS256.

Path C requires no wording change beyond keeping RC-7 prominent and audit-ready.

## Delegator Execution Requests

The following commands reproduce the local evidence and can be re-run by a
delegator with Nix store access:

```bash
nix develop -c bash -lc 'printf "HACL_FSTAR_PATH=%s\n" "$HACL_FSTAR_PATH"; printf "EVERCRYPT_SRC_DIR=%s\n" "$EVERCRYPT_SRC_DIR"'
nix develop -c bash -lc 'find "$HACL_FSTAR_PATH" -type f \( -name "*RSAPSS*" -o -name "Spec.RSAPSS.fst" \) | sort'
nix develop -c bash -lc 'find "$HACL_FSTAR_PATH" -type f \( -name "*Bignum*" -o -name "*Exponentiation*" \) | sort'
nix develop -c bash -lc 'rg -n "PKCS1|PKCS_1|PKCS#1|PKCS|EMSA|emsa|DigestInfo|v1_5|v1\.5|rsassa" "$HACL_FSTAR_PATH" -g "*.fst" -g "*.fsti"'
nix develop -c bash -lc 'rg -n "Hacl_RSAPSS_rsapss_(verify|pkey_verify)|Hacl_RSAPSS_new_rsapss_load_pkey" "$EVERCRYPT_SRC_DIR" -g "*.h" -g "*.c"'
```

`nix build --no-link --print-out-paths .#haclStar` is not a valid reproduction
command in this repository because HACL\* is packaged through `nix/`, not exposed
as a public flake output named `haclStar`.

## Open Questions

- The exact proof effort for EMSA-PKCS1-v1_5 in F\* is `不明` until a prototype.
- Whether a newer upstream HACL\* release adds PKCS#1 v1.5 verification is
  `不明`; this investigation checked only the pinned `2024.08.26` input.
- Whether HACL\* RSAPSS key loading can be reused cleanly for RS256 is `不明`.
- Whether RS256 public verification must be constant-time for the release claim
  is a policy decision; signature verification is public-key only, but exact
  comparison behavior still needs a clear claim boundary.
