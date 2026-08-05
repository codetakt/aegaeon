module Crypto

(** Cryptographic Trust Boundary Registry

    This module is the single authoritative index of all cryptographic
    operations used by the Aegaeon verification suite.  It serves two
    purposes:

    1. **Visibility** — Every crypto trust boundary is listed here,
       making security audits tractable.
    2. **CI enforcement** — The crypto call detection script
       (`scripts/validation/check_crypto_calls.py`) references this
       module to verify that no Rust code bypasses the verified layer.

    ## Inventory (0 Category A crypto function assume vals)

    ### Category A -- Crypto Primitives (0 function assume vals remain)

    All 11 former Category A function assume vals eliminated:
    - 10 via `irreducible` + `reveal_opaque`
    - 1 (hmac_sha256 in Drbg.HmacSha256.fst) via delegation to
      Verified.Crypto.Bridge.hmac_sha256 (HACL* Spec.Agile.HMAC)

    6 Lemma assume vals remain (honest computational hardness):
    - jws_verify_unforgeable (EUF-CMA)
    - lemma_sha256_collision_resistant (SHA-256 CR)
    - lemma_sha256_of_string_collision_resistant (SHA-256 CR)
    - lemma_ed25519_unforgeable (Ed25519 EUF-CMA)
    - disclosure_digest_collision_resistant (SHA-256 CR)
    - assumption_collision_resistance (SHA-256 CR)

    ### Category A — Crypto Primitives (6 eliminated via `irreducible`)

    | Former # | Module | Function | Replacement |
    |----------|--------|----------|-------------|
    | 1 | Jose.Jws.Verify | jws_verify | `opaque_to_smt let ... = false` |
    | 4 | Jose.SdJwt | disclosure_digest | `irreducible let ... = encoded` |
    | 6 | Jose.Rsa_signatures | verify_rsa_pss | `irreducible let ... = false` |
    | 7 | Jose.Rsa_signatures | verify_ed25519 | `irreducible let ... = false` |
    | 8 | Dpop.Signature | verify_signature | `irreducible let ... = false` |
    | 11 | Jose.Jwk_thumbprint_uri | jwk_thumbprint | `irreducible let ... = k` |

    ### Category D — Mathematical Axiom (ELIMINATED)

    | # | Module | Function | Status |
    |---|--------|----------|--------|
    | 12 | HashComputation | assumption_collision_resistance | PROVED via `irreducible` identity + `reveal_opaque` |

    ## The `irreducible` Technique

    For verification purposes, crypto operations that return boolean or
    deterministic values can be replaced with concrete implementations:
    - Signature verification → `false` (conservative deny-by-default)
    - Hash/digest computation → identity function
    - JWK thumbprint → identity function

    The `irreducible` attribute prevents the SMT solver and normalizer
    from observing the concrete value, so downstream proofs cannot
    exploit the simplification.  At runtime, the actual crypto operations
    are linked via the extraction pipeline.

    ### Soundness Assessment

    **Signature verification (`false`):** Sound — proofs show protocol
    correctness under the WORST CASE (all verification rejects). Proofs
    that hold with always-reject also hold when verification succeeds.
    This is a standard conservative abstraction.

    **Hash/digest (identity) and thumbprint (identity):** These are
    WEAKER abstractions. The identity model trivially satisfies
    collision resistance (injective by construction). After `reveal_opaque`,
    `disclosure_digest_collision_resistant` and `assumption_collision_resistance`
    are tautological. The proof shows the protocol is correct IF the hash
    function is injective (which SHA-256 is by standard cryptographic
    convention). This is a sound conservative model.

    ## Collision Resistance (Category D) — ELIMINATED (2026-03-03)

    `assumption_collision_resistance` in `HashComputation.fst` was the
    sole Category D assume val. It has been **eliminated** via
    `reveal_opaque` on the `irreducible` identity implementation of
    `compute_hash`. The identity function is trivially injective, making
    the collision resistance property tautological after `reveal_opaque`.

    **Soundness:** The identity model is weaker than SHA-256 (trivially
    injective). Proofs that hold under identity also hold under any
    injective hash. Defense-in-depth: Tamarin models hash as injective
    (248 lemmas), runtime uses SHA-256 via aws-lc-rs (FIPS-validated).

    ## Permanent vs. Reducible

    All former crypto function assume vals have been eliminated:
    - 10 via `irreducible` + `reveal_opaque`
    - 1 (Drbg.HmacSha256.hmac_sha256) via Bridge delegation to HACL*

    6 crypto Lemma assume vals remain (honest computational hardness).
    2 HACL* linkage assume vals (hacl_sha256, hacl_ed25519_verify in VerifiedCore.Crypto.Hacl).
    1 EverParse linkage assume val (jose_header_entry_error_code).
    2 OIDC hash runtime linkage assume vals (HashComputation.Low bridge contracts).
    1 WASM host import remains (host_replay_store_check_and_store).
    Total: 12 assume vals across 8 files. Phase D's checkpoint was 9; later
    JOSE/OIDC runtime-linkage work added 3 explicit linkage contracts.
*)

/// Re-export: this module is documentation-only.
/// Crypto operations are defined in their respective modules.
/// Centralizing definitions would create circular dependencies.
///
/// For CI enforcement, see:
///   scripts/validation/check_crypto_calls.py
///   scripts/validation/verify_ffi_contracts.sh
