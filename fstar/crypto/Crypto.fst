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

    ## Inventory (assumption-boundary revision)

    ### Tracked `assume val` declarations: 6, all linkage contracts

    | Module | Declaration | Kind |
    |--------|-------------|------|
    | VerifiedCore.Crypto.Hacl | hacl_sha256, hacl_ed25519_verify | HACL* C linkage (-library) |
    | VerifiedCore.Api.Claims.Runtime | host_replay_store_check_and_store | WASM host import |
    | Jose.HeaderParser.Runtime | jose_header_entry_error_code | EverParse C linkage |
    | HashComputation.Low | bytes_prefix_of_buffer, evercrypt_hash_incremental_hash | OIDC hash C linkage |

    None of them states a cryptographic hardness property.

    ### Cryptographic premises: 0 `assume val`, stated as events

    The former six "honest crypto assumption" lemmas were removed because
    their mathematical content was wrong or empty:

    - lemma_sha256_collision_resistant, lemma_sha256_of_string_collision_resistant
      (Verified.Crypto.Bridge), assumption_collision_resistance (HashComputation,
      SMTPat) and disclosure_digest_collision_resistant (Jose.SdJwt, SMTPat)
      asserted universal injectivity of a fixed-output hash, which is false
      by counting.
    - lemma_ed25519_unforgeable ensured `True`.
    - jws_verify_unforgeable derived verification failure from raw-key
      inequality; HMAC key padding makes distinct raw keys equivalent
      (Verified.Crypto.Hmac.KeyEquiv proves the witness).

    They are replaced by definitions of bad events and proved case splits:

    | Module | Event / lemma |
    |--------|---------------|
    | Verified.Crypto.Bridge | sha256_collision, sha384_collision, sha512_collision, string_encoding_collision, sha256_of_string_collision, lemma_sha256_hash_eq_cases, lemma_sha256_of_string_eq_cases, ed25519_forgery, lemma_ed25519_verify_cases, hmac_sha256_key_equiv |
    | Verified.Crypto.Hmac.KeyEquiv | lemma_hmac_sha256_zero_pad, lemma_hmac_sha256_zero_pad_key_equiv |
    | HashComputation | hash_collision, truncation_collision, oidc_hash_collision, lemma_compute_hash_eq_cases, lemma_hash_collision_refines, lemma_oidc_hash_collision_cases |
    | Jose.SdJwt | disclosure_digest_collision, no_collision_with_issued, no_presented_collision, lemma_non_forgeability_or_collision, lemma_reconstruction_subset_or_collision |
    | Jose.Jws.Verify | mac_key_equiv, jws_mac_forgery, jws_eddsa_forgery, lemma_jws_verify_hs_key_equiv, lemma_jws_verify_hs_accepts_mac, lemma_jws_verify_cases |
    | Pkce | s256_collision, lemma_pkce_s256_binding_cases |

    The computational premises that these events are infeasible
    (SHA-256/384/512 collision resistance, HMAC-SHA-2 PRF/EUF-CMA,
    Ed25519 EUF-CMA) live in
    `spec/assumption-register.json` and
    `docs/verification/claims/assumptions/current-register.md`, outside the
    F* logic.  The effective premises of a verification run (including the
    builder-injected `C.Loops` and lax-loaded provider sources) are
    reconstructed by `scripts/validation/assumption_graph.py`.

    ### Crypto function models

    Hash, HMAC and Ed25519 wrappers are real HACL* spec computations
    (Verified.Crypto.Bridge).  The heavy wrappers (`sha256_hash`,
    `ed25519_verify`, ...) stay `irreducible`; the thin dispatchers
    (`sha256_of_string`, `compute_hash`, `disclosure_digest`, `jws_verify`,
    `hmac_sha256/384/512`, `s256`) are `opaque_to_smt` so that the lemmas
    above can reveal their one-line bodies. These named Bridge dispatch paths
    no longer use identity or constant digest models. This does not describe
    the entire pass closure: HACL_Wrapper and EverCrypt.HMAC retain the
    separately disclosed zero-output models and lax-import boundaries.
*)

/// Re-export: this module is documentation-only.
/// Crypto operations are defined in their respective modules.
/// Centralizing definitions would create circular dependencies.
///
/// For CI enforcement, see:
///   scripts/validation/check_crypto_calls.py
///   scripts/validation/verify_ffi_contracts.sh
