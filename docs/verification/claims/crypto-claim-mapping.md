# Crypto Claim Mapping

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document maps each cryptographic `assume val` to the compliance matrix
entries it protects, the Tamarin lemmas that cross-validate the same security
properties, and the runtime policy fields that control activation of the
affected code paths.

For the full assumption register, see
[assumptions/current-register.md](assumptions/current-register.md).
For the authoritative F\* inventory, see `fstar/crypto/Crypto.fst`.

Program posture note (2026-06-30): the server runtime is fixed to the verified profile.
Only the verified allowlist (`HS256/384/512`, `EdDSA`) participates in the general
strong-constraint claim. The OIDC `RS256 Required Slice` and `RS256 Interop Slice`
are closed promoted exceptions; broad RSA remains outside the current server claim.

---

## 1. Assume Val Impact Matrix

| # | Assume Val | Category | Entries Affected | Tamarin Cross-Refs | Runtime activation |
|---|---|---|---|---|---|
| 1 | `jws_verify_unforgeable` | A: Crypto | 7515-001/004, 9068-001, 9449-001, 9901-001, OIDC-1-010, Fed-\* | 10 unforgeability lemmas | `policy.jwtAccessTokensEnabled`, `policy.clientJwtAllowedAlgs`, `policy.oidcEnabled` |
| 2 | `lemma_sha256_collision_resistant` | A: Crypto | hash-dependent entries (PKCE S256, DPoP `ath`, OIDC hashes; see current-register.md §3.2) | collision-resistance lemmas | *(always active)* |
| 3 | `lemma_sha256_of_string_collision_resistant` | A: Crypto | string-to-hash entries (see current-register.md §3.2) | (via #2) | *(always active)* |
| 4 | `lemma_ed25519_unforgeable` | A: Crypto | EdDSA verification entries (see current-register.md §3.2) | unforgeability lemmas | *(always active)* |
| 5 | `disclosure_digest_collision_resistant` | A: Crypto | 9901-001/002/003 | 6 SD-JWT lemmas | *(always active)* |
| 6 | `assumption_collision_resistance` | A: Crypto | 7636-002, 8693-001, 9278-001, 9449-008, 9901-001 | (via #5) | *(always active)* |
| 7 | `hacl_sha256` | B': HACL\* linkage | WASM-verified entries | — | *(WASM target only)* |
| 8 | `hacl_ed25519_verify` | B': HACL\* linkage | WASM-verified entries | — | *(WASM target only)* |
| 9 | `jose_header_entry_error_code` | B'': EverParse linkage | JOSE header entry validation entries | — | *(always active)* |
| 10 | `bytes_prefix_of_buffer` | B''': OIDC hash runtime linkage | OIDC `at_hash`/`c_hash` entries | — | `policy.oidcEnabled` |
| 11 | `evercrypt_hash_incremental_hash` | B''': OIDC hash runtime linkage | OIDC `at_hash`/`c_hash` entries | — | `policy.oidcEnabled` |
| 12 | `host_replay_store_check_and_store` | C: WASM | WASM-verified entries | — | *(WASM target only)* |

> The table above reflects the current 12 `assume val` declarations. Eliminated
> assumptions (FFI stubs, encoding models, WASM host imports #8–#11, DRBG
> `hmac_sha256`, `generate_secure_random`, `fresh_challenge_id`,
> `entity_keys_fresh`) are recorded in
> [assumptions/historical-reductions.md](assumptions/historical-reductions.md).

---

## 2. Security Property Cross-Validation

Each crypto assume val is cross-validated by an independent Tamarin lemma
operating in the symbolic Dolev-Yao model (adversarial network, perfect
cryptography). This provides defense-in-depth: even if the F\* assumption is
violated, the protocol design remains secure under the Tamarin model.

### 2.1 Unforgeability (#2: jws\_verify\_unforgeable)

**F\* property:** Distinct key material implies distinct verification results.

**Tamarin cross-references (10 lemmas):**

| Lemma | File | Property |
|---|---|---|
| `pkjwt_unforgeability` | `client_auth/private_key_jwt.spthy` | Only holder of private key can produce valid JWT |
| `id_token_unforgeability` | `federation/rp_authorize_callback.spthy` | ID token unforgeability under key compromise |
| `downstream_token_unforgeability` | `federation/id_token_chain.spthy` | Downstream token unforgeability |
| `chain_unforgeability` | `federation/op_entity_configuration.spthy` | Trust chain verification unforgeability |
| `jwt_bearer_unforgeability` | `jwt_bearer/jwt_bearer_security.spthy` | JWT Bearer grant unforgeability |
| `response_unforgeability` | `introspection/jwt_introspection_security.spthy` | JWT introspection response unforgeability |
| `disclosure_non_forgeability` | `sd_jwt/sd_jwt_selective_disclosure.spthy` | Only issuer-committed disclosures accepted |
| `entity_config_integrity` | `federation/op_entity_configuration.spthy` | Self-signed entity config integrity |
| `entity_config_self_signed` | `federation/op_entity_configuration.spthy` | Entity config self-signature |
| `dpop_authentication` | `dpop/dpop_replay.spthy` | DPoP proof validity |

### 2.2 Key Freshness (#3: entity\_keys\_fresh)

**F\* property:** Distinct entity identifiers imply distinct key material.

**Tamarin cross-references (5 lemmas):**

| Lemma | File | Property |
|---|---|---|
| `entity_key_uniqueness` | `federation/trust_chain.spthy` | Each entity's key is distinct (`Fr(~sk)`) |
| `key_rotation_authorization` | `federation/trust_chain.spthy` | Only authorized entities rotate keys |
| `anchor_key_authenticity` | `federation/trust_chain.spthy` | Trust anchor key is authentic |
| `registered_key_authenticity` | `federation/federation_key_rotation.spthy` | Registered key is authentic |
| `verified_uses_registered_key` | `federation/federation_key_rotation.spthy` | Verification uses only registered keys |

### 2.3 Collision Resistance (#5, #12)

**F\* property:** Different inputs produce different hashes (SHA-256/384/512).

**Tamarin cross-references (3 lemmas):**

| Lemma | File | Property |
|---|---|---|
| `disclosure_non_forgeability` | `sd_jwt/sd_jwt_selective_disclosure.spthy` | Disclosure digest collision resistance |
| `salt_uniqueness` | `sd_jwt/sd_jwt_selective_disclosure.spthy` | `Fr(~salt)` ensures unpredictability |
| `no_disclosure_without_salt` | `sd_jwt/sd_jwt_selective_disclosure.spthy` | Withheld disclosure salt remains secret |

### 2.4 Freshness (#9, #10: CSPRNG)

**F\* property:** Generate unpredictable random values.

**Tamarin cross-references (5 lemmas):**

| Lemma | File | Property |
|---|---|---|
| `dpop_freshness_guaranteed` | `dpop/dpop_replay.spthy` | DPoP token cannot be replayed |
| `code_freshness` | `authcode/code_replay.spthy` | Authorization code freshness |
| `salt_uniqueness` | `sd_jwt/sd_jwt_selective_disclosure.spthy` | SD-JWT salt unpredictability |
| `entity_key_uniqueness` | `federation/trust_chain.spthy` | Entity key distinctness |
| `idp_key_was_active` | `federation/federation_key_rotation.spthy` | IdP key freshness across rotation |

---

## 3. Runtime Policy Impact

Active PostgreSQL Environment policy fields control which code paths are active,
which determines which crypto assume vals are exercised at runtime.

| Runtime policy field | Default | Crypto Assume Vals Exercised | Entries Gated |
|---|---|---|---|
| `policy.jwtAccessTokensEnabled` | `false` | #2 (JWS unforgeability) | 9068-\* |
| `policy.dpopRequireNonce` | `true` | #9 (CSPRNG) | 9449-011\u2013014 |
| `policy.dpopNonceTtlSeconds` | `300` | #9 (freshness window) | 9449-013 |
| `policy.allowedGrantTypes` includes `urn:ietf:params:oauth:grant-type:device_code` | `false` | #9 (CSPRNG) | 8628-\* |
| `policy.clientJwtAllowedAlgs` | `RS256` | #2 (promoted RS256 client assertion slice) | 7523-\* |
| `policy.federationEntityCacheTtlSeconds` | `86400` | #3 (key freshness window) | Fed-\* |
| `policy.stepupChallengeTtlSeconds` | varies | #10 (challenge ID) | 9470-\* |

**Note:** When a runtime policy field disables a surface, the gated compliance
entries are **out of scope** for the formal claim (see
[assurance-case/claim-definition.md §0.4](assurance-case/claim-definition.md#04-configuration-conditions)).

---

## 4. Runtime Crypto Library Mapping

Each crypto assume val may be exercised by different runtime libraries depending
on the call site. The F\* specification models the security *property*; the
server runtime fixes `policy.cryptoProfile` to `verified`, so compatibility-only
library paths are not a selectable server posture.

**Scope:** This table covers the Rust server runtime path (`crates/server/`).
The Low\*/C extraction path and WASM host path use different implementations
(see [FFI contract register](../runbooks/ffi-contracts/README.md) and [extraction-status.md](../runbooks/extraction-status.md)).

| Assume Val | Verified server runtime | Out-of-claim/runtime-only surfaces | Notes |
|---|---|---|---|
| #2 `jws_verify_unforgeable` | HACL*/EverCrypt-backed HMAC plus verified Ed25519 FFI for `HS*` / `EdDSA`; promoted OIDC `RS256 Required Slice` and `RS256 Interop Slice` by explicit exception | Broad RSA outside the promoted slices, aws-lc-rs (`PS*`), `p256` (`ES*`), and non-promoted JOSE runtime call sites | OIDC `RS256` ID Tokens, signed Request Objects / `request_uri`, JWT bearer grant assertions, and `private_key_jwt` are in-scope only through the promoted slices; broad RSA remains compat |
| #3 `entity_keys_fresh` | ring / host CSPRNG contracts | N/A | External entropy / storage assumptions remain explicit trust boundaries |
| #5 `disclosure_digest_collision_resistant` | `sha2` / verified hash model | N/A | Hash hardness remains an honest theorem premise, not a proved computational fact |
| #9 `generate_secure_random` | ring / OS CSPRNG | N/A | External entropy assumption |
| #10 `fresh_challenge_id` | ring / OS CSPRNG | N/A | External entropy assumption |
| #12 `assumption_collision_resistance` | `sha2` / `aws-lc-rs` as runtime providers | N/A | Models collision resistance as a premise; runtime implementation differs by call site |

---

## 5. Constant-Time Guarantees

| Operation | Verified server path | Out-of-claim path | Evidence note |
|---|---|---|---|
| HMAC comparison | Verified FFI + constant-time comparison | N/A for server profile selection | Formal path plus dudect monitoring |
| Signature verification | `HS*` / `EdDSA` use the verified path; promoted `RS256` slices are explicit boundary exceptions | Broad `RS*` outside the promoted slices, `PS*`, and `ES*` remain library-dependent and outside the current strong-constraint claim | Treat non-promoted signature timing as operational evidence, not formal proof |
| Byte comparison (WASM) | Host contract | Host contract | `host_bytes_eq` MUST be constant-time |
| Token comparison | Verified model | Same constant-time helper semantics | `ConstTime.fst` verified model |

**dudect coverage:** `crates/server/tests/dudect_*.rs` provides empirical
constant-time evidence for the monitored paths. This is classified as
*empirical* evidence, not formal proof (see
[assurance-case/verification-scope.md §1.6](assurance-case/verification-scope.md#16-proof-quality-classification)).

---

## 6. CI Enforcement

| Check | Script | Mode | Scope |
|---|---|---|---|
| Assume val count | `verify_ffi_contracts.sh` | Blocking | 12 total, 0 Category B |
| Direct crypto calls | `check_crypto_calls.py --check` | Warning | Production Rust code |
| Runtime-link drift | `check_runtime_drift.py --check` | Warning (crypto: fail-close) | All runtime-linked files |
| Proof references | `verify_verified_reqs.py --strict` | Blocking | all `status: verified` entries (currently 178) |
| Crypto trust registry | `fstar/crypto/Crypto.fst` | F\* verified | Documentation module |

---

## Cross-References

- [Assumption Register](assumptions/current-register.md) - full assume val details, risk, reducibility
- [Assurance Case](assurance-case/claim-definition.md) - formal claim definition and scope
- [Crypto Extraction Roadmap](../workplans/crypto-extraction-roadmap.md) \u2014 reduction history and future work
- [FFI Contracts](../runbooks/ffi-contracts/README.md) \u2014 Category B assume val details
- `fstar/crypto/Crypto.fst` \u2014 authoritative F\* crypto trust boundary registry
