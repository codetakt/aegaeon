# Crypto Claim Mapping

Last updated: 2026-09-11

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document maps each cryptographic premise — the remaining linkage
`assume val`s and the external computational premises attached to the F\*
bad events — to the compliance matrix entries it protects, the Tamarin lemmas
that cross-validate related properties, and the runtime policy fields that
control activation of the affected code paths. Since 2026-09-11 no
cryptographic hardness property is an `assume val`; rows 1–6 below describe
the events and the register entries that replaced the former axioms.

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
| 1 | *(removed)* `jws_verify_unforgeable` → events `jws_mac_forgery`, `jws_eddsa_forgery`; premises `A-HMAC-SHA2-EUF-CMA`, `A-ED25519-EUF-CMA` | A: Crypto (event) | No verified matrix row cites the former axiom; `Jose.Federation` and `TrustMark` only use `jws_verify` and its excluded-middle lemma. Rows that would rely on unforgeability (Fed-\*, 9449-001) are protocol-level Tamarin evidence. | `trust_chain.spthy`, `federation_key_rotation.spthy` (symbolic signatures; not a proof of the computational premise) | `policy.jwtAccessTokensEnabled`, `policy.clientJwtAllowedAlgs`, `policy.oidcEnabled` |
| 2 | *(removed)* `lemma_sha256_collision_resistant` → event `sha256_collision`; premise `A-SHA256-CR` | A: Crypto (event) | 7636-002/007 (through `s256_collision`), 9449-008 (`hash_collision SHA256`), 9278-101 (thumbprint prefix only; no injectivity used) | `pkce_security.spthy` (`mismatched_verifiers_cannot_inject_codes`, symbolic hash) | *(always active)* |
| 3 | *(removed)* `lemma_sha256_of_string_collision_resistant` → events `string_encoding_collision`, `sha256_of_string_collision` | A: Crypto (event) + symbolic abstraction | 7636-002/007, 9901-001 | (via #2) | *(always active)* |
| 4 | *(removed)* `lemma_ed25519_unforgeable` (was vacuous) → event `ed25519_forgery`; premise `A-ED25519-EUF-CMA` | A: Crypto (event) | No verified row cited it; `Dpop.Signature` and `Jose.Rsa_signatures` call `ed25519_verify` without an unforgeability lemma | `dpop_replay.spthy` (`dpop_authentication`, symbolic) | *(always active)* |
| 5 | *(removed)* `disclosure_digest_collision_resistant` → event `disclosure_digest_collision`; finite premises `no_collision_with_issued`, `no_presented_collision` | A: Crypto (event) | 9901-001 (`lemma_non_forgeability`, `lemma_reconstruction_subset` now conditional; `*_or_collision` unconditional) | `sd_jwt_selective_disclosure.spthy` (`disclosure_non_forgeability`, symbolic hash) | *(always active)* |
| 6 | *(removed)* `assumption_collision_resistance` → events `hash_collision`, `truncation_collision`, `oidc_hash_collision`; premises `A-SHA256-CR`, `A-SHA384-CR`, `A-SHA512-CR`, `A-SHA256-TRUNC128-CR` | A: Crypto (event) | 9449-008, OIDC-1-003, OIDC-1-010 (no verified row used injectivity; the SMTPat axiom was available to all of them) | — | *(always active)* |
| 7 | `hacl_sha256` | B': HACL\* linkage | WASM-verified entries | — | *(WASM target only)* |
| 8 | `hacl_ed25519_verify` | B': HACL\* linkage | WASM-verified entries | — | *(WASM target only)* |
| 9 | `jose_header_entry_error_code` | B'': EverParse linkage | JOSE header entry validation entries | — | *(always active)* |
| 10 | `bytes_prefix_of_buffer` | B''': OIDC hash runtime linkage | OIDC `at_hash`/`c_hash` entries | — | `policy.oidcEnabled` |
| 11 | `evercrypt_hash_incremental_hash` | B''': OIDC hash runtime linkage | OIDC `at_hash`/`c_hash` entries | — | `policy.oidcEnabled` |
| 12 | `host_replay_store_check_and_store` | C: WASM | WASM-verified entries | — | *(WASM target only)* |

> Rows 7–12 are the 6 remaining `assume val` declarations (linkage
> contracts). Rows 1–6 record the removed crypto axioms and their
> replacements; the earlier claim that #1 backed "10 unforgeability lemmas"
> was not supported by the sources (no F\* lemma consumed the axiom).
> Eliminated assumptions (FFI stubs, encoding models, WASM host imports
> #8–#11, DRBG `hmac_sha256`, `generate_secure_random`, `fresh_challenge_id`,
> `entity_keys_fresh`) are recorded in
> [assumptions/historical-reductions.md](assumptions/historical-reductions.md).

---

## 2. Security Property Cross-Validation

Each crypto premise is cross-referenced to independent Tamarin lemmas operating
in the symbolic Dolev-Yao model (adversarial network, perfect cryptography).
This is defense-in-depth for the protocol design only: a symbolic model treats
hashing and signatures as perfect and therefore cannot attest the computational
premises `A-*`; it does not replace them.

### 2.1 Unforgeability (#2: jws\_verify\_unforgeable)

**F\* property:** successful JWS verification is classified as key compromise,
a message issued under the applicable key equivalence, or an explicit forgery event
(`lemma_jws_verify_cases`). Distinct raw HMAC keys can be equivalent and accept
the same token (`lemma_jws_verify_hs_key_equiv`); verification does not establish
that the presenter holds the signing key. The computational unforgeability
premises are external and remain unaccepted.

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

**F\* property:** equal digests come from equal inputs or from a named collision
event (`lemma_sha256_hash_eq_cases`, `lemma_compute_hash_eq_cases`,
`lemma_disclosure_digest_eq_cases`); the premise that the event is infeasible
is external (`A-SHA256-CR`, `A-SHA384-CR`, or `A-SHA512-CR` for the
corresponding full digest). A string-domain digest additionally requires the
separate `string_encoding_collision` boundary; SHA-256 collision resistance alone
does not rule out a disclosure-digest collision. OIDC truncation has its own
128/192/256-bit output premise.

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

Each cryptographic event or assumption concerns different runtime libraries depending
on the call site. The F\* specification models the security *property*; the
server runtime fixes `policy.cryptoProfile` to `verified`, so compatibility-only
library paths are not a selectable server posture.

**Scope:** This table covers the Rust server runtime path (`crates/server/`).
The Low\*/C extraction path and WASM host path use different implementations
(see [FFI contract register](../runbooks/ffi-contracts/README.md) and [extraction-status.md](../runbooks/extraction-status.md)).

| Premise or event | Verified server runtime | Out-of-claim/runtime-only surfaces | Notes |
|---|---|---|---|
| `jws_mac_forgery` / `jws_eddsa_forgery` events (`A-HMAC-SHA2-EUF-CMA`, `A-ED25519-EUF-CMA`) | HACL*/EverCrypt-backed HMAC plus verified Ed25519 FFI for `HS*` / `EdDSA`; promoted OIDC `RS256 Required Slice` and `RS256 Interop Slice` by explicit exception | Broad RSA outside the promoted slices, aws-lc-rs (`PS*`), `p256` (`ES*`), and non-promoted JOSE runtime call sites | OIDC `RS256` ID Tokens, signed Request Objects / `request_uri`, JWT bearer grant assertions, and `private_key_jwt` are in-scope only through the promoted slices; broad RSA remains compat. Runtime key-equivalence handling (HMAC padding) and key-length policy are runtime obligations, not covered by the F\* event. |
| #3 `entity_keys_fresh` | ring / host CSPRNG contracts | N/A | External entropy / storage assumptions remain explicit trust boundaries |
| `disclosure_digest_collision` event (`A-SHA256-CR` plus `string_encoding_collision`) | `sha2` / verified hash model | N/A | The composed string digest can collide through string encoding or SHA-256; hash hardness alone does not discharge both boundaries. The F\* theorems are conditional on finite no-collision predicates or exhibit a witness |
| #9 `generate_secure_random` | ring / OS CSPRNG | N/A | External entropy assumption |
| #10 `fresh_challenge_id` | ring / OS CSPRNG | N/A | External entropy assumption |
| `hash_collision` / `truncation_collision` events (`A-SHA256-CR`, `A-SHA384-CR`, `A-SHA512-CR`, `A-SHA256-TRUNC128-CR`) | `sha2` / `aws-lc-rs` as runtime providers | N/A | Collision resistance is an external premise; the truncated OIDC form has its own weaker premise; runtime implementation differs by call site |

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
