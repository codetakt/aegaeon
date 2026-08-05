# Runtime Contract Register

Last updated: 2026-08-05

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This register enumerates the runtime and TCB contracts that the formal claim
**presupposes in addition to** the 12 F\*-logic axioms in
[current-register.md](current-register.md). Each contract is a property that
the proofs take as given but that is satisfied by unverified runtime
components. If a contract is violated, dependent proofs may not describe
actual system behaviour, even though the F\* verification itself remains
sound.

These contracts are distinct from `assume val` declarations: they are not
visible to the F\* type-checker. They were previously documented across the
claim definition, the TCB inventory, and the RNG workplan; this register is
now the canonical index. IDs are stable and citable (RC-1 through RC-7).

## Contracts

| ID | Contract | Satisfied by (runtime) | Modeled as (proof side) | If violated | Risk |
|---|---|---|---|---|---|
| RC-1 | **OS entropy quality.** Each 32-byte read from the OS CSPRNG (`getrandom`) is fresh, unpredictable output with full cryptographic strength. | Kernel CSPRNG via `getrandom` (`crates/crypto/src/drbg.rs`) | Opaque 32-byte seed parameter; quality not modeled | Auth codes, tokens, challenges, session identifiers, and DPoP nonces become predictable; Tamarin freshness assumptions fail | Low |
| RC-2 | **Seed freshness / no-reuse.** Every DRBG instantiate/reseed consumes a fresh seed exactly once; seeds are never stored, logged, or reused. | Per-request DRBG instantiation at Rust call sites (`crates/crypto/src/drbg.rs`) | Not expressible in the `Tot` DRBG model (same seed yields same output by design) | Duplicate DRBG outputs; colliding identifiers | Low |
| RC-3 | **HMAC-SHA256 is a PRF, and the runtime implements it correctly.** DRBG unpredictability and distinctness of derived values (challenge IDs, session identifiers, generated tokens) require HMAC-SHA256 to be a pseudorandom function and the `hmac`/`sha2` crates (`crates/crypto/src/mac.rs`) to implement HMAC correctly. | RustCrypto `hmac` + `sha2` crates (unverified) | F\* proves the SP 800-90A **construction** only (composition, lengths, counters), not PRF security | DRBG output predictable or colliding despite the verified construction | Low |
| RC-4 | **Signing-key generation randomness.** OIDC signing keypairs are generated with secure randomness outside the DRBG boundary. | `ring`/`aws-lc-rs` `SystemRandom` (`crates/crypto/src/signing.rs`) | Not modeled | Weak or recoverable issuer signing keys | Low |
| RC-5 | **Replay-store atomicity.** The DPoP `jti` replay store and nonce state provide atomic check-and-store under concurrency. | Redis-backed fail-closed runtime-state surfaces (`AEGAEON_*_REDIS_URL`) | Server-runtime counterpart of WASM host assumption #12 in [current-register.md](current-register.md); F\*/Tamarin replay-prevention lemmas presuppose atomicity | DPoP proof replay within the race window | Medium |
| RC-6 | **Time source correctness.** The OS clock supplying `now` is accurate within the modeled skew tolerance. | OS clock via the server runtime | Proofs are parameterized over `now`; skew handling is modeled for specific checks (`is_token_valid_time`, `iat_in_window`) | Expired tokens accepted or valid tokens rejected; TTL bounds unenforced | Low |
| RC-7 | **Promoted-slice compat crypto correctness.** For the promoted RS256 Required/Interop slices, the underlying RSA PKCS#1 v1.5 + SHA-256 verification implementation is functionally correct and cryptographically sound. | `aws-lc-rs` RSA PKCS#1 v1.5 SHA-256 verification via `aegaeon_crypto::signature::verify_rsa_pkcs1_sha256` (`crates/crypto/src/signature.rs`), reached from `crates/jose/src/jws.rs`; residual `jsonwebtoken` / `ring` paths remain outside the promoted verifier | **Not modeled.** The promoted slices are in scope for protocol logic and boundary conditions only; the RSA/SHA implementation is an unverified but FIPS-lineage TCB dependency | Forged or malformed RS256 signatures accepted on the mandatory OIDC ID-Token surface or promoted interop surfaces | Medium |

## Direct UUID Boundary

Direct `uuid::Uuid::new_v4()` use is limited to values that do not require
unpredictability:

- Public identifiers such as `kid`, `client_id`, request IDs, DCR client IDs,
  and record IDs require uniqueness rather than secrecy.
- Logout JWT identifiers (`jti` and `logout_jti`) require collision resistance
  under RFC 7519 section 4.1.7, not unpredictability.
- Management-console session identifiers under `web/management/` are outside
  the formal claim boundary documented in `CLAUDE.md` and are managed
  separately.

OIDC and authorization session identifiers (`sid`) and step-up challenge
identifiers, which do require unpredictability, use the DRBG surface. Argon2
password salts use the same declared entropy boundary.

## Future Closure

RC-7 is reduced from hand-written bigint arithmetic to a maintained `aws-lc-rs`
backend. It is not eliminated. A future HACL*/EverCrypt-backed or otherwise
verified RSA PKCS#1 v1.5 / RSASSA-PKCS1-v1_5 verification path would be needed
to remove this runtime contract.

RSASSA-PSS (`PS256`) verification on the JOSE verified dispatch is outside
this assumption class from 2026-08-02 onward because it is wired to
`Hacl_RSAPSS`; from 2026-08-03 the promoted request-object and
client-assertion surfaces route PS256 through the same verified backend.
PS256 signing remains a compatibility provider path.

## Relationship to Other Documents

- [current-register.md](current-register.md) — the 12 F\*-logic axioms.
  Together with this register, these are the complete set of assumptions
  qualifying the claim.
- [../assurance-case/claim-definition.md](../assurance-case/claim-definition.md)
  — the claim statement that cites both registers.
- [../../../security/tcb-inventory.md](../../../security/tcb-inventory.md) —
  component-level TCB (which software is trusted); this register is
  contract-level (which properties are presupposed).
- [../../workplans/rng/README.md](../../workplans/rng/README.md) — DRBG and
  entropy-input design detail behind RC-1, RC-2, and RC-3.
