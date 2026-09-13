# Model Fidelity Register

Last updated: 2026-09-12

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This register classifies every checked-in F* module by how directly it mirrors
the current implementation semantics. The machine-readable inventory is
`model-fidelity.yaml`; `verify_verified_reqs.py --strict` rejects `toy-stub`
modules as grounding for `status: verified` entries.

## Classification

- `faithful`: the module is intended to model the implementation behavior used
  by the referenced claim.
- `simplified`: the module intentionally abstracts implementation detail, but
  may ground a verified entry when the matrix row states the narrowed claim.
- `toy-stub`: the module contains placeholder behavior or toy data and must not
  ground a verified matrix entry.

## Initial High-Risk Entries

| Module | Classification | Reason |
|---|---|---|
| `fstar/pkce/Pkce.Verification.fst` | `toy-stub` | `base64url_encode` returns a constant 43-character placeholder at lines 34-39; verified PKCE S256 rows must use `fstar/pkce/Pkce.fst`, whose S256 model delegates through `Verified.Crypto.Bridge.sha256_of_string`. |
| `fstar/token/Bearer_validation.fst` | `toy-stub` | `validate_bearer` is a constant-`true` stub at lines 5-6 and is referenced only by implemented rows `6750-001` and `6750-003`, not by verified grounding. |
| `fstar/HACL_Wrapper.fst` | `toy-stub` | AEAD/HMAC wrappers return zero-filled placeholder outputs or unconditional decrypt success at lines 19-43; HACL grounding must use the bridge modules or linked C integration. |
| `fstar/par/Client_auth.fst` | `toy-stub` | Lines 5-14 define a toy in-memory registry for `client_a`; partial rows `9126-002` and `9700-004` may reference it, but verified rows must not. |
| `fstar/par/Request_uri.fst` | `simplified` | Lines 62-72 model request URI issuance as a sequential counter; this preserves uniqueness reasoning but does not model RFC 9126 entropy. Runtime entropy remains evidenced by tests and runtime code. |
| `fstar/dpop/Dpop.Htu_validation.fst` | `simplified` | `validate_htu` models only the final exact string comparison; the runtime (`crates/ffi/src/lib.rs` DPoP checks) additionally rejects `?`/`#` in the proof `htu` and strips query/fragment from the request URI before the modeled comparison. The trace for `9449-006` claims the comparison step; the normalization prefix remains evidenced by runtime tests. |
| `fstar/stepup/StepUp.fst` | `simplified` | The F* module is a small pure model that binds a challenge to one immutable `session`. It does not model the runtime successor transfer during login session rotation (`crates/server/src/web/local_auth/post.rs` `complete_stepup_for_local_login`) or authorize-endpoint error responses. Its four lemmas are shallow properties discharged by definition unfolding with `()` proofs. |

## JWS protected-header decoding remains open

`fstar/FStar.Json.fst` is a `toy-stub`: `parse` always returns `None` and
`stringify` always returns `"{}"`. It supplies a JSON value type, but it cannot
ground byte-decoding correctness or a reachable successful byte-parser path.
`Jose.Jws_header` and `Jose.Jws_signature` are therefore `simplified`.
The header-record and `parse_json_spec` policy lemmas concern an already decoded
JSON value. Their byte wrappers depend on this stub. A conditional theorem over
successful decoding does not establish that decoding can succeed.

`Jose.Jws.Verify` is a simplified cryptographic signing-input primitive. It
decodes the compact segments and verifies the signature using `key.alg`, but
does not parse the protected JSON header or compare its `alg` with the key.
Its MAC/key-equivalence lemmas and forgery-event case split apply at that
primitive boundary. They do not establish RFC 7515 Sections 4.1.1/5.2 or
RFC 8725 Section 3.1 algorithm binding from protected bytes. Federation and
TrustMark models using this primitive inherit that open obligation.

Full wire-level algorithm binding requires a concrete protected-byte decoder,
header validation, equality with the verification algorithm, and reachable
matching-algorithm positive controls. Adding the current stub decoder as a
guard would reject every token and does not close this gap. The Rust header/key
comparison and runtime tests are separate evidence; this register does not
establish their correspondence to the F* models. The existing partial JWS
serialization/signing-input rows remain partial. Header AST guard rows retain
only their stated guard-level scope, with no byte-decoding or complete wire
verification claim.

## Review Rule

`fstar/oidc/OIDC.AuthorizationTransactions.fst` is a simplified admission and
retention slice. Serialized fresh counters bound capacity and a rolling insertion
budget; completion does not refund the budget. Cleanup preserves live and foreign
rows and removes expired local rows. The lock model separates advisory acquisition
from FK row locks and distinguishes waiting from a deadline failure. A source
bucket rejects before storage admission; arithmetic bounds cover one source's
overlapping rate windows under explicit clock and identity assumptions. The
runtime uses READ COMMITTED so counts after acquisition see earlier commits.
SQL locking/isolation, lock-key hash collisions, scheduler progress, source
identity, Redis windows, measured byte sizes and cleanup scheduling remain
test/review obligations, not machine-checked correspondence. The source budget
does not prove availability against many sources or shared-NAT fairness. This
module introduces no verified matrix claim.

The effective-target slice also models same-grant access-token re-minting:
a saved target takes precedence over legacy resource/client selection, just as
for refresh. The saved-target success and incorrect client fallback rejection
are separate obligations exercised against both token-store backends.

`fstar/authcode/AuthCode.Snapshot.fst` is an initial, simplified migration design
slice. Its public transition reads, validates and commits the same snapshot,
including the two successful encoding witnesses. It proves single consumption
in a successful single-key compare-and-consume transition. Its total decoder and
authorization predicate are parameters; their correspondence to serde and
production validation is unproved. A second transition specifies retiring the
code before publication, including partial errors and response loss without
restoring the code. The grant Lua uses that ordering; its complete correspondence
to this model is not mechanically checked.
Five further lemmas model lease ownership, expiry, acquisition, stale-owner
release and code retirement. Clock observation, Redis TTL and code-key reuse
remain outside that pure slice. Complete Lua effects are separately transcribed
in the finite-domain module described below. Concrete two-encoding witnesses are model examples, not JSON
integration tests. The module is selected by the F* gate and adds no matrix claim or release
assurance status. Hosted acceptance must be checked for the exact PR head.

`proofs/tamarin/authcode/snapshot_redemption.spthy` is a symbolic design slice
with attacker requests, overlapping workers and nondeterministic lease expiry.
Reads may return a historical snapshot even after consumption; only the current
linear code permits commit. Dropping lease exclusion and allowing stale reads
overapproximates concurrency. The model assumes fresh code generations and
immutable decoded records; it does not prove JSON decoding, Lua failure handling,
lease timing, recovery or storage durability. It has no conclusion-shaped
restrictions and adds no matrix claim.

`fstar/resource/ResourceIndicators.EffectiveTarget.fst` is a simplified migration
design slice for choosing an initial target and preserving its saved context on
refresh. It covers the implicit OIDC UserInfo target missing from the older
resource-only selector. The single-target model also checks scope attenuation,
sender binding, expiry, authorization and OIDC offline-consent inputs, and
requires supplied historical evidence to restore a legacy context. Scope
attenuation affects the access token only: RFC 6749 section 6 requires the
replacement refresh token to retain its original granted scope. The model
preserves that grant and the saved target, including an attenuated refresh
followed by another refresh with omitted scope. Earlier scope-context models
that narrowed the saved grant did not establish this requirement.
Code redemption additionally models the single-resource server policy permitted
by RFC 8707 section 2.2: omission preserves the grant, an exact explicit target
is accepted, and an unrecorded or different explicit target is rejected. A
default-target grant does not authorize adding a target at the token endpoint.
This models selection over parsed inputs, not the approval of the original grant.
Code redemption and refresh use a shared runtime selector. A local Kani harness
directly checks its production acceptance predicate on optional byte strings of
length 0 through 64, including both acceptance and rejection. The string adapter,
URI parsing, original grant approval and complete issuance are outside that
bounded check; the selector's retained target is also exercised by regressions.
Runtime refresh records save a versioned target context (audience, token issuer,
OIDC issuer). The HTTP path now parses requested scope, checks containment in the
stored grant, and carries the selected access scope separately through issuance
and rotation. HTTP and real Redis regressions exercise these transitions;
mechanically checked correspondence for parsing, the stored representation, and
Rust/Lua execution remains open. HTTP authorization now obtains explicit
per-request consent with a durable decision before code issuance; direct issuer
tests still start with an already-authorized grant. Complete consent provenance
correspondence, revocation freshness and obtaining legacy evidence remain open.
This module is selected by the F* gate and adds no matrix claim.

`fstar/oidc/OIDC.OfflineConsent.fst` models explicit, per-request consent at
the parsed-request and authenticated-session boundary. Without an established
alternative consent contract, offline access requires a code response and
`prompt=consent`; conflicting silent prompts are invalid. Its source selection
uses the signed or pushed prompt without an unsigned outer fallback, even
when a wrapper contains no prompt. PAR storage and continuation carry this
value, with HTTP regressions and a real Redis storage regression. Signed-request
HTTP regressions include direct JAR and PAR+JAR, with a combined Redis PAR/code/
token/JTI flow. These tests do not establish mechanical correspondence or a
complete Request Object conformance claim.
The decision transition
preserves the environment, issuer, subject, browser session and request binding,
requires an unexpired pending transaction and an affirmative action, and consumes
both approval and denial. HTTP parsing, random-token entropy, PostgreSQL
atomicity and Rust/SQL correspondence are not proven by these lemmas. The
module adds no verified matrix claim and is selected by the F* gate.

`fstar/oidc/OIDC.RequestObjectTarget.fst` separates a signed request's JWT issuer
from its authorization-server recipient. Its parsed-input admission model
requires successful client-key and JWT checks, a matching signed client ID and
the canonical AS issuer in the audience. The admitted recipient cannot come from
the JWT issuer or an unsigned outer issuer. Client-key and JWT validity are
abstract inputs: these lemmas do not prove signatures, JOSE parsing, freshness
checks, replay storage or Rust correspondence. The module is simplified, is selected by the F* gate and adds no verified
matrix claim.

Four additional lemmas describe assertion admission that excludes the Request
Object media type and authorization-request shape independently of audience.
Real-signature substitution regressions exercise both assertion validators,
including ordinary assertion controls. These parsed-input lemmas do not prove
JOSE decoding or Rust correspondence. The broader JWT-use separation row
`8725-107` is partial because complete correspondence and all JWT-kind
combinations remain open.

The runtime resolver uses the canonical issuer as its expected JWT audience and
returns a distinct AS recipient alongside unchanged signed claims. Stored PAR
requests are checked for that recipient before consent; obsolete target records
require a new request. Real-signature HTTP regressions exercise valid requests,
wrong audiences/client IDs, invalid signatures, expiry, outer parameters and
legacy records. Five tests of the former issuer-merging helpers were replaced
by these request-level regressions because the helpers conflated JWT issuer
and AS recipient; no verified row cites the new simplified model.

When adding a F* module or using a new module in `spec/compliance-matrix.yaml`,
update `model-fidelity.yaml` in the same change. Do not cite a `toy-stub`
module from a `verified` row; replace the block with a faithful or explicitly
simplified model, or downgrade the row status.

`fstar/oidc/OIDC.Reauthentication.fst` models a pending login challenge bound to
an immutable request snapshot, issuer, environment, client and browser. A form
CSRF binding and successful credentials complete it for a new session; a matching
session consumes the receipt once. Expiry, substitution and replay are rejected.
The receipt satisfies the login prompt without changing signed claims; session
validity and step-up checks remain independent. Parsed inputs, credential checks,
randomness and storage atomicity are assumptions. HTTP, SQL and Rust correspondence
remain review and test obligations. No verified matrix claim is added.

`fstar/authcode/AuthCode.RedisGrant.fst` transcribes the production authorization
grant Lua's preflight, OIDC cleanup and ordered publication into a small Redis
command model. Failed commands preserve earlier writes; successful `SET` clears
expiry while mutation of existing collections and `INCR` preserve it. Shared
JSON fixtures generate concrete F* trace obligations and drive the unmodified
production Lua in isolated Redis. All keys, complete values, collection members,
ZSET scores and version values are compared. The comparator also observes exact
absolute expiration when the script should preserve it. A TCP proxy discards a
completed Lua success reply; resubmission must not change any observed state.

This is finite test-and-review correspondence, not mechanically checked
Rust/Lua refinement. The adapter supplies finite canonical integer parsing and
increment tables, string concatenation and the singleton refresh-children JSON
encoding. General parsing, arbitrary key aliasing/corruption, arbitrary runtime
faults, distributed durability, clock scheduling and Rust/HTTP response delivery
are outside this proof. Disabled-feature placeholder aliases and selected
malformed Redis states are explicitly tested; dynamic cleanup links are not
claimed to be constrained against arbitrary corrupted records. The model adds
no verified matrix claim. Regenerate cases with
`python3 scripts/validation/authcode_redis_fixtures.py`; run them against real Redis
with `python3 scripts/validation/check_authcode_redis_grant.py --out-dir OUTPUT`.

## Management initialization

`Management.Initialization` is a simplified atomic transaction model. It proves
first-owner immutability, complete initialization, rollback, and isolation of
other environments under serialized fresh reads. Rust/SQL correspondence, input
validation, password hashing and PostgreSQL locking remain separate obligations.
The namespace-selection lemma assumes the managed digest function and proves
independence from the caller's function; PostgreSQL name resolution and SHA-256
implementation are outside that lemma. No compliance row is promoted on the
strength of this model.

## Token exchange target authority

`fstar/token/TokenExchange.TargetPolicy.fst` is `simplified`. It proves decisions
on canonical target identities, explicit original/current capability sets,
source-scope attenuation, and monotone revocation-root denial. String/URI parsing,
policy serialization and digest construction, snapshot persistence, real-time
rounding, and Redis implementation correspondence remain separate obligations.
The companion Tamarin target model is a fixed read-only temporal slice with
abstract client and sender authentication. Its online-use property requires a
root check at use time and says nothing about offline JWT validation.

The new target-aware behavior supersedes raw audience equality and raw scope
subset as global exchange requirements. The legacy bearer models still describe
the same-audience mode. Target-aware rows remain partial until their concrete
correspondence and full model obligations are discharged.

## Exchange and configuration composition

`TokenExchange.GrantLaws`, `TokenExchange.Lifetime`,
`Configuration.Membership`, and `TokenExchange.Integration` are `simplified`.
They prove general capability attenuation, an integer-nanosecond lifetime bound,
membership preservation across an abstract atomic activation, and composition
with immutable captured authority, refresh-parent target precedence and root
denial. A non-exchange configuration change can preserve exchange-policy identity;
a changed exchange-policy identity rejects the old captured grant.

These models do not refine Rust ownership, clock conversion, PostgreSQL
transactions or runtime reload, Redis scripts or their error prefixes. Production
endpoint and database regressions provide separate test evidence. Neither those
tests nor these model proofs establish machine-checked implementation
correspondence, and no compliance row is promoted on their strength.

The lifetime model accepts signed integer timestamps, including dates before the
Unix epoch. `server-exchange-lifetime` separately checks the actual
`token_exchange_expires_in` Rust helper over every i64 second field, valid
nanosecond field and positive u64 TTL on the pinned x86_64 Linux target. It uses
real `SystemTime` construction and subtraction without stubs, and compares the
result with the seconds/borrow oracle proved in `TokenExchange.Lifetime`.
This helper proof does not establish JWT NumericDate conversion, real-clock
behavior, Redis numeric/time semantics, root horizons or grant composition.
The model remains `simplified`; machine-checked implementation correspondence
for the complete token lifecycle remains open.

## Assumption-Boundary Changes (2026-09-11)

Material model changes made when the six crypto lemma `assume val`s were
removed. Classifications are unchanged (`faithful` for the Bridge, hash, JWS
and PKCE modules; `simplified` for `Jose.SdJwt`); the entries record what a
reviewer must re-check.

| Module | Change | Reviewer note |
|---|---|---|
| `fstar/crypto/Verified.Crypto.Bridge.fst` | `sha256_of_string` and the HMAC wrappers are `opaque_to_smt` instead of `irreducible`; new bad-event definitions (`sha256_collision`, `string_encoding_collision`, `ed25519_forgery`), key-equivalence predicate and proved case-split lemmas; three axioms removed. | The HACL\* hash/Ed25519 wrappers stay `irreducible`; no identity or constant model was introduced. Over-length fallbacks are proved unreachable for `FStar.Bytes`. |
| `fstar/crypto/Verified.Crypto.Hmac.KeyEquiv.fst` (new, `faithful`) | Proves that a short HMAC key and its zero-padded form are distinct yet equivalent, via `friend Spec.Agile.HMAC`. | The `friend` exposes the provider's `wrap`/`hmac` bodies; the graph records it as an implementation-exposing edge. |
| `fstar/HashComputation.fst` | `compute_hash` is `opaque_to_smt`; SMTPat injectivity axiom removed; `hash_collision`, `truncation_collision`, `oidc_hash_collision` and case-split lemmas added. | Consumers (`HashComputation.Model`, `Dpop.Ath_validation`, `IdToken.Spec`) re-verified without the axiom. |
| `fstar/jose/Jose.SdJwt.fst` | `disclosure_digest` is `opaque_to_smt`; SMTPat axiom removed; `lemma_non_forgeability`, `lemma_reconstruction_subset` and helpers carry the finite premise `no_collision_with_issued` / `no_presented_collision`; `*_or_collision` theorems added. | Matrix row 9901-001 states the conditional form. |
| `fstar/jose/Jose.Jws.Verify.fst` | `jws_verify` is `opaque_to_smt` (body unchanged); false axiom removed; `mac_key_equiv`, forgery events, key-equivalence, success-path and case-split lemmas added. Compromise is closed under the same normalized-key equivalence as issuance. | `Jose.Federation` and `TrustMark` use only `jws_verify` and its excluded-middle lemma; re-verified. The regression theorem rejects classifying a MAC made with a leaked equivalent key as a cryptographic forgery. |
| `fstar/pkce/Pkce.fst` | `s256` is `opaque_to_smt`; `s256_collision`, `lemma_s256_collision_witness`, `lemma_pkce_s256_binding_cases` added. | Abstraction of `s256` for downstream proofs is unchanged unless revealed. |

## Forgery-event key provenance (2026-09-12)

The Bridge and JWS Ed25519 events now require membership in an explicit honest
key-generation history. HMAC events require an algorithm-specific generation
record, normalized-key equivalence and at least 32/48/64 bytes for HS256/384/512
on both the generated and verifying keys. The case splits retain a separate
outcome for keys outside this domain. Issuance and compromise still use the full
primitive key-equivalence relation: a leaked short equivalent key must exclude
the entire class from the forgery event.

These histories are inputs from an external security game. The HMAC registry is
the game's private key-generation state, not an attacker-visible list of keys.
F* does not prove
their generation, entropy, oracle-history completeness or correspondence to a
runtime key registry. The computational premises apply only to a consistent
external trace, not arbitrary lists accepted by the model's type signatures.
The assumption graph associates events with modules; it does not establish these
argument-level provenance obligations. All premise statuses and model
classifications remain unchanged. The JWS wire/header binding gap remains open.

`TestForgeryKeyProvenance` checks the positive registration domain, missing
registrations, all three HMAC length boundaries and algorithm separation.
`TestHmacEquivalentCompromise` supplies a qualified registry and proves that
leaking an equivalent key still excludes the forgery event.
