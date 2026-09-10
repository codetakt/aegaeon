# Model Fidelity Register

Last updated: 2026-09-09

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

## Review Rule

`fstar/oidc/OIDC.AuthorizationTransactions.fst` is a simplified admission and
retention slice. Serialized fresh counters bound capacity and a rolling insertion
budget; completion does not refund the budget. Cleanup preserves live and foreign
rows and removes expired local rows. The runtime fixes admission to READ COMMITTED
so counts after its environment lock see earlier commits regardless of the pool
default. SQL locking and isolation, measured byte sizes, database
clock observations and cleanup scheduling remain test/review obligations, not
machine-checked correspondence. It introduces no verified matrix claim.

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
