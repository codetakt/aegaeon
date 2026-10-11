# OpenID Connect Federation 1.0 Runtime Specification

Last updated: 2026-10-11

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

> **Status note:** RP trust-chain runtime is active. OP publication runtime is
> deferred and remains outside the production router.

This document records the Aegaeon server OpenID Federation runtime contract for the current
release claim. The active server boundary is standards-first and fail-closed: OpenID Federation
is used for outbound entity-statement fetch, trust-chain validation, and upstream connection
metadata admission. Public OP publication endpoints are not routed in production.

## Active Runtime Surfaces

The active runtime supports OpenID Federation as a relying-party / trust-chain consumer:

- federation entity ID URL construction for `/.well-known/openid-federation`
- subordinate fetch URL construction from the authority's advertised endpoint
- outbound entity-statement fetch with SSRF and redirect guards
- environment-scoped trust anchors
- persistent federation entity and trust-chain caches
- trust-chain validation and metadata-policy application
- upstream connection integration for validated federation metadata

The public OP publication surfaces below are intentionally not part of the production router and
return the normal application 404 when requested:

- `/.well-known/openid-federation`
- `/.well-known/openid-federation/fetch`
- `/.well-known/openid-federation/list`
- `/.well-known/openid-federation/resolve`
- `/federation/fetch`
- `/federation/list`
- `/federation/resolve`

The retired OP policy fields `federationEntityExpSeconds` and `federationAuthorityHints` are not
accepted in runtime configuration documents. Federation cache TTL/capacity and outbound-domain
allowlist policy remain environment-scoped database policy because they govern active RP-side
runtime behaviour.

## Metadata Policy Resolution

`TrustChain::resolved_metadata` implements the common metadata policy rules in
OpenID Federation 1.0 and 1.1 section 6.1. It requires a previously verified,
canonical alternating configuration/subordinate chain. Its layout and identity
checks do not authenticate a manually constructed typed chain.

Every supplied policy must have three nonempty object levels, including policies
for undeclared entity types. Policies merge from the most superior statement to
the immediate superior by entity type, exact parameter name and operator.
Repeated value/default must be structurally equal; add/superset use union,
one_of/subset use intersection, and essential uses OR. Each input and intermediate
merge is validated independently of metadata presence. An empty merged one_of
is an error; an empty subset is permitted.

Immediate-superior metadata replaces or adds parameters only within types declared
by the leaf configuration. Other ancestor metadata does not propagate to the leaf.
The merged policy is applied once, in value/add/default/one_of/subset/superset/essential
order. Resolved metadata is a derived result; retained signed statements are unchanged.

Upgrade behavior: value:null removes a field; default cannot be null and applies
only to absence, after add. subset_of filters an array, potentially to an empty
array, which satisfies essential presence. Null top-level metadata parameters,
empty supplied policies and contradictory operator combinations are rejected.
The historical `intersect` operator is a local compatibility alias for subset_of,
not a standard operator. When both occur, their original operand types are checked
before intersection and combination validation. Client scope operands, including
alias operands, must contain valid tokens before normalization. Previously accepted
contradictory or invalid alias combinations may fail.

Set operators support homogeneous arrays of strings, objects or numbers, including
empty arrays. Nonempty set operands within one parameter policy must use the same
element type, even for undeclared entity types; empty operands impose no element type.
This check also applies after each ancestor merge. Different ancestors' subset
operands may still intersect to an empty, type-neutral set. one_of accepts
string/object/number metadata, so it rejects present client scope arrays; absent
optional scope remains allowed. value/default also
support objects and arbitrary arrays; essential supports objects. Structural equality
ignores object key order and retains array order. Decimal comparison uses Number's
representation without converting integers to floating point. Precision already lost
while parsing original JSON remains outside this typed API's guarantee.

The public `apply_metadata_policy` helper keeps generic JSON representations.
`apply_metadata_policy_for_entity_type` additionally processes `scope` for
`openid_relying_party` and `oauth_client` as token arrays and returns a space-separated
string, including an empty string for an empty set. Tokens follow the RFC 6749 ASCII
scope-token alphabet with single SP separators; invalid or empty interior tokens fail.
Scope policy set operands, value and default use arrays of valid tokens. Other strings
and OP `scopes_supported` do not receive this representation conversion.
Conversion occurs only when the normalized scope policy has a recognized operator.
Absent scope policies and ignored unknown operators preserve the original scope.
A valid `value` operator replaces or removes scope without decoding its prior
value; operator operands and the null-metadata admission rule remain validated.

Unknown noncritical operators are ignored after structural validation. Critical
declarations remain rejected by raw statement admission; these helpers cannot validate
critical declarations or recover duplicate members discarded during JSON parsing.
Fresh and cached chain APIs now require policy resolution before returning success.
The upstream OIDC authorize, callback and refresh workflows consume resolved OP
metadata as described below. Successful chain admission and these consumer checks
do not establish full Federation conformance.

## Optional Local Anchor Pins and Complete-Chain Admission

The nullable `TrustAnchor.metadata_policy` and management `metadataPolicy` field
are an optional local equality pin. Absence means no additional pin; configured
anchor identity/keys, signatures, time/path checks and every signed subordinate
policy still apply. A valid chain with no signed policies is permitted.

When a pin is supplied, the anchor-issued subordinate statement must contain the
same policy. Object key order is ignored and array order remains significant.
Unknown noncritical operators remain part of the pin's original JSON comparison.
The pin is validated using the same three-level grammar and operator combinations
as signed policies, but is never merged or applied as an extra ancestor policy.
Empty objects, explicit null, scalars and malformed nested policies are rejected.
Management creation returns 400 before writing the anchor or success audit;
production repository upserts and stored-to-runtime conversion also validate pins.

**Upgrade:** Missing pins previously prevented all chains through those anchors;
now they allow otherwise valid configured-anchor chains. Administrators who used
a missing pin to disable an anchor must remove that configured anchor before
upgrading. Valid nonempty pins retain their exact restriction. Malformed existing
pins remain readable and deletable by authorized administrators but cannot authorize
chains; correct or recreate them through management. No values are silently rewritten,
no migration or cache purge is required, and an invalid stored anchor still prevents
conversion of that environment's full configured-anchor list.

The common raw signed-path admission checks policy grammar, merge, immediate-superior
overlay and application after signature/path/pin validation and before returning
success. Policy errors participate in existing bounded authority-hint backtracking.
Caches reverify original JWS against current keys/pins and policies before returning
a hit; a rejected hit follows existing fresh resolution. Custom fresh callbacks are
independently checked before cache upsert. Signed claims and cached raw evidence are
not replaced with derived metadata, and freely constructed public chain types attest
no validation by themselves.

The subordinate-statement builder omits `metadata_policy` when it has no policy
to impose. It does not emit an empty object, which would invalidate the signed
chain. This compatibility rule does not enable the deferred publication endpoints.
The management OpenAPI request schema describes the pin's three nonempty object
levels; operator operand, combination and scope rules remain runtime validations.

Management chain refresh rechecks acquired raw JWS against the expected leaf and
configured anchor, including policy resolution, before cache renewal and success
audit. Acquisition targets the cached row's anchor even when other anchors are
configured. After acquisition, refresh reloads configured anchors with shared
row locks and verifies the raw path again inside the write transaction, using
the current keys, pin and time. The locks remain held through renewal and audit,
so a concurrent key/pin change or removal cannot authorize a stale refresh.
No database lock is held during remote acquisition. Refused stored evidence may
remain for inspection but is not renewed or
accepted. Existing role/environment checks, explicit-now behavior and cache write
failure semantics remain. Complete-chain cache TTL versus signed time remains a
separate temporal obligation; this change does not alter it.

## Standard Entity Type Constraints

Every Subordinate Statement's optional `constraints.allowed_entity_types`
restricts the derived metadata to the listed exact, case-sensitive type names.
All present lists apply independently: omission adds no restriction, while an
empty list leaves only an already declared `federation_entity` type. That type
is always retained and must not be explicitly included in the list. Unknown
type names and duplicate strings remain supported; original list ordering and
signed statement bytes are preserved.

Resolution validates every supplied metadata policy and representable entity
type constraint, applies immediate-superior metadata only to types originally
declared by the leaf, removes excluded types, then applies policies to the
remaining types. Policies cannot recreate removed or undeclared types, and
filtering cannot hide malformed policy for an unused type. A leaf without metadata still resolves to
`None`; a metadata object emptied by filtering remains a present empty object.
A generic chain can therefore be valid while unsuitable for an OIDC role.

The separate `allowed_leaf_entity_types` local extension still requires any
matching type in the original leaf metadata. It is not an alias for the
standard filter. A local match cannot preserve a type removed by the standard
filter, and a local mismatch still rejects the chain. Raw signature/profile
admission rejects present-null or wrong-shaped `allowed_entity_types`,
`allowed_leaf_entity_types` and `max_path_length` values. Unrecognized additional
constraints remain ignored. Standard naming constraints and critical extension
processing remain separate implementation obligations; the existing `u32`
max-path representation and numerical domain are unchanged.

Rust callers constructing the public `Constraints` struct must add
`allowed_entity_types: None` to preserve prior behavior, or use
`..Constraints::default()` for omitted fields. This is a Rust source-compatibility
change; serialized inputs lacking the field remain compatible. Unverified
parsing retains valid new data but does not establish signature/profile validity.
Direct serde construction cannot preserve malformed raw null presence for later
typed validation.

Cached signed chains are re-evaluated through common admission without rewriting
or purging stored evidence. Invalid new fields use the existing fresh-fallback
behavior and cannot be repaired by detached parsed data. Live authorize,
callback and refresh operations refuse when filtering removes
`openid_provider`, before codes or credentials are sent, including in-flight
transactions. Independently cached ordinary Discovery does not refill the type.
No new management-router or PostgreSQL execution is established by this change;
management refresh retains the same common raw-chain gate.

## Resolved OP Metadata in Upstream OIDC Operations

Each authorize, callback and refresh operation selects one effective typed
Discovery object. With configured trust anchors, it comes entirely from the
resolved signed `openid_provider` metadata after common raw chain and ordinary
OIDC-context admission. Missing required fields fail; optional fields removed by
policy remain absent. Only an actually empty configured-anchor list permits
ordinary Discovery. Repository, chain or policy failures never trigger fallback.
Raw signed statements and the ordinary Discovery cache are not overwritten with
policy-derived metadata. Every non-null inline `jwks` is parsed at this selection
boundary, with unique present `kid` values, canonical public-key encodings and at
least one signature-capable key.
Malformed inline sets fail before authorize redirects or callback/refresh
credential exchange, including refresh responses without an ID Token. The parsed
signature-key identities are retained for the later fetched-key comparison.

Aegaeon retains a local consistency guard: the selected issuer and required
authorization, token and JWKS endpoint strings must match independently fetched
Discovery exactly. This is an Aegaeon restriction, not a Federation requirement.
Policy replacements for those endpoints work when Discovery agrees. Selected
endpoints retain the existing outbound allowlist, SSRF, redirect, timeout and
body-size checks. Optional logout replacement or deletion is captured from the
selected object when a callback creates a session; older sessions are unchanged.

Authorize uses selected response/grant/auth support, profile-required S256 and
iss support, scopes and ACR before storing a transaction or returning a redirect.
The captured iss requirement is the profile requirement OR advertised support.
Absent supported scopes retain unknown-advertisement behavior; an explicit empty
list rejects requested scopes. Absent token authentication metadata defaults to
`client_secret_basic`. Policy-selected capability and algorithm identifiers are
compared exactly, without case or whitespace normalization. In both ordinary
Discovery and resolved Federation metadata, `rs256` does not authorize an `RS256`
ID Token; providers relying on the former case-insensitive comparison must publish
the registered spelling. An exact matching member still permits the algorithm
when other, unsupported identifiers are also advertised. This follows the
case-sensitive JWA identifiers in [RFC 7518 §7.1.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-7.1.1).

Callback selects and validates current signed metadata before sending the code
or client credentials. It retains captured token/JWKS endpoints, authentication
method, verifier-implied PKCE, iss and ACR requirements. A newly excluding policy
can therefore refuse an in-flight transaction before exchange. The selected
algorithms and optional inline-JWKS consistency constraint then govern ID Token
verification without resolving another chain after exchange. The existing managed
connection/configuration-currentness, state and single-use checks are unchanged.
The browser binding and exact issuer checks remain enforced. This change adds no
fresh DB OAuth-profile query and claims no atomic concurrent revocation barrier.

Refresh validates actual `refresh_token` support before sending credentials.
Absent grant metadata defaults to `authorization_code` and `implicit`, so it
does not advertise refresh support. Aegaeon also retains its existing local
provider/profile admission guard: code response, authorization-code support in
a present grant list, selected authentication and profile-required iss/S256.
This is not a normative assertion that every refresh performs an authorization
code flow. A refresh-only provider is refused by that existing local guard.
A valid response without an ID Token remains supported after metadata admission;
a returned ID Token uses the same selected algorithms and inline-key constraint.
Refresh requests add no scope parameter or new granted-scope lineage check.

Required `jwks_uri` plus optional inline signature-key consistency remains the
key-source contract. Inline-only or `signed_jwks_uri` support, unconsumed
UserInfo/registration fields, broader logout behavior and full Federation
critical/constraint/numeric/cache-time domains remain separate obligations.
Key retrieval for an unfamiliar `kid` uses this same selected metadata context;
the final fetched set must satisfy its retained inline-key constraint before
signature and claim verification. These checks do not establish whole-product
assurance.

## Entity Fetch

The fetcher constructs the standard entity-configuration URL by appending
`/.well-known/openid-federation` to the entity ID. The entity ID must be an HTTPS URL with no
userinfo, query, or fragment. Non-routable literal hosts, private DNS targets, unsafe redirects,
and redirect targets outside the optional environment-scoped domain allowlist are rejected before
entity-statement processing.

Individual HTTP fetches verify the original signed JWT and common statement profile, then require
exact requested identities and current temporal validity. Entity Configurations must have
`iss == sub == requested entity ID`; Subordinate Statements must be non-self-issued with the
requested issuer and subject. JSON escapes are decoded for comparison, but URL normalization,
redirects and endpoint construction do not create entity-identifier aliases. The existing
60-second clock skew, claim ordering and checked arithmetic remain in force.

A subordinate fetch validates the caller-supplied authority configuration's identity, typed
profile and time before acquisition and again after it. That configuration supplies discovery
metadata; it does not authenticate its detached contents. Signature verification uses the
separately supplied issuer keys, which may be superior-endorsed keys. Individual admission does
not establish signed parent membership, configured-anchor trust or complete-chain policies.
The generic `verify_entity_configuration` / `verify_entity_statement` APIs remain limited to
signature and profile verification, and the explicit raw-JWS transport API remains unparsed.

The exported `CachedFederationFetcher` wrapper revalidates raw JWTs on cache hits and fresh
callback results. It checks the returned row's environment, original entity key and current
cache expiry, ignores detached parsed data, and caps writes at the earlier of configured TTL
and signed `exp`. Zero TTL or an already elapsed signed expiry produces no reusable entry.
Clock samples are refreshed after awaited lookup, acquisition and writes; lookup failures
propagate, invalid entries trigger refetch, and a write failure can still return a valid fresh
result. There is no stale-success fallback. The live upstream resolver uses the complete-chain
cache and direct HTTP fetcher; it does not construct this individual cache wrapper.

The management entity-cache refresh operation applies the same contextual raw admission to the
existing row's entity ID. Its second lifecycle-role gate remains before mutation. It rechecks
time after that gate, stores only raw-derived parsed data, and binds a checked absolute expiry
capped by signed `exp`. Validation failure leaves the old row and success audit unchanged;
update and audit share a transaction. Administrative lists may display expired rows without
authorizing their protocol use.

### Compatibility for custom fetchers

The public trait signatures and decoded-only defaults remain source compatible. Custom fetchers
used with the contextual cache wrapper must retain the compact JWT in both `*_with_jws` methods;
missing raw now fails, as it already does for complete-chain resolution. Detached result fields
and public result constructors do not establish verification. Wrong-entity, expired or future
responses previously accepted by individual paths now fail. Entity keys remain unchanged and no cache purge is required.

### Database upgrade

Apply `20261002100000_federation_entity_cache_expiration.sql` with the matching Atlas migration
inventory and deploy the matching binary through the existing schema gates. It removes only the
individual entity-cache `expires_at > fetched_at` CHECK; it does not rewrite existing rows. A
statement accepted within the clock-skew allowance can retain an already elapsed signed expiry
with an accurate acquisition timestamp. Cache reads still exclude expired rows and cleanup still
removes them. Management policy TTL remains 1..=86400 seconds; zero-TTL tests cover only the
direct API seam.

Once such rows exist, re-adding the old CHECK or rolling back the binary is not automatically
valid. Follow the matching database/binary recovery procedure in
[database development](../development/database.md#startup-schema-checks-and-upgrades); do not
extend signed expiry or falsify acquisition time to make rollback succeed.

## Trust-Chain Resolution

Trust-chain resolution starts from a subject entity statement and configured trust anchors. The
resolver fetches authority hints, validates each compact Entity Statement in chain order, applies
metadata policies, and accepts only chains that terminate at a configured trust anchor.

Resolution is bounded by:

- chain depth
- authority-hint fanout per statement
- total authority-hint attempts per resolution
- total resolution wall-clock time
- per-fetch HTTP timeout
- persistent trust-chain cache TTL and capacity

The trust-chain cache stores compact JWS sequences and reconstructs cached chains only after
revalidating the stored sequence against the configured anchor.

## Query Parsers and Statement Builders

The former public OP query parsers and statement builders are retained only as test/internal
structural components. They are useful for proof and regression coverage of OpenID Federation
object shape, duplicate-query rejection, cursor bounds, and JWT envelope construction, but they do
not imply public OP runtime publication.

Future OP publication work must reintroduce production routes only with a database-managed OP
signing key boundary and explicit compliance activation. Until then, OP Entity Configuration,
fetch, list, and resolve rows in the compliance matrix remain planned/non-active.

## Security Boundaries

- Trust anchor configuration is environment-scoped and PostgreSQL-backed.
- Federation entity and trust-chain caches are repository-backed and shared across server
  instances.
- Outbound federation fetches use the same SSRF and redirect policy as other upstream metadata
  fetches.
- Optional outbound domain allowlisting is environment-scoped in the management database as
  `policy.federationOutboundAllowedDomains`; when non-empty, entity configuration and subordinate
  statement fetches must target an exact listed domain or one of its subdomains. Redirect targets
  are checked against the same allowlist.
- OP signing key material is not part of the production runtime state. Test-only statement
  builders may use in-memory key managers, but production Aegaeon server state must not include a
  federation OP signing manager.

## Current Non-Claims

The current server claim does not include:

- public OP Entity Configuration publication
- public OP fetch/list/resolve endpoints
- signed resolve-response JWT publication
- validated trust mark inclusion in resolve responses

Trust mark verification exists as a lower-level capability, but no active production endpoint
currently filters or embeds trust marks in a public resolve response.

## References

- `crates/server/src/federation/fetcher/url_policy.rs`
- `crates/server/src/federation/trust_chain/resolution.rs`
- `crates/server/src/federation/repositories/cache.rs`
- `crates/server/src/federation/repositories/cache/fetcher.rs`
- `crates/server/src/federation/repositories/cache/trust_chain.rs`
- `crates/server/src/web/upstream_metadata/federation.rs`
- `crates/server/src/web/openid_federation.rs` (test-only structural parsers/builders)
- `proofs/tamarin/federation/trust_chain.spthy`
- `proofs/tamarin/federation/op_entity_configuration.spthy`
