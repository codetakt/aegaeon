# OpenID Connect Federation 1.0 Runtime Specification

Last updated: 2026-10-02

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
not a standard operator. When both occur, their operands are intersected before
combination validation. Previously accepted contradictory alias combinations may fail.

Set operators support homogeneous arrays of strings, objects or numbers, including
empty arrays. one_of accepts string/object/number metadata. value/default also
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

Unknown noncritical operators are ignored after structural validation. Critical
declarations remain rejected by raw statement admission; these helpers cannot validate
critical declarations or recover duplicate members discarded during JSON parsing.
Local anchor policy pinning, complete-chain/cache admission timing and authoritative
use of resolved metadata by every OIDC consumer remain separate integration boundaries.
This functional resolver does not establish full Federation conformance.

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
