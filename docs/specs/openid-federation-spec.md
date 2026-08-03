# OpenID Connect Federation 1.0 Runtime Specification

Last updated: 2026-07-07

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
- federation fetch URL construction for `/.well-known/openid-federation/fetch`
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

## Entity Fetch

The fetcher constructs the standard entity-configuration URL by appending
`/.well-known/openid-federation` to the entity ID. The entity ID must be an HTTPS URL with no
userinfo, query, or fragment. Non-routable literal hosts, private DNS targets, unsafe redirects,
and redirect targets outside the optional environment-scoped domain allowlist are rejected before
entity-statement processing.

Fetched Entity Statements are retained as compact JWS artifacts in the persistent entity cache.
Cache admission is bounded by the environment policy for federation entity cache TTL and maximum
entry count.

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
