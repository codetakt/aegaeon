# OIDC RP Brokering Specification

Last updated: 2026-10-01

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Purpose

This document specifies the current upstream IdP brokering boundary where Aegaeon acts as an OIDC RP
to external Identity Providers, enabling federated authentication flows.

This document is the canonical current specification for the delivered broker / federation
control-plane posture. The completed Phase B delivery record remains in
`docs/program-management/historical/roadmaps/federated-broker-idp-delivery.md`.

This specification does not widen the released verification claim by itself.

## Implemented Runtime And Control-Plane Boundary

The current broker baseline includes:

- upstream authorization, callback, refresh, and logout relay runtime routes
- upstream discovery and JWKS caching with HTTPS and outbound-domain admission
- environment-scoped account-link storage, search, explicit link, unlink, relink, conflict
  preview/resolution, and bulk relink operations
- broker JIT provisioning controls for enablement, email-domain allowlists, verified-email policy,
  collision policy, and initial local status
- attribute mapping from upstream claims into local profile state
- downstream custom-claim release policy for ID Token and UserInfo surfaces
- trust-anchor inventory, entity-cache diagnostics, trust-chain diagnostics, refresh, and eviction
  operations
- federation logout posture, front-channel upstream logout relay, durable logout-recovery
  incidents, and operator clear flows
- audit events for federation configuration, mapping, claim release, account-link, trust
  diagnostics, logout posture, runtime relay, and recovery operations
- generated management-client and sibling admin-console surfaces for the same day-2 operations

Configuration transactions are the current federation-management surface. A separate top-level
federation resource is not required for the delivered posture.

## Upstream ID Token Hash Claims

For an already admitted and verified PS256, PS384 or PS512 ID Token signature, Aegaeon
validates supplied `at_hash` and `c_hash` using SHA-256, SHA-384 or SHA-512 respectively:
the leftmost half of the digest is encoded as unpadded base64url. The original signature
algorithm remains attached to the token. Signature selection, discovery advertisement,
key admission and hash-claim optionality are unchanged. A supplied hash requires the
corresponding access token or authorization code; omitted code-flow hash claims remain optional.

The server's hash adapter selects the existing RS256/384/512 digest operation when calling
the Low* hash runtime for a PSS signature. This selects a digest only; it does not reinterpret
the signature as RSA PKCS#1 v1.5. The extracted dispatcher and public FFI helper retain their
existing accepted-name domain. The Rust fallback uses the same SHA family. The `verified-claim`
profile continues to reject unavailable or failed required hash runtime operations.

This follows OpenID Connect Core errata set 2 §§3.1.3.6–3.1.3.8 and 3.3.2.11 with the
RSA-PSS digest associations in RFC 7518 §3.5. Finite signed-token and runtime-vector tests
cover the server adapter; the new PSS mapping does not expand the extracted proof domain.
No migration, environment setting or signature-algorithm enablement is introduced.

## Federation Signing-Key Endorsements

Fresh resolution and cache reconstruction verify retained compact JWS artifacts against the
current configured trust anchor. Each subordinate statement supplies the endorsed keys used to
verify the next lower statement; the leaf configuration must verify with its superior's endorsed
keys as well as its self-published keys. The anchor configuration must verify with the configured
anchor keys. Each subordinate signature must also verify with its issuer configuration's keys.
Self-published intermediate keys alone do not authorize lower signatures. Overlapping endorsed
and self-published key sets are supported during rollover;
complete key-set equality is not required.

The internal cache layout remains `[leaf configuration, subordinate statement, superior
configuration, ...]`. Intermediate configurations are discovery artifacts, not extra normative
Trust Chain links. Invalid candidate paths backtrack within the existing resolution limits.
Cache reads and fresh resolver callbacks reconstruct metadata from the signed bytes and recheck
the requested leaf and current anchor, so detached parsed metadata cannot override those bytes.

Custom `FederationFetcher` implementations must retain compact JWS in both `*_with_jws` methods
to support either public trust-chain resolver. Decoded-only implementations remain source
compatible through trait defaults but resolution fails explicitly when JWS evidence is absent.
Existing caches require no migration and are revalidated on use; stale or invalid chains trigger
fresh resolution. Anchor key changes require an explicit configuration update.

This boundary implements the signing-key endorsement requirements common to OpenID Federation
1.0 sections 3.2, 4, and 10.2 and Federation 1.1. It does not adopt a new Federation edition or establish
complete header, statement-profile, metadata-policy, or constraints conformance.

## Federation Signed Parent Relation

Every subordinate statement's issuer must exactly match an `authority_hints` entry in its
subject's signed Entity Configuration. The comparison is case sensitive and does not normalize
URLs or remove trailing slashes. Missing, null, empty, or nonmatching hints reject that path even
when its signatures and key endorsements are valid. Additional hints are permitted when one
matches the immediate superior. A configured terminal anchor may itself have superiors; its
hints do not add another edge to the selected path.

Fresh resolution, custom resolver callbacks, and cache reconstruction check this relation from
retained compact JWS. Final path validation uses signed hints; detached parsed hints cannot replace
them. Invalid cache entries still trigger fresh resolution, and invalid fresh paths
are neither returned as accepted nor written to the cache. Existing caches need no migration.

This implements the parent-relation requirement in the adopted OpenID Federation 1.0,
2026-02-17 edition, section 3.2. It does not establish full statement-profile conformance.

## Federation JWT Purpose And Key Identification

Entity Statement verification, including Entity Configurations and every statement retained in a
trust chain, requires the exact protected header `typ: entity-statement+jwt`. Trust Mark
verification requires `typ: trust-mark+jwt`. Missing, null, empty, or differently typed/purposed
values are rejected even when the signature could otherwise verify. No alternative Trust Mark
media-type profile is configured.

Both verification boundaries require a nonempty string `kid` that exactly selects a supplied
signing key. An absent key ID cannot fall back to the only available key. Type and key identifiers
are case sensitive; key IDs are opaque and are not trimmed, including IDs containing whitespace.
Duplicate protected headers remain rejected by the existing JWS parser. These requirements are
scoped to Federation verification and do not change generic JWS, ID Token, or DPoP handling.

Federation key sets reject duplicate named `kid` values across the whole set before selecting
signature-capable keys. The rule applies to parsed Entity Statement and stored trust-anchor JWKS,
as well as directly supplied verification keys. Repeated IDs reject even when the key material is
identical or only one repeated key permits signature verification. Case-distinct and
whitespace-distinct IDs remain distinct. Empty key arrays and keys without an optional `kid` retain
their existing parsing behavior; signature verification fails when no usable matching key exists.
This admission rule does not implement the separate all-key mandatory-`kid` profile requirement.

Fresh and cached trust-chain verification use the same checks. Existing cached statements with
missing or invalid purpose/key identification are rejected and trigger fresh resolution; there is
no database migration. The explicitly unverified Entity Statement payload parser remains a
discovery/parser API and does not establish acceptance.

The scoped requirements are grounded in OpenID Federation 1.0, 2026-02-17 edition, sections 3,
3.1.1, 3.2, and 7. Entity Statement header `kid` must be nonempty; the Trust Mark verifier retains
the same product admission policy. This does not change the adopted edition or establish full
statement profile conformance, Trust Mark issuer accreditation, or delegation validation.

## Federation Statement Claim Admission

Signature verification admits the exact verified payload through the existing structural JSON
backend and a common claim-profile gate. Duplicate members and trailing JSON are rejected before
projection. The public unverified parser remains structural; typed validation cannot reconstruct
raw null presence or discarded extensions. Signature and profile success alone do not establish
requested identity, freshness, anchor trust, or complete-chain acceptance.

Entity Identifiers require HTTPS authority and host without userinfo, query, fragment, whitespace,
control characters, or backslashes. Strings retain their original spelling for identity checks.
Endpoint URLs permit query parameters. Shape checks do not retrieve unused identifiers or endpoints;
actual retrieval retains the existing SSRF, domain, and rebinding protections.

Both configurations and subordinate statements require a nonempty signing JWKS. Every original
member must have a unique string `kid`, including unused keys, before material parsing. Existing
strict material admission remains; this does not establish full mixed-key or public-key conformance.
Configuration-only hints and Trust Mark fields and subordinate-only constraints, metadata policy,
policy critical members, and source endpoint reject wrong-kind presence, including null. Hints,
when present, must be nonempty identifier arrays. Metadata entity types must be objects and their
immediate parameters non-null; null inside structured parameter values remains supported.

Trust Mark envelopes require the exact `trust_mark_type` and a signed compact JWT whose raw type
matches the envelope. Owner and issuer maps receive shape and identifier checks. This does not
verify Trust Mark accreditation, issuer trust, or delegation. Any present payload `crit` or
`metadata_policy_crit` is refused because no corresponding critical extension is implemented.
Entity Statements explicitly prohibit `trust_chain` and `peer_trust_chain` protected headers.

Every known superior in a selected chain must publish its own signed `federation_entity` metadata
with HTTPS fetch and list endpoints. Subordinate statements cannot supply these two endpoints.
Fetch URL construction requires the advertised endpoint; the inferred well-known fetch fallback
has been removed. A first entity may also offer subordinate services, and a configured terminal
anchor may have superiors. Those path positions do not assert global leaf or rootless roles.

The upstream OIDC consumer additionally rejects raw `aud` and `trust_anchor` presence, even null,
in every selected statement, and requires `openid_provider` in the signed first configuration.
An empty provider object passes this role check, with resolved issuer, endpoint, and key checks
still required. This context gate applies to fresh and cached use. Generic Federation processing
continues to ignore these ordinary extension claims; a core-valid cached chain need not be valid
for OIDC authorization.

Existing cache entries need no migration. Invalid core/profile entries are refused on use and
follow the existing fresh-resolution fallback, including cache replacement after successful
resolution. Test-only statement builders omit empty hints and require explicit subject Federation public
keys, separate from issuer keys and registered OAuth client keys. These builders do not activate
public Federation producer endpoints.

These changes implement common subsets of Federation 1.0/1.1 sections 3.1, 3.2, 5.1.1, 8.1, and 8.2,
and ordinary OIDC restrictions shared by Federation 1.0 and Federation Connect 1.1 section 3.2.
Full metadata-policy, constraints, key-material, temporal-domain, and individual entity admission
remain separate obligations. No edition adoption or new formal assurance follows from these checks.

## Upstream Discovery Endpoint Admission

The server validates upstream OIDC discovery metadata before using any discovered endpoint. The
following discovery members are admitted under the same endpoint policy:

- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`
- optional `end_session_endpoint`

Each admitted endpoint MUST be an absolute URL with a host, MUST use `https`, MUST NOT contain
userinfo credentials, and MUST NOT contain a query or fragment component. Rust test builds may use
loopback `http` endpoints for local mock providers only; this exception is not part of the
production runtime boundary.

When `policy.upstreamOutboundAllowedDomains` is non-empty, every admitted upstream discovery
endpoint, including the optional `end_session_endpoint`, MUST match the configured allowlist. Literal
non-routable hosts are rejected during metadata/redirect admission. Server-performed discovery,
token, JWKS, and upstream refresh HTTP calls additionally use the upstream SSRF policy's DNS/private
target checks and redirect policy.

OIDC treats `end_session_endpoint` as optional. Aegaeon keeps that protocol optionality, but if the
provider publishes `end_session_endpoint`, the value is admitted fail-closed under the same upstream
outbound policy as the mandatory discovery endpoints. This avoids a weaker logout-only URL path and
prevents the server from appending relay state to a provider-supplied URL that already carries a
query or fragment.

## Upstream Issuer Identity

The stored connection issuer is an exact identifier. HTTPS URL validation rejects credentials,
query, fragment, whitespace, control characters and backslashes without rewriting the identifier.
`https://issuer.example` and `https://issuer.example/` are distinct valid identifiers. Case,
explicit default ports and percent-encoding spelling are also significant. Discovery, federation
metadata, callback `iss`, ID Token validation, refresh and active connection currentness compare
against the exact identifier; metadata cache keys preserve it.

Discovery transport removes one terminating slash before appending
`/.well-known/openid-configuration`, as specified by OpenID Connect Discovery 1.0 section 4.1.
Transport URL processing does not alter the expected issuer. Existing outbound protections apply.
The management database's supported issuer domain remains unchanged; accepting a path in the
internal validator does not enable path issuers in managed connections.

Each authorization freezes whether callback `iss` is required: the resolved profile requires it,
or discovery advertises `authorization_response_iss_parameter_supported=true`. A profile that
requires `iss` still rejects metadata without that support. Both success and error callbacks enforce
the frozen requirement, and every present `iss` must exactly match even when omission is permitted.
Later metadata cannot lower the stored requirement (RFC 9207 sections 2, 2.4 and 3).

Deploy authorization writers and callback consumers together and restart pending upstream logins.
Older transactions whose normalized issuer differs from the stored connection fail currentness
checks; their identifier is never reinterpreted. Metadata caches are nonauthoritative and cached
issuer mismatches fail closed. This update requires no schema migration or identity-link rename.

Managed create/update inputs preserve issuer bytes and apply the same strict issuer validator
as runtime, in addition to management's non-routable-host rejection. Whitespace and backslash
spellings are rejected, never trimmed or repaired. Existing invalid stored issuers must be corrected
through a new managed configuration before activation/use; no identifier migration is performed.

Redis authorization records require `issuer_policy_version: 1`, denoting the exact issuer and
profile-OR-discovery `iss` policy. Missing or unsupported versions fail decoding/admission before
atomic consumption; legacy pending records cannot bypass the new policy and may expire naturally.
Deploy authorization and callback instances together: old consumers do not enforce this marker.
Restart pending logins after upgrade. The existing browser-binding namespace remains `v2`.

## Upstream Authorization Browser Binding

Each authorization stores the SHA-256 digest of an independent 256-bit random browser secret.
The secret is sent only in a per-transaction `__Host-aegaeon-upstream-<state-sha256>` cookie with
`Secure; HttpOnly; SameSite=Lax; Path=/`, no Domain, and a lifetime bounded by the configured
authorization lifetime. Positive fractional seconds round up for cookie expiry; the store enforces
the transaction deadline independently. The secret is never included in the upstream authorization
URL or persisted in Redis. The cookie-issuing redirect sends `Cache-Control: no-store` and
`Pragma: no-cache`.
Different pending authorizations use distinct cookies so separate browser tabs can finish independently.

Success and upstream-error callbacks require exactly one well-formed matching cookie across all
Cookie headers. The store atomically checks the digest, the original callback URI reconstructed
from the configured base URL and connection route, and expiry before consuming the transaction.
Missing, malformed, duplicated or mismatched cookies and wrong routes do not consume it. State
alone is insufficient. Only one matching callback can proceed, and backend failures fail closed.
Redis preserves the deadline as whole seconds plus nanoseconds. It validates the complete record
in Rust, then atomically compares the unchanged serialized bytes and the Redis clock before
deleting the key. This requires one additional Redis read. Key retention rounds up to milliseconds;
the stored absolute deadline still determines admission. Records without the fractional field retain
their conservative whole-second deadline. A final Rust freshness check also rejects an already
expired transaction if transport delay or clock differences cross the deadline after atomic
consumption; that authorization must restart.
Issuer validation also applies before an upstream error can redirect to the saved return location.
Every response after consumption expires that transaction's cookie, preserving other pending
transaction cookies and any new login session cookie. Existing successful-login connection
currentness, PKCE, nonce, token validation and session checks still apply.

This implements Aegaeon's browser binding for the OAuth client CSRF protections in
[RFC 6749 section 10.12](https://www.rfc-editor.org/rfc/rfc6749#section-10.12) and
[RFC 9700 section 4.7](https://www.rfc-editor.org/rfc/rfc9700#section-4.7).

### Verification Scope

The browser-binding checks have complementary verification boundaries:

| Check | Covered boundary | Remaining implementation dependencies |
| --- | --- | --- |
| [Tamarin callback model](../../proofs/tamarin/federation/upstream_browser_binding.md) | Symbolic browser/route binding, concurrent consumption and stale snapshots, with normal and error traces | Fresh unpredictable values, protected cookies, ideal hash, trusted storage and a coherent logical deadline |
| [F* callback contract](../verification/oidc/upstream-browser-binding-fstar.md) | Decoded-snapshot admission, state changes, independent clock observations and code/error outcomes | Cookie parsing, decoding, hashing, Redis execution and correspondence to Rust/Lua |
| `crates/kani-harness/src/upstream_deadline.rs` | The production `aegaeon-pure::upstream_deadline` functions over their declared machine domains: fraction validation, checked reconstruction, strict expiry and exact millisecond ceiling | Pinned Linux `SystemTime` representation; actual clocks, serialization and Redis/Lua behavior |

Single consumption applies to a stored transaction without intervening reinsertion.
Exact byte comparison detects different replacement values; it cannot detect restoration
of identical bytes. Protocol-level uniqueness relies on fresh random state and a trusted
store that does not restore consumed records. Transport failure after Redis execution can
leave a transaction consumed even when the caller receives an error. These dependencies
and the complete token/session flow remain outside the narrow models. Passing these
checks does not establish a release-artifact or full-product assurance claim.

### Upgrade And API Compatibility

Upstream authorization keys now use storage version `upstream-auth:v2`. Deploy authorization
writers and callback consumers together, draining or stopping old instances before resuming
upstream login traffic. Mixed old/new callback instances are unsupported: the new namespace
prevents old state-only consumers from accepting new transactions, but old instances retain their
old behavior for old records. In-flight legacy authorizations must be restarted. Old records
without a valid browser digest are never accepted by the new callback gate and can expire naturally.
No database migration or new configuration setting is required.

Rust callers constructing `UpstreamAuthRequest` must provide `browser_binding_digest`.
The state-only `try_consume` / `try_consume_async` APIs are replaced by
`try_consume_bound` / `try_consume_bound_async`, requiring the browser digest and expected callback
URI. The serialized digest remains optional for legacy decoding; absence never grants access.

## Front-Channel Upstream Logout Relay

When brokered upstream logout is enabled for a connection, Aegaeon appends `logout_hint`,
`post_logout_redirect_uri`, and relay `state` only after the discovered `end_session_endpoint` has
passed endpoint admission and the stored endpoint still satisfies the current active upstream
outbound policy at logout time. A preexisting query or fragment on that endpoint suppresses the
front-channel redirect target fail-closed.

Unknown or incomplete upstream logout results remain handled by the logout-recovery model in
`federation-logout-recovery-spec.md`; endpoint admission does not claim that the upstream OP actually
destroyed its own session.

## Account Linking Requirements

Account-link operations must remain environment-scoped and auditable. Relink, conflict-resolution,
and bulk-relink flows fail closed when a moved link stores an upstream refresh token unless the
operator explicitly chooses `clear` or `retain`. Low-confidence reassignment and reassignment to a
non-`ACTIVE` target user also require explicit operator acknowledgement.

## Mapping And Claim Release Requirements

Attribute mapping supports direct copy, lower-case normalization, and group mapping for supported
targets such as `email`, `email_verified`, `name` / `display_name`, and non-reserved custom claims.
Mapped values synchronize into the local profile surface used by downstream ID Token and UserInfo
issuance.

Broker-managed custom claims must be explicitly allowed per downstream surface. Blocked
broker-managed custom claims may remain in local profile storage but are not released downstream.
UserInfo custom-claim release still requires `profile` scope.

## Logout Recovery Requirements

Front-channel upstream logout relay uses durable incident records as the source of truth. Successful
callbacks mark incidents `completed`; timed-out callbacks mark incidents `expired`; replayed or
already-resolved callbacks are rejected and audited. Active incidents affect subsequent upstream
authorization according to the configured recovery policy (`force_prompt_login` or
`disable_connection`).

## References

- Existing test harness: `crates/server/tests/oidc_rp_flow_test.rs`
- Management plane connections container: `management-plane/README.md`
- Logout recovery: `federation-logout-recovery-spec.md`
- Delivery record: `../program-management/historical/roadmaps/federated-broker-idp-delivery.md`
- Tamarin models: `proofs/tamarin/federation/rp_brokering.spthy`
