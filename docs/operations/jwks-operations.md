# JWKS Operations

Last updated: 2026-10-01

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Overview

- The Authorization Server (AS) publishes its own JWKS at:
  - `/jwks`
  - `/.well-known/jwks.json` (compatibility)
- OAuth discovery metadata exposes this via `jwks_uri`.
- The server also fetches *client* JWKS (via a client `jwks_uri`) for client authentication flows such as `private_key_jwt`.
  See: `docs/operations/private-key-jwt.md`.

## JWKS Publication (AS keys)

- `jwks_uri` in `/.well-known/oauth-authorization-server` points to AS public keys (not client keys).
- When OIDC is enabled, the `/jwks` response is derived from ACTIVE and RETIRING
  `OIDC_ID_TOKEN_SIGNING` runtime keys in `aegaeon.runtime_keys`.

## Client JWKS Fetch (`jwks_uri` hardening)

Key knobs (see `docs/configurations/environment/README.md` for the canonical list):
- HTTP/retries, cache TTL, refresh skew, circuit, body cap, and `kid` reuse policy:
  management database fields under `policy.jwks*`
- TLS trust: `AEGAEON_JWKS_CA_BUNDLE`, `AEGAEON_JWKS_INSECURE_SKIP_VERIFY` (development only)
- Shared runtime state: `AEGAEON_JWKS_REDIS_URL`
- Body cache: bounded, process-local, and non-authoritative; on-disk shared body caching is removed.

Monitoring:
- The JWKS fetcher exports counters/latency series and circuit labels.
  See: `docs/operations/monitoring/README.md`.

## Declared algorithms and curves

Client JWKs and upstream OIDC signing keys must use the exact registered
algorithm and curve names. A present JWK `alg` must match the token algorithm;
an absent `alg` retains the existing unspecified-metadata behavior. EC keys
used for `ES256` must declare `P-256`, and keys used for `ES384` must declare
`P-384`, including fetched client keys. Upstream discovery must advertise the
exact token algorithm, such as `RS256`, `ES256`, or `ES384`.

Publishers must correct case aliases, surrounding whitespace and misdeclared
curves before deployment. Even a valid signature is refused when these names
do not match. Signature and claims validation still apply. No schema migration,
automatic key rewriting or new algorithm support is introduced.

This correction binds declared names. Mixed-set admission, `kid`/`alg` null
handling, key material validity, selection ambiguity and public-registration
input ownership remain separate concerns.

## Verification-use metadata

Inline client JWKS, fetched client JWKS (including cached/reloaded entries),
and upstream OIDC signing keys use exact, case-sensitive usage metadata.
`use` must be absent or exactly `sig` to permit signature verification.
If `key_ops` is present, it must include exactly `verify` and may additionally
include `sign`; empty, sign-only, unknown, duplicate, or unrelated operations
cannot grant verification. Restricting combinations to `sign` and `verify` is
Aegaeon's consumer policy; RFC 7517 section 4.3 recommends against unrelated
combinations rather than universally prohibiting them.

Present `use` must be a string and present `key_ops` an array of strings.
Explicit `null` is invalid. The strict parser rejects duplicate operations and
known contradictions between `use` and `key_ops`. Unknown extension values are
retained without trimming or case normalization but do not grant verification.
Other material, algorithm, signature, issuer and claims checks still apply.

Publishers using `SIG`, sign-only operations, explicit null, or other
incompatible metadata must correct their published keys before deployment.
Omitted usage fields remain omitted during cache serialization and valid old
cache records remain readable. There is no cache namespace change or automatic
purge. Malformed mixed-set quarantine, generic `kid`/`alg` null handling, key
material/curve validity and private-input ownership in public registration are
separate concerns; this metadata correction does not establish those properties.

For Rust callers, `Jwk::is_signature_capable` and `JwkSet::signature_keys` retain
their public names and now mean eligibility for **verification** under this
metadata policy. `JwkError` adds `DuplicateKeyOperation(String)` and
`InconsistentKeyUsage`; downstream exhaustive matches must handle both.

## Security Notes

- HTTPS and routable targets are required for `jwks_uri` and redirects; configure a CA bundle when an additional trust anchor is needed.
- Cap response size; malformed or structurally invalid JWKS responses fail admission.
- Keep `kid` unique per key material; do not reuse `kid` with different keys unless explicitly allowed by policy.
- In multi-node deployments, use `AEGAEON_JWKS_REDIS_URL` whenever remote client JWKS can affect
  `private_key_jwt` or JWT bearer verification. Redis coordinates circuit state, half-open probes,
  and `kid` fingerprint history. A failed acquisition can reuse only a body that
  passes the current process-local freshness check.

## Key Rotation Guide

### Authorization Server (AS keys)

- Rotate OIDC signing keys through the management API `runtimeKeys` endpoints.
- The KMS/HSM-backed OIDC signing path is tracked in
  `docs/design/oidc-kms-signing-design.md`; hosted bootstrap can create a provider `awsKms`
  OIDC signing runtime key, while the general management API currently accepts provider `databaseEncrypted`.
- Ensure `kid` uniqueness per key material; never reuse a `kid` for different keys.
- OIDC ID Token signing key rotation (recommended overlap pattern):
  1. Create a NEXT `OIDC_ID_TOKEN_SIGNING` runtime key with a fresh `kid`.
  2. Activate that NEXT key through the management API; the previous ACTIVE key becomes RETIRING.
  3. Revoke the RETIRING key after the maximum ID Token TTL has elapsed.

### Server-side fetcher (this project)

- Uses HTTPS with certificate verification and an optional CA bundle; retries with backoff and caps body size.
- Owns the admitted response body for the current call, even when `max-age=0` or
  a cache copy is evicted. Later reuse requires the strict age/lifetime and live
  fingerprint-guard checks below.
- Captures one body and its validators after acquiring the registered URI's refresh
  lock. Sends valid singleton ETag/Last-Modified validators only to the exact
  effective target that produced that body. HTTP dates support the three HTTP
  forms and are emitted as IMF-fixdate.
- Requires a `304` to select that owned candidate: a returned tag must match the
  sent tag; a returned strong tag also requires matching strong history. With no
  returned tag, an equal valid Last-Modified can select it. Missing, malformed,
  duplicate, or conflicting response validators can require unconditional recovery.
- Follows at most two `301`/`302`/`303`/`307`/`308` redirects for unconditional GETs,
  applying the HTTPS/target checks to each hop. Redirect targets are canonicalized
  before request construction, including encoded dot segments. Validators are not
  transferred to another target, even if it reports the same ETag.
- Makes at most one unconditional recovery from the original registered URI after
  an unusable conditional `304` or usable conditional redirect. Ordinary errors
  share one `policy.jwksHttpRetries` budget across phases and hops.
- Applies `policy.jwksHttpTimeoutSeconds` separately to each request's response
  wait and each blocking body read. This setting does not bound the entire fetch,
  URI-lock waiting, scheduling, retries, or downstream admission work.
- Uses an explicit application policy for parsed client keys. Only a complete
  admitted `200` obtained without following a redirect can be reused. Safe
  redirected responses and other admitted `2xx` responses remain usable by the
  current call; a later call fetches again. Any `private`, nonempty or malformed
  `Vary`, `no-store`, or malformed Cache-Control prevents body retention.
- Parses all Cache-Control field lines, quoted values and full nonnegative
  delta-seconds; duplicate numeric directives do not grant cache permission.
  `s-maxage` supplies the application lifetime, further capped by `max-age` when
  both occur. Otherwise use `max-age`, then `Expires`, then the configured default
  TTL only when no explicit lifetime is present. Lifetime is capped at 86,400s.
- Reads the first `Age` member across comma-separated values and repeated field
  lines, as recommended by RFC 9111 section 5.1. An invalid first member makes
  freshness unavailable; later valid members do not replace it.
- Accounts for Date, Age, the actual response delay and time spent reading and
  admitting the body. Reuse requires age strictly less than lifetime and a live,
  matching local security guard. Equality is stale, including for the default
  TTL. Missing Date is synthesized at receipt; invalid or unavailable clock
  arithmetic never grants a fresh default. Valid leap-second dates that cannot
  be projected into this arithmetic require validation on subsequent use.
  Each response captures one wall-clock sample at receipt for age calculation
  and the RFC 850 two-digit-year interpretation of Date, Expires, and
  Last-Modified. Redirects, retries, and `304` validation use their own response
  receipt; time spent waiting or reading the body cannot move that reference.
- Treats `no-cache` as requiring validation on every later use. A strictly
  identifying `304` re-admits the owned keys against local and shared fingerprint
  state and updates policy/age. Present policy groups replace their predecessors;
  absent Cache-Control/Expires/Vary groups inherit. Missing Date/Age describe the
  new validation exchange. This can renew an inherited max-age lifetime; an
  inherited absolute Expires remains the same absolute expiration.
- Separates reusable body/validator state from security-only kid fingerprints.
  `no-store` removes reusable representation state while retaining this explicit
  application security ledger. Each admission or GC operation uses the URI entry
  capacity from its captured policy snapshot. Older in-flight snapshots can
  overlap a newer management setting. Lowering capacity therefore takes effect
  per operation; it is not an immediate global bound on in-flight work. Guard
  replacement, expiry or eviction invalidates its associated body;
  body eviction alone preserves the guard. Stale/no-cache bodies may remain
  briefly for validation, without permission for automatic use. Both retention
  horizons use a fixed instant before shared admission; later parsing or
  publication delays cannot renew them.
- Bounds the local guard horizon by
  `max(jwksCacheTtlSeconds, jwksSharedStateMaxAgeSeconds, 4 * jwksCircuitResetSeconds, 60)`.
  Hits and failed attempts never renew it. Successful 200/304 admission can renew
  local/shared security state. Redis retains the union of distinct kids until the
  URI hash expires; this shared cardinality is not capped by local URI capacity.
  Redis expiry uses the backend clock independently of the local monotonic horizon.
- Detects duplicate `kid` and `kid` reuse with different material according to management policy.
- Supports Redis-backed shared runtime state (`AEGAEON_JWKS_REDIS_URL`) for multi-node circuit,
  probe, and `kid` reuse coordination.

## Compatibility and regression tests

Origins using `no-cache` now require successful revalidation before each reuse.
Responses with `no-store`, `private`, nonempty `Vary`, or malformed cache policy
remain usable for the current admitted call but are fetched again on later calls.
Expired keys are no longer returned after refresh failure. These changes can
increase request volume for origins whose headers previously allowed accidental
reuse; no database migration or new runtime configuration is required.

Backend client JWKS requests never send `Referer`, including same-origin
redirects. A registered URI or intermediate redirect URI is therefore not copied
into the next request's headers; query parameters remain part of their own
requested target only.

The parser follows the field grammar and age calculation in
[RFC 9111 sections 4 and 5](https://www.rfc-editor.org/rfc/rfc9111.html#section-4),
with the stricter application retention policy described above. Validator and
HTTP-date handling use
[RFC 9110 sections 8.8 and 13](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8),
with the rolling 50-year rule in
[section 5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7).

Run the client JWKS tests from the repository root on Linux:

```sh
nix develop -c python3 scripts/validation/test_client_jwks_cache.py
```

The runner requires `unshare`, `ip`, `redis-server`, and `redis-cli`, and permission
to create user and network namespaces. It compiles before creating the namespace,
then verifies that only loopback is active and no non-loopback routes exist
(kernel-created tunnel templates may remain down). HTTPS fixtures use
a local CONNECT proxy and ephemeral certificates; they never forward traffic to
the routable literal addresses used to exercise URL policy. Shared-state tests
start a disposable Redis on a Unix socket with persistence disabled. Temporary
files and Redis state are removed after the run. The default command includes the
otherwise ignored HTTPS and Redis tests as well as ordinary JWKS unit tests,
except for the fingerprint-ledger module. That entire module runs separately via
[`test_jwks_fingerprint_ledger.py`](../../scripts/validation/test_jwks_fingerprint_ledger.py),
which supplies its backend profile and isolated fixture context; see
[fingerprint state](jwks-fingerprint-state.md). The cache runner excludes that
module even with a custom filter and rejects an empty selection before starting
a namespace or backend. Listing and execution use the same selection.

CI runs this command as a required step with `--sudo-netns`. Use that option on
Linux hosts that restrict unprivileged user namespaces. Compilation still runs
as the caller; sudo only creates the network namespace and configures loopback.
After verifying the isolated interfaces and routes, the runner drops all
supplementary groups and restores the caller's UID/GID before starting fixtures.
Both IDs must be positive; a non-root UID with primary group 0 is rejected.
The container integration driver excludes these namespace-only modules from its
ordinary ignored sweeps; the dedicated runner executes them and propagates any
failure. The fixture's namespace checks remain mandatory in both modes.
