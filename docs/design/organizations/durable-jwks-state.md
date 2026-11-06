# Durable JWKS admission and disposable response cache

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers and reviewers

S05 separates retained security decisions from cached HTTP representations under
[the storage migration rules](recovery-storage-migration.md). Client registration
and selected DB state remain authoritative. A fetched JWKS body is an optional
projection of the registered remote trust source; losing it requires a new
validated fetch, not reconstruction from audit history.

## Current decisions

Retain the enforced binding from a URI and `kid` to admitted key material for
its configured security horizon. Keep the binding in PostgreSQL, with its expiry
and a fixed serialized-size bound. A conflicting key is refused when the current
policy disallows reuse; full capacity also refuses new admission rather than
discarding an unexpired binding. These are current trust constraints, not a
state-transition journal. PITR restores them at the selected point. Later audit
events neither overwrite them nor trigger automatic revocation.

Keep the shared fetch failure count, open-until decision and one finite fetch
owner for each URI in PostgreSQL. The owner is a current lease for an external
HTTP operation. Completion must match its nonce and unexpired deadline; a late
success cannot close a successor's circuit or publish keys. Expired ownership is
a failed attempt for the current circuit. Store outages refuse new admission.
The native SQL path must preserve accumulated closed-state failures until success;
the old Redis allow script resets them on every closed-state admission and cannot
be copied as the transition specification.

The response body, HTTP validators and monotonic cache deadlines stay in bounded
memory. They are accepted only with their validated current binding and serving
namespace. Cache publication failure does not create authority. Cleanup, cache
misses and new processes cannot erase retained unexpired SQL bindings. Controlled
restore activation discards old process state and selects a fresh serving
namespace as part of REC-T06–09, which remains open.

## Execution and resource design

Use native asynchronous SQL and HTTP for the PostgreSQL path. Do not block a
worker thread on SQL or hold a database connection during remote network I/O.
The current synchronous Redis/fixture APIs remain compatibility paths until all
request-object, assertion and registration-key callers have native entry points.
Crypto verification receives admitted key material from the matching captured
client registration; it cannot silently fall back to a synchronous remote fetch.

Preserve URL/SSRF validation, each actual request/response target correspondence,
conditional-request downgrade rules, redirect limits, metadata parsing, bounded
body reads, retries and total deadlines. Background refreshes retain the owning
runtime scope and cannot publish after that scope closes. Resource exhaustion
or a busy URI does not poison the process. A fresh-cache hit must still validate its admitted body digest and unexpired
positive authority using one indexed SQL read; it cannot infer current permission
from an absent SQL row. The body digest stays stable across equivalent admitted
material, avoiding cross-node cache invalidation on every successful refresh.
An unavailable or incompatible authority discards/refuses that cached result.
Normal fresh-cache reads do not write a global synchronization record. Per-URI single ownership bounds remote fetch
storms; current-PR tests must distinguish refusal, successful refresh and stale
completion. A finite lease is not an exactly-once network-delivery claim.

## Implementation ToDo

- [x] Add current binding/circuit/lease schema, constraints and bounded cleanup.
- [x] Implement asynchronous acquire, failure and admitted-success transactions;
  preserve exact owner identity, TTL and key-conflict behavior.
- [x] Add current admitted body digest/expiry and an indexed positive cache-use
  check; a missing/currently incompatible authority cannot use cached keys.
- [x] Port remote acquisition while reusing the existing validation/HTTP semantics.
- [x] Wire assertion, request-object and client-key callers to admitted keys;
  synchronous SQL access must refuse.
- [ ] Integrate owned background refresh and current serving namespace.
- [ ] Test fresh/cold caches, changed keys, competing fetches, expiry, stale
  completion, cancellation, malformed responses and unavailable SQL.
- [ ] Complete coupled production selection and remove the last JWKS Redis
  requirement only after those callers pass.

Task 1b retains renewed protocol/source mapping. Task 3 retains strict refinement,
clock/isolation/transport premises, provider qualification and the 10,000 HTTP/s,
p99 200 ms measurement. The necessary functional/threat checks remain this PR;
no new proof discharge or load guarantee is claimed here.

The current development catalog is 85 revisions through
`20261105029000_runtime_security_catalog`. A 30-second fetch ownership bound fits
the existing ordinary-work deadline. The native HTTP path shares the remaining
lease budget across redirects, retries, body decoding and SQL completion; it
reserves five seconds for completion and never holds a SQL connection across HTTP.

The initial pin/circuit adapter artifact `hjkykn13glgci3rww0myijfmjv381hs4` passes
three isolated PostgreSQL checks. The v2 successor
`vjxf47kfrxjyndgm920ij7k9a4c99ag7` passes four PostgreSQL checks and one native
body-identity check. They cover 32 contenders, stale completion, threshold-three
failures, expired ownership, binding capacity, 8,193-row cleanup, missing/expired/
replaced positive body authority and order-independent validated material.
All supplier processes for these runs were stopped. These are adapter results,
not integrated request-path results.

The local successor now includes native asynchronous HTTP, explicit admitted-key
handoff to assertion/Request Object workers, asynchronous client-key resolution,
production-constructor selection and replay/JWKS cleanup. Verification is ongoing. Six native HTTP/SQL checks pass, including all three
signed consumers, an owned near-expiry refresh and local capacity refusal. The
JWKS Redis requirement has now been removed from the local config/preflight
inventory; affected inventory and final routing checks are pending. Initial compile failures (test-only
Debug requirement, exhaustive backend match and Arc construction) are retained in
the private evidence directory and corrected in source.

The native cache uses Arc bodies and logarithmic URI lookup. It limits retained
entries by policy and charges them against 64 MiB: sixteen times the bounded wire
body length, plus URI/metadata allowances. This is an explicit accounting budget,
not an allocator/RSS proof or load measurement. Fetch admission is non-queuing and
limited to 32 local operations; per-URI SQL ownership remains the cross-node bound.
Near-expiry refreshes use at most 32 owned asynchronous tasks, deduplicate each URI,
and retain the captured Organizations scope. They are subject to the same finite
fetch lease. Connection pool, in-flight body/crypto ownership, metrics cardinality,
shutdown/drain and full 10,000 HTTP/s capacity remain REC-T06/T07/T11 review items.
The HTTP client is pooled, validates actual DNS resolution, disables implicit
proxies, follows redirects explicitly and never forwards conditional headers to a
redirect target. Existing metadata/validator grammar is reused.

The v6 native HTTP artifact `xkv3pcwg3q2ybpqlkyibmnnrhajbvn06` passes four
PostgreSQL/HTTP tests. The v7 successor `gd29az85n8v6zlzwf1lgz6gvvcn1gfhp`
passes six, adding actual signed consumers and owned background/capacity behavior.
A separately requested legacy replay filter matched no tests (runner exit 99),
so it is retained as an inventory error and is not counted as evidence; its
correct `registry_core::postgres_replay` path will be used in the successor.
Suppliers stopped without cleanup errors. Clippy v8
`7025jk9dmfybbdi0wg4idymac7jkdamp` checks library and binary cleanly; it predates
subsequent test/config/cleanup-label edits. The v8 native build adds optional
cache poison/discard, exact wire-body limits and cache-accounting checks and is
still pending. Full request-route regressions and lifecycle-generation binding
remain open. The 8,805 baseline obligations and new product discharge of zero
remain unchanged.

The v8 native artifact `si8gy3w6wxa428iksrbs5alijz59h76r` passes seven JWKS
PostgreSQL/HTTP checks (including poisoned optional-cache discard and exact body
limits), one native replay check and three existing HTTP route regressions.
Thirty affected native checks also pass: two new identity/resource checks,
nineteen registry checks and nine authorize-query checks. The corrected replay
filter executed one test. Supplier cleanup is confirmed. The native source now
separates JWKS cleanup from assertion replay cleanup for distinct operational
failure visibility. Coupled startup verification is the next increment.
