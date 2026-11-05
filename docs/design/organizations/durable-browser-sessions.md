# Durable browser sessions

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, reviewers, operators

This implements S07 in the [storage migration](recovery-storage-migration.md).
PostgreSQL stores each current session's namespace, token digest, subject digest,
creation time, absolute expiry and validated authentication payload. It retains
original authentication facts and upstream logout context without refreshing the
original authentication time. No operation history or audit replay is introduced.

## Authority and lookup

Production uses asynchronous PostgreSQL access. An ordinary lookup selects one
row by namespace and SHA-256 token digest; it does not scan a session inventory,
update last-use state or lock the namespace capacity row. Stored subject and time
columns must match the payload. Original-authentication binding, future creation,
authentication time, absolute expiry and upstream context are checked. Freshness
is checked after owned connection cleanup. Missing or expired state does not
authenticate; database or integrity failure has no memory or Redis fallback.

The existing management inventory and OIDC logout paths need the internal session
identifier. Its recoverable representation uses AES-256-GCM with a 256-bit key
derived per session from the existing runtime key-encryption key. HKDF-SHA-256
extracts with the token digest as salt, then expands with the framed envelope
context (domain, namespace and digest) as info. This separates the keys used for
different sessions instead of aggregating every random nonce under one long-lived
AES key. The derivation follows [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html);
its source and the persisted envelope remain application-specific composition.
A versioned envelope binds the same context as associated data, and decoding
checks the canonical UUID and its digest. The derived key buffer is erased on drop;
provider-internal copies and the process's root key are outside that buffer contract.
The plaintext bearer identifier is not written to its row or logs. The existing
key-backup and runtime-key confidentiality obligations apply; this adds no external
revocation ledger or post-PITR credential replay. It does not encrypt the whole
authentication payload or claim resistance to an attacker who controls the DB.

## Creation, revocation and resource bounds

Only creation serializes within the session namespace to enforce the existing
session-capacity policy. Expiry cleanup, oldest-session eviction and insertion
share one statement. A token collision is rejected before eviction, and failed
insertion or rollback preserves prior rows. The application publishes a cookie
only after confirmed success and does not retry an uncertain mutation.

Subject and token selectors support indexed inventory and scoped revocation.
Background expiry cleanup uses the common bounded batches and backlog metrics.
The management inventory uses indexed keyset pagination with 50 entries by default
and a maximum of 200, ordered by original authentication time and then token digest.
It reads at most one additional row to detect a following page. Deleting a prior
page's session does not shift the next page. The opaque cursor contains the time
and digest; its subject and namespace still come from the authorized request.
Old offset cursors are invalid after this stopped-worker upgrade. Expiry or
concurrent revocation may shorten a page; the cursor follows the selected rows.
Individual revocation resolves the subject and inventory digest directly rather
than listing all sessions. Stored payloads are bounded to 65,536 bytes before SQL
and by a database constraint. The test-only whole-inventory helper retains its
4,096-row refusal; production does not call it. Namespace creation counts, sharp
capacity reductions and high-cardinality subject deletion remain REC-T11 resource
obligations. SQL work has a five-second
deadline separate from owned cleanup. These are functional limits, not a measured
10,000 HTTP requests/s or p99 200 ms result.

## Upgrade, recovery and checks

Apply migrations through `20261105021000_runtime_security_catalog` and stop old
workers before switching this family. `AEGAEON_AUTH_SESSION_REDIS_URL` no longer
selects a production backend. Legacy Redis storage remains a test oracle; seven
production Redis families remain. Generation activation and old-worker exclusion
are REC-T06/T08 work and are not complete in this increment.

Selected PITR state determines credentials and revocations. Old sessions are to
be discarded through the new runtime generation; users can establish new sessions
using credentials valid in that selected state. Audit records do not automatically
reapply later revocations or credential changes.

Required current-PR checks cover concurrent capacity, unlocked ordinary reads,
namespace/subject binding, inventory and scoped deletion, original authentication,
corrupt envelopes/payloads, expiry, unavailable DB, collision and rollback, and
actual login/logout routes. Strict protocol refinement, whole-product proof
composition and qualified provider/load evidence remain Task 1b/3 work. No new
product proof discharge follows from this migration.

The increment passes 29 distinct affected server-native checks, one crypto check
covering two RFC 5869 vectors, and eight PostgreSQL/HTTP checks. After the subkey
change the envelope check and all eight integration checks pass on the final
artifact. Clippy and source guards pass; owned suppliers are stopped. Initial
compile/lint/fixture failures, the stale pre-review native build cancellation,
and the corrected artifacts remain in the local evidence. The Atlas description
mismatch found during fixture setup now has a source-to-manifest regression check.
