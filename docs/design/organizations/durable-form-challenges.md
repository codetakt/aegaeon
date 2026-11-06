# Durable form capabilities and DPoP challenges

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, reviewers, operators

Production device/local-login/recovery CSRF capabilities and DPoP nonce challenges
use current rows in the selected application database. This implements S09/S11/S17
of the [storage migration](recovery-storage-migration.md). They contain no change
history and do not restore an earlier in-memory state. The existing guards for
other, unmigrated families remain in place.

## Form capabilities

`runtime_csrf_tokens` stores the Environment/flow namespace, a SHA-256 digest of
an unpredictable 32-byte token, and expiry. The raw token remains in the form and
cookie. Cookie/field binding and duplicate-field checks precede consumption.
`DELETE ... RETURNING expires_at > clock_timestamp()` consumes one row atomically;
only one competing submission can succeed. The expiry decision occurs after the
row is acquired. A missing, expired, already consumed or foreign-flow token does
not authorize the form. Backend failure returns unavailable, with no memory or
Redis fallback and no retry of an uncertain consumption.

Generation retries only a confirmed random-key collision, at most 16 attempts.
It does not retry an ambiguous database result. Login and password-recovery form
parsing now awaits the store directly. Password hashing remains on the bounded
blocking-work path. The existing reauthentication rule remains: a losing invalid
CSRF submission cannot replace the winning request's form binding or cookie.

The schema contains no raw password, raw CSRF token, submitted identifier or
request transcript. Expired rows use the shared [bounded cleanup and
metrics](durable-replay-decisions.md#admission-and-expiry).

## DPoP challenges

`runtime_dpop_nonces` contains at most one current/previous pair per namespace and
endpoint role (`as` or `rs`). Current validity is bounded to twice the configured
rotation period. Rotation preserves the previous value's original deadline;
neither validation nor repeated challenges extend it. The database clock governs
these deadlines. Authorization-server and resource-server roles cannot substitute
for each other.

Validation is a read-only query and takes no row lock. Issuance locks only that
role row, including concurrent first issuance, and returns the shared current
value until its rotation deadline. Invalid or idle validation cannot recreate
an expired row. A missing or invalid proof nonce produces a fresh challenge before
recording proof replay. The opaque prepared-proof value exposes no sender binding
until nonce, replay and final proof freshness checks finish.

The legacy Redis nonce adapter is test-only. Synchronous legacy middleware calls
cannot admit the production SQL nonce backend; serving routes use the asynchronous
facade. SQL errors and unknown replies fail closed for that request. Challenge
issuance does not retry an uncertain mutation.

## Upgrade, restore and checks

Apply migrations through `20261105021000_runtime_security_catalog`. The runtime
role requires the ordinary table privileges and EXECUTE on
`issue_runtime_dpop_nonce`. The three former Redis URL settings have no production
effect. The current required Redis inventory has eight families after the management-session migration; this does not mean
managed Redis support or interrupted-store recovery is complete.

A stopped-worker upgrade may discard outstanding forms and nonce challenges:
clients obtain a new form or challenge. There is no need to import consumed tokens
or recreate vanished memory. It must still respect the old-proof waiting period
for the separately migrated [replay decisions](durable-replay-decisions.md).
Authorized PITR selects the historical database; fresh volatile/session generation
and old-worker exclusion remain REC-T06/T08 work. Audit never reapplies later
credential changes or revocations automatically.

The nonce increment passes 48 affected native checks and two direct PostgreSQL
checks, including real signed proof verification; supplier cleanup completed.
CSRF passes 31 affected native checks and four direct-store/form-route checks
covering login, account recovery and device approval/denial. Initial build/fixture
failures remain in the private evidence. No new formal discharge, provider result
or 10,000 requests/s performance claim follows. Strict refinement/composition and
qualified scale checks retain the [Task 1b/Task 3 boundary](recovery-security.md).
