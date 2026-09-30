# Shared Client JWKS Fingerprint State

Last updated: 2026-09-30

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Purpose

The shared client JWKS fingerprint ledger detects reuse of a `kid` with different
key material across server processes. It uses the runtime Redis connection
configured by `AEGAEON_JWKS_REDIS_URL`. It stores security fingerprints, not fetched
JWKS response bodies. See [JWKS operations](jwks-operations.md) for key distribution
and HTTP acquisition behavior.

## Admission behavior

For a nonempty fingerprint map, the Rust caller sends one Redis key, a positive
decimal TTL, and unique `kid`/fingerprint pairs. The Lua script validates the wire
shape, then checks all existing fingerprints before any write. A conflicting
fingerprint returns the integer `1` without writing or renewing expiry, including
when the later expiry operation would be denied or its TTL would overflow.

When there is no conflict, the script rejects TTL seconds greater than
`9223372036854775` before writing. It compares decimal bytes without converting the
number to Lua floating point, preventing overflow in seconds-to-milliseconds
conversion while preserving integers above the floating-point exact range.

When the backend exposes `redis.acl_check_cmd`, the script checks the exact key,
fields, values, and expiry arguments for `HSET` and `EXPIRE` permission before the
first write. Each check must return boolean `true`. A denied or malformed
capability fails admission. If the capability is absent, the script keeps the
legacy execution path described below.

After writes, `EXPIRE` must return the integer `1`. Rust accepts only integer `0`
(admitted) and integer `1` (conflict) from the script. Strings, other integers,
aggregate values, nil, malformed replies, and transport/backend errors are
reported as backend unavailability. No new retry is added to this helper.

Empty maps keep their existing no-op behavior. The existing policy allowing
`kid` reuse still bypasses fingerprint enforcement. The TTL calculation remains
`max(jwksCacheTtlSeconds, jwksSharedStateMaxAgeSeconds, 4 * jwksCircuitResetSeconds, 60)`.
Successful admissions renew the URI hash expiry and retain the union of distinct
`kid` entries; local URI cache capacity does not bound that union's cardinality.

## Error and recovery limits

Redis script execution does not provide rollback for commands completed before
a later error. This change prevents specific detectable failures before writes;
it does not make every failed call free of remote effects.

- On engines without `redis.acl_check_cmd`, including Redis 6.2, an `EXPIRE` ACL
  denial can occur after `HSET` and leave fingerprints behind, possibly without
  expiry. Upgrading to a backend with the capability enables the permission
  preflight without a schema change.
- A TTL within the seconds-to-milliseconds limit can still overflow when the
  backend adds its current time. That later failure can also leave written
  fingerprints without expiry. The largest accepted internal TTL exercises this
  distinction; the preflight does not inspect or control the backend clock.
- Loss of the response can report an error after Redis completed both the write
  and expiry update. A caller error therefore does not establish that no mutation
  occurred. Other write-time/backend errors can likewise have partial effects.

For persistent failures, check the deployed principal's command, key, and database
permissions and inspect the affected ledger state through the existing controlled
operations process. Do not clear fingerprint history merely to turn a failed
admission into a success: that discards the shared key-reuse check.

## Regression tests

Run the tests locally on Linux with the pinned development shell:

```sh
nix develop -c python3 scripts/validation/test_jwks_fingerprint_ledger.py
```

The runner requires `unshare`, `ip`, and permission to create user/network
namespaces. It verifies that only loopback is active and no non-loopback routes
exist, then starts disposable backend processes on Unix sockets with persistence
disabled. It never connects to the configured production Redis. Ordinary
workspace test selection does not run the ignored backend fixtures; the command
above includes them explicitly.

Use `--server /path/to/valkey-server` or another Redis binary to select a backend.
The runner identifies its version and exercises database ACL selectors on Valkey
9.1 or later. It explicitly omits the newer-engine time-addition regression on
Redis versions before 7; the remaining tests still exercise legacy ACL residue.
Other cases cover normal admission, conflict precedence, expiry renewal, exact
reply types, cold script loading, and a completed remote write whose reply is lost.
Controlled Lua API tests are separate from the real backend permission tests.

Local validation of this change used Redis 8.8.1. The optional Valkey and legacy
Redis profiles were not executed in that validation; their presence in the runner
does not establish results for those backends.
