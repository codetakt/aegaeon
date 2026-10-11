# DPoP Replay Store Operations Guide

Last updated: 2026-10-11

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This guide describes Redis-backed replay protection for DPoP sender constraints. Rust FFI checks signatures and freshness and returns the `jti` and optional nonce. Rust middleware applies replay storage and nonce policy, failing closed if storage fails.

## 1. Environment variables

| Variable | Purpose | Default | Notes |
|------|------|--------|------|
| `AEGAEON_DPOP_REDIS_URL` | Connection URL for the Redis replay store (`rediss://`; `redis://` is also allowed for loopback development endpoints) | Required at server startup when the DPoP runtime is enabled | The in-memory implementation is for direct unit tests, fuzzing, and protocol harnesses; it is not a supported startup configuration for `aegaeon-server`. |
| `AEGAEON_DPOP_NONCE_REDIS_URL` | Connection URL for the Redis DPoP nonce store | Required at server startup when nonce enforcement is enabled | There is no fallback to `AEGAEON_DPOP_REDIS_URL`. |

The authoritative settings for the `iat` acceptance window, JWT leeway, and DPoP
nonce TTL are `policy.dpopIatWindowSeconds`, `policy.jwtLeewaySeconds`, and
`policy.dpopNonceTtlSeconds` in the active configuration document, rather than
startup environment variables. The Redis key namespace is derived from the
Environment ID in the management database; operators do not override it through
the process environment.

If Redis is unavailable, the application returns **503 (temporarily_unavailable)** and fails closed. Configure monitoring and notifications to verify that failures do not cause the application to fail open.

## 2. Key design and TTL

1. After FFI proof validation, Rust middleware applies nonce policy. FFI itself does not check `jti` reuse.
2. Replay keys are derived from the existing environment namespace and length-delimited `jkt` / `jti` inputs. The shared Redis namespace and key format remain unchanged.
3. Before storing a successful proof, raise retention to the maximum of:
   - `2 * MAX_DPOP_IAT_WINDOW_SECS + 1` seconds (currently `2 * 300 + 1 = 601` seconds);
   - `2 * iat_window_secs + 1` seconds for directly constructed middleware;
   - any longer caller-supplied retention.
4. Store atomically with `SET <key> 1 NX PX <ttl_ms>` and reject an existing key as a replay. Reject arithmetic overflow or storage failure before admission; never truncate the TTL.

Freshness uses whole seconds and `abs(now - iat) <= window`. A proof accepted at
the future edge can remain acceptable for twice the window, so adding one window
to JWT leeway is insufficient. JWT leeway is not added to DPoP freshness. The
extra second covers the inclusive final second and fractional insertion time.
The production maximum also covers supported window increases between instances
sharing the store. Revisit this derivation if NumericDate semantics change.

Apply the same minimum with nonce enforcement enabled or disabled. Do not shorten
replay retention to the nonce lifetime or assume a nonce is single-use. Production
checks `iat` freshness even when a nonce is enabled. This is Aegaeon's chosen
single-use policy under RFC 9449 sections 4.3 and 11.1, rather than an unconditional
replay-store requirement for every DPoP deployment.

At R accepted unique proofs per second, estimate at least `601 * R` retained keys,
before expiration processing and memory overhead. Provision capacity for the
increase from the previous 360-second default while preserving `noeviction`.
All replicas must share the store, records must survive the acceptance interval,
and clocks must be trusted. Finite relative TTL cannot protect against arbitrary
backward clock changes; this change does not establish those premises.

### Suspend admission during upgrade

New instances cannot restore or extend expired short-lived records from old
instances. If uninterrupted strict replay exclusion is required, suspend DPoP
admission before the final old instance stops. Wait the maximum prior acceptance
horizon after the last old acceptance, then resume only patched instances.
For the currently supported maximum, wait 601 seconds under the clock premises
above. Existing namespaces preserve surviving records but do not restore expired
records. A rolling deployment alone cannot immediately update prior replay
history. No new configuration or storage schema is required.

## 3. Recommended Redis settings

- Allocate a dedicated instance or database (DB number) to isolate the store from other uses.
- Enforce `maxmemory-policy noeviction` so that eviction cannot undermine replay protection.
- Enable TLS and authentication, and manage connection details with a service such as Secret Manager. Use `rediss://` for non-loopback endpoints and restrict plaintext `redis://` to local loopback validation.
- Operational monitoring:
  - Detect connection errors and timeouts through metrics and logs.
  - Monitor `keyspace_misses` and `used_memory`, and alert when capacity is running low.

## 4. Failure behavior

- If the Redis `SET ... NX PX` operation fails, return 503 as `DpopError::BackendUnavailable` and notify the client with "DPoP replay backend unavailable".
- Application logging (`tracing::error!`) is recommended so that failure events appear in audit logs and monitoring.

## 5. Testing and validation

### Local validation procedure

1. Validate the in-memory implementation only through direct store or middleware unit tests, or fuzz/protocol harnesses, rather than server startup.
2. Start a dedicated Redis instance and run the retention test, including its normally ignored service-dependent case:
   ```bash
   AEGAEON_TEST_REDIS_URL=redis://127.0.0.1:6379 \
     nix develop -c cargo test -p aegaeon-server --lib \
     middleware::dpop::retention_tests:: -- --include-ignored --test-threads=1
   ```
   The Redis case checks actual PTTL, duplicate rejection, and backend failure
   using an owned endpoint that closes its connection. Keep Redis running for
   this test. Controlled-time middleware fixtures use a claims-only verifier;
   real-signature freshness checks are separate FFI tests.

### CI integration examples

- Run the retention command above with `AEGAEON_TEST_REDIS_URL` set; Cargo test filters are substrings, not shell globs.
- For regression tests that start a server process, provide `AEGAEON_TEST_REDIS_URL` with a loopback `redis://` or `rediss://` URL, or the complete set of `AEGAEON_*_REDIS_URL` runtime-store environment variables. The legacy `REDIS_URL` is outside the supported server configuration. Tests that fall back to a process-local store when configuration is absent are also outside the supported server configuration.

## 6. Notes on future extensions

- Expose detailed Redis outcomes (such as success, replay, and failure) as metrics and monitor trends on a dashboard.
- If multiple `AEGAEON_DPOP_REDIS_URL` values are supported in the future for replica redundancy (Redis Cluster/Active-Active), consider atomic multi-writes using Lua scripts or a similar mechanism.
- Replicas admitting proofs for the same environment must share its replay namespace and atomic history, including across regions. Region-specific namespaces would permit cross-region replay.

---

These are the current operating procedures for the DPoP replay store. Server operation requires Redis, with consistent fail-closed behavior, monitoring, and alerts. Use the in-memory implementation only as an auxiliary boundary for direct unit tests, fuzzing, and protocol harnesses.
