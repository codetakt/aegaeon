# DPoP Replay Store Operations Guide

Last updated: 2026-07-01

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This document describes procedures and recommended settings for operating Redis-backed replay protection for DPoP sender constraints. Verified Core (F*/Low*/WASM) only returns a `replay_ticket` and does not manage storage, so the host must ensure that the application fails closed.

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

1. Verified Core returns a `replay_ticket` containing fields such as `method`/`uri`/`jti`/`jkt`/`ath`.
2. The Rust middleware concatenates the following values, hashes them with SHA-256, and uses the base64url-encoded result in the key.
   ```text
   dpop:v1:{namespace}:{base64url(SHA256(method || uri || jti || jkt || ath-or-'-'))}
   ```
3. The TTL is `dpopIatWindowSeconds + jwtLeewaySeconds` from the active policy (360 seconds by default). Store the record with `SET <key> 1 NX PX <ttl_ms>` and reject the request as a replay if the key already exists.

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
2. Start Redis using Docker or a similar tool, set `AEGAEON_DPOP_REDIS_URL=redis://127.0.0.1:6379`, and run:
   ```bash
   AEGAEON_DPOP_REDIS_URL=redis://127.0.0.1:6379 \
   cargo test -p aegaeon-server dpop_middleware_integration_test::test_protected_endpoint_detects_replay
   ```
   Verify that sending the same JTI twice results in 401/invalid_token.
3. Stop Redis and run the same test. Verify that it returns 503 / temporarily_unavailable and fails closed.

### CI integration examples

- Start Redis with `docker compose` and add a `cargo test -p aegaeon-server dpop_*` target with `AEGAEON_DPOP_REDIS_URL` set.
- For regression tests that start a server process, provide `AEGAEON_TEST_REDIS_URL` with a loopback `redis://` or `rediss://` URL, or the complete set of `AEGAEON_*_REDIS_URL` runtime-store environment variables. The legacy `REDIS_URL` is outside the supported server configuration. Tests that fall back to a process-local store when configuration is absent are also outside the supported server configuration.

## 6. Notes on future extensions

- Expose detailed Redis outcomes (such as success, replay, and failure) as metrics and monitor trends on a dashboard.
- If multiple `AEGAEON_DPOP_REDIS_URL` values are supported in the future for replica redundancy (Redis Cluster/Active-Active), consider atomic multi-writes using Lua scripts or a similar mechanism.
- For cross-region redundancy, include region information in the `namespace` to avoid hash collisions between regions.

---

These are the current operating procedures for the DPoP replay store. Server operation requires Redis, with consistent fail-closed behavior, monitoring, and alerts. Use the in-memory implementation only as an auxiliary boundary for direct unit tests, fuzzing, and protocol harnesses.
