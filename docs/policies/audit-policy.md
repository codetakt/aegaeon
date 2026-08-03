# Audit Policy — Strong Audit Baseline (AS/OP + Upstream OIDC RP)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Platform/Operations

## Status
- Phase 1 baseline policy (intended to be enforceable and re-evaluable).
- This policy is written for deployments where Aegaeon acts as:
  - **AS/OP** (OAuth Authorization Server / OIDC Provider) for downstream applications, and
  - **OIDC RP / OAuth Client** towards one or more upstream IdPs (SoT) for federation/brokering.

## Goals
- **Fail-closed for security-critical outcomes**: Aegaeon MUST NOT issue credentials or mutate
  authorization state unless an audit record is durably written.
- **Operator clarity**: the “audit-required line” is explicit, versioned, and can be re-evaluated.
- **Evidence-first**: audit records should be sufficient to reconstruct “who did what, when, why”.
- **Data minimization**: never store secrets or raw tokens; prefer stable pseudonymous identifiers.

## Non-goals (Phase 1)
- Auditing *business* APIs of downstream Resource Servers (RS). RS auditing belongs to those RSs.
- SAML federation/brokering. If needed, it is handled by a separate facade component.

## Definitions
- **Audit sink**: the primary durable store for audit events (Phase 1: PostgreSQL).
- **Audit-required operation**: an operation that MUST write an audit event successfully; if the
  audit write fails, the operation MUST fail (no side effects).
- **Best-effort audit**: Aegaeon SHOULD attempt to write an audit event, but the request may
  still return an error response even if auditing fails (used for reject-path noise control).

## Audit event storage (Phase 1)
- Primary sink: PostgreSQL `aegaeon.audit_events` (partitioned by `occurred_at`).
  - See schema migration: `db/migrations/20260101090444_management_plane_phase1.sql`.
  - Ensure at least one partition exists (default partition is provided by
    `db/migrations/20260103074127_audit_events_default_partition.sql`).
- Access control (recommended):
  - The runtime audit writer role: **INSERT-only** to `aegaeon.audit_events` partitions.
  - No UPDATE/DELETE permissions for the runtime role (append-only semantics at the DB layer).

## The “audit-required line” (normative)

### MUST (hard-gated; fail-closed)
The following operations MUST be audit-required. If the audit write fails, Aegaeon MUST:
1) return an OAuth/OIDC error response (prefer `temporarily_unavailable` + HTTP 503), and
2) ensure no security-relevant side effect occurred (no token/code issuance, no config mutation).

For side effects that cannot share the same database transaction as the audit insert (for example
process/Redis token stores, authorization-code stores, upstream-account link side effects, or local
session creation), the durable audit gate MUST be written before the side effect and SHOULD use an
event name that describes the gate (`*.requested.v1` or `*.authorized.v1`) rather than claiming that
the side effect has already completed. Completion may be represented by transactional success events
where the mutation and audit insert commit together, or by non-normative telemetry/logging when the
runtime store is outside PostgreSQL.

### AS/OP security outcomes
- Authorization code issuance success (`/authorize` → code minted).
- Token issuance success (`/token` → access token and any refresh/id token minted).
- Refresh rotation success (`/token` with `refresh_token` → new tokens minted and parent marked).
- Token revocation success (`/revoke` mutates revocation state).
- Client registration and policy changes (DCR and management plane writes).
- Signing key lifecycle changes (activate/rotate/retire/revoke).

### Federation (upstream OIDC RP) security outcomes
- Upstream login completion that establishes a local authenticated session (successful callback).
- Identity link / unlink operations (any mutation of `(upstream_iss, upstream_sub) → local_subject`).

### Management plane writes
- Any write that changes tenant/environment configuration, clients, secrets, keys, policies, or
  federation connections.

### SHOULD (best-effort; not hard-gated)
These events are valuable but can be high-volume or attacker-controlled. They SHOULD be audited
when possible, but failures MUST NOT change the response semantics (the request is already a
reject-path and has no sensitive side effects).

- Invalid requests that are rejected before any credential/state issuance.
- Failed authentication attempts (downstream and upstream).
- Request validation failures (PKCE mismatch, DPoP replay, unsupported response_mode, etc.).

## Data minimization rules (normative)
- **Never store**:
  - raw access tokens, refresh tokens, ID tokens, authorization codes
  - passwords, client secrets, private keys
- **Store instead**:
  - stable identifiers (UUIDs, client identifiers), plus *pseudonymous* hashes where needed
  - request correlation IDs (request_id / trace_id / span_id)
- **Upstream identities**:
  - record `upstream_iss` as a string (issuer).
  - record a pseudonymous `upstream_sub_hash` instead of raw `sub`.
    - Recommended: HMAC-SHA-256 over `upstream_iss || 0x00 || upstream_sub` using a per-environment
      secret (`audit_hash_key`), so correlation is possible within an environment without leaking
      global identifiers across tenants/environments.

## Required event fields (normative)
Each audit event MUST include at least:
- `event_type`, `category`, `outcome`, `severity`
- `occurred_at`
- `actor_type` and an `actor_id` (pseudonymous if needed)
- `target_type` and `target_id` (pseudonymous if needed)
- `request_id` (stable per HTTP request; propagate across internal calls)
- `organization_id` (NOT NULL; scoping key for multi-tenant isolation)
- optional `tenant_id`, `environment_id` (nullable; narrower scope within organization)
- optional `data` JSON for structured context (no secrets)

### Additional schema fields (informational)
The `aegaeon.audit_events` table includes these additional columns beyond the normative minimum:
- `mfa` (boolean) — whether the actor session involved multi-factor authentication
- `ip_address` — source IP of the request (for forensic correlation; subject to data retention)
- `user_agent` — HTTP User-Agent header (for forensic correlation)
- `from_configuration_version_id`, `to_configuration_version_id` — configuration change tracking
  (populated on management plane mutations that alter configuration snapshots)
- `trace_id`, `span_id` — OpenTelemetry correlation identifiers

### Indexes
- `(team_id, occurred_at DESC)` — primary query path for team-scoped audit retrieval
- `(environment_id, occurred_at DESC)` — environment-scoped audit retrieval

## Re-evaluation checklist (how to revisit this policy)
Re-evaluate the “audit-required line” when:
- Introducing a new endpoint that mints or extends authorization state.
- Adding additional federation protocols or new upstream token/claim sources.
- A read-only endpoint becomes a high-value data surface (PII or privileged metadata).
- Switching primary audit sink (DB → object storage / SIEM) or adding a new export pipeline.
- Observing sustained audit volume/latency that threatens availability (may require sampling for
  best-effort classes while keeping MUST-class strict).

Document any changes as a new “Phase X” section and keep Phase 1 behaviour as a historical record.
