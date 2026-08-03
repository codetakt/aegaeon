# Primary Authority User Management Specification

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

This document is the canonical current specification for the local user-management posture used
when Aegaeon is the system of truth or primary authority for end users. It replaces the completed
Phase A roadmap as the durable implementation reference. The delivery record remains in
`docs/program-management/historical/roadmaps/primary-authority-user-management-delivery.md`.

This specification does not widen the released verification claim by itself. Credential handling,
MFA, and browser authentication remain product/runtime capabilities unless a separate claim update
promotes a narrower verified surface.

## Boundary Model

- Control-plane identities use `administrators`, management sessions, RBAC, and the admin console.
- Issuer-plane identities use `end_users`, local auth sessions, and downstream OIDC flows.
- The two domains must not be collapsed into a shared identity table or browser session model.
- End-user credential submission is server-handled on `/auth/*`; the admin console may issue,
  revoke, inspect, and audit credential artifacts, but must not own password submission or local
  session issuance.

## Implemented Capabilities

The current primary-authority baseline includes:

- end-user create, edit, suspend, soft-delete, restore, include-deleted listing, invite, and CSV
  import operations
- lifecycle vocabulary aligned to `INVITED`, `ACTIVE`, `SUSPENDED`, and `DELETED`
- local password credential records and one-time activation / password-reset artifacts
- management endpoints to inspect credential state and issue or revoke credential-plane artifacts
- server-handled `/auth/login`, `/auth/activate`, `/auth/password/reset`, and `/auth/logout`
  surfaces
- local profile storage for issuer-relevant attributes, including email, email verification state,
  display name, and auditable custom attributes
- local profile consumption by ID Token and UserInfo issuance
- issuer-plane session, consent-grant, and refresh-token inventory with selective revoke operations
- audit events that distinguish management mutations from issuer-plane authentication/session
  events
- sibling admin-console affordances for the operator workflows above, without moving credential
  submission into the SPA

## Data And API Requirements

Credential records are stored outside `end_users` in dedicated issuer-plane tables such as password
credentials and recovery tokens. Secrets and one-time tokens are stored as hashes or verifier
material. Activation and reset artifacts are single-use, time-bounded, and auditable.

Management API responses must never return reusable credential material after issuance. If a
temporary secret or one-time token is shown, it appears only in the creation response and is not
recoverable from storage.

Issuer/auth routes issue the existing `aegaeon_auth_session` cookie after successful server-side
authentication. Authorization flows continue from that issuer-plane session rather than from a new
browser-held bearer-token layer.

## Operational Requirements

Every lifecycle, credential, profile, session, grant, refresh-token, invite, and import mutation
must emit an audit event. Bulk operations must fail closed on invalid rows and preserve per-row
evidence. Administrative repair operations must be possible without direct database access.

## Detailed References

- Local credential-plane detail: `primary-authority-local-credential-plane.md`
- Management plane: `management-plane/README.md`
- Delivery record: `../program-management/historical/roadmaps/primary-authority-user-management-delivery.md`
