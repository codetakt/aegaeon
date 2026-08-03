# Primary Authority User Management Delivery Record

Last updated: 2026-04-22

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

This historical record captures the Phase A delivery that closed the local user-management gap
when Aegaeon is the **system of truth (SoT)** or **primary authority** for end users. The current
implementation specification is `docs/specs/primary-authority-user-management.md`.

This record does **not** widen the current released verification claim by itself.

Status note (2026-04-22): Phase A1-A6 is complete. This document now serves as a delivery record
and regression checklist for the local primary-authority posture.

## Current status

- `administrators` and `end_users` are intentionally separate tables and separate security
  domains.
- Management API now supports end-user provisioning, lifecycle operations, profile mutation,
  credential inspection, activation/password-reset artifact issuance, session/grant/refresh-token
  inventory, invite flows, and CSV import.
- Issuer-plane local authentication is handled on the server-owned `/auth/*` surface rather than
  the admin SPA.
- The sibling admin console exposes the minimum local-IAM operations required for SoT operation
  without widening the control-plane browser boundary into credential submission.

Implication: the local SoT / primary-authority gap described by this record is closed for the
current product posture. Follow-on work belongs in separate operational roadmaps, not in Phase A.

## Scope

### Phase A1 — End-user lifecycle baseline

- Add first-class end-user CRUD to the management API.
- Keep `administrators` and `end_users` separate; do not collapse control-plane and issuer-plane
  identities into one table.
- Introduce explicit lifecycle states for end users:
  - invited
  - active
  - suspended
  - deleted / recoverable

Target surfaces:
- `POST /users`
- `PATCH /users/{userId}`
- `DELETE /users/{userId}` or soft-delete equivalent
- `POST /users/{userId}/restore`

Definition of done:
- end users can be created, edited, suspended, restored, and deleted without any upstream IdP
- audit events are emitted for every mutation
- admin console can perform the same lifecycle operations

Current status (2026-04-22):
- complete: runtime/API/admin-console baseline covers create / edit / delete / restore,
  include-deleted listing, and lifecycle vocabulary aligned to `INVITED` / `ACTIVE` /
  `SUSPENDED` / `DELETED`

### Phase A2 — Local credential plane

- Add local credential management for end users.
- Supported credentials should be introduced in this order:
  1. password
  2. recovery / reset tokens
  3. passkey / WebAuthn
  4. TOTP / MFA

Requirements:
- secrets must remain outside the current formal server claim unless separately promoted
- the management API must never expose raw credential material after issuance
- reset and activation flows must be one-time and time-bounded

Definition of done:
- Aegaeon can authenticate local end users without upstream federation
- bootstrap / invite / password reset flows exist and are auditable

### Credential UI architecture decision

The local credential plane must be **server-handled** (server-terminated), not implemented as an
extension of the current admin SPA. The intended split is:

- the current admin console remains a first-party **control-plane SPA** for operator workflows
- end-user credential and authentication flows live on a separate **issuer-plane auth surface**
  (for example `/auth/*`) that terminates credentials on the server
- browser JavaScript may still participate where the platform requires it (for example WebAuthn
  ceremony APIs), but credential validation, reset-token redemption, activation, MFA verification,
  and session issuance remain server-owned

Rationale:

- it keeps the management-plane and issuer-plane threat models separate
- it avoids widening the admin-console boundary from operational control plane into credential UI
- it keeps raw credential handling out of the admin SPA and aligns with the existing
  `management_session` posture
- it lets Aegaeon reuse the issuer-side auth/session machinery without coupling local end-user auth
  to the management API boundary

Operational implication:

- A2 should introduce a dedicated server-handled auth surface rather than adding password / reset /
  MFA / WebAuthn forms to `aegaeon-admin-console`
- the admin console may link to, configure, or audit those flows, but it should not become the
  browser endpoint that owns credential submission

Detailed design for A2 lives in `../../../specs/primary-authority-local-credential-plane.md`.

### Phase A3 — End-user profile and claim-source management

- Add local profile management for the claims that downstream RP surfaces need.
- Manage at least:
  - subject policy
  - email and email verification
  - display name / profile attributes
  - custom attributes intended for claim mapping

Requirements:
- local claim sources must be explicit and versioned
- any attribute that can reach ID Token or UserInfo must be auditable

Definition of done:
- ID Token and UserInfo claim sources can be local, not only upstream-derived
- management UI can inspect and update profile state safely

### Phase A4 — Consent, session, and token operations

- Add end-user-facing operational views to the management plane:
  - active sessions
  - consent grants
  - refresh-token inventory
  - selective revoke

Definition of done:
- administrators can inspect and revoke user-level authorisation artefacts without database access
- audit surfaces distinguish authentication events from management mutations

### Phase A5 — Import, invite, and bulk provisioning

- Add operator-friendly onboarding flows:
  - invite-based user creation
  - CSV import
  - optional SCIM or batch import later

Definition of done:
- initial population of a greenfield SoT deployment is possible without upstream IdP support

### Phase A6 — Admin console completion

- Extend the sibling admin console so the local IAM plane is operationally usable.
- Minimum UI:
  - create/edit user
  - invite / activate
  - reset password
  - suspend / restore
  - inspect sessions, grants, refresh tokens

Definition of done:
- SoT posture is operable from the admin console and not only from raw API calls

## Sequencing

Recommended order:

1. A1 — end-user lifecycle baseline
2. A2 — local credential plane
3. A3 — profile and claim-source management
4. A6 — admin-console completion
5. A4 — consent/session/token operations
6. A5 — import and invite flows

Rationale:
- A1+A2 are the minimum to make Aegaeon a real authority for local users.
- A3 is required before local claims become a dependable issuer-plane source.
- A6 should land before deeper operational features so the control plane stays usable.

## Execution Record (completed 2026-04-22)

This section records the batches that closed Phase A. The batching remains source-managed so future
regressions can be checked against the delivered scope.

### Batch A-1 — lifecycle alignment

- [x] Align `end_user_status` with the roadmap vocabulary:
  - `INVITED`
  - `ACTIVE`
  - `SUSPENDED`
  - `DELETED`
- [x] Keep existing operational APIs backward-compatible where needed, but update returned state and
      management UX wording to use `suspended` rather than `blocked`.
- [x] Ensure upstream JIT provisioning maps any legacy `BLOCKED` operator input onto the
      `SUSPENDED` end-user lifecycle state.
- [x] Regenerate OpenAPI and update handoff/admin docs so runtime, SDK, and console language agree.

### Batch A-2 — local credential plane baseline

- [x] Add issuer-plane credential tables and migration:
  - `end_user_password_credentials`
  - `end_user_recovery_tokens`
- [x] Add management-plane A2 endpoints:
  - `GET /users/{userId}/credentials`
  - `POST /users/{userId}/activation-tokens`
  - `POST /users/{userId}/password-reset-tokens`
  - `POST /users/{userId}/credentials/password:revoke`
  - `POST /users/{userId}/recovery-tokens/{tokenId}:revoke`
- [x] Add server-handled issuer/auth endpoints:
  - `GET/POST /auth/login`
  - `GET/POST /auth/activate`
  - `GET/POST /auth/password/reset`
  - `POST /auth/logout`
- [x] Replace the demo-only `/authorize` login shortcut with a local-login redirect whenever the DB
      credential plane is enabled and no active auth session is present.
- [x] Emit issuer-plane audit events for:
  - local login success/failure
  - activation/reset token issue
  - activation/reset token redemption
  - password credential revocation
- [x] Extend SDK/admin-console so operators can inspect credential state and issue/revoke
      credential-plane artifacts without handling raw end-user passwords in the SPA.

### Batch A-3 — profile and claim-source management

- [x] Extend local end-user profile storage with issuer-relevant attributes (at minimum email,
      email verification state, display name, and auditable custom attributes).
- [x] Add versioned management-plane profile mutation APIs and audit evidence.
- [x] Ensure local profile state can be consumed by ID Token and UserInfo issuance without relying
      on upstream claims.

### Batch A-4 — session, grant, and refresh-token operations

- [x] Introduce inspectable issuer-plane session inventory rather than audit-only invalidation.
- [x] Add consent-grant and refresh-token inventory endpoints with selective revoke operations.
- [x] Distinguish management mutations from end-user authentication/session events in both API
      responses and audit views.

### Batch A-5 — invite and bulk provisioning

- [x] Add invite-oriented user creation that lands in `INVITED` state and can immediately issue an
      activation artifact.
- [x] Add CSV import with fail-closed validation and per-row audit evidence.
- [x] Keep any future SCIM/batch sync explicitly out-of-scope until the local SoT path is stable.

### Batch A-6 — admin console completion

- [x] Update the sibling `aegaeon-admin-console` so operators can:
  - create/edit/delete/restore users
  - invite users and bulk-import users from CSV
  - suspend/restore users
  - inspect credential state
  - issue activation/reset artifacts
  - inspect sessions/grants/refresh tokens
- [x] Keep the console inside the current control-plane boundary:
  - no end-user password entry
  - no end-user reset/MFA/WebAuthn browser flows inside the SPA

### Verification / evidence gates

- [x] `nix build .#server --print-build-logs`
- [x] `nix develop .#default --command cargo xtask openapi`
- [x] `cargo test -p aegaeon-server`
  This gate currently covers management APIs plus local credential/auth/session logic. Direct
  DB-backed `/auth/*` HTTP integration remains a hardening follow-up and is not claimed here.
- [x] `node --experimental-strip-types scripts/sdk/management_client_reference_test.ts`
- [x] `nix shell nixpkgs#nodejs_24 nixpkgs#pnpm -c bash -lc 'cd ../aegaeon-sdk/sdk && pnpm --filter @aegaeon/management-client test'`
- [x] `bash -lc 'cd ../aegaeon-admin-console && node node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit'`
- [x] `bash -lc 'cd ../aegaeon-admin-console && node node_modules/vitest/vitest.mjs run'`
- [x] handoff/docs refreshed in the same change set

## Claim boundary note

- This roadmap expands the management and issuer-plane operational surface.
- It must not be described as a released verified-client or verified-admin-console claim by itself.
- Any future claim change requires updated policy, evidence, and compatibility wording.
