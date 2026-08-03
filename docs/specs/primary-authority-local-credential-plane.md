# Primary Authority Local Credential Plane Specification

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

This document defines the **A2 local credential plane** used when Aegaeon operates as the
**system of truth (SoT)** or **primary authority** for end users. The broader current
primary-authority specification lives in `primary-authority-user-management.md`; this file is the
credential-plane detail reference.

The goal of A2 is to let Aegaeon authenticate local end users **without upstream federation** while
preserving the current separation between:

- the **management plane** (`administrators`, management session, admin console SPA)
- the **issuer/auth plane** (`end_users`, end-user authentication session, downstream OIDC RP flows)

This document is intentionally scoped to the local credential plane. It does **not** widen the
current released verification claim by itself.

## Design decision

The local credential plane is **server-handled** (server-terminated).

That means:

- the current `aegaeon-admin-console` remains a first-party **control-plane SPA**
- end-user credential submission lives on a separate **issuer-plane auth surface** (for example
  `/auth/*`)
- raw end-user credentials are not handled by admin-console application logic
- browser JavaScript may still participate where platform APIs require it (for example WebAuthn
  ceremonies), but credential verification, token redemption, MFA checks, and session issuance are
  server-owned

This split is required to keep the management-plane and issuer-plane threat models separate.

## Existing primitives to reuse

The current implementation already provides the following building blocks:

- `end_users` as issuer-plane identities
- `AuthSessionStore` plus the `aegaeon_auth_session` cookie for end-user auth sessions
- management-plane bootstrap and management sessions for administrators
- audit infrastructure for management mutations

A2 should reuse those primitives instead of collapsing management-plane and issuer-plane identity
handling into one surface.

## Non-goals

A2 does not include:

- replacing the admin-console management-session flow with OIDC
- merging `administrators` and `end_users`
- moving local end-user credential collection into the admin SPA
- broadening the current formal server claim to cover password/MFA/WebAuthn internals
- full profile/claim-source management (Phase A3)
- consent/session/token inventory UI (Phase A4)
- import/SCIM/bulk onboarding (Phase A5)

## Minimal capability set

A2 capability expansion follows this order:

1. password credential
2. activation / reset token issuance and redemption
3. passkey / WebAuthn
4. TOTP / MFA

The current delivered A2 baseline covers the first two items. Passkey / WebAuthn and TOTP / MFA are
future credential-family extensions unless a separate implementation record promotes them.

## Data model

### End-user lifecycle state

A2 assumes A1 will finish the richer lifecycle states for `end_users`:

- `INVITED`
- `ACTIVE`
- `SUSPENDED`
- `DELETED`

Credential issuance and authentication policy MUST respect those lifecycle states.

### Credential records

Credentials SHOULD NOT be stored directly on `end_users`.

Add dedicated issuer-plane tables instead, for example:

- `end_user_password_credentials`
- `end_user_recovery_tokens`
- `end_user_webauthn_credentials`
- `end_user_mfa_factors`

Common principles:

- one table per credential family
- all rows reference `end_users(id)`
- credential state is auditable and revocable
- secrets or authenticators are stored in hashed or verifier form only
- one-time tokens are time-bounded and single-use

### Password credential record

Minimum fields:

- `id`
- `end_user_id`
- `password_hash`
- `status` (`ACTIVE`, `REVOKED`)
- `created_at`
- `updated_at`
- `last_used_at` (optional)
- `created_by_administrator_id` (nullable)
- `revoked_by_administrator_id` (nullable)

### Activation / reset token record

Minimum fields:

- `id`
- `end_user_id`
- `token_hash`
- `purpose` (`activation`, `password_reset`)
- `expires_at`
- `redeemed_at`
- `created_at`
- `created_by_administrator_id` (nullable)

Rules:

- store a hash, not the raw token
- token may be redeemed exactly once
- expiry is mandatory
- redemption must atomically invalidate the token
- browser delivery may carry the raw one-time token in the `/auth/activate?token=...` or
  `/auth/password/reset?token=...` request URI only for this server-handled credential surface
- any response that renders or re-renders the token must send no-cache headers, HTML-escape the
  value, and keep the token non-recoverable from storage after issuance

## API surfaces

### Management API (control plane)

The management API remains the operator surface. It manages credential lifecycle but does **not**
accept raw end-user passwords except where an operator deliberately sets an initial temporary
credential.

Minimum A2 additions:

- `POST /users/{userId}/activation-tokens`
- `POST /users/{userId}/password-reset-tokens`
- `POST /users/{userId}/credentials/password:set-temporary` (optional for first cut)
- `POST /users/{userId}/credentials/password:revoke`
- `GET /users/{userId}/credentials`

Rules:

- responses must never return reusable raw credential material after issuance
- if a token or temporary password must be shown once, it is returned **only** in the creation
  response and never recoverable afterwards
- every mutation emits an audit event

### Issuer/auth API (server-handled surface)

The issuer/auth surface is the browser-visible end-user auth flow.

Minimum A2 additions:

- `GET /auth/login`
- `POST /auth/login`
- `GET /auth/activate`
- `POST /auth/activate`
- `GET /auth/password/reset`
- `POST /auth/password/reset`
- `POST /auth/logout`

Rules:

- `POST /auth/login` authenticates against local credential state for `end_users`
- successful authentication issues the existing issuer-plane auth session cookie
  (`aegaeon_auth_session`)
- activation and reset redemption are one-time and server-terminated
- `/auth/activate` and `/auth/password/reset` are the only local credential routes allowed to
  accept the `token` query parameter; all other credential-like query keys remain rejected by the
  request-admission guard
- error handling must be fail-closed and not leak whether an account exists beyond policy

## Session model

A2 does not introduce a new browser token model.

The intended model is:

- end-user credentials are validated on the server
- the server issues the existing issuer-plane auth session
- downstream OIDC authorisation continues from that issuer-plane session

This keeps browser handling aligned with the current `AuthSessionStore` model rather than creating
an additional browser-held bearer-token layer.

## Audit requirements

A2 must emit audit events for at least:

- credential issued
- credential revoked
- activation token issued
- activation token redeemed
- password reset token issued
- password reset token redeemed
- successful local login
- failed local login (policy-controlled detail)
- MFA factor enrolled / revoked (when added)
- WebAuthn credential enrolled / revoked (when added)

Management-plane and issuer-plane events must remain distinguishable.

## Admin-console role

The admin console is **not** the credential UI.

It may:

- create users
- issue activation or reset links/tokens
- inspect credential state
- revoke credentials or factors
- view audit evidence

It must not:

- become the browser endpoint that owns end-user password submission
- hand-roll end-user auth/session handling
- bypass the `management_session` boundary already defined in
  `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`

## Initial implementation sequence

Recommended order:

1. add password credential and activation/reset token tables
2. add management API issuance/revocation endpoints
3. add server-handled `/auth/login`, `/auth/activate`, `/auth/password/reset`
4. bind those flows to the existing issuer auth session
5. add admin-console control-plane affordances
6. add WebAuthn and MFA after password/reset is stable

## Definition of done for A2

A2 is complete when all of the following are true:

- Aegaeon can authenticate local end users without upstream federation
- activation and reset flows are single-use and time-bounded
- the admin console can issue and revoke credential-plane artefacts without handling raw end-user
  credential submission
- the issuer/auth surface owns local credential submission and session issuance
- all credential lifecycle mutations are auditable

## Claim boundary note

This design improves product completeness for the primary-authority posture, but it does not change
current claim wording by itself.

Any future claim change would require:

- explicit policy updates
- fresh evidence
- updated compatibility wording
- a separate decision on whether any credential-plane internals are promoted into a stronger claim
