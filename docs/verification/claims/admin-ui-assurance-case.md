# Admin UI Assurance Case

Last updated: 2026-05-20

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This assurance case defines the bounded Phase 3 admin UI security claim. It does
not claim that React, browser rendering, CSS, browser extensions, OS UI
behaviour, or every possible visual interaction is formally verified.

## Claim

The admissible future wording is:

> Admin control-plane security boundary with formally specified and mechanically
> checked authorization/session state-machine invariants.

This wording is allowed only after the claim gate in
`spec/admin-ui-assurance-claim.current.json` is activated in Phase 4. Until then,
the safe wording remains:

> First-party control-plane UI constrained by SDK and management-session boundary
> audits; not claimed as formally verified.

## Boundary

Included:

- management-session acquisition and loss
- CSRF and Origin guarded management API writes
- `@aegaeon/management-client` as the only management-plane transport boundary
- route groups that require an active management session
- dangerous operation confirmation and audit expectations
- OpenAPI to management-client operation drift

Excluded:

- React runtime correctness
- browser rendering
- CSS/layout behaviour
- browser extensions
- OS UI behaviour
- all possible visual interactions
- end-user password, reset, MFA, or WebAuthn submission on the admin SPA

## Trust And Assumptions

- The server-owned management API enforces authentication, authorization, CSRF,
  Origin, and audit semantics.
- The `aegaeon_admin_session` cookie is an HttpOnly management-session boundary
  controlled by the server.
- The browser can participate in transport and confirmation flows, but it is not
  trusted to enforce authorization.
- The management client is the only allowed low-level transport adapter for
  application source code.
- End-user credential submission stays on server-handled issuer/auth surfaces,
  not in the admin SPA.

## Mechanically Checked Model

The finite model is source-managed in:

- `spec/admin-ui-security-state-machine.current.json`

The model contains:

- session states: anonymous, CSRF-primed, authenticated, confirmed intent
- operation classes: public read, public session write, logout write,
  privileged read, privileged write, dangerous write
- route groups mapped to allowed operation classes
- forbidden client-side surfaces
- drift policy for OpenAPI and management-client operation coverage

The validator is:

- `scripts/validation/validate_admin_ui_assurance.py`

It checks:

- privileged route groups require `management_session=present`
- management API writes require `@aegaeon/management-client`
- management API writes require server-enforced CSRF and Origin guards
- dangerous writes require administrator confirmation and audit expectations
- every OpenAPI management operation is represented by the management-client
  reference
- the management-client reference contains the write-method CSRF/Origin
  implementation hooks
- the claim gate remains inactive while public evidence is not complete

## Evidence Position

Phase 3 internal completion is recorded in:

- `docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json`

Hosted runtime evidence is still a Phase 4/public-activation blocker. Playwright
and hosted stack evidence are runtime regression evidence for the bounded
security boundary; they are not the proof itself.

## Non-Expansion Rule

Do not expand the admin console into a credential-submission or cryptographic
verification surface to satisfy this claim. If stronger administrator
reauthentication or step-up is needed, the assurance-bearing logic must stay on
a server-owned management-auth surface, with the browser acting only as a
transport and ceremony participant where platform APIs require it.
