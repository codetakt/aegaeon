# Invitation-linked registration and recovery

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This implements ORG-R14, ORG-G04/G09 and ORG-P05/P06/P07/P13/P15. This design
records the next implementation boundary; it does not assert delivery or proof.

Environment policy defaults to disabled. A current human Team owner with an
explicit domain configure grant can set independent registration and password
recovery flags and select the `uuid` subject format. Policy reads and changes
use authenticated management HTTP, a strong Environment policy version,
idempotency key and reason. Changes advance a monotonic policy revision;
requests captured under an older revision cannot resume after re-enablement.
Disabling has reserved admission capacity and never grants business access.

The initial self-service profile is invitation-linked. An unauthenticated browser
can request registration or recovery only with a currently live invitation
capability and fresh CSRF token. The capability permits an address proof request,
not login or membership. Recheck current inviter/root authority, organization,
delivery revision, policy and expiration at request, send and completion. An
expired or revoked invitation cannot authorize identity changes. The recipient
address comes from the invitation; request fields cannot redirect delivery.

Each request has an opaque UUID, a 256-bit secret stored only as a scoped hash,
a fixed 600-second expiry bounded by the invitation, five delivery attempts and
at least 60 seconds between attempts. Limit five requests per invitation and
10,000 retained requests per Environment. Retain delivery uncertainty before
network I/O, recheck admission immediately before sending, and condition late
completion on the exact attempt. A configured HTTPS transport receives a fixed
identity-registration or identity-recovery template, exact address, issuer,
request UUID, proof and expiry. It receives no password or membership authority.
Use the existing finite TLS/DNS/SSRF/response limits and scoped credential check.

GET displays a form only. Proofs and passwords enter POST bodies, not server URL
queries. The browser binds a fresh CSRF token, request UUID and proof. Completion
requires matching password confirmation and the existing password policy/KDF,
with bounded owned blocking work. Never persist a plaintext password, proof,
access token or DPoP key. A transaction commits the identity/credential change,
request consumption and audit/outbox together. A repeated completion cannot
change credentials again. It returns a consumed result only under the same proof
and current authority; it never opens a session or accepts the invitation.

A consumed completion binds the resulting user UUID, credential UUID and identity
revision. Replay verifies the supplied password against that exact current
Argon2 credential, with the same bounded worker and admission ownership as initial
hashing. A changed password or identity revision refuses replay. No fast password
digest, plaintext or email-secret-derived password verifier is retained. Database
locks cover the verification and commit; disconnected HTTP callers do not release
the worker's capacity early. The public result includes the UUID subject used for
ordinary login, so an ambiguous legacy email alias is never required for login.

Registration creates a new random UUID user and UUID subject, preserving all
existing identities. It refuses an existing login email rather than attaching
that account. The legacy lowercase email is a login alias, not address proof.
Retain the exact verified delivery address separately. Set the standard email
verified flag only if the stored email exactly equals that address; uppercase
local parts are never silently attested as another mailbox. The actual password
login still authenticates the selected account. Recovery requires an explicitly
supplied login identifier, a unique active local-password identity, and exact
agreement with its verified address (or a legacy exactly matching email whose
verification flag is true). Ambiguous, suspended, deleted or unverified identities
cannot be recovered through this path. No email-based account linking occurs.

Changing the login email or verified address also advances the identity revision
and cutoff; restoring an earlier address never restores pending recovery authority.

Recovery replaces the existing password under the identity lock and advances the
nonrollback identity revision/cutoff. Other pending recovery requests bound to
the old revision refuse. Signup and recovery do not grant roles, extend an OAuth
ceiling or activate a suspended identity. After completion the user performs a
new ordinary authentication in a later second, obtains a fresh DPoP recipient
token, then completes the separate invitation address challenge and acceptance.

Public request responses do not reveal whether a login exists. Request progress
and completion require the scoped proof; errors contain no address, token or
password. The protected audit records purpose, request UUID, identity UUID when
established and before/after authority revisions. Export omits proof hashes and
password material. Historical request cleanup follows the separate audited
retention/export contract; reaching a limit fails closed, never drops evidence.
