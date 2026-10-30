# Recovery after loss of the last organization administrator

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This implements the recovery boundary of ORG-R05/R14, ORG-G09 and ORG-P05/P06.
Global identity suspension remains independent of the last-administrator check.
Neither suspension nor password recovery grants a replacement membership.

An authenticated current human Team owner with an explicit domain provisioning
grant can POST `.../organizations/{id}/administrator-recovery`, using the normal
management session, CSRF/Origin checks, reason, strong If-Match version and
idempotency key. An active or suspended organization must have no effective
administrator: an active membership with a member-management role and an active
local identity. Lock the organization and its existing member identities before
this check. An existing administrator, including a concurrent identity resume,
prevents this recovery transition. Foreign scopes and missing authority refuse
before resource disclosure or receipt lookup.

Recovery advances the organization revision and authorization generation and
sets its state to `provisioning` in one transaction with audit/outbox/receipt.
All organization access refuses during this state. Existing users, memberships,
incarnations, subjects and external identifiers are retained. The original
authorization generation can never become current again. Deleted organizations
are terminal. Repeated committed requests return the original receipt only under
current caller authority; they never repeat the transition.

The existing first-administrator invitation operation can then invite a new
member. It requires no effective administrator, an administrator role ceiling,
and a recipient with no existing membership. It never reactivates or replaces an
old membership. Sending, address challenge and acceptance keep their existing
finite lifetimes, current inviter checks and DPoP-bound recipient authority.
Acceptance locks existing identities and rechecks the absence of an effective
administrator. It creates the new membership, activates the organization, advances
its generation again and consumes the invitation atomically with audit/outbox.
Concurrent acceptances have at most one effect. Stale invitations, resumed old
administrators, revoked provisioning authority and storage failures refuse.

After activation, business access requires a new original authorization. Recovery
does not rewrite a previous OAuth root, restore a revoked identity, assign extra
roles to existing members, or change their identifiers. If an old identity is
later deliberately re-enabled, its own identity generation and reauthentication
cutoff still apply. This operation is separate from temporary business support
access and does not require or create an AdminAccessGrant.

Use the existing finite management admission, transaction deadline and retained
receipt budgets. Include recovery receipts in the operator budget. Reaching a
limit refuses new recovery work; suspension/deletion retain their reserved
capacity. Recovery changes no database schema or existing migration history.
