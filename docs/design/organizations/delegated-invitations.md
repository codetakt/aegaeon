# Delegated Organizations invitations

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This is the implementation contract for ORG-R13/R14/R15/R16/R21, ORG-G04/G09/G11/G13
and ORG-P02/P05/P06/P07/P13/P14/P15. No composite proof is discharged here.

A delegated inviter uses a current selected Organizations DPoP token for the
registered management audience and `organization.members.manage`. Issuance
checks the original root ceiling, exact organization/member generations, current
client registration and binding, current role versions, and all assignable roles.
The organization must be active. Operator provisioning is a separate first-admin
path and never supplies delegated business authority.

Retain the original authorization ceiling and binding, the selected authority
used for issuance, and the exchange-root and optional refresh-family references.
Do not retain a token, refresh token, DPoP proof or other bearer credential. The
invitation defaults to 24 hours, bounded by the original root deadline and the currently retained refresh-family
deadline, when present. The root maximum includes authorization-code/access
horizons and need not equal the actual family retention. Capture their minimum;
do not extend the store retention to issue an invitation. Later shorter family
retention refuses the retained authority, and later extension cannot lengthen
an already issued invitation. Expiry of
the short selected token alone does not extend or erase the retained invitation;
root/family revocation, issuer/client/user changes, domain or organization stops,
and changes to the inviter's effective membership or granted role versions refuse
subsequent delivery, challenge and acceptance.

Every such operation checks the retained root against the current token store,
with no positive cache or failure fallback, and checks primary authority under
the domain/organization lock. Root revocation is not a distributed atomic commit
with PostgreSQL: a decision begun after completed revocation must refuse; a prior
admitted transaction may finish. Recheck before send admission and before commit.
The owned blocking store worker retains the finite request lease until it ends,
including when the caller times out. Missing runtime authority refuses delegated
operations; the native first-admin test entry cannot authenticate a delegate.

Acceptance follows the existing fresh address-challenge flow and requires no
existing membership row for that user, including suspended or removed rows.
Such an existing membership refuses both challenge issuance and new acceptance
with 403; it is an authorization refusal, not malformed request input.
Create one active membership with the retained roles and a new incarnation.
Do not change the active organization's state/generation or upgrade existing
OAuth grant ceilings. Exact accepted-binding replay remains current-authorized.
Domain membership and invitation capacities still apply.

The delegated HTTP interface below `/organizations/{organization}` adds
`POST /invitations`, `GET/HEAD /invitations/{invitation}`, and
`POST /invitations/{invitation}/revoke`. Mutations use specific ETags,
idempotency keys, reasons and the existing strict bounded JSON/DPoP boundary.
Read/revoke require current delegated management authority over the invitation's
retained roles; they cannot access another organization. Cancellation has its
reserved finite admission and is allowed after original inviter/root expiry.
No response contains a recipient address, capability or retained authority.

The matched methods above use the protected-resource URI credential envelope:
an `access_token` query is refused with 400 `invalid_request` and the presented
DPoP challenge, or Bearer otherwise. This includes percent-decoded credential
keys and HEAD. Early refusal does not validate or consume a proof. Unsupported
methods, unknown routes and other URI credential errors keep their generic
envelopes. This is Aegaeon's URI transport policy; it does not add a standard
requirement or relax the selected-token authorization checks.

Retained first-admin authority documents without a delegated member remain
first-admin documents. A new optional, strictly parsed delegated authority is
never inferred from historical fields. Current code and physical catalog remain
bound to the same schema; this extension needs no table or ACL weakening.

Required regressions include complete delegated delivery/acceptance; root/family,
member, role and client revocation; stale original ceilings; wrong organization;
concurrent acceptance; suspended/removed target refusal; store failure; and
currentness on replay. The delivery supplier and final release obligations remain
separate until evaluated on the complete composition.
