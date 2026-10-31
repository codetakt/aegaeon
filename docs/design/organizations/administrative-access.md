# Explicit temporary administrative access

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This specifies ORG-R12, ORG-G08 and ORG-P09 before their implementation. It
extends the adopted support contract; it does not establish shipment or discharge.

## Policy and independent identities

The domain's support policy is absent by default. A current human Team OWNER
with explicit domain configure permission may GET/PUT `.../support-policy` or
POST `.../support-policy/disable`. Management session, CSRF, exact policy ETag,
reason, idempotency and atomic audit/outbox apply. The policy ETag uses the domain
UUID and a separate monotonic support-policy revision in the opaque
`"support-policy.<domain-uuid>.<revision>"` entity tag. A domain or role-policy
entity tag cannot authorize a support-policy write. Every replacement changes
that revision; disabling has reserved admission and one reserved receipt. There
is no implicit policy from Team status, an organization role or an email address.

A policy contains at most eight accepted providers and 64 explicit entitlements,
and at most 48 KiB of JSON. Each provider names the managed connection UUID,
configuration UUID, exact issuer, exact upstream client ID, one exact signed ACR
and two or three concrete signed AMR methods. Each method has an explicitly
reviewed factor class (knowledge, possession or inherence). At least two classes
and distinct methods are required; generic `mfa`/`mca` markers cannot be factors.
Provider-specific assurance semantics and independence of factors are deployment
configuration obligations; Aegaeon does not infer an assurance level from labels.
Connections must currently belong to the active configuration of this Environment.

Each entitlement names one human administrator UUID, one end-user UUID, one
organization UUID, one exact target audience and an explicit nonempty role set.
This is a reviewed correspondence, never account linking. The administrator must
currently have Team membership and explicit domain support permission. The user,
organization, target and roles must currently exist in the same scope. Duplicate
(user, organization, audience) entries are refused. No caller can acquire a
mapping through matching email/subject text. Policy changes invalidate prior
support approvals, including when a removed entitlement is added again.

## Original approval and current evidence

An original organization grant selection may explicitly request
`administrative_access: true`; omission retains membership semantics. Display
this distinction in consent. This requests permission to activate temporary
support, not a membership or access grant. Capture only the permitted requested
privileges, current role versions, organization generation, policy revision,
operator grant UUID/revision and administrator UUID. Keep this ceiling separately
from membership ceilings. Recheck the original snapshot at consent approval.
A later promotion, new entitlement or role expansion requires new authorization.

The immutable original authentication record must match this Environment/user,
current identity revision, exact managed provider/configuration, exact signed
ACR and all configured concrete methods. Its explicit signed auth_time must be
no later than now and strictly less than 300 seconds old. Check current active
Team/Tenant/Environment, connection and account-link ownership/revision/provenance
on the writable primary. Legacy/unreviewed links are insufficient; JIT v2 and
administrator-confirmed links are eligible only with the explicit entitlement.
Refresh, exchange, request/default ACR, token iat and login time cannot advance
these facts. Missing state or store failure refuses support.

## Activation and use

The parent OAuth token for activation targets the dedicated Environment support
resource and explicit `organization.support.activate offline_access` scopes. Its original RAR
location is the business audience being approved. Activation authenticates the
parent token/root/client and DPoP, including replay, before current primary checks.
A POST specifies the organization, audience, nonempty requested roles and reason;
If-Match/idempotency are bound to the authenticated user/client/root/key and the
complete request. A new plain UUID identifies the AdminAccessGrant. Lifetime is
at most 300 seconds and ends no later than original auth_time + 300, parent/root
expiration. No extension or refresh is available. Revocation is explicit and
permanent; retries never revive expired/revoked authority. Grant, audit, outbox
and receipt commit atomically within finite per-domain and per-root budgets.

Exchange additionally selects `admin_access_grant_id`. A server-selected
`administrative_grant` basis and that UUID appear consistently in token response,
JWT and introspection. The decision contains actual grant authority, never a fake
membership/incarnation. It remains limited by original/current client and target,
original/current role definitions, policy/entitlement, organization generation,
original MFA freshness and current grant state. Each own-RS/introspection check
revalidates those facts without positive caching. Organization-selected tokens
cannot activate grants or chain exchanges. Membership-based delegation does not
accept support as membership. Standard RFC behavior and this Aegaeon profile are
tracked separately in the compliance matrix.

## Evidence and rollout

Native/API regression must cover normal configuration/approval/activation/use,
wrong scope or user/client/root/key, absent/stale/original MFA, default/requested
assurance substitution, provider/link/config changes, role promotion/demotion,
policy revoke/re-enable, expiry, replay/concurrency, audit/store failure and
recovery. Preserve a real removed-check negative control. Extend migration and
physical-catalog evidence without changing sealed predecessors. Configuration,
original approval, activation, enforcement, formal arithmetic and complete
caller/store/artifact proof are separate completion states.

### Activation HTTP and retained storage bounds

`POST /organization-support/{domain}/grants` accepts JSON `organizationId`,
`audience`, a nonempty unique `roles` array (at most 64), and `reason` (1–1024
UTF-8 bytes, nonblank, no controls). It requires the current organization ETag
and a 1–128 ASCII-graphic-byte idempotency key. The dedicated parent audience is
`<issuer>/organization-support`, with exactly `organization.support.activate offline_access`;
its access-token lifetime is at most 300 seconds. This audience must be registered
as a management target in the same domain and explicitly permitted by the same
client binding that was captured in the original business-audience approval.

`GET /organization-support/{domain}/grants/{grant}` reads an owned grant, and
`POST .../{grant}/revoke` revokes it with its exact grant ETag and reason. These
operations use the same authenticated parent/root/user/client/key. Revocation
needs no new MFA or policy enablement, because it only removes that exact root's
existing authority; current primary identity and token/root checks remain
mandatory. The operator policy-disable endpoint remains the independently
authorized administrative revocation route. Revoking a grant is terminal.

Retain at most 10,000 grants per domain and 16 grants per user/client/root. A grant
retains its creation key and complete semantic digest as its ownership receipt;
identical retries recheck authority before returning the original live result.
A changed request conflicts. Expired or revoked grants cannot be replayed as live
results. No creation reclaims or deletes history. Revocation does not allocate a
new grant or consume creation capacity. Repeated exact revocation uses the stored
revocation key/digest/result and must pass current owner authentication.

The existing finite own-resource worker/connection budgets, 30-second transaction
deadline, body limit 64 KiB and 10-second body deadline apply. Activation and reads
use ordinary admission; revoke uses the reserved revocation path. All responses
are no-store. Neither malformed JSON nor unknown/query/repeated inputs are used
as authority. The audit event names both the explicit administrator and business
user/client/root binding; it never labels that user a member.

The activation credential is the original code-issued DPoP token with the exact
`{issuer}/organization-support` audience and exactly `organization.support.activate offline_access`
scopes. Its private original approval names the intended business audience. The
configured exchange rule maps that source scope to the separately approved
business scope. An Organization-bearing root is not exchanged without an explicit
Organization selector; no intermediary unselected token bypass is introduced.

`offline_access` is explicit because the retained Organizations root is backed by
the existing refresh lineage contract. Refresh cannot replace its immutable MFA
evidence or extend an administrative grant past original `auth_time + 300`.
Other scopes on the activation credential are refused.

The activation credential is the original authorization token. Its captured
exchange capabilities name allowed destination scopes; they do not assert that
the source token is an exchanged output. Activation validates the authenticated
source audience/scopes, original RAR, consent and root/key/client bindings. The
exchange-output coverage predicate applies only after Token Exchange.
