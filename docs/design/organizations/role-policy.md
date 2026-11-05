# Organizations Role Policy

Last updated: 2026-10-30

Status: active plan

Owner: Engineering / Verification

Audience: implementers, operators, security reviewers

## Scope and identifiers

This increment implements configuration needed before invitation issuance under
ORG-R04/R05/R06/R15/R16/R20/R21/R22, ORG-G03/G05/G08/G09/G11/G14 and
ORG-P03/P04/P05/P06/P10/P12/P13. It defines one role policy per authorization
domain. It does not issue membership, invitation acceptance or business access.

The authenticated management route is
`/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/role-policy`.
All path object identifiers are UUIDs. Role keys and privilege names are exact
ASCII vocabulary entries inside this configuration, like OAuth scope values;
they are not object IDs, URLs or credentials. The policy's `id` is its domain
UUID. There are no standalone role-object routes or prefixed role object IDs.
Existing persisted keys are preserved, with no aliases, renaming or reuse.

## Read and update contract

GET and PUT both require a current interactive human session and an explicit
current `configure` grant for the exact domain. Team ownership and provisioning
alone do not grant configuration. PUT uses existing origin/CSRF, strict JSON,
finite body/request admission and current-session checks before commit.

The PUT body contains `roles` and a nonblank `reason`. Every role contains
`key`, `privileges`, `managesMembers` and `assignableRoles`. Reject unknown fields,
duplicate keys/privileges/assignable-role entries, missing assignable targets,
and invalid vocabulary. There is no hierarchy inferred from a key's spelling.
The caller cannot supply versions. Each definition has 1–256 privileges, at
most 64 assignable roles, and explicit member-management authority. Nonmanaging
roles cannot assign roles. The catalog retains at most 64 keys. The encoded
configuration must fit within 48 KiB, independently of the 64 KiB HTTP bound.

PUT supplies the complete retained catalog. It may add keys or change definitions
but cannot omit an existing key or rename it. An unchanged definition retains
its version; each changed definition increments its version once. Initial
versions are one. Any definition version change requires fresh authorization
for holders of that role, including reductions to its configured meaning.
Ordinary membership demotion remains governed by the existing old-grant ceiling
and is distinct from changing the domain's vocabulary. Unchanged roles and other
domains keep their versions; role configuration does not increment domain
activation generation or confer membership by itself.

The strong ETag is `"role-policy.<domain UUID>.<revision>"`, with revision one
plus the checked sum of the retained role versions. Retaining all keys and
incrementing every changed definition makes this value monotonic for every
changed representation. It also separates this policy precondition from the
domain-enable ETag. Counter overflow and exhaustion refuse before mutation.
This tag is a representation validator, not an object identifier or authority.
GET returns `id`, `revision` and the ordered catalog including server versions.

## Atomicity and authority

Lock the domain through current operator authorization before reading a receipt
or the policy. Same actor/scope/idempotency key and canonical request digest
replays the previous response only after fresh authorization. Different input
conflicts, and a stale policy precondition returns 412. A successful command
uses one ordinary configuration receipt slot, event and outbox entry. It cannot
consume the reserved domain/operator/client revocation budget. Domain disable
remains available when policy modification is exhausted.

Before changing member-management semantics, serialize against membership
writers under the domain lock. Reject a change that would remove the last
effective manager from an active organization which currently has one. An
organization already orphaned by global security suspension stays blocked for
delegated changes and requires its separately authorized recovery flow; this
configuration API does not impersonate a business administrator. Global user
security suspension itself remains permitted.

Retain reason, operator grant and revision, and before/after policy versions in
the transactional event. Store failure or outbox failure rolls back policy,
receipt and event together. Lost responses replay after authority checks. Read
and write responses use no-store and the existing response size cap.

## Required evidence

Test actual authenticated routes, restricted PostgreSQL, initial empty catalog,
normal configuration and replay, scoped denial, stale preconditions, concurrent
updates, duplicate/unknown-role refusal, version changes and unaffected roles,
last-manager retention, outbox rollback and exhausted ordinary budget with
domain disable retained. Tie resulting role versions to current token and
original-ceiling refusal regressions. Negative controls must detect removed
operator checks and missing version invalidation. Runtime tests, formal
obligations and shipment qualification remain separate results.
