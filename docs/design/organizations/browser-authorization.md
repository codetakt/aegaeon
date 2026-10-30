# Organizations browser authorization

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers and protocol reviewers

## Scope and contract

This increment connects ORG-R06/R07/R08/R09/R10/R21 to ORG-G03/G05/G06/G07/G11
and ORG-P04/P07/P08/P12/P13. It verifies the actual browser consent producer
and configuration admission. The first component fixture supplied an independent
configuration instance and was correctly rejected by the authorization snapshot
guard. Its successor must use the actual database loader and consumed instances.

An existing authenticated browser session, a registered confidential client,
PKCE S256 and a DPoP key identify the original authorization. The request asks
for explicit consent, offline access and the versioned organization grant
detail. The displayed selection includes the exact external organization ID,
target and privileges. Approval is bound to the pending request, browser session
and subject, requires the same issuer Origin and is one-use. Denial never issues
an organization ceiling. Approval rechecks the current primary authority and
rejects any changed membership, role, client, target, domain or identity snapshot.

The resulting authorization code is redeemed through the actual token endpoint.
Its original grant must preserve the approved ceiling through refresh. Selecting
an organization through Token Exchange must reach the own resource endpoint with
the same external ID and a fresh resource-bound DPoP proof. Current suspension
must make that resource access fail even for an earlier successful token.

## Acceptance boundary

Retain normal consent-to-code-to-token-to-resource execution alongside denial,
foreign-session submission, replay, stale snapshots, missing proof and backend
fault cases. Do not replace the browser producer with a directly constructed
approval in these tests. Existing direct issuer fixtures remain separate
component evidence. Public activation additionally requires bounded actual
browser caller paths, configuration and advertisement validation, and the
remaining Organizations delivery conditions. No new composite discharge follows
from these finite tests.

## Explicit configuration candidate

The runtime allowlist is empty by default. Its only initial nonempty supported
set contains both versioned Organizations grant and access types. The pair
requires authorization-code, refresh-token and Token Exchange grant support,
JWT access tokens, retained refresh lineage and enforced refresh sender binding.
Partial and unknown handler sets fail configuration validation. Existing list
normalization remains configuration syntax; external organization IDs are never
normalized by that mechanism. Domain enablement, exact targets and current
confidential DPoP client bindings remain separately required. Advertising these
types creates no membership, grant or client entitlement.

[RFC 9396 section 10](https://www.rfc-editor.org/rfc/rfc9396.html#section-10)
defines the supported-type metadata. The two Aegaeon handlers have different
entry contracts: the grant type acquires original browser consent, while the
access type selects one organization in Token Exchange. This distinction is
part of this profile, not a general RFC restriction. Metadata and compliance
records must describe this candidate without claiming complete RAR conformance.
The configuration candidate is not ready for publication until the remaining
browser, operational and assurance conditions have been evaluated.

## Browser operation budget

The mounted `/authorize` GET/HEAD/POST and `/auth/consent` POST paths share eight
process-wide operation owners. Admission precedes request body consumption and
runtime-authority database middleware. A ninth request receives a no-store 503
without entering those paths. The 30-second response deadline and disconnect
only detach the owned request: they do not release its slot while store or SQL
work is still running. Unexpected worker loss closes admission until restart.
A store fault has no permissive fallback or automatic mutation retry.

The source rate limiter must use the same finite Redis driver as browser sessions,
PAR and token stores. Its DNS/setup, command and connection lifetime bounds and
uncancellable-resolver limits are recorded in `redis-operations.md`. PostgreSQL
pool and existing authorization transaction budgets remain independent bounds;
the response deadline is not a guarantee that all cleanup or external work has
terminated. A stuck owner continues to consume capacity. Actual stall, client
cancellation and healthy-store recovery must be tested before claiming this
increment validated. This bounds these mounted routes; it does not qualify
unrelated login, device or logout routes or arbitrary deployment capacity.

Runtime-authority database failure requests a graceful restart and returns an
uncacheable 503. Recovery means a fresh runtime loaded from the primary and
retained stores; replacing a failed pool or clearing the restart flag in place
is not recovery. The browser regression retains the failed runtime's refusal
and checks the surviving pending consent in a newly loaded runtime. An initial
integration fixture omitted signed-introspection enablement and was correctly
refused with 406; the runtime-authority 503 also exposed missing cache headers,
which this successor fixes without changing its restart policy.
