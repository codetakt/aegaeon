# LTI Core Platform assurance obligations

Last updated: 2026-11-02

Status: active plan

Owner: Protocol Engineering / Verification

Audience: implementers, Task1b and Task3 reviewers, release managers

## Adopted scope

1EdTech Learning Tools Interoperability Core 1.3, document version 3, is an adopted
Platform conformance and formal/security-assurance target. The existing
[server contract](assurance-contract.md) and [source register](../../../../spec/server-assurance-contract.v1.json)
govern it; this record does not introduce another claim authority. The register
pins Core, Security Framework 1.0 and both official errata status pages, reusing
the adopted OIDC Core errata set 2 and Form Post sources. All six retained source
digests were checked against the adopted bytes before this integration.

Applicable Platform requirements remain obligations even if the compliance matrix
omits them or the implementation lacks them. Classify optional features and roles
from their normative conditions. Implementation omission cannot make a mandatory
requirement inapplicable. Source reading and transitive dependency projection are
incomplete; three composite matrix entries are not three atomic proof obligations.

The current implementation slice is authenticated, top-level
`LtiResourceLinkRequest` with manual Tool/deployment/resource-link registration.
Separate Advantage specifications, dynamic registration and the Tool implementation
are outside this slice. No 1EdTech certification or Advantage Complete claim is
established. The Aegaeon secure-default policy and explicit permitted relaxations
are assessed separately from normative LTI/OIDC conformance.

## Task1b implementation closure

The current integration uses published main `55e22e34639c970a69fd29f53ee233ad7ea60ff3`
and its canonical subject ownership/local attribute API. The new LTI migrations
follow that complete history; existing migration bytes and applied ledger rows
are retained. Earlier unmerged LTI/ownership candidates are historical inputs,
not an interchangeable installation history.

Resolve launch/profile, identity, recipient, current authorization, SQL concurrency,
replay and error-path defects within this feature. Required acceptance includes
independent Tool-side JWT/JWKS validation, normal browser round trips, malformed
input, cross-owner/context references, revision revocation, simultaneous use,
DPoP replay, signing/store failures and recovery. Preserve tests for ordinary OIDC
and local attribute APIs when composing the feature. Tests must use the actual
restricted runtime and compiled source; an administrator-only fixture is insufficient.

External source ingestion, historical account-link proof, runtime-read versus
management-write database credentials and whole-provider/browser composition
remain explicitly tracked integration obligations. They close only with concrete
implementation and tests, or a supported-scope decision that retains all applicable
requirements. A handoff does not authorize serving an unresolved dependency.

## Task3 assurance closure

Project normative clauses and incorporated dependencies onto stable atomic
obligations before reporting added, changed or reused proof counts. Retain the
existing obligation inventory and historical dispositions. New discharge is zero.
For each obligation bind its source edition, applicability, real code and callers,
store and supplier assumptions, proof model and security tests. Cover successful
behavior as well as denial, finite resources, concurrency, cancellation, rollback
and restoration. Bind the final build and distribution to the reviewed evidence.

The producer is an authenticated source of membership facts; its claims are not
independent proof that those facts are true. Record that premise and the explicit
producer/context/role ceiling. Session and SQL state are separate consistency
domains: qualification must assess the actual revocation/issuance boundary, not
assume distributed atomicity. Form Post, signing keys and ordinary OAuth state
require composition analysis. Models and passing finite tests alone do not close
these whole-system obligations or activate a product claim.
