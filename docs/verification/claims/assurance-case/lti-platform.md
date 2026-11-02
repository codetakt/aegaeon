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

The current integration uses published main `cd95bcc1b5c4f31e7197e6fdfc1294acd01a06c0`
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

The launch authority reads reuse the caller's locked SQL transaction. The producer
endpoint always requires `lti:launch` and its own audience, even if generic token
policy toggles are disabled. A real restricted-PostgreSQL launch with a one-connection
pool and the relaxed-policy denial regression cover these fixes; the pool must be
validated again after replacement before it can supply the subject namespace.
The local integration ran 46 launch/management/OIDC regressions plus seven mapping
and four Form Post tests. A requested ignored-only mapping selector selected zero
tests; the seven ordinary mapping tests were then run explicitly and are counted
once. This is bounded regression evidence, not complete protocol assurance.

The same two regressions detect the original published launch implementation:
one connection returns 503 instead of creating the launch, and missing scope is
accepted with 201 instead of 403. The original implementation still passes its
ordinary signed resource-launch/replay control. An initial control selector found
zero tests; the correctly named control was subsequently executed separately.

The Nix source inventory now accepts the adopted canonical LTI host and source-ID
archive names. The two runtime manifest changes bind the added ID-token Form Post
helper and LTI module registration. Existing OAuth response paths remain covered;
these digest updates do not discharge the matrix entries that reference those files.

The management reference client registers all three LTI OpenAPI operations for
its generic `requestOperation` interface. Regression coverage checks escaped
Team/Environment paths, opaque UTF-8 client queries, write CSRF/Origin handling,
request bodies and conflict propagation without retries. This closes the client
inventory mismatch found by the full assurance-integrity job; it is not proof
of a browser or whole-provider interaction.

The four LTI HTML pages have volatile Drupal asset-cache and theme-token fields.
The archive fetch restores only these fields to their saved values and requires
the entire result to match the original adopted SHA-256. It does not substitute
visible-text equality, remove arbitrary markup or update the source pins. Metadata
records the restoration method. A changed body, host, markup, extra/missing field,
inconsistent cache tokens or oversized page fails closed. The saved and currently
fetched four documents reproduce the original bytes exactly. This is retrieval
reconstruction, not a new source edition or a new protocol proof.

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

## Consent and concurrent authority reads

The consent response permits form redirects only to its own origin and the stored
Tool initiation origin. All other authentication HTML keeps its existing policy.
The browser regression uses Chromium with CDP transport to the actual router and
PostgreSQL state: approval, cancellation, replay, a foreign destination and the
original self-only CSP are separate cases. It does not qualify production TLS.

Browser requests retain shared Environment and registration locks; configuration
writes and admission count-and-insert retain exclusive Environment locks. Each
intent retains its exclusive consumption lock. Concurrent independent launches,
writer exclusion, revocation and the existing consume-once race remain regression
conditions. A forward Environment/time index supports bounded-window admission;
its successor physical catalog preserves previous migration bytes and ledger.
Task1b tracks these implementation conditions; Task3 still requires the complete
caller/store/supplier, normative and artifact-bound proof composition.
