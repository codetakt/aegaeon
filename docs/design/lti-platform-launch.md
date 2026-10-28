# LTI Platform resource-link launches

Last updated: 2026-10-13

Status: current implementation baseline

Owner: Engineering

Audience: protocol implementers, operators, reviewers

## Scope and responsibility

An existing OAuth/OIDC client can acquire an explicit LTI Tool capability.
The capability does not replace its ordinary protocol configuration or grant
token-endpoint permissions. Aegaeon acts as the Platform. The initial flow is
an authenticated, top-level resource-link launch with manual registration.
Advantage services, dynamic registration, anonymous and embedded launches are
separate capabilities, not advertised by this implementation.

This contract refines the adopted shared mapping and configurable secure-default
boundaries. It supersedes the earlier candidate's exclusive client type and
mandatory bespoke activation sequence. It does not establish certification or
product assurance. Ordinary OAuth/OIDC output integration is not a prerequisite
for the LTI mapping adapter.

Normative references are [LTI Core 1.3, document 3](https://www.imsglobal.org/spec/lti/v1p3/)
sections 3–5, [Security Framework 1.0](https://www.imsglobal.org/spec/security/v1p0/)
sections 5.1, 5.4 and 6, [OIDC Core 1.0 errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
sections 3.2 and 4, and [Form Post Response Mode 1.0](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).

## Mapping and input authority

The generic engine receives an immutable environment/user owner, exact recipient,
authenticated attributes, policy revision and adapter-owned output contract.
Recipient permission and transformation permission remain separate. LTI is a
named output surface with a predefined policy for resource placement, context
and roles; internal attributes can supplement it through explicit release rules.
Custom rules cannot replace identity, deployment, target or message claims.
Context and resource identities must agree with the admitted placement. Mapped
roles cannot exceed the authenticated producer's admitted facts.

A context producer uses its own current client-credentials authorization. A
deployment explicitly names permitted producers, contexts and roles. The producer
asserts membership facts; Aegaeon checks producer authority, freshness, owner and
recipient, without claiming to independently establish the truth of those facts.
A management administrator configures this authority but does not acquire an
end-user authentication session or become a producer through the management role.

## Lifecycle and storage

The registration belongs to the environment and an existing canonical client
row. Explicit LTI revisions contain deployments, placements, producer grants,
mapping rules and security options. A revision is a bounded complete document;
updates use compare-and-swap and retain prior revisions. Stable deployment and
resource identifiers cannot be reused for another client, parent or context.
Copying a placement requires a fresh identifier. Retirement is terminal.

Defaults require explicit activation, browser consent for each launch and DPoP
on producer requests. An authorized administrator can explicitly relax these
additional requirements per registration. Such settings cannot relax protocol
validation, current authorization, session correspondence or single use.
Ordinary configuration rollback does not restore retired LTI authority. Every
launch pins the active registration and runtime authority revision; issuance
rechecks current authority and rejects superseded or disabled state.

The producer creates a short-lived intent for a specific internal owner and
placement. Browser confirmation binds it to an authenticated session before
Tool initiation. Opaque login/message hints reveal no subject. The LTI
authorization profile accepts GET and POST and validates the registered redirect
before any protocol error delivery. It accepts the required `openid`, `id_token`,
`form_post`, `none` combination and never falls back to ordinary authorization.
Consent is resolved before Tool initiation, not by prompting inside a silent
authentication request. Missing or mismatched sessions fail closed.

Signing uses the existing RS256/key infrastructure. A database transaction
serializes finalization against competing consumption and authority changes.
The signed response is released only after successful consumption commit;
uncertain commit or response loss cannot authorize a second issuance. Tickets,
tokens and attribute values are excluded from audit payloads. Audit failure is
a transaction failure, not an optional loss of evidence.

## Direct integration obligations

Before a real user claim is released, the shared issuer/subject ownership
contract must bind the session subject to the same immutable owner, including
historical migration and runtime database privileges. Reading the current
`end_users.subject` row alone is insufficient. External federation additionally
requires its account-link/provenance contract when that path is enabled.
The implementation must fail closed if these dependencies are unavailable;
a local test fixture is not an adopted migration or an operational bypass.

Acceptance covers real registration-to-Tool signature validation, exact opaque
parameters, malformed and duplicate inputs, output minimization and authority,
consent and supported relaxations, revocation, concurrency, expiry, replay,
transaction rollback and uncertain outcomes, browser session behavior and ordinary
OAuth/OIDC regression. Finite tests do not discharge formal proof obligations.
The assurance workstream remains paused; new obligations are handed off separately.

## Verification boundaries

The functional suite exercises the public router with a restricted PostgreSQL 18
login, including management session/CSRF, active revisions, producer tokens,
consent, request continuation, exact claims, JWKS-based RS256 validation,
concurrent consumption, audit rollback, lost response delivery and bounded
retention. HTTP unit fixtures use the repository DPoP verifier mock; the DPoP
scenario additionally verifies each real signed proof using the FFI verifier.
This does not establish a full browser interoperability or certification result.

The operational contract defines intent independence from the original access
credential, supported revocation mechanisms, finite capacity and separate session
storage consistency in [the runbook](../operations/lti-platform.md). The common
ownership migration retains the stopped historical-adoption requirement. A new
schema extension updates the complete protected inventory rather than permitting
unexpected migrations or weakening function/role checks.
