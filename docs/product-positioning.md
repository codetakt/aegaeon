# Product Positioning

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Documentation

Audience: contributors, maintainers

## Purpose

This is the public presentation index. The normative meaning, finalized English
wording, required release disclosures, and composition rules live in
the [public assurance statement specification](verification/claims/assurance-statement.md).
That specification defines what may be said; the
[server assurance contract](verification/claims/assurance-case/assurance-contract.md)
and its [standards baseline](verification/claims/assurance-case/standards-baseline.md)
define the target obligations; [contract status](verification/claims/assurance-case/contract-status.md)
controls whether the foundation wording is available. Matrix labels, roadmaps,
historical proof counts, and slice promotions do not activate it.

The separate [SDK assurance contract](verification/claims/sdk-assurance/assurance-contract.md)
and [standards/output baseline](verification/claims/sdk-assurance/standards-baseline.md)
govern distributed client/RP and management-client implementations. Its
[activation status](verification/claims/sdk-assurance/contract-status.md) is
independent of server completion and older client-core promotion reports.

## Claimable Today

**Aegaeon is an OAuth/OIDC server with formal-verification assets and security-test
tooling; completion of its published server assurance contract is pending.**

**The Aegaeon SDK has client-core verification assets and security-test tooling.
Completion of its published SDK assurance contract for distributed implementations
is pending.**

Individual component results may be described using the exact checked property,
model/program, bounds, assumptions, dated evidence and runtime relationship.
Do not turn component results into an assertion that the server implementation
or current release satisfies the whole contract.

Runtime capability descriptions remain separate: the server includes OIDC RP /
brokering and Federation trust-chain consumer paths. Public Federation OP
publication is deferred, as specified in
[the runtime specification](specs/openid-federation-spec.md).
Standalone client/SDK and admin-UI claims remain separately gated. Server-side
management/session boundaries that can affect foundation guarantees are part of
the foundation obligations even though browser rendering is not.

## Finalized Target Wording

Use the matching template in section 7 of the
[assurance statement specification](verification/claims/assurance-statement.md):

- Server foundation: section 7.1.
- Client/RP SDK: section 7.2, identifying Node and/or browser output profiles.
- Management API client: section 7.3, with its own operation/output scope.
- Combined server/SDK foundation: section 7.4, requiring both contracts and
  compatible, verified interface/composition conditions.
- Short descriptions and badges: section 7.5, with a release/profile identifier
  and a link to the release assurance record.

Each template is complete as a wording specification; it becomes a release claim
only after its bracketed fields are filled from a qualified release assurance
record meeting sections 5 and 6. No template applies to an unassessed release.
Use section 8 for wording before qualification.

Specification conformance, implementation proof, symbolic security proof,
empirical testing, and certification remain distinct. Fixed draft/errata editions,
external primitive correctness assumptions, own-code obligations, and target/output
limits follow the contracts. A verified core does not establish a verified SDK;
neither contract certifies an admin UI, arbitrary IdP, or another language output.

## Statements To Avoid Today

| Statement | Required basis |
| --- | --- |
| `assumption-qualified formally verified and security-tested foundation` | Complete the server contract and activate it for the actual artifact/configuration |
| `all MUST requirements verified` / `fully verified OAuth/OIDC` | Complete every role-applicable clause in the selected baseline; matrix roll-ups and labels are insufficient |
| `security-tested release` | Identify tests/results for that release and resolve findings under G-18 |
| `verified OIDC interoperability` | Name the exact surfaces, configurations, test results and formal properties |
| `OpenID Federation OP support` | Deliver and assess the currently deferred publication endpoints |
| `cryptographic hardness is the only assumption` | Eliminate or disclose unverified primitive implementations and all other external trust contracts |
| `verified SDK` | Discharge the SDK contract for the named profiles and actual distributed outputs, and satisfy the reconciled client release gates |
| `formally verified server and client` | Activate both contracts and the combined gates with compatible interface assumptions |
| `formally verified admin UI` | Activate the bounded admin assurance gate; no browser/rendering assurance is implied |
| `certified` | Name the certification target and provide its active gate and actual listing/evidence |

## Adjacent Gates

These gates add obligations; they do not establish foundation completion:

- `spec/released-client-claim.current.json`
- `spec/server-client-formal-assurance-claim.current.json`
- `spec/enterprise-readiness-claim.current.json`
- `spec/certification-claim.current.json`
- `spec/admin-ui-assurance-claim.current.json`

Existing records of March 2026 verification and beta OIDF conformance are dated
snapshots. They cannot attest a new baseline, artifact or configuration without
reconciliation. Use [the contract status](verification/claims/assurance-case/contract-status.md)
for the current foundation backlog and the individual gates for adjacent work.
The [SDK backlog](verification/claims/sdk-assurance/contract-status.md) also applies;
the older gates do not yet evaluate its full requirements or output correspondence.

## Update Rule

Update contract obligations and obtain the required evidence before widening
public wording. An evidence-status change cannot silently remove an obligation.
The current claimable wording applies until a reviewed release attestation
satisfies the contract's activation criteria.
