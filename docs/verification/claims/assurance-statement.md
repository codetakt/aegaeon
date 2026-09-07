# Aegaeon Technical Assurance Statement Specification

Last updated: 2026-09-07

Document revision: **2026-09-07-r4**.

Status: current implementation baseline

Owner: Verification / Security / Release Engineering

Audience: users, adoption reviewers, implementers, verification and release owners

## 1. Authority

The statement identifier is **aegaeon-assurance-statement-v1**. The document
revision appears above. Detailed qualification decisions follow the normative
[assurance evaluation rules](assurance-evaluation.md). This specification defines
the meaning, scope, public wording, required disclosures and activation conditions
of Aegaeon's technical claim of being an "assumption-qualified formally verified
and security-tested" foundation.

Completing this specification and establishing assurance for a particular release
are separate events. **As of 2026-09-07, release assurance under this specification
is inactive for both the server and SDK.** Use section 8 for current public wording.
The finalized templates in section 7 may be used only for targets with a release
assurance record satisfying section 6.

The following contracts and registers define the detailed obligations:

| Target | Assurance contract | Standards and implementation scope |
| --- | --- | --- |
| Server | [aegaeon-server-assurance-v1](assurance-case/assurance-contract.md) | [Server baseline](assurance-case/standards-baseline.md), [register](../../../spec/server-assurance-contract.v1.json) |
| SDK / management client | [aegaeon-sdk-assurance-v1](sdk-assurance/assurance-contract.md) | [SDK standards/output baseline](sdk-assurance/standards-baseline.md), [register](../../../spec/sdk-assurance-contract.v1.json) |

This specification fixes the meaning of public claims; the contracts define the
obligations supporting them. [Product positioning](../../product-positioning.md),
the README, release notes, badges, existing promotion records and verification
counts cannot reduce those obligations. If documents disagree in meaning, the
claim affected by that disagreement MUST NOT be used until it is resolved.

MUST, MUST NOT, SHOULD, SHOULD NOT and MAY follow RFC 2119 and RFC 8174.
**English is normative.**

## 2. Unit of assurance

The unit of a claim is **Q = (B, C, P, R, A, E, D)**.

| Element | Meaning |
| --- | --- |
| B | The actual distributed artifacts and their dependencies, including binaries, JS/WASM, packages and public entry points, identified by digest |
| C | Supported configurations and execution conditions, including features, cryptographic operation directions, providers, runtimes, storage, concurrency and recovery conditions, and time/input bounds |
| P | Applicable assurance profiles and roles such as server, client and RP |
| R | All normative requirements of the pinned specifications applicable to P and C, plus contract and public-API obligations |
| A | Audited assumptions, external dependency contracts and excluded boundaries |
| E | Target-bound evidence of satisfaction of R, implementation correspondence, formal proofs and security tests |
| D | The reviewed release decision, identifying its scope, decision makers, date, conclusion and disposition of remaining findings |

This is not an unconditional claim about the entire repository, product name,
a branch tip or every future release. Generalizing from one configuration to a
supported range requires evidence that proofs and tests cover that range and
that runtime controls prevent use outside it.

The available profiles are:

| Profile | Assured roles and outputs | Not automatically included |
| --- | --- | --- |
| `server-foundation-v1` | AS, OP and RS for its own OAuth-protected resources such as UserInfo; applicable obligations also cover server-side RP/brokering, Federation consumption, management, authentication and recovery paths in use | Independent SDKs, external RP code, public Federation OP capabilities, dynamic OP configurations incompatible with the current implicit-flow prohibition |
| `sdk-rp-node-v1` | Client/RP on Node, including its JS/WASM, declarations and package layout | Browser outputs, other language outputs, management UI |
| `sdk-rp-web-v1` | Client/RP in browsers, including its JS/WASM, declarations and package layout | Proof of the browser engine itself, arbitrary consuming applications, other language outputs |
| `sdk-management-v1` | Client implementation of published management API operations, including transport, authentication helpers, scopes, error handling and distributed outputs | Proof of server-side RBAC, complete management-UI rendering and interactions |

Optional features in use, public APIs, capabilities advertised in metadata and
features affecting shared state MUST enter R according to the contracts'
applicability rules. Missing proofs or matrix classifications alone MUST NOT
justify exclusion.

Applicability of OIDC Core section 15.2 depends on dynamically establishing
relationships with RPs without prior relationships; the mere presence of a DCR
API does not decide it. Where applicable, conflicts between mandatory response
types, grants or Request URI obligations and the current profile block
qualification until resolved in a separate versioned profile under the
[server contract](assurance-case/assurance-contract.md). A MUST deviation cannot
be treated as conformance. Management APIs are assessed according to their actual
authentication mechanisms, such as cookies or API keys, rather than uniformly
classified as OAuth resource servers.

## 3. Four distinct claims

### 3.1 Specification conformance

This claim means satisfying requirements applicable to the listed specification
editions, roles and supported capabilities, including error behavior, metadata,
mandatory algorithms and normative security requirements. No applicable MUST or
MUST NOT may remain unsatisfied. Permitted SHOULD deviations require review and
disclosure of their impact and specification-consistent justification.

This does not imply conformance to every OAuth/OIDC specification or feature.
Draft identifiers and revisions MUST be explicit; drafts MUST NOT be described
as published RFCs. OIDF or other certification is a separate claim and MUST NOT
be inferred from self-administered conformance tests.

### 3.2 Formal verification of implementation and internal state

This claim means that machine-checked proofs establish, under explicit assumptions
and bounds, that the target implementation satisfies the specifications,
invariants and state transitions required by the contract. The server requires
evidence for applicable G-01 through G-16; the SDK requires evidence for applicable
C-01 through C-18.

Scope includes input interpretation, authentication and authorization decisions,
state changes, concurrency, failure and recovery, project-owned cryptographic and
storage integration code, FFI, and SDK adapters and authentication processing.
Correspondence from proof targets to distributed binaries or generated JS/WASM
MUST be established.

Model-only proofs, differential tests, linkage traces, type checks, source scans,
and the existence of proof files or symbols do not establish this claim. Results
from bounded exploration cannot be generalized to an implementation accepting
inputs or executions beyond those bounds.

### 3.3 Security proofs in symbolic models

This claim means that the listed authentication, authority-separation, replay
prevention, secrecy and other properties hold for the target protocols and their
composition under an explicit adversary model. Evidence MUST show that the model
and proofs capture the relevant threats, including reachability of target
executions and verification failure when relevant defenses are removed.

A symbolic proof MUST NOT be represented as an implementation refinement proof
or a computational security proof for concrete cryptography. Each property's
target, assumptions, bounds and relationship to the implementation MUST be stated.

### 3.4 Security testing of distributed artifacts

This claim means that threat-relevant tests required by the contract have been
performed on the actual distributed artifacts and target configurations, and that
results and finding dispositions have been reviewed. Protocols, parsers/FFI,
authentication and management, concurrency and recovery, dependencies, and
transport, storage and distribution boundaries are assessed under applicable
G-17/G-18 and C-19/C-20.

SDK testing covers packaged and installed outputs, not only source code. Failures,
skips, coverage, tool/runtime versions and remaining findings MUST be disclosed.
No applicable assurance violation, unresolved Critical/High finding or omitted
mandatory test may remain.

"Security-tested" does not prove the absence of unknown vulnerabilities.
Identify who performed the work. Naming an external audit, penetration test or
certification requires evidence identifying the assessor, target, date, methods
and results.

## 4. Meaning of qualification

Qualification identifies applicable specifications, roles, artifacts,
configurations, proof domains and explicit external assumptions. It does not
permit arbitrary exclusion of unproved implementation code while claiming proof
of the whole implementation.

Permitted assumptions are limited to those allowed by the relevant contract.

| Assumption category | Required disclosure |
| --- | --- |
| Cryptographic assumptions | Computational hardness, failure events such as collisions, and the relationship between symbolic models and concrete cryptography, distinguished from correctness of concrete implementations |
| Entropy | OS/device quality and interface contracts; project-owned seeding, lengths, reuse prevention and error handling remain implementation obligations |
| External cryptographic implementations | Primitives, providers, versions, operation directions, key purposes and unverified properties |
| Toolchain | Trusted scope and versions of proof tools, extraction, compilation, linking and JS/WASM engines |
| External platforms | Concrete contracts and configurations for OS, transport, storage, time and browser isolation |
| Users and peers | Required behavior of applications, IdPs, RPs, ASs and RSs; project-owned acceptance decisions and integration code cannot be transferred into external assumptions |

Each assumption MUST record the guarantees depending on it, its precise meaning,
where it applies, the impact of violation and conditions enforceable at runtime.
Generic statements such as "trust the host" or "trust storage" are insufficient.
Unverified parts of external primitive implementations MUST NOT be described as
merely computational-hardness assumptions.

This statement does not itself assure arbitrary third-party IdPs, consuming
applications, UIs, external platforms, every cryptographic algorithm or every
language output. Labeling a component out of scope does not exempt its effects
on state or keys shared with assured components.

## 5. Required release assurance record

Public wording MUST identify the target release, applicable profiles and a
**reference to the release assurance record**. Short forms and badges must also
provide access to scope and assumptions. The record MUST have a fixed identifier
and digest and include the following:

| Record field | Required content |
| --- | --- |
| Statement identity | Revision of this specification, public wording used, release identifier, decision date and current validity state |
| Contract identity | Server/SDK contracts, normative documents and specification-register revisions and digests; archive location of adopted originals |
| Distributed artifacts | Digests of every artifact, package, public output and dependencies, retrieval locations and authenticity verification methods |
| Build correspondence | Relationship of sources, lockfiles, generation/extraction, compilers, settings and targets to distributed artifacts |
| Target configuration | Profiles, roles, enabled features, authentication methods, MFA availability and assurance levels, cryptographic algorithms/directions/providers, runtimes, storage, recovery, time and other conditions |
| Requirement inventory | Stable individual requirement IDs, original sections/anchors, roles, applicability conditions, dispositions, guarantee IDs and mappings to implementation/evidence; aggregate rows alone are insufficient |
| Formal evidence | Propositions, target code/models, assumptions, invariants/refinement relations, exploration bounds, results and tools, distinguishing implementation proofs from symbolic models |
| Test evidence | Target artifacts/configurations, methods, inputs, coverage, tools, results, failures, skips, findings and dispositions; external-service results must also identify their target |
| Assumptions and exceptions | Audited A, exclusions, permitted SHOULD deviations, interoperability conditions and consequences of violations or use outside scope |
| Composition evidence | Configuration, interface compatibility and composition evidence when multiple products/profiles are claimed as one foundation |
| Review decision | Digests of reviewed inputs, accountable decision makers, dates, conclusion and rationale; absence of unsatisfied mandatory obligations or blocking findings |
| Maintenance and correction | Supported versions, vulnerability reporting contacts, corrections, revocations and successor records, distinguishing historical decisions from current applicability |

If a public summary is insufficient to assess the basis, necessary evidence MUST
be supplied in a verifiable form. Keeping secrets or vulnerability details private
MUST NOT conceal scope, results, limitations or dispositions in a way that suggests
broader assurance. Signatures and hashes establish authenticity or identity; they
do not substitute for successful proofs or tests.

Each record MUST satisfy the data relationships, completeness review and decision
procedure in the evaluation rules. A contract register's `adoption_state` does not
establish release assurance. Release decisions and current validity states are
separate records. Their schemas, evaluator and validity-state registry remain
unimplemented; this revision does not establish them.

## 6. Activation, composition and maintenance

### 6.1 Activation conditions

Section 7 wording may be used only when all of the following hold:

1. B/C/P are fixed and R is completely enumerated at individual-requirement level.
2. Applicable guarantee obligations are satisfied, and A and its dependencies
   have been audited for adequacy.
3. Required formal evidence is established, including correspondence between
   implementation, models and distributed artifacts.
4. Mandatory security tests for B/C succeed, and dispositions of findings,
   failures and skips comply with the contract.
5. Review of the section 5 record is complete, with no unsatisfied obligations or
   blocking findings, and the publication decision has been approved.

Schema validation, the presence of evidence files, `verified`/`complete`/`ready`
labels, signed SBOMs and previous release results alone do not meet these
conditions. Automated evaluators MUST distinguish evaluated conditions from
unevaluated ones. Existing publication/promotion gates MUST NOT activate the new
assurance claim while they do not evaluate these conditions.

Separation of decision-maker roles, conflicts of interest, severity and remaining
findings follow the evaluation rules. AI review MUST NOT be treated as human
approval or an organizationally independent external audit.

### 6.2 Server and SDK composition

The server and SDK may be claimed independently. Claiming a combined foundation
requires both relevant contracts to be satisfied and evidence of compatible
issuer, client, redirect, algorithm, sender-binding, session, logout, time,
revocation-propagation, error and retry conditions.

Evidence on both sides does not automatically establish composition assurance.
Evidence for the actual combination and satisfaction of each side's assumptions
about the other are required. A ledger MUST map both sides' guarantees,
assumptions, configurations and evidence for IF-01 through IF-10 in the evaluation
rules and any additional applicable interfaces. Circular assumptions and equal
configuration strings alone do not discharge these obligations. Assurance of the
server's own RP behavior does not assure the independent SDK. Management-client
or management-UI assurance MUST NOT be added implicitly through combined wording.

### 6.3 Changes, corrections and revocation

Changes to specifications, APIs, contracts or applicability rules MUST record
versions and impact analyses. Changes to source, generated outputs, dependencies,
toolchains, configurations, providers or supported runtimes require updating
affected evidence and reassessing satisfaction of the same guarantees.

A confirmed defect or assumption violation overturning assurance requires
correction, suspension or revocation of affected claims and publication of
relevant security information and successor-release references. Distinguish the
passage of time from changes or new findings that invalidate evidence. Historical
records MUST NOT be reinterpreted as applying to current artifacts or overwritten
to erase earlier decisions.

Keep immutable assurance records separate from authenticated histories of current
status, and make both discoverable from the artifacts. State transitions,
authenticity and behavior when status cannot be verified follow the evaluation
rules.

## 7. Public wording after qualification

These are the finalized templates for qualified targets. Fill bracketed fields
from the established release assurance record. They are not wording for releases
that have not satisfied the contract.

### 7.1 Server

> Aegaeon [release] is an assumption-qualified formally verified and security-tested
> OAuth/OIDC foundation for [profiles and configuration]. The release assurance
> record [reference] identifies the applicable specification requirements,
> implementation and state-transition guarantees, symbolic security properties,
> distributed artifacts, successful security tests, assumptions and bounds.

### 7.2 Client/RP SDK

> Aegaeon SDK [release] is an assumption-qualified formally verified and
> security-tested OAuth/OIDC client and RP implementation for [profiles and
> configuration]. The release assurance record [reference] identifies the
> applicable requirements, implementation and state-transition guarantees,
> symbolic security properties, correspondence to the distributed JavaScript/WASM
> packages, successful security tests, assumptions and bounds.

### 7.3 Management client

> Aegaeon Management Client [release] is an assumption-qualified formally verified
> and security-tested implementation of [management API profile and configuration].
> The release assurance record [reference] identifies the supported client
> operations, implementation guarantees, distributed packages, successful security
> tests, server/host assumptions and bounds.

### 7.4 Combined server/SDK foundation

> Aegaeon [server/SDK release combination] is an assumption-qualified formally
> verified and security-tested OAuth/OIDC foundation for [profiles and configuration].
> Both assurance contracts and their composition requirements are satisfied for
> the identified artifacts. The release assurance record [reference] states the
> specification, implementation, state and symbolic security guarantees, successful
> security tests, interface conditions, assumptions and bounds.

### 7.5 Short form

> Formally verified and security-tested under the stated assumptions and bounds
> for [release/profile]; scope, assumptions, bounds, and evidence: [release assurance record].

Assumptions and bounds MUST NOT be removed to create an unconditional claim, nor
may scope be omitted without the record reference. If a badge and surrounding
text have different targets, the badge MUST identify its own target explicitly.

## 8. Public wording before qualification

Use the following wording at present:

> Aegaeon is an OAuth/OIDC server and SDK with formal-verification assets and
> security-test tooling. Its server and SDK assurance contracts and public
> statement specification are defined; work to satisfy them for target releases
> is ongoing. Release assurance under this specification is not currently established.

Descriptions of individual component results must identify the target code/model,
proposition, assumptions, bounds, assessment date and relationship to runtime
implementation. Verified-core results MUST NOT be presented as proof of the
entire SDK. Historical `verified`, promoted or internally reviewed labels remain
limited to their original targets and evidence.

Current outstanding work is recorded in the [server](assurance-case/contract-status.md)
and [SDK](sdk-assurance/contract-status.md) qualification status documents. Completing
this statement specification MUST NOT be treated as completing that work.

## 9. Relationship to the OSS license

This specification defines the scope and meaning of evidence-based technical
assurance. It does not create promises of indemnification, uptime or support
response times. OSS use and redistribution are governed by the
[Apache License 2.0](../../../LICENSE); any separate commercial warranty,
indemnification or support terms must identify their own agreement. The accuracy
of technical claims and the conditions of the license MUST be explained separately.
