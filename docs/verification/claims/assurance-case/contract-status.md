# Server Assurance Contract Status

Last updated: 2026-09-07

Document revision: **2026-09-07-r3**.

Status: snapshot

Owner: Verification / Security / Release Engineering

Audience: maintainers, verification reviewers, release managers

> **Status note (2026-09-07):** Contract v1 is specified. The foundation claim is
> **inactive**; no release artifact is attested by this document. Formal tools,
> the security suite, and the release build were not rerun to adopt the contract.

## Current posture

The [contract](assurance-contract.md) defines the obligations to discharge.
The [standards baseline](standards-baseline.md) fixes editions and applicability.
The compliance matrix and existing assumption/proof registers remain evidence
inventories. Their status labels do not activate the foundation claim.

Revision **2026-09-07-r2** added the [evaluation rules](../assurance-evaluation.md)
and makes the dynamic-OP incompatibility explicit. Review dispositions have not
closed the implementation, proof or release work. An AI-assisted design review
is not organizationally independent third-party security testing.
The r3 revision pins each companion document revision, names critical Discovery
defaults, and specifies evaluator provenance and reviewer selection records.
Suitable human reviewers still need to be selected and engaged before activation;
neither this status snapshot nor an AI design review supplies that approval.

Safe current wording is: **Aegaeon is an OAuth/OIDC server with formal-verification
assets and security-test tooling; completion of its published server assurance
contract is pending.** Individual component results may be described with their
exact model, bounds, assumptions, runtime relationship, and dated evidence.

## Activation backlog

| Work item | Guarantees | Required completion evidence |
| --- | --- | --- |
| Requirement inventory | All | Every role-applicable normative requirement from the pinned baseline has a stable clause ID, trigger/disposition and evidence; reconcile OAuth 2.1 draft-16 and expand OIDC roll-ups |
| Dynamic OP profile conflict | G-03, G-06, G-15, G-16 | Resolve Core 15.2 / Discovery 3 mandatory response types, implicit grant and Request URI duties in a separate versioned profile; current foundation configurations must prove any pre-configured-relationship restriction |
| Dependency and errata review | All | Complete source-section/incorporation dispositions, pin applicable inherited clauses and record errata decisions; current pins are not a completed transitive audit |
| Axiom soundness | G-08, G-11 and dependents | Remove concrete hash injectivity and vacuous/misnamed crypto assumptions; audit dependency closure and rerun affected proofs |
| Adversarial model adequacy | G-03 through G-09, G-12, G-16 | Replay/authentication models permit the relevant attacker actions, demonstrate reachability, fail under defense mutations, and cover composition |
| Implementation correspondence | G-01 through G-16 | Actual runtime code, extraction/FFI/adapters, state effects and models have a checked refinement relationship; separate Kani substitutes from production proofs |
| Durable state and recovery | G-04 through G-07, G-10 through G-13 | Transaction semantics, time, partial failure, concurrency, lost acknowledgements, failover and restoration preserve the contract |
| Authentication and management authority | G-01, G-03, G-09 through G-11 | Actual authentication evidence drives ACR/AMR; configuration/key/management changes cannot bypass obligations |
| Release correspondence | G-17 | A fixed build/configuration maps to proof/test results and signed distributed artifacts; no unassessed fallback build |
| Evaluation implementation and governance | G-17, G-18 | Separate release-record schemas, approved requirement inventory, result/provenance evaluator, human role-separated approvals and authenticated current-status history implement the evaluation rules |
| Counterparty and combined assurance | G-15, G-16 | Populate IF-01 through IF-10 and additional applicable interfaces with paired guarantees/assumptions and checked composition evidence |
| Security-test completion | G-18 | Threat-directed tests on that release, reviewed findings/skips, and a decision checking result success rather than evidence-file presence |
| Public evidence reconciliation | G-15, G-17, G-18 | Current product text and security/conformance reports cite supported scope and actual evidence; historical unsupported assertions are corrected before reuse |

The current public release workflow's tarball build uses `cargo build --release
--all` without explicit `verified-claim`, separately from the Nix container build.
Its audit path can issue a warning rather than block. These are release-assurance
blockers unless every advertised artifact has the required build/result binding
and failing required checks prevent activation. Prefer packaging the same reviewed
build outputs across distribution formats. Nix use alone is not proof, and another
build system could qualify with equivalent evidence. Runtime/toolchain selection
must be established from the actual build, not inferred from an action's name.

Ordinary archive validation is not a successful-release decision. The workflow
was not repaired by these contract clarifications. The March 2026 proof/security snapshots and beta
OIDF results cannot attest a later binary or the new baseline.

## Completion rule

Update this snapshot only from reviewed evidence. Contract-integrity validation,
matrix reference validation, or documentation lint success means the documents
are consistent, not that guarantees are proved. Activation requires a release
record satisfying the contract's complete decision criteria. Adjacent SDK,
enterprise, certification, and admin-UI gates remain independent and cannot
activate this foundation claim by implication.
