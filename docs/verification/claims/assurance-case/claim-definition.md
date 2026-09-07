# Formal Verification Claim Definition

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

## Authority

The [public assurance statement specification](../assurance-statement.md) defines
the release claim's meaning and mandatory public record for server and SDK
profiles. This document retains the server-specific evidence interpretation.

The [server assurance contract](assurance-contract.md) defines the fixed target
obligations. The [standards baseline](standards-baseline.md) fixes specifications
and applicability. This document defines how evidence supports that contract.
[Contract status](contract-status.md) records that the foundation claim is
inactive. Historical slice promotions and matrix labels are not release activation.

## 0. Formal Claim Definition

### 0.1 System Definition

A claimed system is a particular artifact B, release configuration C, and profile
P = `server-foundation-v1`, identified by source, lockfile, toolchain/target,
features, generated-code and artifact digests, providers, policy and storage
parameters. The intended release path uses the pinned Nix build. The current
existence of `nix build .#server` is not evidence that its output satisfies P.

### 0.2 Claim Scope

The contract defines R(C), the role-applicable normative requirements of the
pinned specifications, plus its G-01 through G-18 guarantee obligations. Scope
is determined before proof completion and includes all required and triggered
capabilities. Unproved own-code transitions remain open obligations.

The legacy evidence selector remains useful for reports:

```text
VerifiedReqs = { r in compliance-matrix
              | r.status = verified
              and r has a formal proof reference }
```

`VerifiedReqs` is an evidence inventory, not R(C), a release gate, or the
contract's completion denominator. A requirement does not leave R(C) when it
has no proof, no matrix row, or a status other than `verified`. Existing OIDC
roll-ups require clause-level expansion before contract activation.

### 0.3 Claim Statement (Assumption-Qualified)

After activation for B/C/P, the permitted statement is that the specified
implementation invariants/refinement obligations and symbolic protocol
properties have been formally checked under disclosed assumptions and bounds,
and B/C has passed the required security tests with findings resolved under the
contract. This does not assert computational security of real cryptography,
correctness of every external dependency, or absence of unknown vulnerabilities.

The following evidence meanings MUST remain separate:

| Evidence | Meaning and necessary qualification |
| --- | --- |
| F* | The named property holds for the specified program/model under audited premises; connection to runtime requires refinement/extraction evidence |
| Low*/HACL* | The checked implementation property applies only to the extracted/linked path, with compilation, linkage and integration contracts disclosed |
| EverParse | Generated parser properties relative to the exact grammar; schema validity does not alone establish all protocol semantics or runtime invocation |
| Tamarin | The property holds in the stated adversarial symbolic model; adequacy, reachability and composition must be assessed |
| Kani | The selected code/model satisfies the property within the checked bounds; substituted models and production code must be distinguished |
| Runtime, fuzz, sanitizer, dudect and conformance tests | Empirical results for identified executions/configurations; they do not replace formal implementation correspondence |

### 0.4 Configuration Conditions

The contract requires a release configuration with explicit capabilities,
algorithm/provider directions, bounds, lifetimes, replay domain and retention,
time tolerance, durability and recovery semantics. PostgreSQL-backed active
policy remains the current runtime configuration authority; environment-variable
shortcuts do not alter the contract. Startup and dynamic changes must preserve
its guarantees. Invalid/unsupported changes must fail closed.

The [crypto allowlist](../crypto-allowlist.md) and
[runtime contracts](../assumptions/runtime-contract-register.md) inventory the
current implementation. Promoted RS256 slices still depend on the unverified
provider's correctness; they are not proof of RSA implementation correctness.
Mandatory OP algorithm support cannot be excluded solely for lacking a proof.

### 0.5 Implementation Refinement Scope

For contract activation, the relevant raw-input interpretation, authentication,
policy decisions, state transitions, own storage/crypto adapters, FFI and response
construction require a checked relationship to the specifications. A handwritten
oracle, HTTP guard, file/symbol reference or refinement trace is supporting
evidence, not a refinement proof. Current extraction and runtime linkage are
recorded in the runbooks; their existence does not close the activation backlog.

### 0.6 Out of Scope (Non-Goals)

External primitive, entropy, compiler, OS, network and storage implementations
may enter through precise disclosed trust contracts. Own-code use of those
interfaces remains a verification obligation. Cryptographic hardness and symbolic
to computational security are not proved by listing assumptions. Unsupported
features require evidence of rejection and non-interference with shared state.

Standalone client/SDK behavior has its own
[SDK assurance contract](../sdk-assurance/assurance-contract.md). Browser rendering
and named certifications need separate assurance. Server-side upstream RP,
authentication/session management,
control-plane authorization and recovery remain in scope when they influence
foundation guarantees. A generic exclusion for misconfiguration or middleware
cannot discharge G-02, G-09, G-10 or G-13.

## Evidence freshness and release decision

The March 2026 verification/security reports and beta conformance summaries are
historical snapshots. An activation record must bind the pinned contract and
R(C) inventory to B/C, audited assumptions, successful formal results and security
tests, reviewed exceptions, and an approved decision. A changed artifact or
configuration requires impact review and refreshed affected evidence.

The ordinary evidence-manifest validator checks archive structure. A successful
archive validation, signed SBOM, or successful reference check cannot establish
this release decision. The implementation of that complete decision gate is
tracked in [contract status](contract-status.md).
