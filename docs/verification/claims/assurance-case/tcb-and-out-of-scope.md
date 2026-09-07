# Formal Verification TCB and Out-of-Scope Boundaries

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification / Security

Audience: verification reviewers, maintainers

The [server assurance contract](assurance-contract.md) controls the target
boundary. This document distinguishes permitted external trust from own-code
obligations. [Contract status](contract-status.md) lists current closure gaps;
those gaps do not become exclusions by appearing in a TCB inventory.

## 2. Trusted Computing Base

A release must identify exact versions/configurations and the assumed interface
property, not just a dependency name. The [component inventory](../../../security/tcb-inventory.md)
and [runtime register](../assumptions/runtime-contract-register.md) are starting
points to reconcile with the actual artifact.

### 2.1 Verification and Compilation

F*, Z3, Tamarin, Kani/CBMC, EverParse, KaRaMeL, Rust/C compilers, linkers and the
build system contribute soundness, extraction, compilation or custody assumptions.
Pinning makes these dependencies identifiable; it does not prove their correctness.
Proof selection, substitutions, bounds, generated outputs and actual linkage
must be recorded under G-17.

### 2.2 Cryptography and Entropy

Separate primitive functional correctness, computational hardness, key generation,
OS/device entropy quality, and application use. HACL*/EverCrypt results apply to
the precise verified/linked paths. aws-lc/ring/RustCrypto or KMS provider correctness
may remain external trust dependencies; lineage or a provider brand is not a
validation of this binary, configuration or integration.

The promoted RS256 protocol slices do not establish the provider implementation's
correctness. Current provider/direction details remain in the crypto allowlist.
Own dispatch, seed handling, DRBG state, key-purpose binding and error handling
are obligations, even where a primitive or entropy source is external.

### 2.3 Platform and Storage

Hardware, OS, HTTP/TLS/async libraries, external database engines, clock and
network services may be assumed to meet explicit interface contracts. Specify
isolation, durability, time/skew, failover and recovery assumptions rather than
assuming an unspecified store is atomic and permanent.

Own SQL/Lua operations, FFI, serialization, HTTP security middleware, proxy-identity
validation, callback interpretation, transaction orchestration and configuration
admission are G-01 through G-16 obligations. A database's ACID claim does not
prove own SQL is correct; exclusive Lua execution does not imply rollback on
script errors; memory safety does not imply protocol-level concurrency safety.

## 3. Exclusions and Their Limits

| Boundary | Permitted exclusion | Remaining server obligation |
| --- | --- | --- |
| External RP/SDK | Code running in an independently deployed client | Correct AS/OP behavior and explicit client assumptions; own upstream RP checks when brokering |
| Browser/UI | Rendering, browser implementation and extensions | Server login/session/CSRF, management authorization and authenticated state changes |
| Third-party identity provider | Correctness and compromise of the external provider under the stated threat model | Trusted issuer/key selection, token validation, subject/freshness/assurance binding and compromise consequences |
| External storage engine | Engine implementation meeting the declared interface | Adapter semantics, state transitions, retention, supported failover/restore and fail-closed admission |
| Misconfiguration | Operation outside the published, enforced release envelope | Reject invalid startup/dynamic settings; preserve guarantees for every admitted configuration |
| Unsupported features | Explicitly disabled and unadvertised capabilities | Reject requests and establish non-interference with shared keys, state and authorization |
| Physical/microarchitectural leakage | Channels outside the stated formal model | Identify tested constant-time paths and limitations; do not describe dudect as a universal proof |
| Certification | Named standards/program certification not obtained | Truthful conformance/test evidence and no certification wording without the separate gate |

Current implementation gaps belong in the activation backlog. The contract does
not mandate proving the external platform from first principles, and it does
not permit moving the server's own security decisions into an unspecified TCB.
