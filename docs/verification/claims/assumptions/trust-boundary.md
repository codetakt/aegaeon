# Conditional assurance and external trust

Last updated: 2026-09-15

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

Aegaeon's proof scope covers the stated properties of its models and the
implementation boundaries for which correspondence evidence is supplied.
The guarantees are conditional on explicit external contracts. Aegaeon does
not prove the soundness of its verification tools, the security of external
cryptographic primitives, or the correctness of every external runtime system.

An external contract identifies what a dependency must provide. It does not
turn that dependency's implementation into an Aegaeon theorem. Aegaeon remains
responsible for satisfying the dependency's calling conditions and showing that
its own code uses the result in the way required by the claimed property.

## What must be stated

For each premise used by a claim, retain:

- The premise identifier and exact contract, including failure behavior,
  input domain and relevant time, resource or attacker bounds.
- The applicable source revision, artifact or executable digest, build options
  and deployment conditions. A dependency name alone does not fix the subject.
- The claims that depend on it and the evidence relating those claims to the
  actual call, imported module or linked artifact.
- The basis for relying on it, its limitations and the recorded review status.
  Source identity, successful execution and acceptance are distinct facts.

`spec/assumption-register.json` records named premises and their status. The
[assumption graph](../../fstar/assumption-graph.md) reconstructs the effective
dependencies for a fixed proof run, including imported and lax-loaded modules.
The graph's consistency check is not a proof that its premises are true.

## Boundaries and retained Aegaeon obligations

| Boundary | External premise | Aegaeon obligation |
| --- | --- | --- |
| F*, SMT solver, Kani and symbolic tools | The fixed toolchain implements the verification semantics on which the result relies. | Record actual tools, options, inputs and outputs; reject incomplete results; state each theorem's domain. |
| Cryptographic provider | The selected primitive implementation meets its specified contract; computational security holds under the stated key, parameter and attacker assumptions. | Bind the selected provider and ABI, meet buffer and ownership conditions, preserve results and error meaning, and retain explicit bad-event conditions. |
| Storage and host callbacks | The specified deployment provides its documented command, atomicity, retention and time behavior. | Prove the application's key construction, arguments, decoding, command ordering, CAS, failure/retry behavior and recovery against those semantics. |
| Clock, entropy, operating system and build/link environment | The explicitly scoped platform behavior and deployment configuration hold. | Preserve units and bounds, bind the compiled and linked artifact, and reject unsupported configurations where the contract requires it. |

Treating Redis command semantics as an external premise does not establish the
correctness of an Aegaeon Lua script. Trusting a cryptographic provider does not
prove an Aegaeon wrapper's postcondition. A local placeholder, lax-loaded local
model or unproved implementation adapter remains an Aegaeon obligation even
when it depends on an external component.

## Disclosure and qualification

Fixing this boundary is a scope decision. It does not require expanding Aegaeon
into a project to prove the external tools or providers themselves. It also does
not automatically attest every recorded premise or activate a guarantee.
The register's `specified-not-attested` status means that a premise has been
stated, while the qualification required by the assurance contract is incomplete.
Conditional theorem results and that incomplete qualification can coexist.

The [current register](current-register.md) and
[contract status](../assurance-case/contract-status.md) remain authoritative for
the recorded state. Reviews and tests may supply evidence within their stated
scope; their success does not substitute for missing production correspondence
or change the status of unrelated premises.
