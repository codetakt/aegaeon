# Formal Verification Scope And Proof Quality

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

The [server assurance contract](assurance-contract.md) determines obligations.
This document describes evidence classes and the legacy matrix vocabulary;
[contract status](contract-status.md) records that foundation activation is pending.
No inventory count or reference check establishes contract completion.

## 1. Verification Scope

### 1.1 F\* — Specification and Implementation Properties

A result applies to its named program/model, theorem, preconditions and audited
axioms. Specification-level properties require a checked relationship to the
runtime. Extracted Low\* and HACL\* evidence additionally needs the exact linked
code, compiler assumptions, integration contracts and build configuration.

Zero `admit` counts do not establish the adequacy of the theorem or soundness of
its assumptions. Concrete hash injectivity is not computational collision
resistance, and an `ensures True` conclusion does not express unforgeability.
The existing assumption inventory requires the audit in the contract backlog.

### 1.2 Tamarin — Symbolic Protocol Security

Results apply to the selected adversarial model and lemma set. Record selected,
completed and successful lemmas separately from declarations. Model adequacy
requires relevant attacker actions, reachability, composition, and defense
mutation checks. A restriction that assumes the desired replay property cannot
serve as evidence that the implementation enforces it. Computational security of
real cryptography requires additional justification beyond a symbolic result.

### 1.3 Kani — Bounded Code or Model Evidence

Record the selected harness, compiled function paths, model substitutions, input
bounds and successful unwinding checks. Production-code checks and separate
`cfg(kani)` models have different meanings. A model's success establishes
production behavior only with a justified abstraction/refinement relationship.
Runtime inputs must stay within the proved domain for a bounded result to cover
all supported executions. Counts of `#[kani::proof]` are declaration counts.

### 1.4 EverParse — Grammar and Runtime Boundaries

Evidence applies to the pinned schema/generated parser and its checked
properties. Parser memory safety, grammar acceptance, encoding correspondence,
protocol semantics and actual runtime invocation are distinct obligations.
Compiled but uncalled validators do not establish request validation.

### 1.5 Assumption-Qualified Verification

The [F\* inventory](../assumptions/current-register.md) and
[runtime inventory](../assumptions/runtime-contract-register.md) identify
premises to audit. The contract separates hardness, entropy quality, primitive
implementation, external platform/toolchain behavior, and own-code obligations.
A reference to either register does not certify all its current assumptions.

For release activation, each premise must identify its meaning, provider and
configuration, dependent guarantees, and failure impact. All required formal
results must be fresh for the target. Different tools do not automatically prove
one another's models or the composition of independently verified components.

### 1.6 Proof Quality Classification

The matrix tooling classifies proof blocks along two inventory dimensions. These
are reference categories, not a semantic proof-validity or release decision.

**Quality**, from `proof[].type`:

- **Formal:** `fstar`, `tamarin`, `kani`, `everparse`, `lowstar`, `hacl`.
- **Empirical:** `dudect`, a statistical test under stated parameters.
- **Unknown/auxiliary:** `policy`, `plan`, `code_review`, `property_test`,
  `rust_test`, `unit_test`, and other supporting entries. The legacy name
  `unknown` does not mean runtime tests lack empirical value; those entries
  simply do not constitute formal proof references in this classifier.

**Strength**, from the reference fields:

- **Lemma:** a named `lemma`/`harness`, or `spec` for EverParse.
- **Refinement:** a `refinement` field referencing a type-level constraint.
- **Semantic:** another property description, such as an `invariant` field.

A field named `refinement` is not by itself a proof that a whole runtime refines
a protocol specification. Every formal block on a `verified` matrix row must be
grounded by `python3 scripts/validation/verify_verified_reqs.py --strict` and
must not cite an F\* `toy-stub`. Grounding checks references; the contract requires
additional semantic, execution and integration evidence.

#### Refinement Trace

Existing trace kinds record connections:

- `oracle`: references a specification function, runtime symbol and differential
  test. The current oracle may be handwritten; it is not necessarily extracted
  from or proved equivalent to F\*.
- `structural`: references a type/parser/artifact correspondence.
- `guard`: references an HTTP-boundary rejection and test.
- `exempt`: records why a direct function-level correspondence is not asserted.

A complete trace inventory is connection coverage. None of these categories,
including `exempt`, independently discharges implementation refinement or removes
an applicable contract requirement. Trace coverage and implementation closure
must be reported separately rather than using an ambiguous common level number.

An empirical-only matrix entry uses `implemented`, not `verified`. A formal
reference is necessary for `verified` under existing matrix rules, but is not
sufficient for foundation activation. The generated
[claim index](../claim-index.md) reports the inventory without selecting the
contract's obligations.

### 1.7 MUST-Level Coverage

The evidence denominator for a release is R(C): every applicable clause in the
pinned baseline, independently of existing row status. Current matrix MUST/MUST
NOT counts measure indexed rows, not every normative requirement in an RFC or
OIDC specification. Missing, partial, and implemented-only obligations remain
open until discharged.

In particular, the ten `openid_core` entries are roll-ups. They cannot establish
individual coverage of ID Token, UserInfo, nonce/azp, auth_time/max_age, acr/amr,
and other role-specific clauses. The contract requires clause-level extraction
and reconciliation with the pinned editions before activation.
