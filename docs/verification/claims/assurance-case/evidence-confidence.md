# Formal Verification Evidence Assessment

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification / Security

Audience: verification reviewers, maintainers

## 5. Assessment Rule

The [server assurance contract](assurance-contract.md) requires evidence by
obligation and release. The [foundation claim is inactive](contract-status.md).
This document replaces the previous blanket confidence labels and stale counts;
no new proof or security execution is attested by that documentation change.

| Evidence layer | Assessment required before activation |
| --- | --- |
| F* specifications | Named nontrivial properties, valid premises, source/version and successful selected runs |
| Symbolic protocol models | Relevant attacker actions, reachability, defense mutations, composition and completed lemmas |
| Extracted code and FFI | Correspondence to the actual linked path, ownership/encoding/bounds and adapter correctness |
| Kani | Production code versus substituted model, checked input/unwinding bounds and selected successful harnesses |
| Storage and runtime orchestration | Legal concurrent transitions, partial-failure semantics, durability, time and recovery |
| Crypto/other external dependencies | Exact provider and interface assumptions, tested integration and dependent guarantees |
| Security tests | Identified artifact/configuration, threat coverage, executed results and reviewed findings/skips |
| Distribution | Build/proof/test correspondence, evidence integrity and an approved release-specific decision |

The [claim index](../claim-index.md) and runbooks locate existing assets. Their
counts measure an inventory; they do not establish model adequacy, standards
completeness or implementation refinement. Confidence in a release must follow
from the contract's closed obligations and evidence, not a total lemma/module count.
