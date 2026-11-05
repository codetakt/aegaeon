# Organizations recovery implementation workplan

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, reviewers

The user authorized implementation and directly affected checks until completion
or a necessary human decision. Both policy decisions are adopted; no answer is
pending. PR #295 remains Draft. Publication, hosted CI, AWS, queue admission and
merge are outside this local work.

The original REC items below retain their completed scope. Subsequently reported
CI and operational defects are tracked separately in
[OPS-01–08](operational-followup.md); they remain open until their own acceptance
checks pass. Signed publication and CI were later authorized; Draft/no-merge and
provider/measurement boundaries remain.

## Work items

| ID | Status | Result / closure evidence |
| --- | --- | --- |
| REC-T01 | Done | Adopted DB/application responsibility rules; historical durable credentials are selected state |
| REC-T02 | Done | Threat assessment and Tamarin/Kani/F\* allocation; concrete defects remain this PR's responsibility |
| REC-T03 | Done | Pre-admission refusal/cancellation cannot poison the replacement runtime; saturation and subsequent admission checked |
| REC-T04 | Done | All security-state families classified; durable PostgreSQL decisions and disposable projections selected |
| REC-T05 | Done | Production stores migrated; atomic code/OIDC/token publication, positive token authority and durable replay/budgets verified in affected SQL/HTTP checks |
| REC-T06 | Done | Lifecycle-only generation selection, physical-session fencing, fresh namespaces and same-generation restart behavior implemented |
| REC-T07 | Done | Independent control, paired-store seals and generic mutation journal retired from production; historical fixtures explicitly isolated |
| REC-T08 | Done | Operator-selected activation, audit-tail/gap and external-effect runbook; actual maintenance and activation refusal checked |
| REC-T09 | Done | One migration over 24 unchanged published files; populated upgrade, rollback/retry, fresh/schema/dump equivalence; no production Redis requirement |
| REC-T10 | Done | Final lifecycle nine and seven-route HTTP checks, actual distribution, scoped models and source binding pass; failures retained |
| REC-T11 | Done | SQL reserve, response budget and bulk/cleanup bounds implemented and checked; 10k HTTP/s/p99 200 ms remains unmeasured |
| REC-T12 | Done | Operator/docs and Task 1b/3 handoff complete; full-PR hooks pass; final history has one cohesive implementation commit and one validation/status commit |

## Adopted decisions

REC-D01 selects historical durable passwords, client secrets, keys, revocations
and ownership. It does not replay audit into application state or require blanket
credential replacement. REC-D02 preserves single-use for external signed proofs:
JWT assertions/JAR defer for their acceptance horizon; fresh generation/role
nonces allow DPoP to resume. Ordinary restart preserves the same deadlines.

An empty database may be a restored historical database. Skipping the wait needs
an explicit operator assertion of first-ever installation, no selected predecessor
and no Environment. Application inspection alone cannot establish external history.
Operational clock bounds and old-writer exclusion are explicit preconditions.

## Evidence and handoffs

The [final validation record](recovery-validation.md) closes the local work items.
No policy decision is pending; publication and release admission remain separate.

The affected checks cover real PostgreSQL transaction/lock behavior, exact HTTP
responses, current packaged startup and maintenance, bounded resource ownership,
production arithmetic and finite protocol models. Increment records under the
linked storage documents retain source-specific results and failures. Inventories
overlap and must not be combined into one full-suite total. No current full-suite,
provider, performance or product-assurance result is claimed.

[REC-H01–05](recovery-security.md#handoff-contract) specify Task 1b standards mapping
and Task 3 refinement/composition, external custody/provider qualification and
qualified measurement. They do not reassign known functional/security defects.
The frozen 8,805-obligation baseline and unrelated paused campaigns remain intact.

## Local delivery boundary

The implementation checkout is `aegaeon-organizations-integration-20261102`.
Its starting head is `aa44e360d36ff7e91b65634f284e8eed9c853035`; the pre-PR
base is `46eaed0497fc2005cc10dc483803c108df68865b`. Original history and failure
records are preserved privately before local history reconstruction. The final
migration supports the published base to the final PR state, without retaining
trial schemas or fixup commits as compatibility requirements.

Publication requires the designated signatures and normal candidate CI/review.
The temporary exception permits unsigned local preparation only, with pending
re-signing and tree comparison recorded. No unsigned publication is authorized.

## References

- [Responsibility rules](recovery-responsibilities.md)
- [Threats, verification and handoffs](recovery-security.md)
- [Current implementation status](implementation-status.md)
- [Migration and commit structure](migration-composition.md)
- [Restore runbook](restore-runbook.md)
- [Resource and performance design](recovery-performance.md)
