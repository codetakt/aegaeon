# Assurance Evaluation Rules

Last updated: 2026-09-07

Document revision: **2026-09-07-r3**.

Status: current implementation baseline

Owner: Verification / Security / Release Engineering

Audience: contract reviewers, evidence producers, release decision makers

## Authority and implementation status

Evaluation specification: **aegaeon-assurance-evaluation-v1**. Its revision is
identified by the Document revision declaration above. This is a normative companion to the
[public statement](assurance-statement.md), [server contract](assurance-case/assurance-contract.md),
and [SDK contract](sdk-assurance/assurance-contract.md). MUST and related keywords
have their RFC 2119 / RFC 8174 meanings.

These rules define the required decision model. The release-record schemas,
closure evaluator, authenticated status registry, and release-specific populated
inventories are **not implemented by adopting this document**. Both release claims
remain inactive. Existing contract-integrity validators do not evaluate these rules.

An obligation register and a release attestation are different objects.
`adoption_state: specified-not-attested` MUST remain fixed in the server/SDK
obligation registers. An active release decision belongs in a separate record;
changing a contract's status field cannot discharge its obligations.

## Required records and relationships

A release assurance record MUST bind Q = (B, C, P, R, A, E, D) to immutable,
content-addressed records with the following relationships. A prose summary is
not a substitute for the required structured records and referential checks.

| Record | Required content and relationship |
| --- | --- |
| Contract snapshot | Statement, contracts, evaluation rules, registers and every adopted source, each with revision and digest |
| Configuration and output inventory | Every artifact, export, dependency, runtime, provider, role, feature, state/recovery bound and supported authentication method; producing build inputs and digests |
| Requirement inventory | Stable requirement ID; source digest, section/anchor and text; normative strength; role and trigger; applicable disposition; guarantee IDs; implementation surfaces; evidence IDs |
| Source and dependency review | Each source's reviewed sections, normative incorporations and informative guidance, dependency dispositions, errata decisions and reviewed edition; completeness judgment and reviewer |
| Assumption inventory | Stable ID, exact predicate, provider/version/configuration, dependent requirements/properties, owner, enforcement and violation consequences |
| Proof/property inventory | Stable property ID, precise proposition, program/model digests, refinement relation or invariant, assumptions, domains, tool versions, checked result and adequacy evidence |
| Security plan and results | Stable test IDs, threat/requirement links, method, exact target, input/runtime domain, pass/fail criteria fixed before execution, actual result, findings and deviations |
| Composition inventory | Interface IDs as below; paired guarantee/assumption predicates, both participants' digests, compatibility evidence and disposition |
| Evaluation run | Evaluator source/build identity and digest, version, rules/plugins/configuration and execution environment; run ID, invocation, start/end times; immutable input-manifest digest; output/report digests, exit status, evaluated/unevaluated conditions, reasons and authenticated producer provenance |
| Findings and decision | Findings linked to violated obligations; severity reasoning and changes; remediation/retest results; reviewer identity, roles, conflicts, decision, date and exact reviewed digests |
| Current-status entry | Immutable record ID/digest, artifact digests, ordered authenticated status events, successor/reason, publication location and current applicability |

Each obligation register MUST pin the revisions of its contract, standards
baseline, status snapshot, public statement and evaluation rules separately in
`document_revisions`. Every referenced document declares exactly one
`Document revision` metadata line before its `Status` metadata. `contract_revision` equals the contract
document's revision; the other documents may be revised independently with an
explicitly reviewed combination. Historical revision references in prose are not
current metadata. The integrity checker verifies these declarations and paths;
semantic compatibility and the release's exact byte digests remain review duties.

Requirement strength, vulnerability severity and tracking category MUST be separate
fields. Existing matrix `requirement` values such as `HIGH` or `TRACKING` are not
normative strengths. Group-level `guarantee_ids` are minimum cross-references,
not exhaustive applicability lists. An unlisted applicable guarantee still applies.

The requirement inventory MUST be reviewed against every applicable source section,
including mandatory behavior expressed without uppercase keywords. Keyword extraction
can assist; neither keyword counts nor the existing matrix establish completeness.
Each source section needs a disposition, including sections with no resulting
implementation obligation. Stable IDs MUST survive editorial movement through
explicit migration mappings rather than silently changing their meaning.

Referenced documents do not all become whole-product obligations. Each incorporation
needs its source clause, inherited role/trigger, adopted edition and applicable
meaning. Required incorporated clauses MUST have pinned original bytes and their
own dispositions, recursively. Informative guidance selected as a project obligation
MUST be identified as such. External primitive assumptions do not erase the
software's integration requirements. Unreviewed dependencies block completeness.

For RFCs, enumerate relevant published errata, their official status at review,
adoption/rejection/defer decisions and reasons; an unresolved correction affecting
a claimed guarantee blocks activation. A verified erratum or newer RFC/draft is not
an automatic overlay. Review replacements and their semantic impact explicitly;
claiming a fixed edition does not require silently following subsequent editions.

## Evaluation and approval

The evaluator MUST report at least `invalid`, `incomplete`, `blocked`, or
`eligible-for-review`, with a reason and obligation IDs. `eligible-for-review`
is not an active claim. Unknown, unexecuted, unsupported or unreviewed checks
MUST NOT be converted to success. Every required evaluation condition must have
a recorded machine result or an explicit, scoped human judgment.

The decision sequence is:

1. Validate record types, required fields, identities, digests and unique IDs.
2. Check references, output/configuration closure, applicability and the independently
   reviewed completeness of requirements, dependencies, exports and security plans.
3. Match each applicable obligation to its required evidence kind. Require successful
   proof/test outcomes on the specified inputs and enforce every domain bound.
4. Verify that current build inputs, dependency/provider versions, artifacts and
   configuration match the evidence. Unchanged evidence can be reused only with
   an explicit dependency/impact justification; age alone proves neither validity
   nor invalidity.
5. Check model adequacy, assumptions, normal executions, and composition when claimed.
6. Reject unmet guarantees and unresolved applicable Critical/High findings. Check
   every skip, non-applicability decision and accepted residual finding.
7. Obtain and authenticate the required review decision over the complete record.
   Publish an active status only after this decision succeeds.

Schema validation cannot establish mathematical soundness, specification
completeness or truthful test results. `result: success` entered in JSON is not
proof of successful execution. Results need verifiable producer provenance,
tool output and its interpretation, target correspondence and scoped review.
The evaluator MUST identify which checks it actually performs and which judgments
it relies on. Tests of the evaluator MUST include missing requirements relative
to an approved inventory, failed/skipped runs, changed targets/inputs, stale
approvals, broken evidence references and incompatible composition.

The evaluator is itself an evidence-producing tool. Its code, version, runtime,
rules and configuration MUST be identified with the same precision as other
evidence producers. Authenticate each evaluation output and bind it to a frozen
assessment-input manifest. That manifest MUST exclude the evaluation output and
subsequent approvals, avoiding a self-referential digest. Human approvals MUST
identify both the assessed input-manifest digest and the exact evaluation-run
record/output digests. A later run or changed evaluator cannot inherit an approval
without impact review, including the risk of changed or omitted checks.

## Decision governance

Each activation requires two identified human approvals: a technical/security
reviewer and an accountable release decision maker. At least one approver MUST
not have authored the assessed implementation or its primary assurance evidence.
Record competence relevant to the reviewed scope, contribution/conflict disclosures,
and the exact scope each person reviewed. Where an uninvolved reviewer is unavailable,
obtain one before activation. This separation does not itself constitute an
organizationally independent external audit.

Before the release review starts, record reviewer selection: identity and
affiliation, assessed scope, relevant competence demonstrated by experience or
reviewable work, contribution history, conflicts, who commissions/pays for the
review, and any outcome-dependent compensation. An approver's compensation MUST
NOT depend on a positive decision. The selected reviewer must have access to the
needed evidence and authority to record an adverse conclusion; a nominal second
signature is insufficient. The review record must identify the checks and limits
of the person's work and carry their authenticated approval or rejection.

A sole maintainer may serve as the release decision maker while retaining an
uninvolved competent human reviewer, whether a community contributor or an
external specialist. Their affiliation and financial relationship must be
disclosed; paying for a review does not itself make it independent. If no suitable
reviewer is available, the claim remains inactive. An AI tool or a second account
belonging to the same person cannot supply the second human approval. A Git author
name alone establishes neither reviewer identity nor the number of maintainers.

AI-generated analysis is supporting material. It MUST NOT be represented as an
independent human approval or an organizationally independent third-party audit.

The security plan MUST fix the severity method/version and protocol-specific impact
rules before results are adjudicated. Record attack prerequisites, authority or
confidentiality loss, affected configurations, and rationale; a numeric score alone
does not override a guarantee violation. Reclassification and false-positive
decisions require the technical reviewer to approve their evidence and rationale.

Residual Medium/Low findings may be accepted only if no applicable guarantee is
violated. Each needs an owner, corrective deadline, disclosed residual impact and
reviewed treatment. A missed deadline triggers renewed review and suspension unless
the revised treatment is approved; it cannot silently remain an accepted exception.
MUST-level obligations cannot be waived through risk acceptance.

## Adversarial adequacy and security plans

For each security property, record a capability matrix with `included`,
`excluded-by-explicit-assumption`, or `inapplicable`, and a rationale. At minimum,
consider the following capabilities and their timing:

| Capability family | Required consideration |
| --- | --- |
| Network and input | Injection, interception where allowed by the transport model, replay, reordering, malformed encodings, redirects and endpoint substitution |
| Principals and authorities | Malicious client under the same issuer, malicious upstream AS/OP/RS, cross-issuer/tenant interaction and mix-up |
| Compromise | Client secret, code, refresh/access token, sender key, signing key and session/store compromise; before/after compromise claims and recovery |
| State and execution | Concurrent workers/tabs/processes, cancellation, loss of responses/ACKs, restart, failover, stale caches, clock changes and permitted restoration |
| Host and application | Malicious callback or SDK caller input, mutable objects, browser origin and injected script capabilities, management authority abuse |

Including a compromised secret does not require proving its confidentiality after
compromise. The property must specify what still holds and for whom. Excluding
arbitrary same-origin script execution may be appropriate for a browser profile;
the scope and resulting limit MUST be explicit. A generic trusted-host assumption
cannot discard attacker-controlled inputs that own code must validate.

The following mutation families require per-property dispositions: removal or
weakening of PKCE, transaction/state correlation, issuer/audience checks, nonce,
redirect matching, sender/ath/htu binding, replay identity/retention, one-time
consumption, refresh-family revocation, signature-result provenance, and
tenant/management authority binding. Select the relevant requirement or property
that each mutation should violate and record the expected counterexample/rejection.

A defense mutation need not break every overlapping security property: another
defense may imply the same property. In that case record the redundancy argument
and use a targeted property or combined mutation that exercises the dependency.
A timeout or failure to terminate is **inconclusive**, not a found attack, successful
negative test, or proof of vacuity. Required honest executions need reachability
witnesses under the same assumptions and bounds.

State which flows and principals execute concurrently in each model. Shared keys,
sessions, stores and acceptance paths require a common composition argument or
an explicit noninterference proof; isolated flow lemmas alone are insufficient.

Before executing release tests, approve a profile-specific security plan containing
the applicable cases below and objective result criteria. Non-applicability requires
a reason and supporting scope/isolation evidence; mandatory obligations cannot be skipped.

| Test family | Minimum case selection |
| --- | --- |
| Protocol and identity | Required normal flows; invalid/mismatched issuer, audience, redirect, state/nonce, signature/algorithm, replay, auth strength and authorization context |
| Parsing and boundaries | Malformed, duplicate, oversized, aliased and encoding/numeric boundary inputs; parser/FFI fuzzing and applicable memory/undefined-behavior checks |
| Durable state | Concurrent redemption/rotation, retry, cancellation, lost ACK, crash, cache invalidation and each admitted restore/failover mode |
| SDK and management | Installed package exports/loaders/declarations; callback and flag injection; session restoration; origin/CSRF/credential scope; operation and error/version correspondence |
| Dependencies and deployment | Actual artifact/dependency vulnerability inventory, endpoint/transport/storage protections, configuration boundaries, secret leakage and delivery authenticity |

Each plan needs tool/runtime versions, targets, corpus/input domains, execution
budget, coverage or adequacy measure, expected outcomes, required environments
and retest conditions. Fuzz time or code coverage alone is not a success criterion.
Applicable mandatory normal behavior requires both an implementation-linked
reachability/functional argument and successful release-output interoperability
or end-to-end tests. Rejecting every input cannot satisfy the contracts.

## Composition inventory

Use stable interface IDs. Each entry MUST identify participants and directions,
required guarantees/assumptions on both sides, value domains/units, state semantics,
and evidence that supplied guarantees entail the other's assumptions. Identical
strings or successful example traffic alone do not establish this implication.

| Interface ID | Minimum boundary to resolve |
| --- | --- |
| IF-01 | Issuer, client, tenant/resource, endpoint/metadata/key trust and redirect identity |
| IF-02 | Token class, algorithm/key purpose/provider and signature-verification provenance |
| IF-03 | Code transaction, PKCE, state/nonce and callback/session admission |
| IF-04 | Sender binding, DPoP/mTLS direction, nonces, retries and replay domain |
| IF-05 | Refresh ownership, concurrency, unknown outcomes and family invalidation |
| IF-06 | Time units/skew, lifetimes, cache freshness, revocation propagation and offline acceptance |
| IF-07 | Local/remote logout, session invalidation and concurrent refresh |
| IF-08 | Storage isolation/durability, failover/restore, fencing and policy/key versions |
| IF-09 | Errors, cancellation, retry/idempotency and bounded resource use |
| IF-10 | Management auth mode, origin/CSRF, authority scope, API operations and version preconditions |

Every applicable interface needs evidence from both sides and a reviewed result;
inapplicable entries need reasons. Additional interface duties require new IDs.
Circular assumptions need a joint invariant or a justified base case; an assumption
cannot be discharged merely by another assumption. External parties are subject
to the same disclosure of requirements and limits. The combined statement is
blocked until the populated inventory closes, even if individual releases qualify.

## Authenticated validity and correction

The assurance record is immutable. A separately authenticated, ordered status
history records `active`, `suspended`, `withdrawn` and `superseded` events, their
reason, effective time, decision identity and successor where applicable. It MUST
retain past decisions and prevent rollback to an earlier active view without detection.

Release metadata MUST map each artifact/package digest to its assurance record and
the location of the current-status registry. This mapping may use an authenticated
detached manifest; embedding the final record digest into the very binary whose
digest it records would create a circular build dependency and is not required.
Signing keys, trust roots, verification method and status-update responsibilities
MUST be documented. Hashes alone do not authenticate the publisher.

Retrieval/verification failures or an unknown current state MUST NOT be reported
as a confirmed active claim. Historical validity and current applicability must
remain distinguishable. This rule concerns assurance status and does not impose
an unsolicited online kill switch on deployed authentication services.
