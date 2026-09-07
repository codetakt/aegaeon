# SDK Assurance Contract Status

Last updated: 2026-09-07

Document revision: **2026-09-07-r4**.

Status: snapshot

Owner: Verification / SDK Engineering / Security / Release Engineering

Audience: maintainers, verification reviewers, release managers

> **Status note (2026-09-07):** Contract v1 is specified; its qualified SDK and
> management-client claims are inactive. No distributed artifact is attested by
> this document. Proof/security suites and publication were not run for adoption.

## Current decision

Contract **aegaeon-sdk-assurance-v1** is specified. Its qualified SDK and
management-client claims are **inactive**. No npm package, browser bundle, WASM
artifact, or other language output is attested by adopting these documents.

Revision **2026-09-07-r2** added the [evaluation rules](../assurance-evaluation.md),
clarified reference-source status and pinned the current generated OpenAPI for
reconciliation. These changes do not qualify any SDK implementation or close
the release evaluator, requirement inventories or security plans.
The r3 revision pins companion-document revisions and clarifies evaluator
provenance, reviewer selection and the raw ABI's preverification trust boundary.
Human reviewer selection and actual SDK API/ABI isolation remain activation work.

Safe wording today is: **The Aegaeon SDK has client-core verification assets and
security-test tooling. Completion of the published SDK assurance contract for
its distributed implementations is pending.** Component results can be stated
with their exact property, program/model, bounds, assumptions and dated evidence.

The contract was prepared from the backend's SDK reference/scaffold sources,
existing client policies, and the locally available sibling SDK package
descriptions. This review did not establish registry publication state, rerun
formal proofs, run the SDK security suite, or certify any external provider.

## Required activation work

| Work | Guarantees | Completion evidence |
| --- | --- | --- |
| Individual client requirements and public API inventory | All | Exact clauses/roles/triggers plus every public export and management operation; source and output mapping |
| Actual output/runtime configuration | C-01, C-14 through C-20 | Package, JS/WASM, declarations, exports, runtime versions, providers, stores, transports, bundle modes and bounds identified by release |
| Axiom and model adequacy | C-03 through C-10, C-14, C-18 | Audited assumptions, adversarial models, reachability witnesses and defense-removal mutations |
| SDK implementation correspondence | C-01 through C-18 | Checked core and adapter/orchestration refinement/invariants; host primitive assumptions do not swallow own-code decisions |
| Authentication completion boundary | C-05 through C-07, C-18 | High-level login admits only verified transaction-bound identity; supplied exchange callbacks and mutable objects cannot manufacture success |
| Signature provenance and ABI | C-02, C-06, C-14 through C-16 | Exact signed-byte/key/claims binding, safe preverification path, numeric/encoding/handle correspondence, production import behavior |
| Session/store/refresh/logout state | C-04 through C-12 | Legal transitions across concurrency, tabs/processes, cancellation, uncertain exchanges and permitted recovery; enforced sharing assumptions |
| Management output contract | C-01, C-12, C-13, C-16 | Pinned OpenAPI and export inventory; JS/declaration/API agreement, correct scoping/CSRF/version/error/retry behavior |
| Packed-artifact correspondence and custody | C-15 through C-17 | Exact producer/SDK revisions, reproducible or otherwise authenticated build relationship, checked package closure and redistribution notices |
| Actual security/interoperability results | C-19 | Installed-output attack tests across declared environments; successful relevant provider tests; reviewed findings, failures and skips |
| Release-gate reconciliation and SDK adoption | C-20 | SDK archives adopted contract/pins; evaluator binds per-requirement closure and successful evidence to exact packages before approving new wording |
| Decision governance and current validity | C-20 | Role-separated human approvals, explicit severity/residual-finding treatment and authenticated status history implement the evaluation rules |
| Source/dependency and composition closure | C-01, C-18, C-20 | Full section/incorporation/errata review and paired IF-01 through IF-10 obligations for each combined claim; relevant external-party assumptions disclosed |

## Existing evidence and its limits

The [client/RP assurance case](../client-rp-assurance-case.md) records a useful
core and adapter baseline. Existing `aegaeon-rs256` promotion uses host signature
preverification. Those records do not by themselves prove adapter logic or the
emitted JavaScript. Existing core evidence must also be checked for model
adequacy, bounds, axioms, and correspondence to the actual WASM artifact.

The RP/SPA package descriptions expose caller-supplied token-exchange callbacks
and session storage. A complete verified RP needs C-06/C-07/C-18 closure across
those boundaries; naming the callback "external" is insufficient. This is an
activation obligation, not a claim here that a particular exploit was reproduced.

Source inspection on 2026-09-07 confirms that `finishFederatedLogin` normalizes
the exchange callback result and can save its ID Token/issuer/subject without
calling ID Token verification. It does not establish validated-session admission.
Reference Node/Web adapters also propagate caller flags; the current F\* runtime
has JWT/DPoP branches that return `CRYPTO_VALID` for `SIGNATURE_PREVERIFIED`.
This confirms a source-level trust-boundary issue, not an executed exploit against
a distributed WASM/package. C-06 requires verifier-owned authority and proven
adapter preconditions, not merely a renamed flag or a TypeScript-only brand.
The [raw ABI boundary](../../../specs/verified-core-wasm.md) and F\*/C comments now
state that preverification is an assertion by an admitted trusted adapter, not
authority conferred by a public caller. This documentation change does not enforce
that boundary: the current runtime still accepts the bit. Qualified SDK activation
requires the actual isolation/provenance implementation, proof and packed-output
negative tests described by C-06/C-15.

The endpoint prose lists 53 HTTP endpoint bullets. The reference SDK contains
110 operation IDs; the pinned generated management OpenAPI has 106. The four
reference-only IDs are `export_team_audit_events`, `export_team_audit_events_csv`,
`export_environment_audit_events`, and `export_environment_audit_events_csv`.
Pinning the generated file does not resolve this gap, its error/auth semantics,
or correspondence to current server routes. Reconcile the complete inventories
and independently specify each public operation before C-13 can close.

Current publication/promotion tooling checks important hosted provenance,
attestation, custody, and evidence shapes. It predates this contract and is not
an evaluator of complete R_sdk(C) or emitted-code refinement. Its reconciliation
is required before the stronger SDK wording can be used. This document does not
change operational publishing behavior or assert that those tools enforce the
new criteria already.

## Permitted target wording after activation

The normative English templates and mandatory release-record fields
are defined in the [public assurance statement specification](../assurance-statement.md),
sections 5 through 7. Client/RP SDK, management client, and combined server/SDK
claims have distinct scopes and activation conditions. Their wording is fixed;
the implementation, evidence and release work above remains open.
