# Qualification responsibility audit

Last updated: 2026-10-19

Status: active plan

Owner: Engineering

Audience: maintainers, verification reviewers

This audit follows the [CI execution boundary](ci-execution-boundary.md).
Its machine-readable inventory covers every job in the current workflows and
seven external responsibilities. Structural coverage is not qualification:
`check_qualification_responsibilities.py` always reports
`qualification_admitted=false`. New or missing jobs require an inventory update.

## Findings and corrective work

| Responsibility | Available checks | Remaining commissioning work |
| --- | --- | --- |
| Dudect | Functional validators, actual callback self-tests, separately retained physical research | Qualified environment and sensitivity, complete artifact-bound evidence consumer, supported CPU scope |
| Performance | Functional load/error accounting and observability smoke; SLO checker retained for qualified measurements | Exclusive hardware profile, external load generator, exact server and topology, fixed workloads and acceptance evidence |
| Auth0 | Managed-provider schema and import validation; live browser entrypoint in the SDK reference | Dedicated test-tenant IaC, configuration readback, actual browser-case inventory, trusted producer, freshness and cleanup |
| KMS | Local emulator parity and backend configuration checks | Real-backend lifecycle, permissions, key policy and negative-path qualification |
| Conformance | Scheduled notices and pinned suite entrypoints | Complete selected suite executions, configuration, nonempty results and missing-case rejection |
| Admission | Explicit transitional main/release holds | Protected consumer, merge-candidate/release subject binding, freshness and all publication routes |
| Measurement lifecycle | Bounded private measurement/recovery implementation | Reviewed shared leases, independent stop, capacity, authenticated complete/partial recovery and cost limits |

The detailed open obligations and existing entrypoints are in
`ci/qualification-responsibilities.json`. Closing an item requires its own
reviewed implementation and evidence. Removing an item to make this audit pass
is not an admission decision.

## Managed-provider import repair

The reference import tool previously replaced the original GitHub producer with
the importing workflow and forced `lane.hosted=true`. Importing a local result
could therefore misdescribe its execution environment. The tool now preserves
original `source`, `lane`, `runtime`, provider and `generated_at` fields, and
appends a separate `import_history` entry with the hash of the exact input bytes
and importer identity. Repeated imports retain the chain. Existing output files
are not overwritten, including when input and output paths are the same.

The observation timestamp was already preserved; this change does not claim to
fix a timestamp reset. Regression checks cover stale observations, local origins,
repeated imports, malformed metadata and output collisions. The history is an
audit trail, not an authenticated producer attestation. Schema validation alone
cannot establish that the named provider was actually exercised. Previously
overwritten producer metadata cannot be recovered by importing it again: use
the original retained artifact, and keep unverifiable provenance unqualified.

These files are Aegaeon's SDK reference/scaffold tools. The separate SDK repository
must adopt the repair before its deployed import path has this behavior. No live
Auth0 test, tenant provisioning or cross-repository adoption is claimed here.

## Completion boundary

The PR establishes an enforced inventory and repairs the concrete import defect.
It does not commission the external environments or close product assurance.
Transition holds remain until the relevant evidence-consumer and lifecycle work
is reviewed. Inventory validity, functional test success, physical qualification
and admission are distinct results.
