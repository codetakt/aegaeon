# CI execution and qualification boundaries

Last updated: 2026-10-23

Status: active plan

Owner: Engineering

Audience: maintainers, verification reviewers

Migration implementation: external admission is not commissioned. Task 3 remains paused.

The current implementation sequence is Dudect qualification and its CI connection,
then reviewed PR integration and functional completeness, then full assurance.
The owner confirmed this separation on 2026-10-23. Performance and managed-provider
qualification are separate work; completing their whole assurance designs is not
a prerequisite for closing the Dudect work. Existing selected functional checks
remain required. The present full-scope hold names the unfinished Dudect admission
connection; it is not a demand to complete Task3 before ordinary CI can run.

Ordinary GitHub-hosted CI checks build, lint, tests, formal verification, dependency
integrity, real callback self-tests and load/observability functionality. It does
not certify timing independence or performance thresholds. Removing physical
measurements from Hosted does not turn missing qualification into success.

## Execution timing

Keep the current main/PR model; do not introduce a develop branch. The intended
admission sequence is:

1. Every PR runs its selected functional and integrity checks on Hosted.
2. Before a qualification-sensitive change enters main, qualify the reviewed
   merge candidate and actual artifacts in the appropriate external environment.
   Scope selection must follow transitive inputs; until that selector is reviewed,
   full-scope changes conservatively require qualification.
3. At main admission verify that the tested tree, compiler/dependency closure,
   artifact and profile still match. An unchanged qualified artifact may reuse its
   bound receipt under the reviewed freshness policy; a rebuild or changed input
   requires a new decision. Merely sharing a commit message or source SHA is not
   sufficient. A merge queue must not admit an untested merge-group artifact.
4. Scheduled qualification detects environment/dependency drift. A release also
   requires full qualification of its exact distributable artifacts and supported
   profiles, including longer plans where the release contract requires them.

The migration PR intentionally keeps a full-scope **merge admission hold** in
`Required checks` and an unconditional **release hold** in `Validate Release`.
Ordinary checks may pass while these explicit holds fail. Commissioning requires
a separate reviewed implementation; no variable, old receipt or missing job
silently enables admission. Docs/integrity-only scopes retain their existing
selection. Do not merge this transition as a completed qualification system.

## Protected result contract compatibility

The planner accepts result contract version 1 and transition version 2. Version 2
requires the exact functional-only transition record: external admission pending,
qualification-sensitive merge and release blocked, and automatic retry disabled.
Missing, relaxed or unknown transition records fail validation. A version-1 record
cannot carry a transition section. The transport commitment records the actual
protected contract version and bytes; changing the envelope label does not change
its authority.

This check also runs during helper-test discovery. A contract-version mismatch
previously made discovery fail and sent every helper group through the complete
fallback suite. Successful discovery now partitions the inventory normally;
discovery failures still retain the existing fail-closed fallback.

## Responsibility and environments

| Responsibility | Execution | Required evidence |
| --- | --- | --- |
| Dudect | Qualified bare-metal measurement profile, separate from runner agent/build activity | Actual test ELF and product-call correspondence; all 21 cases and both compilers; required raw0/101 controls; numerical and sampling contracts; full raw/prefixes and original/effective decisions |
| Performance acceptance | Same hardware/base-image family where suitable, separate measurement profile and separate load generator | Actual server/image, workloads, DB/Redis/KMS/network topology, arrival/success accounting, saturation, fixed windows and SLO acceptance |
| Auth0 interoperability | Dedicated test tenant; IaC-managed owned configuration provisioned/read back before live browser execution | Exact client/WASM/runtime, provider configuration, browser, cases, original producer and observation time, cleanup outcome |
| KMS | Hosted emulator for API functionality; real backend for backend qualification | Algorithm/key/policy/rotation, permissions and failure paths, exact runtime |
| Protocol conformance | Pinned suite and complete selected plans/variants/modules | Actual nonempty executions; certification is a separate claim |
| Release | Protected evidence consumer | Authenticated receipts bound to the distributable artifact, complete selected obligations, no pending or inconclusive result |

Dudect and performance may reuse one hardware pool, but never run concurrently.
Use exclusive leases, separate profiles, reset/readback and deadlines. A bare-metal
name alone establishes no capability. Preserve required sensitivity, interpretation
of preparation/history and supported CPU scope; one host is not evidence for every
CPU or operational failure rate.

Auth0 provision/readiness/live-test/recovery/cleanup is one bounded operation.
Serialize shared tenant changes. Do not assume a new tenant can be created for
every PR; IaC owns explicitly identified resources in a dedicated test tenant,
while test users/sessions are separately managed fixtures. Never operate on
production tenants. Import preserves the original observation time (`generated_at`), subject and producer;
`imported_at` and a new Actions run ID cannot refresh old observations. Optional
not-run evidence is not a required pass.

## Transition implemented here

- All ordinary Dudect entries (reusable verification, core, integrity and Nix
  scripts) now use builds, callback self-tests or evidence-validator fixtures.
- The automatic Hosted periodic timing schedule is removed. Manual dispatch
  reports that external execution is pending; it does not execute a timing gate.
- Hosted performance validates functional load accounting, errors and report
  shape, with no latency/RPS/memory acceptance thresholds. Existing unavailable
  policy-mixed prerequisites remain unavailable rather than being fabricated.
- Historical timing failures, signatures/receipts, numerical contracts and raw
  evidence are retained. This change neither resolves those failures nor adopts
  research numerical/preparation candidates.

## Follow-up completeness work

Separate reviewable changes must close: external request/artifact identity and
trusted producer verification; finite lifecycle/independent stop/full-capacity
recovery; Dudect capability and every designated role; performance topology and
scenario coverage; Auth0 IaC ownership/readiness/live-vs-import provenance; KMS
and conformance scope; protected merge/release admission and freshness.

Each obligation records owner, exact subject, producer, expected inventory,
acceptance, dependencies, evidence and outstanding failures. Functional readiness,
physical candidate results, formal adoption and operational reliability are
separate decisions. The prior 299-run plan is ended and is not resumed. Its
remaining trials are not a pool for replacement measurements.

## Migration verification

The local Nix `verify-dudect` build completed all 21 actual callback self-tests;
the revised `verified-reqs` build completed its integrity and validator checks.
The boundary/caller regressions passed 53 tests, and the load-test source,
invocation and retention suite passed 95 tests. The load-test Rust library and
CLI passed 47 tests.

An actual load-test CLI against an owned HTTP fixture retained approximately
301 ms median responses: functional mode passed, ordinary SLO mode failed, and
functional mode with HTTP 500 responses failed. This confirms the acceptance-mode
separation, not the Aegaeon server's performance. Shell/workflow/type/style checks
and the documentation inventory also passed. Initial setup/fixture failures were
retained privately and corrected before these results; no Hosted timing or
external provider qualification is asserted by these checks.
