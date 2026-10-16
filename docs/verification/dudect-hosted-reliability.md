# Hosted Dudect reliability evaluation

Last updated: 2026-10-17
Status: active plan
Owner: Aegaeon maintainers
Audience: verification maintainers

Status note: bounded evaluation; ordinary CI adoption remains separate.

The selected evaluation criterion is an unsuccessful complete opportunity rate
at most 1%, evaluated with one-sided 95% confidence under an independent,
common-probability opportunity model. An opportunity is a fresh hosted VM
executing all 21 PR cases under both GCC and Clang, including all specified
controls: 42 case roles, not 42 independent reliability trials.

The fixed maximum is 299 new opportunities. With zero failures the binomial
upper limit is `1 - 0.05^(1/299)`, approximately 0.997%. This is the smallest
zero-failure design for the selected target: `(0.99)^299 < 0.05 < (0.99)^298`.
The prior hosted screen and historical AWS runs are excluded from this count.
The [NIST confidence-interval reference](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm)
describes inversion of the binomial tail; no normal approximation is used here.

## Frozen execution and stopping

`scripts/ci/dudect-hosted-reliability.json` fixes the packages, case contract,
criterion, opportunity inventory and branch namespace before acquisition. All
batch branches point to the same signed commit. There are 19 batches: 18 of 16
opportunities, followed by 11. Each matrix job receives a fresh VM and a unique
slot ID; the ID is bound into its analysis packet before input generation.
The four suites and native cases retain their original order within a VM.

The coordinator submits only one batch at a time. A new batch is permitted only
after the previous batch finishes and all expected evidence has been recovered,
authenticated and replayed successfully. Any failed opportunity stops future
batch submissions. Already submitted jobs finish and their evidence is
retained. There is no replacement, rerun, outcome-dependent candidate change,
post-hoc CPU exclusion, or sample filtering. This early stop can only prevent
acceptance; success requires all 299 original slots to pass.

Preparation, missing allocation, configuration violations, statistical role
failures, numerical uncertainty, timeout, cancellation and missing/corrupt
evidence all prevent a successful opportunity. Unknown timing detections are
retained as detections needing investigation, not labelled false positives.
Early stopping means that the planned maximum was not reached; report the
observed counts and reasons without treating an incomplete campaign as a
fixed-299 failure-rate estimate or silently removing unstarted slots.

The original 900-second case limit, 9,000-second matrix limit, 10-second/256-MiB
prefix limit, all controls, alpha, floors, 16 measurement batches and eight
looks remain unchanged. Builds finish before measurement. A separate 15-minute
post-acquisition replay and 15-minute archive budget are included in the
300-minute job cap; neither extends the measurement deadlines.

## Scope and retained evidence

Use the workflow's standard hosted Ubuntu x86_64 runner label with the existing diagnostic
profile, sibling-aware owned-process separation and explicit competition
limitations. CPU model, topology, image, kernel, placement, available events,
time and package identities are recorded for every opportunity. A fresh guest
does not prove a distinct physical host or independence. Report outcomes by
CPU/image/time batch, and limit the binomial interpretation to its stated model
and observed allocation population. This campaign does not prove a long-term
rate for every runner type or future image.

All raw, original decisions, integrated decisions, prefix proofs, role results,
environment readbacks, failure records and logs are retained. Each artifact has
a file manifest and archive checksum. Download and verify each batch before
starting the next. Missing uploads are failures, not replaceable slots.
The native and analysis packages are pinned to the preceding successful screen;
the known two inert bytecode-cache timestamp differences do not justify accepting
different source, bytecode, native binary, policy or dependency identities.

On 299 fully verified successes, report that the selected operational criterion
is supported under its model. Formal numerical/environment adoption, all
ordinary CI entrypoint migration and disposition of historical detections remain
separate decisions. Periodic and product assurance are not changed.

## Capacity

The previous complete job suggests approximately 270 total runner hours for all
299 opportunities, excluding queueing and local verification. With 16 at a time
the rough elapsed duration is 17 hours plus recovery and verification. These are
planning estimates, not deadlines extended after observing results. Each batch
has its original per-job cap and the coordinator has a 96-hour campaign limit.

Archive estimates are 123 GiB compressed plus 316 GiB extracted. Reserve 600 GiB
locally before beginning. Standard public-repository Linux runner execution is
currently [free](https://docs.github.com/en/actions/reference/runners/github-hosted-runners);
no larger runner or permanent resource is requested. The batch size stays below
the documented [256-job matrix limit](https://docs.github.com/en/actions/reference/limits).
Existing evidence and artifacts are never deleted to make space for this work.
