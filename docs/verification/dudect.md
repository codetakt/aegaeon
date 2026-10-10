# Timing observation profiles

Last updated: 2026-10-10

Status: current implementation baseline

Owner: Engineering

Audience: contributors

Nix is the primary entry point. `bash scripts/ci/dudect_check.sh pr` builds a
source-bound native package and collects **fresh** observations. Building
`.#dudect-check` alone produces binaries and their input manifests, never timing
admission. The existing `.#verify-dudect` derivation retains build-time observations;
a cached derivation cannot replace fresh runtime CI execution.
The `.#verified-reqs` output retains the complete native bundle under `dudect/`;
`.#verify-dudect` retains it under `evidence/`. Reports remain verifiable after
the temporary build directory is removed.

The [per-case observation contract](dudect-case-contract.md) assigns requirements
to each fixture. The legacy suite contains eight target cases and three synthetic
controls; the Nix suite contains seven targets and the same three controls,
executed separately. Every original case remains. A completed contract preserves
public-fixture timing differences and requires nondetection for protected-input
observations. It does not establish universal constant time or product assurance.

The verification workflow uses `pr` for both suites. The weekly/manual workflow
uses `periodic` for Nix; the legacy helper supports that profile too. Both retain
failed and inconclusive attempts. There is no automatic statistical retry.

```sh
bash scripts/ci/dudect_check.sh pr
bash scripts/ci/dudect_check.sh periodic
nix develop .#verification --command bash tests/constant_time/run.sh --profile pr
cargo xtask dudect --profile periodic
python3 scripts/validation/check_dudect.py artifacts/ct/dudect-nix/report.json
```

The shell and xtask adapters share `run_contract.py`, retaining their `cc` and
`gcc` compiler profiles, pinned provider, KaRaMeL headers, C11 and
`_DEFAULT_SOURCE`. RSA setup uses the verifier ABI. Input classes and operation
results are checked before measuring. Unix process groups and file locking are
required. Evidence from one suite cannot replace the other.

## Numerical design

| Parameter | PR profile | Periodic profile |
| --- | ---: | ---: |
| Samples per batch | 65,536 | 65,536 |
| Disjoint pilot batches | 1 | 1 |
| Measured batches | 7 | 98 |
| Inspection batches | 1 through 7 | 1, 2, 4, 8, 16, 32, 64, 98 |
| Minimum observed raw samples, each class | 200,000 | 3,200,000 |
| Maximum native runtime per case | 900 seconds | 7,200 seconds |
| Raw mean standardized effect planning target | 0.02 | 0.005 |

Each case has its own runtime deadline, including its pilot and all inspections.
Only completing a case starts the next case's budget; unused time cannot be
borrowed by another case. The final process exit must also fit within the last
case's remaining budget.

The normal planning approximation is
`n = 2 * (z(1-alpha/2) + z(0.9))^2 / d^2`, approximately 197,075 or 3,153,193
observations per class. It assumes independent, equal-variance observations and
90% power for the raw mean. It establishes neither measured power nor sensitivity
of every cropped or second-order statistic. The batch is a bounded starting
choice; no universal throughput or memory optimum is claimed.

The family includes 15 targets and six control executions, 102 statistics and at
most eight looks: `alpha = 0.01 / (21 * 102 * 8)`, approximately `5.835668e-7`
per inspection. Positive finite variances use the two-sided Student-t tail with
fractional Welch degrees of freedom. Bonferroni allocation does not require
independent tests, but each underlying p-value still depends on its assumptions.

The 102 statistics are the raw mean, 100 cropped means and a second-order mean.
Cutoffs and the common second-order center are frozen from the disjoint pilot.
A crop includes **all** native integer ticks `<=` its cutoff, preserving ties.
Negative deltas are excluded and counted. Each measured batch excludes its first
ten observations and final untimed input, retaining at most 65,525 raw values.
Counts describe actual retained measurements.

The candidate timer uses `MFENCE; LFENCE; RDTSC; LFENCE`. The fences order the
preceding work and following instructions around the timestamp, following the
[Intel SDM RDTSC description](https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf).
The host must provide the documented LFENCE execution serialization. This is an
x86 measurement assumption, not portability evidence for other processors or
compilers. Compiler output and the measured host belong to the retained evidence.
The old MFENCE-only sequence did not establish that ordering. Target call counts
are unchanged; historical mode retains its original sequence for explicit replay.

When both classes have more than 10,000 observations and validated native extrema
certify one identical pooled integer value, the absolute mean-difference statistic
is zero under every label permutation. Its exact upper-tail p-value is one under
the equal-distribution/exchangeability null. This specific rule resolves tied
native support; floating-point equality alone is insufficient. Unequal constants,
one-class zero variance, sparse crops, floating aliases and second-order square
collisions remain ineligible. The [contract](dudect-case-contract.md) details the
assumptions and residual coverage.

## Admission and evidence

The native process streams every scheduled observation and waits for acknowledgment.
The consumer checks identity, accounting, frozen calibration, finite moments,
input-domain audits and exact support for all 102 records. Detection remains
visible through the full schedule. No early successful stopping is permitted.

Protected-input cases and negative controls require complete nondetection, both
raw floors and eligibility of every statistic. Insufficient counts or unsupported
degeneracy are `inconclusive`. The positive mean control must detect in raw statistic
0; the variance control must detect in statistic 101. A difference in another crop
cannot substitute for those designated tests. Public/authentication fixture
characterizations retain their statistical outcomes, including differences, and
require the full schedule and raw floors. None declares production messages public.

Only a complete `observation_contract_satisfied` report is published. Malformed
output, missing cases or controls, protected-case detection, required-case
inconclusiveness, setup/process/deadline failures and evidence-write failures all
return nonzero. A public-fixture difference is reported as characterization,
never as evidence of secret noninterference.

Runs reside under `artifacts/ct/dudect/runs/` or `artifacts/ct/dudect-nix/runs/`.
Each keeps frozen sources, the contract, exact compiler arguments/environment,
build and executable hashes, native stdout/stderr, process status, observations,
decisions and platform context. Nix package imports require exact current source
hashes; cached binaries with different inputs are rejected. Runtime still executes
when the matching build is reused. The validator independently checks the retained
bundle, raw output and final status against the report and current source.

The prior report is archived before building. A unique build directory prevents
stale executable reuse. Only a complete admitted suite atomically replaces
`report.json`; failed runs keep their evidence without publishing success. Uploads
run after failure and require evidence. Shared-output locking prevents concurrent
runs from replacing one another's reports.

Schema version 4 binds case/profile, contract, numerical policy and build identities.
Current consumers reject historical versions 2 and 3 and nominal summaries. The
historical numerical and stream modules remain for regression and replay with
their original outcomes. `run_candidate.py` remains a diagnostic collector: its
`candidate_collection_complete` result has `admission: inactive` and cannot admit
CI. Retired `DUDECT_*` overrides cannot change the active contract.

## Calibration and limitations

Each suite executes class-independent synthetic work, a deliberate mean shift
and a deliberate variance shift. The strong variance control adds an independent
symmetric 1,024-operation offset around a common 2,048-operation workload. This
checks the second-order pipeline; it does not certify sensitivity to smaller
variance changes. Timing outliers can dominate fourth moments. Finite control
repetitions do not establish a universal false-alarm or power bound.

Frozen pilot cutoffs can become sparse when the machine's timing distribution
changes. Even a class-independent control can then be inconclusive; it must fail
that run's admission. Preserve the observed counts and diagnose the environment
or profile. Do not ignore a crop or retry until green. Shared hosted runners and
local contention can invalidate independence and sensitivity assumptions.

Any change to batches, native repetitions, class construction, crop policy or
inference requires a reviewed versioned contract and fresh evidence. Historical
failures remain unchanged. Product domains, supplier/artifact composition and
formal assurance obligations remain separate from this empirical monitor.
