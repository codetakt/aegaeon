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

## Original-run failure diagnostics

The collector retains `runtime.jsonl` for each native process. It records startup,
each existing acknowledgment boundary, and shutdown: timestamps, native affinity,
CPU counters (including steal time), memory/load/pressure, kernel and processor
identity, boot identity, isolation configuration, and available frequency state.
Read-only APERF/MPERF samples are attempted for at most 64 allowed CPUs when the
host exposes `/dev/cpu/*/msr`; absent or denied telemetry is recorded explicitly.
The collector neither changes CPU policy nor requires privileged access. Counter
intervals include work between observations and are not per-sample frequencies.
No additional polling worker runs during a timed loop. Environment dumps and
unrelated process command lines are excluded from these runtime snapshots.
At acknowledgment boundaries the owned native process's `/proc/PID/stat`,
`sched` and `schedstat` retain its last CPU, migration and scheduling counters.
The capture's finishing timestamp makes its duration visible. These snapshots
do not prove the CPU stayed unchanged between observations.

Every native executable also writes `native.timing`: ordered timestamp and
class arrays for **every case and every batch**, including the independent
pilot. This preserves distribution shifts and the observations behind sparse
crops or one-class zero variance in the original failing execution. Its
`AEGTIM02` framing binds the native build, contract, numerical identity, case
order, input stride and full profile. Each case also records the input, timestamp
and class-buffer addresses modulo 4096, so cache-line position need not be
guessed from sample index. These offsets do not reveal full addresses or establish
physical cache placement. Each batch includes monotonic timestamps,
actual CPUs and cumulative process resource counters before and after the
measurement function. CPU lookup failure is recorded as `UINT64_MAX`;
clock/resource lookup failure aborts collection. Boundary CPUs do not exclude
migration away and back inside a batch. Resource intervals also include the
timestamp-difference construction, not only the computation loop.

For `sha256` and `hmac_sha256`, the timing file additionally retains every original
32-byte synthetic message after each batch's timestamp and class arrays. Class 0
must contain the specified `0xAA` or `0xBB` bytes. Class 1 retains the original
random bytes, enabling later analysis of input contents and neighboring samples.
Earlier `AEGTIM01` evidence did not retain these messages or buffer offsets;
they cannot be reconstructed from that evidence. Historical packets stay unchanged
and must be read with their bound source version.

The recorder makes no calls or writes inside the timed loop and stores no
product inputs. It reuses existing native buffers, requiring no additional sample
allocation. Uncompressed size is about 4.5 MiB per case for PR and 55.7 MiB for
periodic; the two message traces increase their respective cases to 20.5 MiB
and 254 MiB. All 21 periodic cases use about 1.53 GiB, plus the separate comparison
input trace below. Missing, truncated, reordered or
misbound timing records prevent a successful report. Partial files remain
retained on failure; recording never retries or changes statistical admission.
As with all instrumentation, boundary capture and writes can affect later
batches. Evidence binds the instrumented artifact and makes no claim of
physical invisibility.

For the local `ct_eq_128` negative control, `native.samples` preserves **every**
batch in the same execution, including the pilot. The name denotes a 128-byte
input stride; the comparison itself reads 32 bytes. Each batch records the
original timestamp order, class labels, and the actual 32-byte synthetic inputs.
The unused 96 bytes of stride padding are omitted. Writes occur after a batch's
measurements and statistical updates, before its observation/acknowledgment.
They can affect the conditions of later batches; instrumentation is not assumed
to be physically invisible. The allocation is 2 MiB plus bounded framing;
files are about 21 MiB for PR and 254 MiB for periodic. The SHA/HMAC messages
are retained in `native.timing`; remaining cases retain ordered timing/class
evidence without their synthetic input bytes.

`AEGAEON_DUDECT_TRACE_FD` and `AEGAEON_DUDECT_TIMING_FD` are internal
parent-to-child verification descriptors, not server settings or user overrides.
The collector replaces inherited values and supplies empty regular files.
Failure to write diagnostics fails the run;
partial files and original stdout remain retained. Complete collection requires
all expected trace frames, the matching build/contract/numerical identities,
and valid class/input framing. The report validator rechecks file hashes and
trace completeness; an incomplete trace cannot publish success. Existing CI
failure uploads include these files with the rest of the run directory.

The VerifiedReqs workflow also copies the requested Nix store output after an
attempted build, including failed builds, before uploading `dudect-nix-gate-output`.
It records the build step outcome and missing or incomplete collection explicitly.
A copied or cached Nix output is not asserted to be a fresh timing execution;
the separate runtime step remains required. Failed outputs must be copied before
garbage collection or runner teardown, and collection errors fail the job.
Both Nix gates make their declared output directories traversable and files
readable when the builder exits, including unsuccessful exits. This lets the
separate CI user copy private temporary run directories that Nix would otherwise
leave inaccessible after a failed build. The original gate failure remains
nonzero; a permission-finalization error also prevents success. This applies
only to the declared Nix output, does not grant write access or follow symlinks,
and leaves ordinary local run directories private. A forcibly killed builder
may not execute its exit handler; missing or inaccessible output remains an
explicit collection failure.

The core CI job evaluates the complete flake inventory, then finishes its other
checks before building `verifyDudect` and `verified-reqs` one at a time. This
avoids concurrent Rust builds/tests and overlapping timing gates on that runner;
it does not establish physical CPU isolation or explain earlier timing failures.
Both gates remain required, including in push/manual runs that also own the
formal checks. Their exact derivations and output paths are recorded before
building, failed builds use `--keep-failed`, and an always-run collector uploads
the original available outputs even when a gate fails. Unstarted gates and
interrupted builds remain explicit; collection does not rerun measurements or
claim cached observations are fresh. The dedicated runtime jobs still collect
fresh observations. A CI inconclusive result without retained observations
cannot be diagnosed from the summary line alone.

The binary format is little endian. Its 200-byte header is ASCII `AEGTRC01`,
then three 64-byte ASCII SHA-256 values: build, contract, numerical policy. Each
frame starts with four unsigned 64-bit integers: zero-based batch index, sample
count (65,536), stride (128), captured input width (32). These are followed by
65,536 signed 64-bit timestamps, 65,536 byte class labels, and 65,536 contiguous
32-byte inputs. Batch zero is the pilot. To reconstruct durations, subtract
adjacent timestamps and apply the documented exclusions; the last timestamp
has no following measured duration. Stored observations preserve the pilot
cutoffs/center needed to replay all 102 statistics. Keep all files from the
failed attempt before any new experiment, and record interventions separately.

A retained historical periodic `ct_eq_128` detection remains causally unresolved.
Subsequent isolated and shared-host diagnostic nondetections do not invalidate
it or establish a repair. This capture closes the missing-data gap for future
runs; it cannot reconstruct the absent ordered samples and CPU history of that
old attempt. Further diagnosis must distinguish input association, temporal
structure, processor state, artifact changes, and collector effects without
weakening the contract or discarding the original failure.

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
