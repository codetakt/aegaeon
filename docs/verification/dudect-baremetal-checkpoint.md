# Dudect bare-metal research checkpoint

Last updated: 2026-10-19

Status: snapshot

Status note: complete finite research evidence; no numerical adoption or CI admission.

Owner: Engineering

Audience: maintainers, verification reviewers

The later [calibration and role qualification](dudect-calibration-qualification.md)
records the completed sensitivity and all-case integration stages. This earlier
checkpoint retains its original scope, identities and results.

The finite GCC/Clang run uses source `118f98f5cace51778efaed4f8bbdc4983de90e5a`
and tree `00e919bcf5ad1ac62ebf708e5719442ca7a0d28f`. Later documentation commits
preserve that measured source identity. The public
[receipt](../../ci/evidence/dudect-baremetal-20261019.json) binds the plan, analysis dependencies,
case contract, package indexes, 22 actual native executables and results.
Recorded input bytes, timing frames, complete execution records and deployment/recovery
receipts are retained privately; no credentials or raw private packet are published.

## Execution and result

A fresh c6i.metal allocation used the frozen Ice Lake research profile: SMT off,
measurement CPU1 and collector CPU0 on separate physical cores, isolated/nohz
measurement CPU, SCHED_OTHER, turbo disabled, requested minimum/maximum frequency
at the 2.9 GHz base, and disabled measurement-core idle states. Configuration was
read back before and after each suite. This is not a claim that firmware or every
interrupt was absent.

The fixed inventory was one complete opportunity: all 21 cases with GCC and
Clang, 22 processes, 336 looks and 714 frames. Limits remained 900 seconds per case
and 9,000 seconds for the matrix. No failure-triggered replacement or extension
was permitted. Required positive controls retain their designated raw0/101
statistics; characterization cases may detect without violating their role.

The run completed in 2,664.301 seconds. All **42 candidate roles** and all
12 original controls were satisfied. The original evaluator satisfied **41/42**
roles: GCC HMAC message retained an inconclusive crop1 with 503/488 observations
at cutoff 95,284. The distributed candidate used cutoff 95,470 and a disjoint
calibration/test split, yielding 34,490/34,974 observations and a final eligible
non-detection. These are different selected populations, not a measured physical
improvement within the original crop.

All 10,868 original detected statistic/look pairs were retained. Neither sparse
supplement applied in this run. Full evidence replay matched all 336 looks.
Independent integer/dyadic calculations checked 137,088 original moments and
32,895 tails with no mismatches under the recorded comparison rules. A separate
sorted-array calculation checked the distributed candidate's 3,200 class moments,
1,600 cutoffs and 1,582 eligible tails with no classification differences.
These arithmetic checks do not establish the sampling model or statistical power.

Encrypted recovery produced 947 files (1,128,486,063 bytes), all matching the
recovery manifest. The full runtime/source inventory was unchanged after execution.
The physical observation and independent replays are recorded as one opportunity,
not additional physical repetitions.

The first setup preflight rejected a requested-frequency mismatch before native
timing began. Correcting the per-policy minimum made the already-frozen profile
match; its requested frequency was not relaxed. The failed preflight and the
subsequent passing readback are both retained. Build/runtime/source hashes were
checked before and after execution. Independent external and guest deadlines,
authenticated encrypted recovery, and compute/disk cleanup were recorded.

## Candidate boundaries

This snapshot contains separately identified research changes:

- Prefix-authenticated PR-only two/three-exception non-rejection supplements.
- A separate four-exception supplement requiring the exact count-conditioned
  lower bound to exceed or equal alpha; it is not an unconditional four-value rule.
- Student-tail interval decisions at frozen binary64 t/df, with unresolved results
  rejected. This does not certify upstream arithmetic or sampling assumptions.
- Distributed calibration replaces only PR HMAC-message crops1–100. Raw0/101 and
  other cases retain their populations; original crop decisions remain available.
  New crops do not inherit the original-population sparse supplement.

The ordinary trace records inputs only for its supported cases; this run does
not add the separate JWE/CT preparation-history diagnostic formats.

No RT scheduling, prepass, masked preparation, trimming, threshold relaxation,
control-strength adjustment or statistical retry was used. Native binding and
analysis binding remain distinct. Publication of this candidate does not adopt
its numerical or monitoring contract.

## Interpretation and remaining work

The result describes this fixed opportunity and environment. It does not estimate
CI failure probability, establish sensitivity to every required weak/time-localized
signal, prove exchangeability, or demonstrate that historical detections were
noise. Older JWE/ct64/ct128 detections, control misses and crop-count failures remain
in their original evidence. A non-recurrence does not establish their repair.

GitHub-hosted CI is being separated into functional/integrity validation and
external physical qualification in an independent change. Before admission, the
external route still needs reviewed environment/capability scope, authenticated
artifact-bound evidence consumption, lifecycle/freshness policy and the chosen
operational reliability evaluation. The ended Hosted campaign is not resumed.

## Earlier PR evidence retained

The earlier CPU-separation/control-input-capture comparison covered 64 cases,
with 208,896 independent moment and 50,079 tail comparisons. Its two inconclusive
comparison cases remain. The following Hosted ct64 rejection likewise remains:
[run38275005039](https://github.com/codetakt/aegaeon/actions/runs/38275005039).
Its 53 retained cases/424 looks yielded 172,992 moment and 42,041 tail comparisons.
Buffer-prefault functional fixtures removed 256 first-write faults without adding
callbacks. Those historical checks are separate from this new physical run and
do not establish future stability.

The PR stays draft. Temporary unsigned publication was authorized; before merge,
re-sign every introduced commit and recheck signatures and tree/artifact identity.
