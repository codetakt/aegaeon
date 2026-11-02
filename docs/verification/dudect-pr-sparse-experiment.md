# Experimental PR sparse-support replay

Last updated: 2026-10-16
Status: draft
Owner: Aegaeon maintainers
Audience: verification maintainers

Status note: implemented for offline evaluation; not an adopted numerical contract or
an active CI gate. The native collector and the existing gate are unchanged.

The existing numerical consumer admits identical native support and a single
exception. It leaves some observations with two or three exceptions and one
zero sample variance inconclusive, despite sufficient counts and complete raw
evidence. This experiment computes a defined conditional permutation tail for
that previously unsupported region. It expands the potential gate pass set; it
does not establish equivalence or add detection sensitivity in this region.

An inconclusive result is useful only insofar as it identifies missing evidence,
insufficient observations, or an unsupported inference. Those reasons are kept
distinct. The name of the old outcome is not itself a reason to preserve a
failure once its specific inference gap has been addressed.

## Preconditions and interpretation

The source numerical identity is
`594123236e82350f69e907ae16825028201cd06a31f5df820b6ec46d1e77f279`.
The base case identity is
`c44d1ac1ef801e229448960e57e90b2851be819cd449492a5500000996c97ca6`.
The separate experimental policy identity covers the restriction to:

- PR, with looks 1–7 and 16, 65,536 samples per batch, the existing 11 fixed
  exclusions, the existing negative-delta rule, and the original fixed cutoffs;
- at least 10,001 observations in each class of the statistic;
- exactly two or three observations outside the pooled native mode;
- the original final per-look numerical result being `degenerate_variance`,
  after the existing identical/single-exception inference has run;
- exact native integer representation below 2^53 and no collision among the
  binary64-transformed values, including centered squaring for statistic 101.

The conditional exact interpretation requires an appropriate uniform label
allocation/exchangeability premise. Neither exact arithmetic nor a disjoint
pilot establishes that physical premise. The eligibility rule includes the
label-dependent original degeneracy result; this proposal does not claim that
the entire rule is invariant to label permutations.

For r exceptions, the observed allocation alone provides the tail lower bound
`falling(10001, r) / falling(1048400, r)`. For r = 3 this is approximately
8.6780111e-7, greater than the exact binary64 value of the current alpha,
5.8356676e-7. The configuration must match the reviewed identity *and* satisfy
the rational lower-bound check. Configuration changes do not automatically
qualify. The explicit lower-bound guarantee does not extend to four exceptions
or to three exceptions in the periodic profile.

The absolute mean difference is evaluated for every allocation state, with
combinatorial multiplicities, using at most eight states. The tail includes
ties. The exact rational tail is compared to the exact binary64 alpha by integer
arithmetic. A tail below the proved lower bound is an implementation/evidence
error, never a passing result. The additional test cannot reject at this alpha;
its non-rejection does not establish absence of a small or rare difference.

## Evidence and result separation

`replay_sparse.py` freshly recomputes the original decisions with the preserved
source, checks native stdout and the original diagnostics, and verifies the
core numerical consumer matches the reviewed source. It then reads the original
timestamp/label frames in order. Calibration is independently reconstructed;
each look sees only its own prefix. Cumulative histograms retain every admitted
delta, including all tied values at each cutoff. Counts are checked for every
statistic. Supplemental candidates also check attained support and exact dyadic
moments against the original aggregates with the existing Welford rounding
budget. Endpoint summaries never substitute for a complete histogram.

Every look stores `original`, separate `supplements`, and an experimental
`effective` result. The original result is not mutated. A valid old result is
never replaced; same-look and earlier detections remain absorbing. Positive
controls retain their specified statistics 0 and 101. Counts below the floor,
unsupported profiles/distributions/transforms, and changed configurations do
not receive supplemental inference. Missing or inconsistent evidence aborts
replay instead of returning non-detection.

The output carries both old input bindings and the new analysis policy and
source identities. It is marked `adopted: false`, `gate_admission: inactive`,
and `fresh_native_timing: false`. It is not a current native-gate receipt.
The adopted report validator does not accept this schema.

Example, using a retained execution and its bound historical source:

```sh
python3 -B tests/constant_time/replay_sparse.py \
  --execution /private/evidence/executions/jwe_key_reject \
  --source /private/evidence/package/sources/tests/constant_time \
  --output /private/new-analysis/jwe-replay.json
```

## Detector integrity before interpreting the amendment

`test_dudect_detector_integrity.py` compiles a deterministic injected-clock
fixture with GCC and Clang. It exercises the real C collection, calibration,
statistics and serialization path, then the original Python inference and
specified-role assessment. Known mean and squared-deviation differences must
detect in statistics 0 and 101. Removing either signal, contaminating the
negative control, or losing one class must produce the corresponding failure.
This is a functional test of the detector, not a hardware timing experiment.

The other existing tests check timing framing, source/build identity, retained
failures, required cases, count floors, the compiler's measurement loop, and
rejection of missing or altered evidence. Passing these tests does not resolve
the retained real-host variance-control miss or observed JWE/comparison
differences. Those are unresolved failures requiring investigation, not
automatically inherent limits of Dudect.

## Before active gate integration

The experiment does not modify the collector's ACK path, native artifact,
active case/numerical contracts, or CI. Active integration still needs a reviewed
contract version, transport/consumer integration, resource/latency checks,
measurement-premise review, and appropriate real-host validation. The existing
mean/variance positive controls and all target cases remain required. The other
known timing and sparse-count failures remain open. CI stability and product
constant-time assurance are not established by this experiment.
