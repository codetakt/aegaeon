# Per-case timing observation contract

Last updated: 2026-10-12

Status: current implementation baseline

Owner: Engineering

Audience: verification tooling maintainers

Version 5 preserves all eleven original case identifiers and historical outcomes,
adds four target-bound observations and executes three synthetic controls in each
suite. This contract governs bounded empirical monitoring. It does not change
product claims, declare production messages public or discharge product assurance
obligations. Runtime evidence, source review and publication disposition remain
separate from implementation status.

| Case | Observation role | Target / remaining limit |
| --- | --- | --- |
| `legacy/compare` | measurement negative control | Local ct_eq copy in compare_timing_test.c; Not production ct_eq; timer quantization makes first three crops degenerate |
| `legacy/hmac` | authentication result characterization | jws_hmac_verify -> EverCrypt_HMAC_compute + c/jws.c ct_eq; Fixed-secret tag validity comparison does not test variation across secrets; output declassification undefined |
| `legacy/ed25519` | public fixture characterization | Jose_Rsa_signatures_verify_ed25519 -> EverCrypt -> HACL verify; No signing-secret argument; classify signature/message exposure and expected public-dependent behavior |
| `legacy/rsa` | public fixture characterization | Jose_Rsa_signatures_verify_rsa_pss -> Hacl_RSAPSS_rsapss_pkey_verify; No private-key argument; classify public validity-dependent work separately before changing acceptance |
| `legacy/jwe` | authentication result characterization | Jose_Jwe_chacha20poly1305_decrypt -> EverCrypt AEAD decrypt; Authentication result changes output and can change decryption/write path; preserve failure pending declassification contract |
| `nix/ct_eq_32` | measurement negative control | Local ct_eq copy in c/dudect_harness.c; 1,000 full comparisons; target is local helper, not product FFI; stride is not comparison length |
| `nix/ct_eq_64` | measurement negative control | Local ct_eq copy in c/dudect_harness.c; 1,000 full comparisons; target is local helper, not product FFI; stride is not comparison length |
| `nix/ct_eq_128` | measurement negative control | Local ct_eq copy in c/dudect_harness.c; 1,000 full comparisons; target is local helper, not product FFI; stride is not comparison length |
| `nix/sha256` | protected input observation | Hacl_Hash_SHA2_hash_256; No keyed secret input; must state whether message is treated as secret for this observation |
| `nix/hmac_sha256` | protected input observation | Hacl_HMAC_compute_sha2_256; Does not vary secret key; input confidentiality/observation contract unspecified |
| `nix/ed25519_verify` | public fixture characterization | Hacl_Ed25519_verify; Trace differs in 99 of 104 table indices; all selectors predictable from the fixture public inputs; exact old timing cause remains unisolated |
| `legacy/compare_product_32` | protected input observation | c/jws.c::ct_eq compiled from the actual product source, not a helper copy; 32-byte empirical coverage only; other lengths and caller composition remain outstanding. |
| `legacy/hmac_key_reject` | protected input observation | c/jws.c::jws_hmac_verify -> EverCrypt_HMAC_compute + product comparison; Covers the sampled rejection stratum only; valid-result and all-key-domain obligations are not discharged. |
| `legacy/jwe_key_reject` | protected input observation | c/jwe.c::Jose_Jwe_chacha20poly1305_decrypt -> EverCrypt AEAD; Valid decryption, plaintext release, all keys and caller composition remain separate obligations. |
| `nix/hmac_sha256_key` | protected input observation | Hacl_HMAC_compute_sha2_256 in the same pinned provider; Finite key observations do not establish universal key/input constant time; artifact and observation-model restrictions remain. |

Native SHA/HMAC observations use the original HACL API targets after the shared
CPU-policy initializer. The [native dispatch description](dudect.md#native-sha-dispatch-and-initialization)
records this setup, the supplier patch and its proof boundary. This implementation
change does not alter the case domains or numerical contract below.

Exact inputs, conditional key domains, class construction, allowed values and
residual obligations are in [the machine-readable contract](../../tests/constant_time/contracts/case-contract-candidate.json).
The historical filename is retained for stable references. These finite cases do
not complete the original full secret domain or caller-composition proof.

The provider comparison uses a compiler memory barrier before each of its 1,000
comparisons. The pinned Clang otherwise hoists it out of the loop and repeats
only the OR of its cached result. The barrier preserves repeated reads of both
32-byte operands without adding a CPU fence or changing the comparison algorithm,
input classes, strides or inference. Generated-code regression checks cover both
compiler profiles; runtime evidence still requires the actual artifact. Historical
artifacts keep their observed workload and outcomes. This correction alone does
not explain or resolve a timing difference detected with the GCC artifact.

## Per-case completion

Protected-input observations and measurement negative controls require the full
schedule and eligible nondetection at all 102 statistics. Public/authentication
fixture cases complete characterization with their actual statistical outcomes,
including detected differences; they still require all records and raw floors.
Authentication-result characterization does not adopt a production timing
declassification policy. The added secret-key rejection strata cannot substitute
for valid-result, all-key or caller-composition obligations.

| Synthetic case, executed in both suites | Required result | Limit |
| --- | --- | --- |
| `control_independent` | Complete eligible nondetection | Independent uniform work count 256–287; no cryptographic coverage |
| `control_mean_shift` | Raw statistic 0 detects the added 64 operations | Finite mean-sensitivity control |
| `control_variance_shift` | Second-order statistic 101 detects a symmetric ±1,024-operation shift | Strong variance control; smaller changes remain uncertified |

The JSON eligibility field describes individual statistics. Each case specifies
which statistics must be eligible: all 102 for nondetection, and the designated
raw/second-order statistic for a positive control. A shifted control may have
sparse other crops; those records remain ineligible and visible.

A failed control rejects the current attempt. Detection at another statistic does
not satisfy a positive control's designated test. All observations are retained;
fixed calibration trials include failures and inconclusive runs in their results.

## Numerical interpretation

The family contains 21 executions × 102 statistics × at most eight looks. The
per-inspection allocation is `5.835667600373483e-7`. Existing raw floors of
200,000 / 3,200,000 remain. The PR profile measures 16 batches, with inspections
at 1 through 7 and 16; periodic still measures 98. The additional final PR look
uses the previously reserved eighth look and cannot cancel earlier detection.
The [profile budget](dudect.md#numerical-design) changes the numerical identity;
seven-batch evidence cannot be admitted as an extended-profile result.
The normal raw-mean
planning approximation needs 197,075 / 3,153,193 observations per class for effects
0.02 / 0.005 at 90% power. This approximation does not establish real power,
second-order sensitivity or runtime.

Native integer crops include every tick equal to the frozen pilot cutoff. This
preserves whole ties without removing any of the 100 crop statistics. Sparse
crops remain inconclusive even if raw counts meet their floors.

Certified identical pooled native integer support, with both counts greater
than 10,000, uses the exact absolute-mean-difference permutation upper tail:
every relabeling yields zero, hence p=1. The null is equality of distributions
with exchangeable class assignment and class-independent measurement behavior.
It is stronger than equality of means under arbitrary unequal distributions.
Positive finite variances retain fractional-df Welch inference and its assumptions.

The single-outlier amendment, adopted on 2026-10-12, adds one prospective case:
the pooled native integer multiset has exactly two values, with multiplicities
1 and N-1. Selection depends on the pooled values, independently of the label
of the exceptional sample. Both class counts must exceed 10,000; both native
values must be exactly representable in binary64 and their actual transformed
values finite and distinct. All original cases, 102 statistics, fixed inspection
schedules, raw floors, alpha allocation and absorbing detections remain required.

Condition on the pooled values and retained class sizes n0,n1 under the same
exchangeability null. If the transformed values differ by D>0, putting the
exceptional value in class j has probability nj/N and absolute mean difference
D/nj. For its observed class g, the inclusive upper tail is therefore exactly:

```text
p = sum(nj for j in {0,1} if nj <= ng) / (n0+n1)
```

The recorded numerator and denominator and the threshold comparison use integer
arithmetic; the decimal p-value is descriptive. This is p=1 for tied class sizes
or an exceptional sample in the larger class, and ng/N otherwise. The method
does not estimate multiplicities from rounded means or M2. Multiple exceptional
samples, wider support, floating aliases, centered-square collisions, sparse
classes and all other unsupported zero-variance configurations remain ineligible.
No general replacement for undefined Welch values is adopted.

Every statistic carries per-class native int64 extrema/count, exact endpoint
multiplicities and binary64 transformed extrema. Coincident endpoints each carry
the full class count; they are counted only once when pooling the multiset.
Validation rejects impossible or shrinking support, incorrect crop/second-order
ranges and moment/support mismatches. For every look using the new method, the
collector and admission replay additionally reconstruct counts and endpoint
multiplicities from the original timing frames, using native sample indices,
labels, nonnegative deltas and inclusive frozen cutoffs. Missing, truncated or
mismatched evidence fails admission. This check keeps bounded per-cutoff summaries
and does not retain all samples in memory. Existing inference remains unchanged.

Schema 5 and a new numerical/contract identity bind this amendment. Versions 2–4
and their frozen validators retain their original outcomes; old failed or
inconclusive evidence cannot be converted into success. The amendment does not
resolve observed SHA/HMAC differences or the historical periodic ct_eq_128 cause.
Finite numerical controls and native calibration do not prove the null assumptions.

When the frozen pilot center is outside or at an endpoint of the attained tick
interval, the centered-square transform is monotone on that interval. Its minimum
and maximum must therefore equal the transformed endpoints. In particular, a
singleton tick cannot claim nonconstant squared support before the exact-tail
shortcut is considered. A center strictly inside the interval can instead have
its squared minimum at an attained interior tick. When exact endpoint counts
cover the whole class, no interior tick exists, so the squared minimum must
also equal the smaller transformed endpoint even with an interior center.

### Necessary moment bounds and rounding

Before Welch inference, each nonconstant class must have moments consistent
with its attained binary64 minimum `a`, maximum `b`, and count `n`. For an exact
mean `mu` and squared-deviation sum `M2`, necessary bounds are:

```text
a + (b-a)/n <= mu <= b - (b-a)/n
(mu-a)^2 + (b-mu)^2 <= M2 <= n*(mu-a)*(b-mu)
```

The mean bounds account for at least one occurrence of each distinct extremum.
The lower M2 bound retains those two contributions. For the upper bound, sum
`(x-a)*(b-x) >= 0` and use `sum(x) = n*mu`. These are necessary conditions,
not a complete reconstruction of the sample distribution.

The native `t_push` uses binary64 Welford updates, so exact bounds are padded;
the observed moments are never clamped, replaced or used to relax a p-value
threshold. Let `R` be `b-a` rounded upward, `q = ulp(b)`, `u = 2^-53`, and
`eta = 2^-1074`. Counts cannot exceed the largest configured retained-sample
budget. For the existing profiles this is fewer than 6.5 million samples and
`n*u < 10^-9`. The consistency check uses:

```text
E = 4*n*q
D = E + q
B = 8*n*(R*D + D^2 + n*u*(R+D)^2 + eta)
```

`E` conservatively bounds accumulated mean roundoff: each convex mean update
adds at most a few ulps on the nonnegative support scale. Each computed delta
then differs from the exact-mean delta by at most `D`, so a product's deviation
is bounded by `2*R*D + D^2`. Product and nonnegative-sum rounding contributes
less than `4*n^2*u*(R+D)^2` at these counts, with an absolute allowance for
underflow. The factor eight covers these terms and evaluation roundoff in the
budget itself. The budget and final comparison endpoints are rounded outward;
nonfinite budgets are rejected. This assumes the existing native binary64
round-to-nearest arithmetic without unsafe floating-point reassociation.

The mean interval is widened by `E`. The M2 lower endpoint uses
`max(0, mean-a-E)^2 + max(0, b-mean-E)^2 - B`; its upper endpoint uses
`n*(mean-a+E)*(b-mean+E) + B`. Large offsets and tiny spreads can make these
necessary checks loose; passing them is not a floating-point accuracy proof.
Singleton and empty-support checks, numerical inference, eligibility, sample
floors and original statistical outcomes retain their existing rules. The
consumer source digest binds this additional fail-closed validation.

## Artifact and migration boundary

The active entry point is `tests/constant_time/run_contract.py`. Nix caches a
build-only package; fresh CI imports it only after matching all current source
hashes and executes the complete native schedule. Each record binds case, profile,
contract, numerical policy and compiler-manifest digests. Retained binary hashes,
process status, observations and stdout must agree with the final report.

Current consumers reject schemas 2 and 3. Old failures retain their original
meaning; replay cannot convert them into version5 success. Statistical outcome
and `observation_contract_satisfied` are distinct. The diagnostic
`run_candidate.py` remains collection-only and cannot publish accepted evidence.

Both compiler profiles can run setup/operations without timing:

```sh
nix develop .#verification -c python3 tests/constant_time/run_candidate.py --suite all --adapter shell --self-test-only
nix develop .#verification -c python3 tests/constant_time/run_candidate.py --suite all --adapter xtask --self-test-only
```

The product comparison compiles the actual static helper from `c/jws.c` and varies
mismatch positions uniformly. HMAC and AEAD rejection cases hold public fixtures
fixed while varying keys. Preparation checks conditional domain membership outside
timing, records draws/exclusions and aborts after 128 unsuccessful draws per input.
AEAD also checks failure destination bytes and restores the same initial buffer.
The provider key case checks a known-answer vector. Setup may change cache state;
its role must be considered when interpreting native calibration.

## References and residual obligations

[Timing observation profiles](dudect.md) documents entry points, thresholds,
retention and failure behavior. Full actual PR/periodic execution, appropriate
source/CI review and recorded evidence remain required for each implementation
revision; none follows merely from successful synthetic tests.

The pinned [HACL* Ed25519 verifier](https://github.com/hacl-star/hacl-star/blob/531820c1af15cafc2437068fb565fa0b8b431e73/dist/gcc-compatible/Hacl_Ed25519.c)
uses variable-time double scalar multiplication and direct table indexing from
verification inputs. Public-fixture characterization does not determine message
confidentiality for every production caller.

The [SciPy permutation-test definition](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.permutation_test.html)
describes the equal-distribution/random-label null and exact tail interpretation.
Our identical-support and single-outlier special cases fix the absolute difference statistic and
its upper tail explicitly. Finite numerical controls do not certify every
continuous, cropped or second-order test, nor the full product observation claim.
