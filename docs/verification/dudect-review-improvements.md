# Dudect replay reporting and operation-test improvements

Last updated: 2026-10-22

Status: draft

Status note: additional offline reporting and launcher checks; measured evaluator and adopted contract unchanged.

Owner: Engineering

Audience: CI maintainers, verification reviewers

The [limited baremetal contract](dudect-baremetal-contract.md) is adopted for its
recorded measurement identity. The improvements here address the optional review
findings without replacing that identity or editing its historical receipts. They
do not grant CI admission or transfer physical qualification to a new executable.

## Replay-bound reporting

[dudect_replay_report.py](../../scripts/validation/dudect_replay_report.py) verifies
one recovered ordinary executable from the finite plan. Use its original pinned
Python/Arb environment and measured modules on `PYTHONPATH`. The expected invocation
digest must come from the fixed plan. A current source checkout cannot silently
replace the measured modules: the existing live identity check still applies.

```sh
python scripts/validation/dudect_replay_report.py \
  --output /path/to/recovered/process \
  --invocation-sha256 "$planned_invocation_sha256" > /path/to/new/report.json
```

The reporter checks the package, exact executable case inventory, analysis identity,
process completion, diagnostics and native stdout. It invokes the existing raw
prefix replay and role evaluator and requires equality with the saved assessments.
It hashes the process files before and after verification. The streaming inventory
is limited to 512 regular files and 4 GiB per recovered process; symlinks and FIFOs
are rejected. This offline limit is separate from the measured per-look budget.
Use quiescent, authenticated recovered storage. These consistency checks do not
provide a sandbox against a concurrent hostile filesystem writer.

Only after those checks does the reporter create `ordinary-local-replay-receipt/1`.
Each case's new `expected_identity` contains its replay receipt digest, analysis
digest, original assessment digest and role contract digest. The original evaluator
and its identity remain unchanged. This implements the additional replay binding
at the reporting boundary; it does not retrofit historical evaluations with new
provenance or establish an independent operator merely by producing another JSON.
The reporter source, ordinary module and interpreter digests are also recorded.

Reports distinguish:

- The original `statistical_outcome` from the new observation display. The latter
  reports `budget_nondetection` only when the raw floor, final raw0/101, final
  statistics, evidence and execution checks hold. An observed detection is retained
  even if its case fails another obligation. Qualification remains the old result.
- Legacy `execution_valid`, which follows the caller's checks, from completed local
  replay checks. The reporter does not claim independently verified environment,
  stopping or recovery merely because the legacy evaluator received `True` flags.
- Original and effective detections at each statistic/look, including original-only
  crop detections in nondetection-role cases. Characterization and positive controls
  remain separate. This reporting does not OR the two gates or equate their power.

The CLI exits 0 for a verified satisfied role inventory, 1 for a verified inventory
with unsatisfied roles, and 2 for verification failure. Every output retains
`ci_admission: false`. Authenticating the producer, independent verifier execution,
request freshness/consumption and the external lifecycle remain CI adapter duties.
Do not connect this command's exit status directly to Required checks.

## Deadline installation order

The public `scheduled_ordinary(cutoff, ...)` helper installs
`schedule.installed(cutoff)` before calling `ordinary.execute`, which installs the
live worker and stream. The cutoff is a finite absolute monotonic time supplied
by the already bounded controller. Insufficient initial time is rejected before
execution. The existing stream withholds the ACK if the next case cannot fit;
success and exceptions restore both installation contexts.

This closes the public-caller and installation-order gap. It does not implement
an independent stop guard, provision infrastructure or authorize a new run. The
external owner must still enforce stopping, authenticated recovery and cleanup.
The CLI above is replay-only and cannot invoke measurement through this helper.

## Portable operation tests

[run_dudect_operations_tests.py](../../scripts/validation/run_dudect_operations_tests.py)
runs the existing operation suite with a supplied absolute `age` executable and
expected SHA256 values for both `age` and adjacent `age-keygen`. Obtain those
paths/digests from the selected pinned dependency, not an untrusted job artifact.
There is no implicit PATH fallback or skip when the tool is missing.

```sh
python scripts/validation/run_dudect_operations_tests.py \
  --age "$pinned_age" --age-sha256 "$pinned_age_sha256" \
  --age-keygen-sha256 "$pinned_age_keygen_sha256"
```

After discovery and before test setup, this runner injects only the test module's
`AGE` dependency, restoring it afterward. The frozen test source retains its
historical store path for source correspondence. Direct discovery of that archived
module retains its original environment requirement; this is the portable entry.
The tests exercise encrypted round trips, corruption rejection and process/deadline
handling, without timing a cryptographic target or using cloud resources.

## Compatibility and disposition

| Review observation | Treatment |
| --- | --- |
| Replay provenance | New replay-bound report, without changing measured evaluation |
| Fixed receipt booleans | Preserve checked caller flow; expose its basis and keep external lifecycle unverified |
| Outcome/raw-floor ambiguity | Separate budget-qualified display and retain original assessment |
| Original-only crop detections | Generate the dedicated reporting axis for every ordinary replay |
| Detection role/sparse counts and sensitivity limits | Already recorded in the contract follow-up receipt and contract documentation |
| Scheduler installation ordering | Public helper plus tests of actual installation contexts and ACK refusal |
| Hardcoded test executable | Explicit digest-checked test dependency injection |
| Historical names | Retain wire identifiers; interpret scope through the bound scope/role contracts |
| Alpha and native-moment asymmetry | Retain the reviewed numerical baseline and its documented limits |

In particular, `six-case-calibration-review/1` is a historical schema identifier,
not a case-count authority. The HMAC-named `distributed.POLICY` describes the
inherited selector/quantile component; it does not replace the seven-case scope
contract. Renaming those hash-bound constants would create a new analysis identity
without improving the measured result, so they remain compatibility identifiers.
New reports use `ordinary-replay-report/1` and explicit case inventories. The
HMAC-only research entry remains outside the adopted seven-case entry.

The limited contract review stays closed. Further review of authenticated CI
admission is separate. The ordinary measurement source, mathematical inference,
role requirements, historical failures and physical evidence are unchanged.

## Verification result

The [implementation receipt](../../ci/evidence/dudect-optional-review-20261022.json)
binds the added files and records 24 new regression tests, 31 including the existing
adoption checks, passing under normal Python and `-O`. The 55 operation tests pass
with the pinned age executable and with the same executable bytes copied to a
different path. The real replay CLI also verifies three existing controls and
rejects an incorrect planned invocation digest.

All 44 retained ordinary processes, 84 cases and 672 looks replay through the new
reporter with zero saved-assessment differences. All 22,350 original detected
statistic/look pairs remain counted, with no original-only crop detection in this
ordinary inventory. Those 84 cases are the existing I21 evidence, not new trials;
the separately tested CLI controls are a repeat subset, not three more observations.
This uses the existing numerical verifier and does not claim a new independent
numerical algorithm. The 54-file historical source correspondence check also passes.
