# Opt-in Dudect analysis package

Last updated: 2026-10-16
Status: draft
Owner: Aegaeon maintainers
Audience: verification maintainers

Status note: implementation candidate, not an adopted monitoring contract. The CI
hold and the product-assurance Task 3 pause remain in force.

## Scope and identities

`dudect-analysis` packages the previously evaluated interval-tail and distributed
calibration consumer. Its native source bundle is the same 80-file candidate used
in the retained AMD integration campaign. That baseline already includes the
PR-only two/three-exception supplement and the collector placement repair; it is
not the unchanged public `91d0` tree.

The new package does not add prepasses, modify callbacks, or change the native
timer. In `distributed` mode it replaces only PR `nix/hmac_sha256` crops 1–100.
Raw 0 and statistic 101 keep their original populations and center. Other cases
keep their populations. `interval-only` does not replace any population. Both
modes use certified Student-tail intervals at the exact values of the already
computed binary64 t and degrees of freedom. This does not certify the upstream
moments, t/df approximation, exchangeability, or independence assumptions.

Original decisions and sparse proofs are retained separately. Original HMAC crop
detections are not ORed into the replacement gate; previous detections within the
new history remain absorbing. The old sparse supplement is not transferred to
the new crop population. Numeric uncertainty remains a failure. The fixed native
16 batches, eight looks, 102 statistics, alpha, floors and 900-second deadline
are unchanged. Prefix work and evidence writes share the 10-second/256-MiB
worker limit and the remaining case deadline.

Native artifact binding and analysis binding are distinct. Analysis schema
`dudect-research-analysis/3` includes implementation hashes, Python, Python-FLINT,
the package recipe, and a runtime-library inventory. Runtime identity includes
both the Nix environment interpreter and the actual kernel executable path;
these may be hard links with different names. The worker verifies this binding
before reading observations. Schema 3 also binds the separate, count-conditioned
four-exception policy; see [its domain and proof](dudect-pr-four-exception.md).
Its private C locale with explicit UTF-8 avoids a
large inherited locale mapping without changing the native environment.

## Build and use

The following builds perform functional checks, not physical timing admission:

```sh
nix build .#dudect-analysis
nix build .#dudect-analysis-native-gcc-legacy .#dudect-analysis-native-gcc-nix
nix build .#dudect-analysis-native-clang-legacy .#dudect-analysis-native-clang-nix
```

The analysis install check runs deterministic clock fixtures with the real HMAC
callback, plus numerical, prefix, resource and failure tests. Native packages run
`--self-test` for every case: 11 legacy and 10 Nix per compiler. Building these
packages does not run a real-clock timing gate, retry a statistical failure, or
wire the candidate into the existing CI workflow.

An explicitly planned physical invocation uses the packaged native directory:

```sh
result/bin/dudect-analysis \
  --package /absolute/path/to/native-package \
  --output /absolute/path/to/new-evidence-directory \
  --suite nix --mode distributed \
  --packet frozen-campaign-id --unit frozen-run-id
```

This command **does run native measurements**. Its identifiers affect the frozen
calibration partition and must be fixed before acquisition. The output directory
must be new. Configure and verify the intended CPU/environment profile before
invocation; the consumer's owned-process affinity checks do not establish
exclusive hardware, absent IRQs, or absent hypervisor interference. The evidence
uses a research envelope, never the adopted gate's success envelope.

Use `--output PATH --verify-only` to replay evidence with its original matching
analysis package. A different implementation/runtime identity is rejected. A
cross-version reanalysis must create a separate record linking both identities;
it must not rewrite the source evidence or become a fresh measurement result.

## Dependency and deployment limits

The package currently targets x86_64 Linux and pins Python-FLINT 0.9.0's CPython
3.13 manylinux wheel by URL and SHA-256. Nix patches its loader paths and records
the resulting extension/shared-library bytes. The pinned wheel is a binary
dependency, not a claim that FLINT and its bundled libraries were rebuilt from
source here. Python-FLINT and bundled-library licenses remain dependency review
inputs. `flake.lock` is unchanged.

Rebuilding native packages can change compiler, linked-library, and executable
bytes despite an unchanged measurement source inventory. Non-timing tests and
replaying old observations do not physically qualify those new executables.
The exact five outputs recorded in the 2026-10-16 Nix AMD validation have now
completed two all-case cycles (84 roles) on one AMD guest allocation. That result
qualifies only those bytes and the recorded configuration. It does not transfer
to another rebuild, generic hosted runner, or a different CPU layer. Formal
adoption, retained historical detections, sensitivity acceptance and an agreed
CI operational failure-rate assessment remain separate requirements. No CI
restart or product assurance follows from a build.

## Contract and CI integration review

Status: review candidate; neither contract adoption nor workflow activation.

The intended numerical norm is the mathematical Student tail at the **computed
binary64 t and degrees of freedom**, enclosed with Arb. It is not the legacy
binary64 tail routine's output, nor a certification of the upstream statistics.
The 63 intentional threshold fixtures include seven legacy/reference decision
differences. Therefore preservation must be stated precisely:

- The sparse supplement cannot remove a valid original detection or add a new
  rejection within its reviewed two/three-exception domain. The separate
  four-exception supplement has the same pointwise property only when its
  exact actual-count lower bound is sufficient.
- Each effective history retains its own earlier detections and numerical
  uncertainty. Positive controls retain the specified statistic 0/101 rule.
- Interval-tail correction can change a legacy decision at the threshold.
  The original decision remains evidence; ORing it into the new decision would
  contradict the new numerical norm.
- Distributed crops replace the old HMAC crop population. Original detections
  remain in the original record, not in an implicit combined rejection family.

Raw 0 and statistic 101, and all statistics of the other 20 cases, retain their
populations. Their PR Welch tail evaluation still changes to the interval norm.
Periodic observations are outside this candidate. Calibration reservation is
one slot per original 16-slot group, before sample eligibility; each look uses
only its current prefix. Counts can decrease when a new boundary is selected.
Complete-prefix recomputation and the existing floors therefore remain required.
Disjoint calibration and testing samples do not prove independence of a timing
series or the Welch sampling approximation.

### Evidence and acceptance boundaries

| Item | Established evidence | Still required for adoption |
| --- | --- | --- |
| Functional detector and numerical boundary | Native callback/clock fixtures, original role tests, exact sparse regression and 63 interval threshold fixtures | Preserve these requirements in the adopted version; this is not empirical power |
| Localized real-clock signal | Intel and fresh AMD: fixed early/late signal detected by new crop1 for both compilers; signal-off did not detect; raw0/101 did not substitute; AMD12 diagnostic screens/96looks and independent arithmetic pass | Adopt the explicit sensitivity domain; the fixed instruction recipe does not define a universal minimum tick effect or measured power |
| Actual packaged AMD execution | Exact analysis output and four native outputs: all 21 cases, both compilers, two cycles; full replay | Target environment decision and treatment of historical unresolved detections |
| Failure contrast | Earlier research artifact: original HMAC count failure with candidate completion on the same raw | Do not transfer the contrast to the 2026-10-16 Nix campaign, where both original and effective roles passed |
| Runtime and environment | Recorded CPU placement, SMT off, no known competing user workload, bounded live analysis | Version the required/read-back/observed/unknown conditions; the generic hosted Ubuntu label is not this environment |
| Operational stability | Two cycles on one guest, without replacement | Choose the target rate, confidence and independent opportunity unit before sizing confirmation; no default 5% target |

The fixed AMD counterpart completed on 2026-10-16: eight processes, twelve diagnostic
cases and 96 looks, without stronger signals or replacement trials. New crop1
first detected early signals at look 6 (GCC) and look 5 (Clang); late signals
detected at look 8 only. GCC early detection remained in history even when its
final instantaneous test did not detect. All signal-off cases and designated
controls met their frozen criteria. All six HMAC raw0/101 histories did not
detect, so they did not substitute for crop sensitivity. Diagnostic wrappers
and isolated HMAC processes remain distinct from ordinary full-suite execution.

This clears the missing AMD engineering screen; it does not establish a
minimum tick effect, measured power or a CI failure rate. Existing CI remains
held. That earlier package left the known HMAC-key four-exception histogram
outside its two/three supplement. The successor now includes a separate
actual-count-bound four-exception policy. Its frozen saved-data regression
covers 340 cases / 2,720 looks: the only incremental four-policy change is the
known HMAC key case (56 statistics across eight looks). All previously valid
decisions and detections survive. Nine failures remain in that sparse-only
regression; it is not a distributed-calibration or physical CI acceptance result.
The new analysis output must be evaluated under its own identity. Formal
contract/environment adoption and migration of all CI owners remain open.

The schema-3/four-exception successor has now completed one additional fixed
42-case AMD opportunity through the fresh matrix owner. All four suite units,
42 role requirements and 336 looks completed in 2,134.17 seconds; replay agrees
with the live results. Both HMAC message replacement crops satisfy the final
floors. The four-exception branch did not occur in this new physical data; its
branch evidence remains the retained histogram and deterministic native-clock
fixtures. Original HMAC crops also completed, so this opportunity is not a new
failure-to-repair contrast. The temporary instance and disk were removed after
hash-verified recovery. This new opportunity does not qualify hosted runners.

The user selected retaining GitHub-hosted runners. See the separate
[hosted migration candidate](dudect-hosted-migration.md) for the environment gap,
bounded next screen and complete ownership migration. The current AMD-specific
supervisor is not a hosted-runner implementation; its checks must not be bypassed
to make that environment appear qualified.

Environment admission and statistical outcomes are separate. Preserve all raw
values and the original/effective roles when an environment requirement fails.
An observed context switch does not by itself prove which samples it affected;
it is not an automatic zero-event acceptance condition. Guest observations do
not certify host scheduling, firmware or physical-core exclusivity.

### Current CI entrypoints

| Entrypoint | Current behavior | Required migration decision |
| --- | --- | --- |
| `scripts/ci/dudect_check.sh` / verification Dudect job | Builds `dudect-check`, invokes old `run_contract.py`, fresh Nix observations | Select pinned analysis and both compiler packages; adopt a new result envelope, retain all evidence |
| verification legacy job | Fresh legacy `run_contract.py` | Include legacy 11 cases for both compilers in the same declared opportunity |
| `verify-dudect` / `scripts/flake/verify_dudect.sh` | Nix build-time old Nix timing gate | Explicitly decide ownership; a cached derivation is not fresh runtime evidence |
| `verified-reqs` / `scripts/flake/verify_reqs.sh` | Nix build-time old legacy timing and old report validator | Preserve unrelated checks; explicitly migrate timing ownership and evidence validation |
| core runner / `collect_dudect_nix_output.py` | Runs and retains both build-time timing outputs | Keep exhaustive ownership and failure retention; do not silently count duplicate attempts as one family |
| periodic workflow | Separate periodic old consumer | Leave unchanged by this PR-only candidate; historical periodic obligations remain |

Changing only the visible fresh Dudect job would leave the old HMAC crop gate
active through the build-time path. Conversely, merely accepting a research
report in the old validator would silently adopt a different numerical contract.
The future migration must name every entrypoint and its owner. It must preserve
complete artifact retention on failure/cancellation, fail on missing or skipped
matrix cells, and keep builds separate from a fresh runtime decision. No such
workflow migration is activated by the package or this review.

### Offline matrix verifier

`scripts/ci/verify_dudect_analysis_matrix.py` is an independent integration aid.
It changes neither the physically checked native packages nor the analysis
implementation. It verifies a declared matrix of full legacy/Nix suites under
both GCC and Clang, for each listed cycle, using the immutable package's
`--verify-only` entrypoint. It never supplies arguments that launch timing.

The plan schema is `dudect-analysis-replay-matrix/1` and binds:

- `adopted: false`, `mode: distributed`, fixed `packet`, unique `cycles`;
- `analysis_package.path` and `executable_sha256`;
- `case_contract_sha256` and four `native_packages` entries (`gcc-legacy`,
  `gcc-nix`, `clang-legacy`, `clang-nix`), each with `path` and `index_sha256`;
- `units`, each with `id`, `cycle`, `compiler`, `suite` and the complete frozen
  `analysis` identity, including the original split identifiers.

The plan is a trusted review input. Its digest is supplied separately; neither
the digest nor the verifier proves when the plan was created. For historical
data, derive identifiers from the pre-acquisition plan and label the new matrix
record as retrospective validation. Never generate new split identifiers for an
existing observation. Each evidence directory is `<evidence>/<unit.id>/gate`.

```sh
python3 scripts/ci/verify_dudect_analysis_matrix.py \
  --plan /private/replay-plan.json --plan-sha256 REVIEWED_SHA256 \
  --evidence /private/campaign --output /private/new-replay-result
```

The output must be new and outside the source evidence. The verifier validates
all declared units even if one is absent or fails, and retains per-unit logs and
partial summaries. A 900-second **offline replay** timeout bounds each unit;
it is separate from the native case deadline and cannot extend a measurement.
The pinned verifier's quiet exit 0/1 protocol is checked, including its complete
raw/prefix/decision/role replay. A traceback, unexpected output, timeout, process
signal, identity mismatch or missing case fails evidence verification. A valid
statistical failure remains a verified failure, never a passing unit.

Exit 0 means only that the complete research matrix was replayed and all its
role requirements were met. Output always records `ci_admission: false`,
`fresh_measurements: false`, and `environment_admission: not_assessed`.
Environment receipts, campaign freshness and formal acceptance must be assessed
separately. This verifier is not connected to the existing CI success envelope.

### Fresh matrix owner candidate

`scripts/ci/run_dudect_analysis_matrix.py` executes one declared opportunity:
all 21 cases under both compilers, four suite units and no replacement trials.
It consumes the same pinned package/index/analysis plan as the offline verifier,
plus an exact `execution` policy. It creates new evidence directories, preserves
statistical failures while continuing the fixed schedule, and stops on
collection, identity, environment or deadline errors. Missing units stay
unstarted; they do not disappear from the denominator. Builds finish before
measurement. It does not launch a cached build-time timing verdict.

The explicitly limited guest environment is EPYC 7R13, two distinct guest cores,
SMT off, CPU1 isolation/nohz/IRQ configuration, supervisor and other known user
threads on CPU0, native measurement on CPU1, SCHED_OTHER and no CPU quota.
Read-back checks at idle boundaries are separate from fault/switch/IRQ/steal
observations. Nonzero event counts do not delete samples or automatically fail a
run. Unreadable required process affinity is an unknown configuration, not zero
competition. Physical core exclusivity and hypervisor/firmware activity remain
unobservable. A cgroup root without `cpu.max` is the explicit root-unlimited
case; an unobservable non-root quota fails.

```
python3 scripts/ci/run_dudect_analysis_matrix.py \
  --plan /private/frozen-matrix-plan.json --plan-sha256 REVIEWED_SHA256 \
  --output /private/new-campaign
```

This command performs fresh timing. It remains a research entrypoint with
`ci_admission: false`; its successful result is not accepted by the old gate
validator. The intended migration has one owner of fresh timing: PR verification
must require this complete matrix, while core/build-time checks retain static
and functional verification only. The old fresh Nix/legacy invocations and both
build-time timing invocations must be changed together. Standalone core and
release callers need an explicit timing dependency or a clearly narrower
non-timing result; no cached receipt can fill that dependency. Periodic retains
its separate contract. Workflow activation remains held until the target
runner, adopted result contract and operational acceptance decision are fixed.
