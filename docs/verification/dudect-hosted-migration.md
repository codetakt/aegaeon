# GitHub-hosted Dudect migration candidate

Last updated: 2026-10-16
Status: draft
Owner: Aegaeon maintainers
Audience: verification maintainers

Status note: hosted diagnostic implementation prepared; no formal adoption or ordinary CI restart.
The user selected retaining GitHub-hosted runners on 2026-10-16. Temporary AMD
guest evidence remains useful for the implementation but does not qualify that
different execution environment. No permanent runner is proposed.

## First hosted comparison

The next bounded opportunity should execute all 21 PR cases under GCC and Clang,
once each, on one fresh hosted Linux VM. This is 42 cases in four full-suite
invocations and 22 native processes. It is an engineering screen, not a
failure-rate estimate. Do not add another allocation because a particular CPU,
failure or success was not observed.

Use the existing hosted Ubuntu x86_64 runner label for this first comparison so that
the execution target corresponds to the current workflow. Record the actual
image name/version, kernel, CPU model/features/topology and supplier identity;
the label is not a hardware model or an immutable image version. The official
[hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
currently lists four CPUs and 16 GB memory for public-repository Linux runners.
Neither those capacities nor a fresh guest establish physical-core exclusivity.

Complete all builds, self-tests and evidence-directory setup before timing.
Bind the exact analysis output, four native outputs, full source inventories,
case/numerical policies and runtime dependencies. Different output bytes from
the AMD experiment must be reported as a new artifact, even with equal source.
Freeze packet/unit identifiers and all four invocations before acquisition.
These identifiers select the distributed-calibration partition and must not be
changed after seeing observations.

Run the four suites serially: GCC legacy, GCC Nix, Clang legacy, Clang Nix.
Retain the original case order within each suite. Preserve the existing
900-second case limit, 10-second/256-MiB prefix limit, 16 measurement batches,
eight looks, 102 statistics, floors and alpha. Use a 9,000-second overall timing
limit and a fixed 10-second inter-suite gap, matching the bounded AMD supervisor.
Preparation and recovery need separately enforced time limits; they cannot
extend an in-progress case. No replacement trials or automatic workflow retry.

## Environment differences that must remain explicit

The current AMD supervisor requires CPU IDs 0/1, EPYC 7R13, SMT off, boot-time
isolation/nohz/IRQ settings and no competing known user thread. It must not be
invoked on hosted runners by bypassing its checks or labelling a hosted guest as
that AMD profile. A distinct hosted diagnostic profile is required.

The existing collector placement algorithm can select a native CPU and
collector CPUs on different *exposed* cores, without assuming dense IDs. Use
that algorithm and read back the actual affinities at launch and existing
observation boundaries. Reserve the native CPU's exposed sibling set from the
owned collector, worker, supervisor and logging processes. Do not equate
exposed topology with proof of physical host placement.

Record SMT, scheduler, cgroup quota/cpuset, boot settings, known task affinities,
IRQ configuration and available fault/switch/IRQ/steal observations. Required
read-back failures are unknown or configuration failures, never zeros. Events
do not delete samples or clear a statistical failure. Unlike the AMD profile,
this first hosted screen cannot presume that unrelated guest services or
host-side activity have been excluded. Its result must name that limitation.
This is a proposed diagnostic environment, not a relaxation adopted for the
production gate. If known competing user threads remain, the stronger
competition-exclusion requirement from the AMD profile is not satisfied even
when all statistical roles pass. Production admission needs that discrepancy
resolved or an explicitly reviewed, evidence-supported hosted environment
contract; it must not be hidden in a successful test summary.

Lack of two exposed cores, incorrect owned-process placement, quota restriction,
identity mismatch, incomplete collection or timeout stops measurement and
retains the partial opportunity. Statistical failures retain their original and
effective outcomes and do not skip the remaining scheduled cases. Preserve
failure/cancellation artifacts before interpreting any success summary.

## Decision from that comparison

| Result | Consequence |
| --- | --- |
| Complete 42-case run and replay, all roles satisfied | Hosted engineering screen passes for the recorded artifact and allocation; no universal stability claim |
| Crop shortage or numerical uncertainty | Retain the failure; revisit the corresponding inference or calibration domain |
| Required 0/101 control fails | The opportunity is not qualified; do not substitute another statistic |
| Protected/negative case detects | Preserve and investigate the detection; do not relabel it as infrastructure noise |
| Environment or collection fails | Record an unsuccessful opportunity and unstarted cases; no replacement |
| Actual hosted bytes/environment differ | Report the difference and limit the conclusion; AMD success is not transferred |

Formal adoption still needs an explicit scope for numerical inference,
calibration populations, sensitivity and environment. Operational stability
requires a separately chosen target, confidence and opportunity unit. One
screen, including all its cases and looks, is not 42 independent stability
trials. The two-compiler family is not automatically the original 1% family.

## Migration ownership

After a qualifying hosted screen and explicit adoption, one fresh runtime owner
should supply the PR timing verdict. Package builds may be cached; its timing
result may not. The migration must handle every current owner together:

| Existing owner | Required change |
| --- | --- |
| Fresh Nix Dudect job | Invoke the adopted analysis/package matrix and retain its full evidence |
| Fresh legacy verification path | Become part of that same complete matrix, retaining all 11 legacy cases per compiler |
| `verify-dudect` build-time timing | Separate build/self-tests from the fresh runtime owner; do not present a cached result as a fresh run |
| `verified-reqs` build-time timing | Migrate only timing ownership/validation; preserve every unrelated verification check |
| Core check inventory and output retention | Name the delegated timing owner, fail if absent/skipped, preserve failure and cancellation evidence |
| Main push, standalone dispatch and PR/group aggregation | Each path must require the complete fresh owner; changing only PR aggregation is insufficient |
| Periodic | Remains the existing separate profile; the PR-only candidate does not qualify or replace it |

The research envelope remains distinct from an adopted gate envelope. Merely
making the old validator accept a research report would silently change the
contract. Existing CI and publication holds remain until the required scoped
decision. No historical private packet is an upload input for the hosted test.

## Implementation status

`prepare_dudect_hosted.py` builds the analysis and four native packages, records
closure/package inventories and freezes all four analysis identities before
acquisition. The identifiers derive from the first workflow opportunity, not
from observed results. `run_dudect_analysis_matrix.py` accepts a separate hosted
profile with dynamic sibling-aware placement; its isolated AMD profile remains
separate. A cgroup v2 ancestor with an active quota or unknown controller state
is rejected. A missing child CPU interface is distinguished from unknown state
only when the parent's readable subtree-control explicitly disables it; all
ancestor quotas are still inspected.

The dedicated `dudect-hosted-screen.yml` runs only on the named diagnostic
branch, never on main, PR or merge-group events. It owns one full 42-case
opportunity, allows no replacement workflow attempt, serializes all four cells,
and bounds preparation to 60 minutes and measurement to 9,000 seconds. Case and
prefix limits are unchanged. All builds and package self-tests finish before
measurement; no logger or build job is deliberately started on the native core.
The supervisor and analysis workers use housekeeping cores, with native and
collector affinity checked by the existing collector at observation boundaries.
Unrelated guest workloads remain recorded limitations, not proof of isolation.

Partial raw and unsuccessful outcomes are archived and hash-verified by
`retain_dudect_hosted.py`; `always()` steps attempt upload after failure or
cancellation. Forced runner loss and the platform cancellation deadline can
still prevent upload. An absent archive is an unsuccessful opportunity, never
a passing or replaceable run. Only this new opportunity's directory is an upload
input; historical private packets are not included. No process environment or
credential files are collected.

The ordinary fresh/build-time gates and their aggregation are unchanged until
a qualifying hosted result and a numerical/environment adoption decision. The
ownership table above is the required subsequent coordinated migration, not a
claim that it has already occurred. A research success cannot satisfy the old
validator, and no cached package build is a timing verdict.

The Linux [cgroup v2 controller rules](https://docs.kernel.org/admin-guide/cgroup-v2.html#enabling-and-disabling)
explain the ancestor/controller distinction. GitHub's
[runner variable reference](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)
and [cancellation procedure](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation)
define the recorded allocation fields and the limits of cancellation retention.
