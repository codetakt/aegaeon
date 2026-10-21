# Dudect calibration and role qualification

Last updated: 2026-10-21

Status: snapshot

Status note: finite qualification complete; the limited contract was adopted on 2026-10-22. CI admission remains open.

Owner: Engineering

Audience: maintainers, verification reviewers

The fixed bare-metal qualification completed its sensitivity and integration
inventories. The final integration satisfied **84/84 candidate roles**: all 21
cases, GCC and Clang, and two rounds. Independent arithmetic and complete consumer
replay found no mismatches. Evidence recovery, input verification and removal of
compute, root disks and temporary resources completed before closure.

The public [receipt](../../ci/evidence/dudect-calibration-qualification-20261021.json)
records each plan and closure digest, aggregate outcomes, native identities and
publication correspondence. It is a projection of retained evidence, not a trusted
CI producer attestation. Full raw inputs, timing frames, execution and authenticated
recovery records remain private. The [2026-10-19 checkpoint](dudect-baremetal-checkpoint.md)
and earlier failures retain their original identities and outcomes.

The [limited monitoring contract](dudect-baremetal-contract.md) records the
2026-10-22 review corrections, exposes the measured source bytes and specifies
the adopted entry and owner approval. It preserves this checkpoint and its original
hashes; it does not grant CI admission or transfer measurements to a rebuild.

## Candidate behavior

The PR-profile candidate replaces crops1–100 for a fixed seven-case scope, common
to GCC and Clang: Nix CT32, CT64, CT128, SHA256, HMAC message, HMAC key, and legacy
compare. HMAC key is distinct from legacy HMAC key rejection. One slot in each
16-slot block is reserved independently of time and class. Each look uses only
the current prefix, derives pooled inclusive boundaries from reserved observations,
and recomputes the remaining observations when those boundaries move. Reserved
observations do not enter the replacement crops. Raw0/101 retain their original
populations and pilot center. Other cases and periodic retain their calibration.

The replacement crops use positive-variance Welch inference. They do not inherit
the original-population sparse supplement. Original crop results remain separate;
there is no OR gate combining original and replacement crops. The 16 measurement
batches, eight looks, 102 statistics, original alpha and count floors remain fixed.
Student-tail intervals certify decisions at frozen binary64 t/df under the pinned
library assumptions; they do not certify upstream rounding or the sampling model.

Qualification follows the existing case roles:

- Protected and negative cases require final eligibility of all 102 statistics
  and a complete nondetection, with any earlier detection retained.
- Original positive controls require eligible detection in their designated
  raw0 or 101 statistic and the complete schedule, raw floor and common validity.
- Deliberate positive fixtures require an eligible detection in their fixed
  statistic set by the last look, final raw0/101 eligibility and all common checks.
  They do not require every crop to remain eligible at the last look.
- Characterization requires a complete valid observation report. It does not
  require nondetection or final eligibility of every statistic.

Insufficient or degenerate crops retain counts and reasons; they are not assigned
p=1 or silently classified as nondetections. Numerical uncertainty, malformed
evidence, incomplete collection and missed designated signals remain failures.
The [candidate implementation](../../tests/dudect_sensitivity_control_roles/README.md)
links the frozen contracts and reproducible functional checks. Historical creation
status fields in those contracts do not override the separate execution receipts.

## Completed physical inventories

Each stage used a separately frozen finite plan on c6i.metal with the required
Ice Lake CPU configuration, SMT off, separate measurement and collector cores,
and read-back environment checks. The ordinary native uses SCHED_OTHER; no prepass,
trimming, signal-dose tuning or threshold relaxation was added. Limits included
900 seconds per case and a shared 10-second/256 MiB prefix-analysis budget. A
statistical failure did not authorize a replacement trial or an extension.

| Fixed stage | Processes / cases / looks | Satisfied roles | Independent original moments / tails | Replacement class moments / tails |
| --- | --- | --- | --- | --- |
| Six-case sensitivity, first stage | 20 / 100 / 800 | 100/100 | 326,400 / 75,998 | 96,000 / 47,409 |
| Six-case sensitivity, second stage | 20 / 100 / 800 | 100/100 | 326,400 / 76,490 | 96,000 / 47,479 |
| Legacy comparison sensitivity | 40 / 80 / 640 | 80/80 | 261,120 / 59,869 | 32,000 / 15,839 |
| All-case integration | 44 / 84 / 672 | 84/84 | 274,176 / 65,713 | 44,800 / 22,285 |

All arithmetic comparisons had zero mismatches under the recorded comparison
rules; all complete consumer replays matched. Replay is not another physical
trial. The earlier six-case stages retain their own contracts and diagnostic
artifacts; they are not relabeled as measurements of the later seven-case build.

Each six-case stage satisfied 30 original controls, 34 ordinary/zero/other roles
and 36 designated physical-signal targets. The comparison stage satisfied 60
original controls, eight ordinary/zero roles and 12 designated signal targets.
The full, early/late and history-dependent physical signals require a witness
in crops1–100 by the final look. The lower-tail crop1 component fixture uses an
injected clock and remains functional evidence, not measured weak-signal power.
Neither these finite signal outcomes nor the count floors establish sensitivity
to arbitrary leakage distributions or detection during the signal's active period.

The final integration completed in 5,719.435 seconds. All 24 original controls
and all 60 remaining candidate roles were satisfied. The original evaluator
satisfied **83/84**: first-round GCC CT32 retained this inconclusive crop1:

| Evaluation | Final cutoff | Class0 / class1 counts | Result |
| --- | --- | --- | --- |
| Original pilot crop | 12,466 | 7,477 / 7,434 | Inconclusive |
| Distributed candidate | 12,474 | 55,961 / 56,424 | All final statistics eligible; no detection |

The boundary and selected population differ. This does not demonstrate a physical
improvement within the original crop. All 22,350 original detected statistic/look
pairs remain in the original record, including detections permitted by positive
control and characterization roles. No earlier failure is rewritten as success.

Authenticated recovery returned 804 files (2,079,095,923 bytes) for the comparison
and 868 files (2,288,287,625 bytes) for integration. All hashes matched, and frozen
inputs remained unchanged after replay and audit. Each stage removed its instance,
root disk and nine temporary resources, with five provider absence checks.
Private encrypted, versioned evidence storage remains. Initial deployment,
authentication and cleanup failures are retained separately from final closure;
the earlier unmeasured startup failure is not a successful trial.

## Publication and artifact correspondence

The publication implementation is commit
`b320610b2ca977f779bd2bfb51908697ee5399fc`, including the main-branch security fixes.
The 54 added files contain the calibration scope, role evaluator, diagnostic
signals, input checks and bounded collection. Formatting preserves measured
executable syntax and import order; JSON contracts and C hooks are byte-identical.
One receipt test now creates its own complete fixture instead of requiring a
private capture. The public receipt records both measured and publication hashes.

The publication copy passed 211 candidate functional tests, 32 existing analysis
unit tests and 11 installed-analysis tests. All configured hooks passed for the
changed files. Four native packages and the analysis package rebuilt; all 42
actual-crypto non-timing case checks passed. Commands for the candidate groups
are in the implementation README. These are not additional timing measurements.

Each native package's 80 source inputs match its measured counterpart. All 22
rebuilt ELF files have identical `.text` bytes and addresses, but their complete
bytes differ. The differences are confined to the output-store path and embedded
build binding: replacing just those strings in memory explains the complete byte
difference. Five additional empty source directories changed the Nix source path.
No transformed ELF was saved or measured. This correspondence does not transfer
physical qualification to the rebuilt binaries; the actual measured identities
remain authoritative in the receipt.

The previously unsigned introduced commits were re-signed without changing their
trees. Publication preserves the measured revision identities rather than
substituting new commit IDs into old receipts. This checkpoint does not merge the
PR or enable ordinary Hosted timing.

## Remaining admission work

The next review concerns the final implementation and evidence: seven-case scope,
role-specific eligibility, signal obligations, numerical assumptions, original
failures, and the supported CPU/state range. No new mismatch in the final
integration requires a wholesale statistical redesign.

CI admission additionally requires a protected request and producer identity,
the exact target revision and artifacts, complete obligation inventory, freshness
and reuse policy, and independent evidence validation. Missing, stale, mismatched,
incomplete or unqualified evidence must fail admission. A JSON record committed
by a PR is insufficient. The separate CI-boundary change retains that hold while
functional checks are separated from external physical qualification.

The finite inventories do not establish an operational failure rate of at most
1% with one-sided 95% confidence. A new plan would require a fixed final artifact,
environment, opportunity definition, dependence model and budget. The ended
Hosted campaign is not resumed. Performance baselines, live provider qualification,
real KMS and conformance retain separate responsibilities; Dudect results cannot
satisfy them. Historical detections and product-claim assurance remain open.
