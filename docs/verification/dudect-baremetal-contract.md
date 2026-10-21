# Limited external Dudect monitoring contract

Last updated: 2026-10-22

Status: current implementation baseline

Status note: adopted in the limited scope on 2026-10-22; CI admission remains disabled.

Owner: Engineering

Audience: maintainers, verification reviewers

This version resolves the scope, precedence and source-availability findings in
the review of PR #216 at `5f1ebd5bcf60d70494368a74607702edb78e6ddf`. It defines a
limited PR-profile monitoring contract for both compilers on the recorded
c6i.metal Ice Lake research configuration. It does not adopt Hosted measurement,
other CPU/image configurations, an operating failure rate or product-wide
constant-time assurance. A machine type alone is not an environment contract.

## Normative documents and execution evidence

The [versioned contract](../../ci/contracts/dudect-baremetal-v1/contract.json)
is the single entry to the adopted specification. Its linked scope,
sensitivity and role documents agree on seven calibrated cases and fourteen
other cases. Scope governs case membership; roles govern final eligibility;
sensitivity governs the retained signals, numerical obligations and deadlines.
An unexplained contradiction is an error, not permission to select a convenient
rule. The original frozen JSON remains an execution input for its recorded
measurements; its superseded wording is not inherited as a current requirement.

In particular, `other17cases` is corrected to `other14cases` in the new
sensitivity version. The new role document inherits that version by hash.
Original IDs, hashes, results and receipts are unchanged. Status, predecessor
and execution-queue fields copied into `creation_state` describe history, not
current authority. Earlier `new_physical_success_in_this_design: 0`, partial
kernel `unknown`, and `I21 not started` statements are preserved there. Current
execution facts refer to the [closed qualification checkpoint](dudect-calibration-qualification.md)
and the [new recount receipt](../../ci/evidence/dudect-contract-review-followup-20261022.json).
Neither document authorizes a new execution or turns historical failures into
successes. `deadline_contract.json` is a counterfactual tool, outside this
adoption specification and the live gate.

The selected cases are `nix/ct_eq_32`, `nix/ct_eq_64`, `nix/ct_eq_128`,
`nix/sha256`, `nix/hmac_sha256`, `nix/hmac_sha256_key` and `legacy/compare`.
Only their PR crops1–100 use current-prefix distributed calibration. Raw0/101
retain their original samples and pilot center; fourteen other cases and
periodic calibration are unchanged. Existing count floors, eight looks,
binary64 alpha and absorbing candidate detections remain. Old and replacement
crops are not OR-combined. Original crop outcomes are retained separately.

## One execution entry and exact identities

The ordinary entry is
`tests/dudect_sensitivity_operations/ordinary.py`, using
`tests/dudect_sensitivity_live/live_runtime.py::identity`, schema
`role-live-analysis/3`, the seven-case scope reader and role evaluator.
`run_live.py` is the separate diagnostic entry. A bare `mode: distributed`
label is insufficient: the HMAC-only `run_analysis.py` research entry and its
CI matrix path are outside this contract.

The physical evidence identifies the **measured** Python files, native ELFs,
analysis package, dependencies and per-stage live identities. The
[measured source archive](../../ci/evidence/dudect-measured-source-20261021.tar.gz)
contains every one of the 54 files in the original correspondence table,
including all 44 Python files. The review's count of 45 Python files does not
match that table; no table entry was omitted. The archive is evidence, not an
automatic import path or replacement for the complete pinned checkout.

The [public verifier](../../scripts/validation/verify_dudect_review_followup.py)
checks archive membership and both sets of hashes, then recomputes normalized
syntax correspondence from the actual bytes. It ignores docstrings and splits
ordered imports without reordering them. The two test-only changes remain
explicit: `test_compare_receipts.py` uses a self-contained fixture, and
`test_operations.py` has its recorded test changes. Markdown is explanatory;
JSON contracts and C hooks must be byte-identical. No equality flag in the old
receipt is trusted in place of recomputation.

```bash
python scripts/validation/verify_dudect_review_followup.py
```

Syntax correspondence is not physical equivalence. The formatted Python and
rebuilt native packages do not acquire the old measurement identity. Reviewers
can obtain the measured bytes and examine the transformation; replay must use
the recorded identity. The original source archive, old receipt and new
contract are bound separately, without rewriting old bindings.

The external controller owns the absolute acquisition deadline, independent
stop guard and recovery. It must install `schedule.installed(cutoff)` before
calling the ordinary or diagnostic entry, which then installs the live worker.
Calling `ordinary.py` alone does not establish the external lifecycle. The
900-second case limit and shared 10-second/256 MiB prefix budget remain required;
the independent guard, capacity, authenticated recovery and cleanup require
their own receipts. Component code or caller-supplied booleans are not proof of
provider read-back or completed cleanup.

## What the retained results establish

The two six-case sensitivity stages belong to their predecessor contracts and
diagnostic artifacts. The comparison stage adds the separate legacy comparison
diagnostic. I21 is ordinary full-suite integration. Recounting or publishing
these results is not another physical experiment.

C1 uses an injected clock and checks the crop1 component path. F1–F6 check the
fixed class-dependent 16-operation shift, distributed over specified batches or
history conditions, with an eligible crops1–100 witness by the last look. Each
fixed case/profile/compiler combination has one physical observation per stage.
The diagnostic wrapper also performs base work on both classes, including its
zero arm. It is not the ordinary artifact. The measured ordinary provider binary
does not contain that diagnostic positive signal; separate synthetic controls
cannot establish arbitrary weak-signal power in the ordinary provider binary.
No detection deadline during the active signal interval is claimed.

The saved-prefix recount agrees with each original detection set in the existing
independent audit. I21's 22,350 original detected statistic/look pairs comprise:

| Original case role | Detected statistic/look pairs |
| --- | ---: |
| Measurement positive control | 9,802 |
| Authentication-result characterization | 4,326 |
| Public-fixture characterization | 8,222 |
| Measurement negative control | 0 |
| Protected-input observation | 0 |

All four stages used zero 2/3-exception and zero 4-exception supplements. The new
receipt reports both computed and crop-superseded supplement counts explicitly.

There is no removed original detection in an ordinary/zero nondetection role in
these stages. This must not be generalized to identical statistic/look
detections: in deliberate positive arms, the candidate does not reproduce
1,050, 780 and 32 original detections at the same statistic/look in SIX-P1,
SIX-P2 and COMPARE respectively. The selected populations differ, and all those
arms still satisfy their designated candidate witness. Original results remain
available. This distinction corrects an overly broad reading of “no detection
was removed”; it does not demonstrate equal detection power.

The recount reads saved decisions, verifies their recovered hashes and compares
sets with prior independent audits. It does not rerun raw-moment/tail analysis,
the physical trials or the reviewer's 211 + 43 functional tests. The unchanged
checkpoint preserves those earlier results and their original verification scope.

## Review and admission boundary

The Fable review supports conditional adoption within the limited scope above.
The repository owner approved the corrected version on 2026-10-22. The
[adoption record](../../ci/evidence/dudect-contract-adoption-20261022.json) binds
the reviewed commit, exact contract bytes, three normative documents and
supporting receipts. It closes the final contract review within the scope above.
The frozen contract and earlier receipts retain their creation-time pending
fields; the new adoption record supplies their current adoption state without
changing those bytes. Remaining statistical assumptions,
historical detections, other environments and sensitivity limits remain explicit.
The partially truncated information findings in the supplied review are not
reconstructed as new requirements.

Protected CI admission still needs an independently trusted producer, exact
revision/artifact binding, obligation completeness, freshness/reuse rules and
independent validation. A PR-controlled JSON receipt or this verifier cannot
authorize CI success. No new physical trial is required merely to publish the
measured source or correct the contract text. New claims about sensitivity,
other configurations or operational rates require their own evidence.
