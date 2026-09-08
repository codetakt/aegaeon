# Tamarin Evidence Admission

Last updated: 2026-09-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

The required Tamarin gate admits results per requested `(theory, lemma)` from the
invocation that requested it. Exit status, a `verified` string somewhere in a
log, or a lemma name that also appears in another theory are not evidence. This
note fixes the output contract that `scripts/validation/admit_tamarin_lemmas.py`
enforces, its request identity, its acceptance and rejection rules, the cache and
tool policy, and the records it writes. It describes tool executions only; it
does not establish model adequacy, implementation refinement or release assurance.

## Why exit status and `verified` strings are not enough

The pinned `tamarin-prover 1.12.0` (Maude 3.5.1) was probed directly; the
recorded outputs are fixtures under `tests/fixtures/tamarin_admission/`.

| Case | Exit | Output |
| --- | --- | --- |
| `--prove=<exact name>` | 0 | that lemma `verified`; every other lemma `analysis incomplete (1 steps)` |
| `--prove=<prefix>` without `*`, or a nonexistent name | 0 | wellformedness warning `'…' from arguments do(es) not correspond to a specified lemma`; nothing analysed |
| theory with a free variable in a lemma formula | 0 | `WARNING: 1 wellformedness check failed!` in the summary, requested lemma still `verified` |
| same theory with `--quit-on-warning` | 1 | aborts before analysis |
| falsified lemma | 0 | `falsified - found trace (N steps)` |
| missing theory file | 1 | `openFile: does not exist`, no summary |

Results exist only as text in the final block:

```text
==============================================================================
summary of summaries:

analyzed: <path as given on the command line>

  processing time: 0.14s

  [WARNING: N wellformedness checks failed!]

  <lemma> (all-traces|exists-trace): verified (N steps)
  <lemma> (all-traces|exists-trace): analysis incomplete (N steps)
  ...

==============================================================================
```

The theory dump before it contains either `/* All wellformedness checks were
successful. */` or a `WARNING: the following wellformedness checks failed!` block
with titled, `=`-underlined sections, and the `Tamarin version` / `Maude version`
lines. This grammar is the supported interface, versioned as
`tamarin-1.12.0-summary-v1` in `spec/tamarin-evidence.json`.

## Request identity

`ci/tamarin_proofs.sh` is the only selection source. The gate normalises it and
the admission tool writes `requests.json`: for each request the theory path
(relative to `proofs/tamarin`), its SHA-256, the lemma name and the trace
quantifier read from the comment-stripped source (`exists-trace` or the default
`all-traces`). Before any run it rejects an empty selection, an empty lemma
name, a duplicate `(theory, lemma)`, a theory that is not a `.spthy` file, and
a lemma that is not declared exactly once in the theory. Results are keyed by
`(theory, lemma)`; fifteen lemma names recur across the selected theories.
No selected theory uses `#include`, so a run's input is the theory file and the
tool; both identities are recorded.

## Admission rule

One invocation per request, from `proofs/tamarin`: `timeout --kill-after=10
<timeout_seconds> tamarin-prover --prove=<lemma> --derivcheck-timeout=<n> <theory>`.
A request is `accepted` only when all of the following hold:

- the process exited 0 (a budget timeout, signal or other status is recorded and
  rejects even when the log contains a `verified` line);
- the theory digest is unchanged after the run;
- the log's `Tamarin version` and `Maude version` lines match the registry;
- exactly one summary block exists, it is closed, its `analyzed:` path is the
  invoked theory, and every line in it is recognised;
- the theory is reported wellformed, or every warning section is a registered
  exception (below);
- the requested lemma has exactly one summary line, with the declared quantifier
  and status `verified`;
- no summary line is `falsified`.

Unrequested lemmas may be `analysis incomplete` (targeted run) or `verified`;
both are recorded and neither substitutes for the requested result. Missing,
duplicate, mismatched-quantifier or `analysis incomplete` requested lines, an
unrecognised or truncated summary, a different `analyzed` path, a changed digest,
an unregistered warning and a tool version mismatch all reject.

## Wellformedness exceptions

Six selected theories carry rule-level wellformedness warnings at this baseline:
unbound claim variables that the sources document as intentionally determined by
`Eq(verify(...))` (`federation/id_token_chain`, `federation/rp_authorize_callback`,
`federation/cache_poisoning_resistance`) and message-derivation checks on
intended pattern matching of `sign(...)` (`federation/federation_key_rotation`,
`management/policy_downgrade`, `sd_jwt/sd_jwt_selective_disclosure`). Rewriting
those rules is a model-adequacy decision. The registry records, for each
theory's exact SHA-256, the digest of each warning section with its reason and
hand-off; the admission accepts such a theory only when every section matches,
labels the request `accepted-with-registered-exception`, and reports the count
in every summary. Any change to the theory or to the warning text rejects until
the exception is re-reviewed. The `--prove/--lemma arguments` warning class is
never registrable. The lemma-level defect in
`authcode/refresh_token_rotation.spthy` (`no_token_after_revocation` used
`new_rt` and `count` without quantifying them) was fixed by universal
quantification; the lemma verifies in 28 steps before and after, and all eight
lemmas verify under `--quit-on-warning`.

## Cache and tool policy

Tamarin has no proof cache between invocations; each request is a fresh run.
The Docker image used by the manual runner ships 1.8.0, whose output is not the
supported contract; the tool identity check rejects it explicitly instead of
reporting `Verified`. Budgets (`timeout_seconds`, `derivcheck_timeout_seconds`)
come from the registry; the `TAMARIN_TIMEOUT` and `TAMARIN_DERIVCHECK_TIMEOUT`
overrides are recorded when used.

## Records and gate wiring

- `requests.json`: the normalised, validated selection.
- `invocations/<id>/command.json`, `output.log`, `result.json`: argv, tool and
  Maude identities, budgets, start/end, wall seconds, return code, theory digests
  before and after, raw log digest, the parsed summary, the decision and reasons.
  Existing invocation directories are refused.
- `admission.json`: written atomically only when every request is accepted or
  accepted-with-registered-exception, removed at the start of each run; it binds
  the registry digest, `requests.json` and every `result.json`.
- `verify-tamarin.log`: the human `=> Proving`, `[OK]`/`[FAIL]` lines, the
  `Lemmas verified/failed` totals, and `TAMARIN-ADMISSION` JSON lines that also
  survive a failed Nix build in its log.

`scripts/flake/verify_tamarin.sh` runs the regressions in
`tests/ci/test_tamarin_admission.py`, then the admission over the selection;
rejection fails `verify-tamarin`. `scripts/verify/verify_tamarin_ci.sh` builds
through `nix … | tee`, keeps both statuses and the build log, copies the fresh
output and runs `verify-records` (digests and a full replay of every decision)
before reporting success; the hosted job uploads that directory on success and
failure. `proofs/tamarin/run_tamarin.sh` runs the same selection and admission
manually, optionally restricted to named theories.

## Limits

This gate establishes that each selected lemma was reported verified by the
invocation that requested it, on a wellformed theory or a theory whose warnings
are registered and reviewed. It does not audit model adequacy, attacker
capabilities, implementation correspondence or the wider lemma set outside
`ci/tamarin_proofs.sh`, and it does not activate any assurance statement.
