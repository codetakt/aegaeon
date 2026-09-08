# F* Per-Module Admission

Last updated: 2026-09-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

The production F* target admits results per requested module, not per process
exit status. This note fixes the output contract that `scripts/validation/admit_fstar_modules.py`
enforces, the dispositions it assigns, its cache policy and the records it
writes. It describes tool executions only; it does not establish assumption
soundness, model adequacy, implementation refinement or release assurance.

## Why exit status and result lines are not enough

The pinned verifier (`F* 2025.10.06`, Nix package) was probed directly with the
cases below; the recorded outputs are kept as fixtures under
`tests/fixtures/fstar_admission/tool-probes/`.

| Case | Exit | Output |
| --- | --- | --- |
| implementation | 0 | `Verified module: <name>`, then `All verification conditions discharged successfully` |
| with `--query_stats` | 0 | additionally `TOTAL TIME <n> ms: <executed argv>` as the last line |
| interface only | 0 | `Verified i'face (or impl+i'face): <name>` |
| interface and implementation | 0 | one `Verified module:` line, no interface line |
| failing lemma | 1 | `* Error 19 at …`, **then** `Verified module: <name>`, then `1 error was reported (see above)` |
| success then failure | 1 | `Verified module:` lines for both sources |
| failure then success | 1 | no line for the later source |
| module/file name mismatch | 1 | `* Error 6 …does not match its filename` |
| `--cache_dir` with an existing `.checked` | 0 | `Verified module:` line printed on reuse |
| `--already_cached <name>` | 0 | no line for the cached module |
| `--silent` | 0 | no output |
| dependency in the working directory, not on the command line | 0 | no result line for the dependency (`Verified module:` is printed for command-line sources only) |
| same module in the working directory and in `--include` | 0 | the working directory's file is used |
| same module in two `--include` directories | 0 / 1 | the later `--include` wins |
| dependency only in the source's own directory or in a subdirectory | 1 | `Error 72` module not found (neither is searched) |

The archived impossible-lemma probe likewise printed `Verified module` after
three errors and exited 1. The search-scope rows come from
`tool-probes/search_scope.out` (script: `search_scope.txt`). A result line therefore only shows that F* processed
the module; it does not show success and does not distinguish a fresh check
from `.checked` reuse. There is no machine-readable result output, so the text
grammar above is the supported interface, versioned as `fstar-2025.10.06-text-v1`
and bound to the tool identity recorded in `inputs.json`.

## Admission rule

A pass is accepted only when all of the following hold:

- the invocation record has `status: succeeded` and return code 0, and
  `inputs.json` / `output.log` match the digests in `result.json`;
- the argv contains none of `--already_cached`, `--cache_dir`,
  `--cache_checked_modules`, `--lax`, `--admit_smt_queries`, `--admit_except`
  or `--silent`;
- the output contains no `* Error <n> at`, `<n> error(s) were reported` or
  `Detailed error report follows` line, exactly one completion marker, and,
  when `--query_stats` was requested, a `TOTAL TIME` line that echoes the
  executed argv;
- every requested source has the disposition below, and no
  `<name>.fst.checked` / `<name>.fsti.checked` for a requested module exists in
  the recorded local context, in the source's own directory or in any include
  directory of the invocation (F* reuses such a file without `--cache_dir`, and
  the result line would then stand for cache reuse); the scanned directories
  and candidates are recorded;
- the invocation record belongs to the pass: `result.json` carries the pass id
  of its directory and the same argv and working directory as `inputs.json`, and
  no two passes share an input or output digest (a relabelled copy of another
  pass's records is not that pass's evidence).

Request identity: each requested `.fst` (implementation) or `.fsti` (interface)
is re-read from the source tree, its SHA-256 must equal the invocation record,
and its declared module name is taken from the first declaration after
comments and `#` directives. The name must match the file stem (F* enforces
the same with Error 6) and must not be declared by another requested source in
the same pass; an interface and its implementation may share a name. Module
abbreviations (`module U8 = FStar.UInt8`) are not declarations; a second
declaration line is an identity error.

| Requested source | Disposition | Requirement |
| --- | --- | --- |
| implementation | `verified` | exactly one `Verified module: <name>` line |
| interface whose implementation is requested in the same pass | `paired-interface` | no separate line; an interface line for it is `contradictory` |
| interface without its implementation | `interface-verified` | exactly one `Verified i'face (or impl+i'face): <name>` line |
| any | `missing`, `duplicate`, `ambiguous`, `identity-error` | rejected |

Result lines for names that were not requested are recorded as `dependency`
only when they bind to the one source F* could have used: the single
`<name>.fst` (for a `Verified module:` line) or `<name>.fsti` (for an
interface line) across the directories the verifier searches: the working
directory and the `--include` directories — never a source's own directory, a
subdirectory or the recorded local context by file name. The candidate must
declare `<name>`; when it lies in the working directory it must appear in the
recorded local context with the same digest. Several candidates are ambiguous
(the verifier's precedence rules are not emulated), and any of these failures
leaves the result `unclassified` and rejects the pass. The resolved path (in
the invocation's recorded working-directory form) and digest are recorded;
replay uses that record, so records can be re-checked where the provider tree
does not exist, but replay still rejects a recorded source that is not of the
result's kind or that lies outside the searched directories. An unrequested
result never satisfies a requested target. The same module selected in
different passes (for example LowStar dependencies) is expected; duplicates
are counted within one pass only.

## Cache and option policy

Production passes replay SMT hints (`--use_hints --hint_dir .`), which do not
create module results and are allowed. They use no `.checked` cache options,
and no `.checked` file exists for first-party sources in the recorded local
context at the reviewed baseline. Because a result line cannot distinguish
fresh checking from reuse, admission requires fresh checking for every
requested module, which the denied-option list and the local-context check
enforce. Dependency modules loaded from provider `.checked` files (HACL*,
KaRaMeL, EverParse, ulib) are imports outside this gate; their assumptions are
the subject of the effective-assumption audit, not of this record.

A completed Nix output may be substituted only because it carries these
records: the hosted wrapper re-checks `admission.json` and every pass record
(`--verify-records`) against the retained invocation digests and replays the
grammar before it reports success.

## Records and gate wiring

- `invocations/<pass-id>/modules.json` (schema 1): contract identifier, pass
  identifier, invocation input/output digests, tool identity, return code,
  the disposition and result line of every requested source, unrequested
  results with their classification and resolved source digest, the checked
  file scan, diagnostics (error and warning counts, completion marker lines,
  argv echo check), status and rejection reasons.
  An existing `modules.json` is never overwritten; evidence directories must be
  fresh.
- `admission.json` (schema 1): the digest of every pass record, written
  atomically only when all required passes are accepted and removed at the
  start of each admission, so a stale acceptance cannot survive a failure.
- `FSTAR-ADMISSION` JSON lines on stdout and in `verify.log` per pass and for
  the summary, so a failed Nix build keeps the reasons in its log.

`scripts/flake/verify_fstar.sh` runs the admission after the fifth invocation
and fails the `verify-fstar` derivation on rejection; `scripts/verify/verify_fstar_ci.sh`
runs `--verify-records` on the copied output. `tests/ci/test_fstar_admission.py`
covers a real hosted pass with its four sources, the real impossible-lemma
probe, the tool probes above and controlled mutations (omitted, duplicated,
wrong and unrequested results, interface pairs, identity ambiguity, changed
digests, truncated output, forged status, denied options, checked files and
tampered records, dependency sources outside the searched directories,
  same-named candidates, kind mismatches and context-order independence); `tests/ci/test_fstar_runner.py` exercises the wired gate
with an omitted module at exit 0. Both run in the PR documentation lane and
inside the proof derivation.

## Limits

This gate establishes that the selected sources were processed without
reported error in one fresh invocation each and that the output belongs to
that invocation. It does not audit the effective assumption graph, lemma
coverage within a module, model adequacy or implementation correspondence, and
it does not activate any assurance statement.
