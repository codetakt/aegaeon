# F\* Effective-Assumption Graph

Last updated: 2026-09-12

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

Per-module admission ([module-admission.md](module-admission.md)) records that a
requested source was processed without reported error. It says nothing about what
the proof of that source actually rested on: which interfaces and implementations
were loaded, which of them were checked from source without SMT, which provider
artifacts were reused or rejected, and which declared axioms and builder-injected
premises were in scope. `scripts/validation/assumption_graph.py` reconstructs that
information from the pinned tool's own output and keeps it next to the pass records.
The graph is a consistency artefact; it does not establish that any premise is sound
and never activates an assurance statement.

## Inputs

| Input | Origin | Used for |
| --- | --- | --- |
| `invocations/<pass>/{inputs,result,modules}.json`, `output.log` | `run_fstar_invocation.py`, `admit_fstar_modules.py` | pass identity, requested sources, tool, recorded solver, admission dispositions, the effective solver line |
| `dependencies/<pass>/depend.txt` | `fstar.exe --dep full` with the pass's arguments (hints and diagnostics stripped) | the module closure the verifier resolved: every `.checked` target, its source and its dependencies |
| `invocations/<pass>/output.log` (batch-trace-v2) | the actual proof with `--debug Dep --debug CheckedFiles` | ordered batch schedules, positive checked-file loads and source checks, together with the admitted proof result |
| `dependencies/<pass>/load.log` | `fstar.exe --admit_smt_queries true` with the same trace options | independent diagnostic schedule/load comparison; never proof evidence |
| `dependencies/<pass>/record.json` | `assumption_graph.py probe` | argv of both probes, working directory, tool digest, output digests, return codes |
| recorded sources | `--source-root` (first-party, generated, tests) and the immutable provider/ulib paths named in `inputs.json` | digest re-check, declaration and premise parsing |
| `scripts/flake/verify_fstar.sh` | generator of the builder-written `C.Loops.fst` | regeneration and digest comparison of the injected premises |
| `spec/assumption-register.json` | hand-reviewed register | premise identity, statement digests, coverage of provider/tool/model premises, review status |
| `spec/compliance-matrix.yaml`, `spec/server-assurance-contract.v1.json` | claim inventory | property nodes, matrix rows, guarantee ids |
| `ci/tamarin_proofs.sh`, `proofs/tamarin/**/*.spthy`, `spec/kani-evidence.json` | other lanes | index of Tamarin builtins/functions/equations/restrictions and Kani bounds |

The load probe is not verification: it admits every SMT query. A plain `--lax` probe
was rejected because the EverParse-generated parsers fail under `--lax` (tactic
unification error 217), whereas `--admit_smt_queries true` runs the full type checker
and can compare its batch schedule and load classifications with the real pass.
Both probes are recorded
as their own invocations, never admitted, and never mistaken for the pass itself.

Mutable include, provider and tool-library inputs are hashed before invocation.
Admission additionally captures the direct searched `.fst`/`.fsti` identities,
including immutable include sources, in `dependency_context`. This preserves
symlink and relative-path spellings for source-free admission replay. Historical
records missing a unique input identity for a reported dependency fail closed.
Graph reconstruction also compares the source identities retained for unrequested
admitted results; conflicting identities are errors. A mutable dependency source
or an adopted `.checked` artifact needs a recorded digest and must still match it.
Nix store inputs without a separate recorded digest retain the explicit store and
provider trust boundary. A cache read superseded by a positive source recheck is
not an adopted cache premise. Rebuilding a graph cannot bless changed dependency
bytes merely by computing their new hashes.

Source inventories share a literal-aware scanner. Comment markers inside strings
or characters cannot hide subsequent premises; literal text cannot create fake
declarations. Nested comments preserve source positions and token separation.
Unsupported lexical forms fail closed. This remains a bounded lexical inventory,
not proof of F* parsing or declaration semantics.
Admission and graph parsing follow the pinned lexer's rule that a block comment
may extend to EOF; unterminated strings are errors. The separate foreign-assumption
inventory retains its stricter rule requiring closed block comments.

## Nodes and edges

| Node kind | Id | Attributes |
| --- | --- | --- |
| `pass` | `pass:<id>` | argv digest, cwd, include order, tool, `solver_recorded`, `solver_effective`, denied options, record digests, include scan |
| `source` | `source:<recorded path>` | module, role (`implementation`/`interface`), origin (`first-party`, `generated-everparse`, `test`, `builder-generated`, `provider:hacl`, `provider:krml`, `provider:steel`, `provider:everparse`, `ulib`), sha256 (repository-side sources), parsed `open`/`include`/`friend`/alias declarations, per-pass load mode |
| `checked` | `checked:<path>` | per-pass state `loaded`, `stale`, `absent`, `not-attempted`; SHA-256 for adopted checked artifacts |
| `premise` | `premise:<Module>#<name>` or `premise:<register id>` | kind (`assume-val`, `assume-term`, `admit`, `lax-option`, `friend-exposure`, `builder-injected`, `lax-module`, `checked-import`, `tool`, `computational`, `symbolic-abstraction`, `tamarin-*`, `kani-*`), normalized statement and its sha256, line |
| `property` | `property:<Module>#<name>` | matrix-cited lemma/invariant/computation/primitive; `declared` when the identifier is found in the module |
| `matrix`, `guarantee`, `tamarin-theory`, `tamarin-lemma`, `kani-group`, `kani-harness`, `generator`, `tool`, `register-entry` | | |

Edges: `requests`, `imports` (module granularity, from the tool), `satisfied-by`
(interface → implementation of the same module), `loads`, `shadows` (a working-directory
or include-directory file with the same name as a later-searched candidate), `exposes`
(`friend`), `generated-by`, `declares`, `depends-on`, `defined-in`, `cites`,
`guarantees`, `selects`, `tamarin-uses`, `kani-uses`, `registers`, `justified-by`, `interprets`.

Load modes per pass: `requested-verified` (admitted result), `checked-artifact`
(loaded from an artifact the verifier validated), `lax-source` (source checked
without SMT), `verified-dependency`, and `unobserved` (a stale artifact without a
subsequent source check, rejected by `check`). A closure source without positive
load evidence becomes `unknown-source`, which contributes an `unknown-load`
premise. It is never inferred to be unused or interface-only, including when
`friend` exposes an implementation. A cited unknown-load premise blocks
qualification even if someone supplies an accepted register flag.
Malformed lines in the pinned load-event families are rejected; both normal
checked-file attempts and the tool's `with tc result` attempts are recognized.

For new `batch-trace-v2` records, both ordered lists printed by the pinned
`FStarC.Universal.batch_mode_tc` must occur exactly once in the actual proof and
match the diagnostic probe. Every scheduled source must have a positive load or
source-check event. The proof argv selects the trace contract; a probe record
cannot downgrade a traced proof to the legacy format. A source scheduled for
verification requires a source check; lax-checking and cache reuse alone are
rejected. Adjacent interface/implementation pairs are checked together;
an interface may use the implementation's source-check event, recorded as
`interleaved_with`. A source-check event takes precedence over a successful cache
read because F* can discard that cache result and recheck the source. A cache
read alone does not show adoption into the typing environment.
This also applies when the interface cache was successfully read for dependency
bookkeeping before its paired implementation falls back to source: interleaving
rechecks that interface, so the implementation's source-check mode takes
precedence over the earlier interface-cache read.

The full dependency graph also includes implementation dependencies examined for
cycle detection beyond the batch schedule. An external source positively present
in that graph and the parsing-cache scan, but outside the complete batch schedule,
is recorded as `dependency-scan`. Its SHA-256 and a `dependency-source` premise
remain in the conservative property closure. This does not establish non-use,
irrelevance or soundness, and its register entry still requires acceptance. It
does not remove interface/implementation edges or exempt a `friend` target from
load evidence. Sources in the schedule with missing events are errors; missing
scan evidence remains unknown. First-party sources do not receive this external
source classification. Old `checkedfiles-v1` records keep the original unknown
obligations; a new parser cannot retroactively supply missing batch evidence.
Legacy requested sources also require a positive non-lax source-check event;
paired interfaces require their admitted implementation's event. Missing,
cache-only, lax-only or contradictory events are rejected. This preserves the
distinction between a successful proof result and a diagnostic load observation.

This contract follows the pinned F* 2025.10.06 source:
`src/fstar/FStarC.CheckedFiles.fst` (`load_checked_file`,
`load_module_from_cache`) and `src/fstar/FStarC.Universal.fst`
(`tc_one_file_from_remaining`, `batch_mode_tc`). `Trying to load` and `Already
loaded` refer to the parsing cache, including invalid cache entries. They are
never counted as positive type-checker loads. Diagnostic options are stripped
from `--dep full` so that its makefile grammar remains separate from debug text.
`Trying to load checked file with tc result` is a type-checker attempt, recorded
separately from a parsing-cache attempt. If it has no positive load/source-check
result, it cannot be classified as a parsing-only dependency scan.

## Granularity

F\* exposes no per-theorem usage relation. `depends-on` edges therefore connect every
cited property of a module to every premise declared in that module's import closure,
including implementations reached through interfaces (`through: interface-satisfaction`),
lax-loaded provider modules, the injected `C.Loops` declarations and the aggregated
checked-artifact imports. Every such edge carries `granularity: module-closure` and
`exact: false`. `explicit_call: true` is added only when the property's own module text
contains the premise name; it never removes an edge. The tool never asserts that a
premise is unused.

Every cited F\* property also depends on the verifier and solver trust premises,
with pass identities retained on the edge. Each external computational or
abstraction entry resolves its qualified `events` to declarations in the fixed
source closure. `interprets` binds that premise to the event's source, and
`depends-on` edges with `dependency_class: security-interpretation` carry it to
properties whose module closure reaches that source. These are conservative
interpretation obligations, not F\* axioms or claims that a conditional lemma
needs computational hardness to type-check. Algorithm-polymorphic hash modules
retain all registered SHA-256/384/512 instances; the graph does not infer exact
per-lemma algorithm use. `justified-by` is checked for implicit external premise
IDs as well as explicitly named declaration premises.

## Checks and exit codes

Source inventories distinguish comments and literals from declarations. Option
directives are read across whitespace and comment boundaries, including a
string argument on the following line. Potentially weakening options (`--lax`,
`--admit_smt_queries`, `--admit_except`) are conservatively recorded even when
their argument would disable the option. Escaped option strings stop graph
construction: F* decodes those escapes before interpreting options, and the
inventory does not claim an equivalent decoder. Ordinary string literals may
still contain escapes. Structural acceptance never substitutes for review of
the meaning of registered premises.

`check` rebuilds the graph from the fixed inputs and compares node and edge sets with
the stored graph; validates the stored graph against
`spec/assumption-graph.schema.json`; requires an accepted admission and matching
requested lists and record digests; requires every declared premise (`assume val`,
term-level `assume`, `admit ()`, `--lax`/`--admit_smt_queries` options, `friend`,
builder-injected declarations) to have a register entry with the same statement digest
and every register declaration to be discovered (or marked `expected_in_closure: false`);
requires every lax-loaded or checked-imported module to be covered by a register
selector; requires a load mode for every closure module; cross-checks each
repository-side source's `open`/`include`/`friend`/alias declarations against the tool's
dependency output; rejects cycles through `justified-by`; and enforces an optional
`--expect` file (`tree`, `selection`, `tool_sha256`, `receiver_sha256`,
`admitter_sha256`, `sources`). Exit 0 = consistent, 1 = inconsistent, 3 = usage/IO.
Consistency is never reported as qualification.

Graph reconstruction replays the proof admission verifier, checks the exact
probe argv derived from the proof command, requires zero integer return codes,
and binds the probe record and proof result digests. Register tool digests are
compared with every pass's observed verifier/solver identity. The resolved graph
node determines this obligation: all registrations selecting a tool node, by
explicit ID or coverage, must be tool entries with the matching digest. An
accepted provider or other non-tool entry cannot qualify a tool node. Duplicate logical
edge keys are rejected even when their attributes are identical. Registration
of an external event without a declaration in the fixed closure is an error.

`qualify` runs `check` and then requires every premise reachable from a matrix-cited
property to have register status `accepted` and no open findings or unknown
loads. Register schema validation runs before construction and qualification.
Acceptance metadata must include nonempty `reviewer_id`, `reviewer_role`, `record`,
a valid calendar `date`, and `subject_sha256`. That digest is SHA-256 of the
canonical entry excluding `status` and `review`; changes to the premise, selectors,
events or pinned tool invalidate its recorded acceptance. This verifies structure
and subject binding, not the authenticity of a reviewer identity or the truth of
the referenced review. The hand-reviewed register remains a trusted input; this
mechanism does not implement signed human attestation or acceptance governance.
Exit 2 = incomplete/blocked with reasons; 0 only when those conditions hold. At the
current baseline every register entry is `specified-not-attested`, so `qualify` exits 2.

Regressions: `tests/ci/test_assumption_graph.py` (synthetic tree with the negatives:
transitive dependency, shadowed module, interface/implementation roles, injected content
and statement changes, unregistered declaration, uncovered provider load, empty/missing/
duplicate/unknown ids, circular justification, deleted or altered elements with
re-signed digests, same-count different dependency, dependency absent from the tool
output, solver identity mismatch, missing load evidence, missing dependency record,
unresolved load mode, expectation anchors) plus the retained records of the production
pass 2b under `tests/fixtures/assumption_graph/baseline-2b/`. The `verified-reqs`
integrity derivation runs them; the `verify-fstar` derivation runs the probes after each
pass and `build`/`check`/`qualify` after admission (`assumption-graph.json`,
`assumption-graph.qualify.json`); `scripts/verify/verify_fstar_ci.sh` re-checks the
shipped graph. `tests/ci/test_assumption_graph_reviews.py` adds the independently
reported false-acceptance controls: rejected tool and external premises, missing
or stale review metadata, implicit justification cycles, altered probe commands
and return codes, failed proof replay, malformed or missing load events,
duplicate edges, and registered tool digest mismatches. The same integrity
derivation selects both graph test files.

## Findings at the reviewed baseline

- **Solver identity: historical mismatch, corrected pin.** The initial records
  named the outer PATH's Z3 4.15.4, while the F\* wrapper actually started its
  bundled Z3 4.13.3. Those records retain the `solver-identity-mismatch` finding.
  The current `verify-fstar` derivation obtains the bundled solver from the same
  pinned nixpkgs F\* definition and supplies `FSTAR_SOLVER`; `run_pass` passes it
  explicitly as `--smt` to verification and both dependency/load probes. In the
  corrected five-pass evidence, `solver_recorded` and `solver_effective` identify
  `/nix/store/jkwr78r1b6c0hr02ad4afz5jb3q0hd7r-z3-4.13.3/bin/z3`, SHA-256
  `f172457b330a7dc69b7abb61c565dc8711867df71b33b09b0a7855af8d6b1d6a`.
  A direct script invocation must supply its intended executable through
  `FSTAR_SOLVER` to establish the same explicit pin. Without it, the recorder
  leaves the requested solver unknown; it does not infer a choice from PATH.
  Missing or non-executable explicit solver paths fail before verification.
  Both the recorder and graph replay require the pinned process argument list
  `["-smt2", "-in"]` in that order and retain it with the effective identity.
  Missing, reordered, duplicate or additional arguments are rejected, including
  in historical logs. The graph still compares recorded and observed identities.
  Matching them establishes executable and supported-startup identity, not solver
  soundness or premise acceptance. Invocation admission rejects proof-skipping
  and cache options in both separate-value and equals-value spellings. Claim YAML
  rejects duplicate mapping keys at every depth, including merge overrides.
- **Injected `C.Loops`.** The builder-written `fstar/C.Loops.fst` (three `assume val`
  loop combinators) shadows KaRaMeL's `lib/krml/C.Loops.fst`; the KaRaMeL checked
  artifact is reported stale and the EverParse artifacts depending on it
  (`LowParse.Low.Base`, `LowParse.Low.ListUpTo`, `EverParse3d.Actions.Base`,
  `EverParse3d.ProbeActions`, …) are re-loaded by lax-checking their sources. The
  generated parsers, `Jose.HeaderParser`, `Jose.HeaderParser.TLV`, `Jose.LowStar` and
  `Jose.LowStar.Json` reach these premises; modules outside that closure do not.
- **Provider sources.** HACL\* and Steel ship no `.checked` files: every HACL\* module in a
  closure is lax-checked from source in every pass. ulib, KaRaMeL and EverParse
  artifacts are loaded when present and not stale.
- **First-party lax imports.** `Spec.Hash.Definitions` (a byte-identical copy of the
  HACL\* file that shadows it), `EverCrypt.Chacha20Poly1305`, `EverCrypt.HMAC`,
  `HACL_Wrapper` and `Steel.Effect` are imported but never requested, so none of their
  declarations is verified by the production target; `Verified.Crypto.Bridge` is lax in
  pass 1b and verified in pass 2b on the same bytes.
- **Outside the passes.** `HashComputation.Low` (two linkage `assume val`s) is not in
  any production pass closure; its register entries are marked
  `expected_in_closure: false`.

## Limits

The graph proves nothing about premise soundness, model adequacy, implementation
correspondence or release assurance. Module-closure granularity over-approximates use.
Provider and ulib sources are identified by their immutable store paths, not re-digested;
replay therefore needs the same pinned provider trees. The load probe reflects the
verifier's checked-file logic under `--admit_smt_queries true`, which shares the loading
code path with the real pass but is a separate invocation.

### Solver restarts

The invocation recorder and graph reconstruction inspect every `Creating new
z3proc` record. Repeated starts of the same resolved executable and reported version value are
accepted. A later change of executable, reported version or resolved identity, or a malformed
start record rejects the invocation or graph, even when the verifier exits zero.
When an explicit solver pin is supplied, the recorder also compares the observed
path and bytes with that pin and requires at least one supported start record.
An explicit pin with no observation fails even if F\* exits zero; the record retains
the actual child exit code and unknown observed identity. Without an explicit pin,
missing start evidence remains unobserved and cannot establish solver identity. F* reports its configured version value here; that string is not an independent
measurement of the executable version. These checks identify recorded tool executions
and do not establish solver soundness or accept any registered premise.

Composed collision events have direct external registrations: string SHA-256
and PKCE require SHA-256 collision resistance and the string encoding boundary;
the OIDC hash dispatcher names each full SHA-2 premise. These annotations do not
replace the separate truncation premise. The prior conservative module closure
already carried these full-hash dependencies; direct registrations make the
composition explicit without accepting any premise or changing a theorem.
