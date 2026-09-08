# Kani Evidence Admission

Last updated: 2026-09-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

## Meaning and selection

Kani evidence establishes properties of the selected program within its actual
input domain and configuration. A fixed fixture, a substituted implementation,
and a model must be distinguished from production-code verification. A passing
fixture does not close a more general requirement. The
[assurance claim definition](../claims/assurance-case/claim-definition.md) governs
these distinctions; compliance-matrix status is an evidence inventory, not
release assurance or proof of implementation refinement.

[The admitted selection](../../../spec/kani-evidence.json) lists six fully
qualified harnesses, their source files, matrix references and exact domains.
They compile package `ffi` with feature `kani` and `cfg(kani)` on
`x86_64-unknown-linux-gnu`. Native parser/signature verification is outside this
slice; the release `verified-claim` feature set is different.

| Selected property | Admitted domain |
| --- | --- |
| `verify_json_member_c_layout` | Rust structure size/alignment on x86_64; no proof of C/Rust layout equivalence |
| `verify_utf8_decode_null_safety` | Two fixed null-pointer calls to the production helper |
| `verify_free_string_null_safety` | One null pointer; no proof of allocated-pointer ownership |
| `verify_jose_context_bounds` | The default context's header limit |
| `verify_json_member_c_pointer_validity` | One fixed structure and its known pointers |
| `oidc_id_token_jwt_canonicalisation_no_panic` | Six fixed byte strings, at most 11 bytes, through production Rust framing |

The last harness selects `AAA.BBB.CCC`, `AA.BB`, `AA.BB.`, `.AA.BB`,
`A=A.BB.CC`, and `AA-.BB_.CC0`. It does not quantify over every string below
that length. Its deliberately unreachable `unexpected canonicalisation error`
assertion is pinned by identity and description; changing or losing that guard
requires review. Other assertions directly belonging to the selected harness
must remain reachable and successful.

## Acceptance and ongoing execution

Run `python3 scripts/validation/run_kani_evidence.py` with the supported Kani
toolchain, or use `nix run .#verify-kani` / `nix build .#verify-kani -L`, which
run the admitted slice before the legacy regression suite. The hosted
`Kani (Pure Harness)` job also requires this slice, using the same pinned Nix
Kani package, compiler and solver as local verification. The separate legacy
`Kani Model Checking` job still uses
0.65.0 and is not evidence for this slice.

The adapter requires the exact compiled package, source and harness identity;
zero exit status; a complete, consecutively numbered property report; matching
property counts; no failed or undetermined property; reviewed reachability of
the selected harness's own assertions;
and exactly one completed harness per invocation. A success string, source
declaration, compilation-only run or empty selection is insufficient. The
adapter rejects unknown report formats. Ordinary safety and unwinding checks
remain enabled. Resource exhaustion and timeout reject admission.

The reachability allowlist applies to property IDs beginning with the selected
harness name followed by `.assertion.`. Assertions in callees and libraries may
be `UNREACHABLE` without an individual allowlist entry. Every property is still
retained and must be `SUCCESS` or `UNREACHABLE`; its counts must agree with the
same invocation's summary. Counts are not pinned across executions. An
unreachable callee assertion gives no evidence about inputs or paths outside
the declared fixture domain. Broader reachability review and changes to this
policy require separate evidence-admission work.

Each invocation gets a fresh target directory. The record retains policy,
source digests, tool identity, commands, full output, compiled metadata and
individual property results. `artifacts/kani-evidence/gate.json` is removed
before running and written only after every selected harness is accepted.
Hosted artifacts preserve these records. The local output directory can be
selected with `--output`; use an ignored location for investigation records.

This adapter covers the listed slice. It is not a general proof-result
evaluator, an independent review, or the release assurance decision procedure.

## Citation dispositions

| Matrix row | Disposition |
| --- | --- |
| `7515-007` | `partial`: five admitted cases do not establish general validated-input FFI memory safety |
| `9701-001` | Remove standalone Kani wrapper citation: it does not exercise HTTP negotiation; retain the existing F* model evidence |
| `9701-002` | Remove Kani citation checking only `typ_len`; retain the F* model and runtime guard/test references |
| `9701-005` | Remove the standalone Kani lifetime-model citation from requirement evidence; retain the F* model with implementation correspondence open |
| `9901-001` | Remove count-only Kani evidence; retain independently cited F*/Tamarin models with their existing qualifications |
| `OIDC-1-007` | `partial`: six examples do not establish arbitrary bounded adversarial-input safety |
| `OIDC-1-009` | Remove count-only Kani evidence; retain F* evidence without implying runtime refinement |
| `OIDC-1-010` | Retain the existing qualified evidence inventory with the Kani contribution explicitly limited to six framing fixtures; this does not close `OIDC-1-007` or activate assurance |

Other formal evidence on those rows was not re-proved by this Kani admission
change. Its retention is not a fresh F*/Tamarin result or an assurance decision.
Requirements remain in the contract when a citation is removed or downgraded.

### Excluded candidates

- `verify_utf8_decode_valid_input` uses only empty, `a`, and `test` byte strings.
  Its bounded execution exhausted the solver memory budget; it remains
  unadmitted rather than being counted as a proof of UTF-8 validity.
- Both `verify_parse_json_entries_*` harnesses call the `cfg(kani)` stub,
  which always returns `ParserUnavailable`. The null case expects `Internal`
  and fails. The overflow case passes for the stub's unconditional error, so
  it cannot support native count-validation or memory-safety claims.
- The three JWT introspection harnesses run a standalone wrapper. Its `typ`
  predicate compares a length, and its lifetime theorem assumes a positive
  configured duration at most 3600 and time below `u64::MAX - 60`.
- The six SD-JWT harnesses in `crates/kani-harness/src/lib.rs` are
  `proof_sd_jwt_disclosure_roundtrip`, `proof_sd_jwt_digest_uniqueness`,
  `proof_sd_jwt_issuer_payload`, `proof_sd_jwt_verifier_reconstruction`,
  `proof_sd_jwt_holder_selection`, and `proof_sd_jwt_format_parsing`.
  They use fixed fixtures and an encoded disclosure as the digest, without
  invoking SHA-256 or the production issuer/holder/verifier.
- The three upstream harnesses in that same `lib.rs` are
  `proof_upstream_refresh_token_rotation`,
  `proof_upstream_refresh_requires_valid_link`, and
  `proof_upstream_refresh_token_single_use`. The cited `bounded_upstream.rs`
  defines the model, not these harnesses. Fixed sequential traces do not
  establish SQL/CAS semantics, concurrency behavior or token invalidation at
  the upstream IdP.

Several SD-JWT/upstream executions reach the Kani intrinsic placeholder loop
for `size_of_val_raw::<[u8]>`, leaving their checks undetermined even with an
increased unwind bound. This is a toolchain investigation obligation, not a
production counterexample. Disabling unwinding checks cannot resolve it.
