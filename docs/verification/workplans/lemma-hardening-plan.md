# Lemma Hardening Plan

Last updated: 2026-07-07

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document is the single source of truth for removing the remaining F* warnings without relying on `--warn_error` suppression. All edits, reprioritisations, and completions should be reflected here.

## Goals

1. Restore evidence-bearing proofs for high-value lemmas instead of permanent `assume val` fallbacks.
2. Drive the current warning set (see inventory below) to zero while keeping `verify-fstar` green.
3. Capture inter-module dependencies so that work can proceed incrementally without breaking downstream proofs.

## Current Warning Inventory

| ID | File / Lemma Group | Warning Type | Notes |
|----|--------------------|--------------|-------|
| W-1 | `JoseNatLemmas.fst` (`lemma_tail_length_*`, `lemma_append_*`) | 252 | Fuel/ifuel exhaustion on list combinator lemmas. Used by Jose Header/JSON modules. |
| W-2 | `ConstTime.fst` (`ct_bytes_eq*`) | 242 | Recursive helper not encoded; need explicit `inline_for_extraction` or `[@opaque_to_smt]` rewrite. |
| W-3 | `Spec.Hash.Definitions.fst` | 241 | Missing hint files after refactors; need stable `.checked` artefact or local hints. |
| W-4 | `Dpop.Replay.fst` | 328 | Pattern-match warning (non-exhaustive). |
| W-5 | `par/ParBinding.fst` | 242 / 252 | List-based store recurrence left as `assume val`; need structural lemmas for `lookup`, `remove`, `filter`. |

(If new warnings appear, add rows rather than silently suppressing them.)

## Dependency Map (first pass)

- `JoseNatLemmas` → used by `Jose.HeaderParser`, `Jose.JsonHeaderSpec`, `Jose.LowStar.*`.
- `ConstTime` ↔ `Jose.Hmac_verification` and Rust FFI wrappers.
- `par/ParBinding` feeds `par/ParApp`, request store, and downstream OAuth flows.

This map will grow as we unwind `assume val` sections; update this table when new relationships are uncovered.

## Proof Style Baseline

1. **Propositions first, witnesses where needed**: keep outward-facing specs and lemmas as
   propositions (`Type0`/`Prop`). Bool equalities (`u = v` / `u <> v`) are handled as propositions via
   `Prims.b2t`, but invariants we want to reason about structurally should introduce constructive
   witness types `*_w : ... -> Type`, with propositional wrappers defined as `squash (*_w ...)`.
2. **Proofs are witness-based**: helper lemmas and internal proofs take `_w` witnesses as inputs and
   decompose structure via recursion and `match`. If a propositional surface is required, provide a
   thin wrapper (witness → proposition) only; avoid unsquash (proposition → witness).
3. **Minimal bridging for bool guards**: when composing with guards like `if u = v`, add only minimal
   lemmas such as `(u <> v) /\ (u = v) -> False`. Do not import implicit bool→prop bridges such as
   `&&` decomposition.
4. **Tactics as a last resort**: avoid relying on `FStar.Tactics` or heavy `rewrite`; prefer
   constructive witnesses and small lemmas. Consider tactics only when unavoidable.

## Work Plan & To‑Dos

- [ ] **Analyze JoseNatLemmas fuel usage**
  - ✅ _Status update 2025-11-27_: Baseline inspection complete. See “JoseNatLemmas Findings” section below for details.
  - Next actions: introduce structural lemmas (`length_cons`, `append_literal_eq`) so that proof scripts no longer rely on SMT fuel.
- [x] **ConstTime recursion rewrite**
  - 2025-11-27: Extracted `ct_bytes_eq_aux` to a top-level recursive helper with explicit arguments, eliminating Warning 242 without suppressing solver visibility.
- [x] **Regenerate hash hints**
  - 2025-11-27: Re-recorded hints via `fstar.exe --record_hints --use_hints --hint_dir . Spec.Hash.Definitions.fst` and added `Spec.Hash.Definitions.fst.hints` under version control. Re-run `verify-fstar` to confirm Warning 241 is gone.
- [ ] **par/ParBinding list proofs**
  - Replace current `assume val` lemmas with constructive proofs for `lookup`, `store_request`, `cleanup_expired`.
  - Ensure helper functions (`find`, `remove`, `filter`) have explicit `Fuel` budgets or are rewritten in structurally smaller form.
  - **2025-11-28 progress**: `ParBinding.fst` now models list entries via an explicit `request_entry` alias, exposes structural predicates (`uri_not_in`, `unique_uris`, `all_uris_lt`), and routes the public API through shared helpers (`lookup_entries`, `remove_uri`, `filter_expired`). All store-facing lemmas are still `assume val`, but they now share the same invariant surface (`store_ok`).
- **Next steps** (propositional style enforced):
    1. Keep `uri_not_in` / `unique_uris` / `all_uris_lt` / `store_ok` in propositional (`Type0`) form; ensure eqtype comparisons inside them use bool equality (`=`/`<>`).
    2. Introduce minimal helper lemmas (for example, `(u <> v) /\ (u = v) -> False`) so bool guards from `if u = v then ...` compose cleanly with the propositional invariants.
    3. Structural lemmas:
        - `lemma_remove_keeps_absent target uri reqs` to argue that removing one URI cannot introduce another one while still reasoning propositionally.
        - `lemma_uri_not_in_append_tail` to extend the uniqueness proof when appending a fresh entry.
        - `lemma_lookup_append_new` to link the appended entry with `lookup_request`.
        - Invariant-preservation lemmas for `store_request`, `use_request_uri`, and `cleanup_expired` composed out of the above.
    4. Once the helper layer is in place, re-introduce `lemma_single_use`, `lemma_client_binding`, and `lemma_expired_unusable` as constructive proofs guarded by the propositional `store_ok`.
  - Status: converted the helper layer to witnesses and reimplemented the `lookup`/`remove`/`filter`
    lemmas as well as store-invariant lemmas for `store_request`/`use_request_uri`/`cleanup_expired`
    structurally. Remaining work is rewriting application-facing lemmas (e.g. `lemma_single_use`)
    and store initialisation (`lemma_init_store_ok`) in the witness style.
  - **Witness conversion baseline (2025-11-29)**:
    - Add constructive witness types (`uri_not_in_w`, `unique_uris_w`, `all_uris_lt_w`, `store_ok_w`) under `par/ParBinding.fst`. Each witness captures one structural step (e.g., `UriNotInCons` stores the head inequality plus the tail witness) so recursive lemmas can pattern-match without using tactics.
    - Redefine the exposed predicates as `squash`ed aliases of their witnesses (for example `let uri_not_in uri reqs = squash (uri_not_in_w uri reqs)`). Never unsquash propositions; helper lemmas must take witnesses explicitly.
    - Provide the single bool-contradiction lemma `(u <> v) /\\ (u = v) -> False` and use it whenever an `if` guard contradicts witness data. Avoid building a larger bool→prop bridge.
    - Re-implement `lemma_lookup_not_in` (and the rest of the lookup/remove/filter helpers) as recursive lemmas over witnesses. Offer thin propositional wrappers only where the call sites insist on the old surface form.
- [ ] **Dpop replay patterns**
  - Cover all constructors explicitly or add `_ ->` branch with contradiction proof to eliminate warning 328.

Use GitHub issue/PR descriptions to reference these checklist items. When a task completes, tick the box and summarize the change here (including commit hash if available).

## Process Notes

- Every time the plan changes (new warning, reordered priority, discovery of new dependencies), edit this file in the same PR/commit that prompted the change.
- Keep `verify-fstar` green at each stage by temporarily guarding new lemmas with feature flags if necessary.
- Avoid reintroducing global `--warn_error` suppressions; instead, aim to delete them once the underlying warnings are gone.

## JoseNatLemmas Findings (2025-11-27)

- **Scope**: `lemma_tail_length_{one..four}` and `lemma_append_{singleton..quad}` repeatedly trigger
  Warning 252.
- **Root cause**: these are empty-body lemmas returning `()`. SMT spends time unfolding `List.length`
  and `List.append`, and with small fuel/ifuel budgets it fails to prove them. Without strengthening
  lemmas (and without `assert_norm`), F* cannot treat them as trivial.
- **Consumers**: used when handling short list patterns in `Jose.HeaderParser`, `Jose.JsonHeaderSpec`,
  and `Jose.LowStar.Json.*`. Replacing them would require touching many files, so proving them here
  is the lowest-cost approach.
- **Proposed fix**:
  1. Add simple lemmas about `List.length` (e.g. `length_cons`, `length_snoc`) and solve length
     comparisons via `rewrite`.
  2. For `List.append`, prove recursive definitions by induction (e.g. `append_singleton_eq`).
  3. If fuel is still insufficient, introduce local tuning such as
     `#push-options "--fuel 1 --ifuel 1"`.
- **Follow-up**: once the lemmas above are complete, mark the checklist item as done and prepare to
  remove `--warn_error -252`.
