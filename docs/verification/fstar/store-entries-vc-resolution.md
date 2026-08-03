# Resolving `store_entries_into_buffer_aux` VC Failures

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This note records the proof decomposition that unblocked verification of the
Low*/Stack helper that writes a list of entries into a `LowStar.Buffer` using
`Buffer.upd`.

It exists because these failures are easy to re-introduce when refactoring loop
structure or changing arithmetic expressions around `idx`/`remaining`/`len`.

## Symptom

F* fails to discharge VC obligations around:

- `idx < Buffer.length buf` for `Buffer.upd` / `Buffer.index`
- recursive-call preconditions like `(idx + 1) + len(rest) <= Buffer.length buf`
- `idx < pow2 32` (needed for `UInt32` conversions)
- preserving `rel` for monotonic buffers after `Seq.upd`

## Resolution strategy

Treat this as an **arithmetic decomposition problem**, not a “turn up Z3” problem:

1. Prove *index-in-range* from a stronger tail-bound.
2. Prove the *successor bound* for the recursive call.
3. Prove *UInt32 safety* (`idx < pow2 32`) from buffer-length bounds.
4. Discharge the monotonic `rel` obligation using `trivial_preorder`.

## Canonical lemmas & locations

- Tail → index bound:
  - `fstar/jose/Jose.BufferListLemmas.fst` (`lemma_idx_lt_from_tail_tot`)
- Recursive successor bound:
  - `fstar/jose/Jose.BufferListLemmas.fst` (`lemma_idx_succ_bound_for_rest`)
- `pow2 32` index bound:
  - `fstar/jose/Jose.BufferListLemmas.fst` (`lemma_idx_lt_pow2_tot`)
  - `fstar/jose/Jose.Arith.Bounds.fst` (additional `UInt32`/buffer-length helper lemmas)
- Monotonic `rel` after update:
  - `fstar/jose/Jose.BufferListLemmas.fst` (`lemma_upd_preserves_trivial_preorder`)

## Verification command

When this regresses, re-run a focused check first:

```bash
fstar.exe --include fstar --detail_errors --query_stats \
  fstar/jose/LowStar/Json/Jose.LowStar.Json.fst
```

Then confirm the full verification gate:

```bash
nix build .#verify-fstar -L
```
