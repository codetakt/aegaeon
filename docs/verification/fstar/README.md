# F\* Verification Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This directory contains F\* proof requirements, troubleshooting notes, and the
small proof-support module inventory needed for Low\* bounds work.

## Scope

- F\* verification requirements and toolchain guidance
- troubleshooting for F\* / KaRaMeL proof and extraction hygiene
- arithmetic lemma inventory for Low\* bounds proofs

## Canonical Documents

- `[runbook]` [F\* verification requirements](verification-requirements.md)
- `[runbook]` [F\* / KaRaMeL troubleshooting](troubleshooting.md)
- `[runbook]` [Store-entry VC resolution](store-entries-vc-resolution.md)
- `[index]` [Assumption register](../claims/assumptions/README.md)

## Proof Support Modules

- `[reference]` `fstar/jose/Jose.BufferListLemmas.fst`
- `[reference]` `fstar/jose/Jose.Arith.Bounds.fst`

The `idx` bound lemmas are implemented in `Jose.BufferListLemmas.fst`
(`lemma_idx_lt_from_tail_tot`, `lemma_idx_succ_bound_for_rest`). The `pow2 32`
bound lemmas are implemented in `Jose.BufferListLemmas.fst`
(`lemma_idx_lt_pow2_tot`) and `Jose.Arith.Bounds.fst`.

## Reading Rule of Thumb

1. Start here for F\* tool and proof hygiene questions.
2. Use the proof-support module list above when a Low\* bounds proof needs
   arithmetic support.
3. Use `../claims/assumptions/current-register.md` for the current assumption register.
4. Use `../runbooks/README.md` for local verification commands.
