# Verification Overview

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This directory is the authoritative home for Aegaeon verification claims,
assumptions, runbooks, and future proof work. For CI entrypoints and local
reproduction details, start with [Verification runbooks](runbooks/README.md).

The [server assurance contract](claims/assurance-case/assurance-contract.md)
fixes obligations independently of evidence status. The foundation claim is
currently inactive. External hardness, entropy, toolchain and platform contracts
must be disclosed; own-code use of those interfaces remains a verification target.

## Scope

- formal-claim definition and assumption register
- verification status and boundary-closure tracking
- tool runbooks and proof-focused implementation notes

## Directory Layout

- `claims/` — short claim/assumption overviews plus detailed claim, assumptions,
  crypto posture, proof-quality index, and maturity-status documents.
- `runbooks/` — local reproduction steps, extraction status, FFI contracts,
  runtime linkage, sanitizer guidance, and HACL*/EverCrypt integration notes.
- `workplans/` — active or future proof work, boundary-closure roadmaps,
  blocker analyses, and source-structure guidance.
- Domain subdirectories such as `fstar/`, `jose/`, `kani/`, and `oidc/` hold
  tool- or protocol-specific notes.

## Quick Status

- Contract v1: [standards baseline](claims/assurance-case/standards-baseline.md)
  fixes source editions and applicability; [contract status](claims/assurance-case/contract-status.md)
  records the release-activation backlog.

- Strong-constraint crypto posture: `docs/verification/claims/crypto-allowlist.md`
  is the canonical allowlist and claim boundary source.
- Boundary-closing work:
  `docs/verification/workplans/verification-boundary-roadmap.md` tracks runtime
  surfaces that need promotion into the formal claim.
- Verification maturity:
  `docs/verification/claims/verification-maturity-model.md` defines the ladder,
  and `docs/verification/claims/verification-maturity-status/README.md` records the
  current assessed level.
- Evidence discipline: docs describe scope and navigation; fresh command output,
  `spec/compliance-matrix.yaml`, and artefacts under `artifacts/` provide current
  evidence.
- Product wording: `../product-positioning.md` maps the current formal boundary
  to safe outward-facing language.

## Canonical Documents

- `[index]` [Claims overview](claims/README.md) — public claim wording,
  assumptions, crypto posture, maturity, and detailed assurance-case indexes.
- `[index]` [Runbooks overview](runbooks/README.md) — local reproduction,
  extraction, runtime linkage, FFI, and sanitizer guidance.
- `[index]` [Workplans overview](workplans/README.md) — active and future
  verification sequencing.
- `[index]` [JOSE verification overview](jose/README.md)
- `[index]` [OIDC verification overview](oidc/README.md)
- `[index]` [F* verification overview](fstar/README.md)
- `[index]` [Kani overview](kani/README.md)

Use [Documentation index](../index.md) for the exhaustive generated inventory.

## Reading Rule of Thumb

1. Start in `claims/` for anything that affects public verification wording.
2. Use `runbooks/` when reproducing checks or inspecting runtime linkage.
3. Use `workplans/` for future proof work and boundary-closure sequencing.
