# Verification Claims Overview

Last updated: 2026-07-24

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This directory contains the current formal-claim boundary, assumptions, crypto
posture, and claim-maturity references. Start with the short overviews, then use
the detailed registers for audit and evidence review.

## Scope

- formal assurance case and assumption register
- verified-vs-compat crypto posture
- claim mapping and proof-quality index
- model fidelity governance for F* proof references
- current maturity assessment and future wording criteria

## Canonical Documents

- `[claim]` Released formal boundary:
  [Formal claim overview](formal-claim-overview.md),
  [Detailed assurance case](assurance-case/README.md), and
  [Claim index](claim-index.md).
- `[claim]` Assumptions:
  [Assumption boundary overview](assumption-boundary-overview.md) and
  [Detailed assumption register](assumptions/README.md).
- `[claim]` Crypto posture:
  [Crypto allowlist](crypto-allowlist.md) and
  [Crypto claim mapping](crypto-claim-mapping.md).
- `[model]` Model fidelity:
  [Model fidelity register](model-fidelity-register.md) and the
  machine-readable `model-fidelity.yaml`.
- `[claim]` Adjacent assurance boundaries:
  [Client / RP assurance case](client-rp-assurance-case.md) and
  [Admin UI assurance case](admin-ui-assurance-case.md).
- `[model]` Future wording criteria:
  [Verification maturity model](verification-maturity-model.md) and
  [Verification maturity status](verification-maturity-status/README.md).

## Reading Rule of Thumb

1. Start with the two overview documents for navigation and claim-boundary triage.
2. Use the detailed assurance case and assumption register directories for audit decisions.
3. Check the crypto allowlist before changing algorithm or runtime wording.
4. Check model fidelity before citing an F* module from a verified matrix row.
5. Use the maturity documents only for stronger future implementation-closure
  wording; they do not widen the released claim by themselves.
