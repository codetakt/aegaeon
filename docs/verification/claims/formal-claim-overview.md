# Formal Claim Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This overview is the short reader entrypoint for the formal verification claim.
The authoritative detailed record remains the [assurance case details](assurance-case/README.md).

## Scope

- current server-side formal claim boundary
- where runtime, host, and deployment assumptions enter the claim
- which documents control public wording and evidence review

## Claim Summary

Aegaeon may claim an assumption-qualified formally verified and security-tested
OIDC 1.0 / OAuth 2.0/2.1 identity-provider server when requirements are marked
`verified` in `spec/compliance-matrix.yaml` and backed by the evidence classes
listed in the assurance case.

The released claim is server-side. Client/RP SDK, admin UI, external host
behaviour, deployment integrity, and cryptographic hardness remain bounded by
their explicit TCB and assumption documents unless separately promoted.

## Canonical Documents

- `[index]` [Detailed assurance case](assurance-case/README.md)
- `[claim]` [Assumption boundary overview](assumption-boundary-overview.md)
- `[claim]` [Assumption register](assumptions/current-register.md)
- `[policy]` [Product positioning](../../product-positioning.md)
- `[reference]` [Compliance matrix](../../../spec/compliance-matrix.yaml)

## Reading Rule of Thumb

1. Use this overview for a quick claim-boundary check.
2. Use [assurance-case/README.md](assurance-case/README.md) for audit, evidence, and section-level detail.
3. Use [product-positioning.md](../../product-positioning.md) before changing public wording.
