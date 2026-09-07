# Formal Claim Overview

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

## Scope

This is the entrypoint for the public assurance statement, server and SDK
contracts, standards/output baselines, and current evidence/activation status.

## Claim Summary

The target is an assumption-qualified formally verified and security-tested
OAuth/OIDC foundation and separately identified SDK profiles. The statement and
contracts are specified; the release claims are
**inactive** until a particular artifact/configuration satisfies all applicable
obligations. Existing `verified` matrix rows inventory component/model evidence
and do not determine the contract's scope or completion.

## Canonical Documents

- `[spec]` [Public assurance statement and release disclosures](assurance-statement.md)
- `[spec]` [Server assurance contract](assurance-case/assurance-contract.md)
- `[spec]` [SDK assurance contract and output profiles](sdk-assurance/README.md)
- `[spec]` [Standards and applicability](assurance-case/standards-baseline.md)
- `[snapshot]` [Activation backlog](assurance-case/contract-status.md)
- `[claim]` [Evidence interpretation](assurance-case/claim-definition.md)
- `[reference]` [Assumption register](assumptions/current-register.md)
- `[policy]` [Public wording](../../product-positioning.md)
- `[reference]` [Compliance matrix](../../../spec/compliance-matrix.yaml)

## Reading Rule of Thumb

1. Read the contract and pinned standards to determine obligations.
2. Read contract status and evidence interpretation before making a release claim.
3. Use the matrix and proof/assumption registers to locate evidence and open work.
