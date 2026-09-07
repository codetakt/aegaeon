# Formal Verification Assurance Case Details

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This directory contains the split formal verification assurance case. Use `../formal-claim-overview.md` for a short reader entrypoint.

## Scope

- fixed server assurance obligations, pinned standards and activation status
- assumption-qualified evidence interpretation
- verification scope, proof-quality classification, and evidence freshness rules
- TCB, out-of-scope boundaries, and security-property mapping

## Canonical Documents

- `[spec]` [Server assurance contract](assurance-contract.md)
- `[spec]` [Standards baseline](standards-baseline.md)
- `[snapshot]` [Contract activation status](contract-status.md)
- `[claim]` [Claim definition and evidence interpretation](claim-definition.md)
- `[claim]` [Verification scope and proof quality](verification-scope.md)
- `[claim]` [TCB and out-of-scope boundaries](tcb-and-out-of-scope.md)
- `[claim]` [Security property mapping](security-property-mapping.md)
- `[claim]` [Evidence confidence summary](evidence-confidence.md)

## Reading Rule of Thumb

1. Start with [assurance-contract.md](assurance-contract.md) and [standards-baseline.md](standards-baseline.md) to determine obligations, then check [contract-status.md](contract-status.md) before changing public wording.
2. Use [verification-scope.md](verification-scope.md) for proof-framework and proof-quality definitions.
3. Use [tcb-and-out-of-scope.md](tcb-and-out-of-scope.md) when a claim touches runtime, host, or dependency boundaries.
