# Formal Verification Assurance Case

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This compatibility entrypoint preserves the historical `docs/verification/claims/assurance-case.md` path. The maintained assurance case now lives in `assurance-case/`.

Retained for: temporary compatibility with historical links, generated evidence, and release artifacts that still reference this moved path.

Review after: 2026-10-08

For quick claim-boundary triage, start with [Formal claim overview](formal-claim-overview.md). The split files below remain authoritative for audit and evidence review.

## Scope

- compatibility pointer for the formal verification assurance case
- navigation to claim definition, verification scope, TCB, security mapping, and confidence details

## Canonical Documents

- `[claim]` [Formal claim overview](formal-claim-overview.md)
- `[index]` [Assurance case details](assurance-case/README.md)
- `[claim]` [Claim definition](assurance-case/claim-definition.md)
- `[claim]` [Verification scope and proof quality](assurance-case/verification-scope.md)
- `[claim]` [TCB and out-of-scope boundaries](assurance-case/tcb-and-out-of-scope.md)
- `[claim]` [Security property mapping](assurance-case/security-property-mapping.md)
- `[claim]` [Evidence confidence summary](assurance-case/evidence-confidence.md)

## Reading Rule of Thumb

1. Use [formal-claim-overview.md](formal-claim-overview.md) for a short reader entrypoint.
2. Use [assurance-case/claim-definition.md](assurance-case/claim-definition.md) for the official released claim definition.
3. Do not add new detailed assurance content to this compatibility page.
