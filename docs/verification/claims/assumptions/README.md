# F* Assumption Register Details

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This directory contains the detailed split assumption register. Use `../assumption-boundary-overview.md` for a short boundary summary.

## Scope

- current assumption categories and full register
- runtime and TCB contracts presupposed by the claim
- mitigation strategy and audit checklist
- historical assumption reductions retained for traceability

## Canonical Documents

- `[claim]` [Current register](current-register.md)
- `[claim]` [Runtime contract register](runtime-contract-register.md)
- `[claim]` [Mitigation and audit checklist](mitigation-and-audit.md)
- `[historical]` [Historical reductions](historical-reductions.md)

## Reading Rule of Thumb

1. Start with [current-register.md](current-register.md) for current assumption IDs and categories.
2. Use [mitigation-and-audit.md](mitigation-and-audit.md) for review criteria.
3. Use [historical-reductions.md](historical-reductions.md) only when tracing eliminated assumptions.
