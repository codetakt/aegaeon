# OAuth Coverage Initiative

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This initiative tracks the next phase of OAuth 2.x standards coverage work: expanding beyond the
currently verified core (RFC 6749/6750/7009/7591/7636/7662/8414/9101/9126/9449/9700 + JOSE).

## Scope

- OAuth RFC coverage expansion planning
- formal verification obligation cataloging
- profile-system sequencing and compliance-matrix updates

## Canonical Documents

- `[workplan]` [Formal verification definition catalog](oauth-formal-verification-plan.md)
- `[workplan]` [OAuth profile system plan](oauth-profile-system-plan.md)
- `[roadmap]` [RFC coverage roadmap](../../roadmaps/active/oauth-rfc-coverage-roadmap.md)
- `[reference]` `../../../../spec/compliance-matrix.yaml`

## Reading Rule of Thumb

1. Start here when adding or reclassifying OAuth RFC coverage.
2. Use the compliance matrix as the authoritative status tracker.
3. Keep broad sequencing in `../../roadmaps/active/`.

## Purpose

1. Translate additional OAuth WG RFCs into **machine-checkable** proof/test obligations.
2. Decide which requirements are **F\*** vs **Tamarin** vs **tests-only** vs **docs-only**.
3. Keep the compliance matrix as the only source of truth for “supported vs not supported”.

## Working rules

- Add RFC stubs to `spec/compliance-matrix.yaml` early as `planned` with applicability tags.
- Do not claim support in discovery/metadata unless the behaviour is enforced end-to-end.
- Any opt-in extension must remain operator-controlled, documented, and fail-closed by default.
