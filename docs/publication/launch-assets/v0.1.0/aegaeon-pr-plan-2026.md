# Aegaeon PR Plan (2026 Revised)

Last updated: 2026-07-08

Status: active plan

Owner: Product / Publication

Audience: publication contributors, maintainers

This document records the active 2026 PR / launch sequencing plan for Aegaeon.
It is a schedule and package index, not the authority for final publication
wording.

It reflects the following planning assumptions:

- the first public launch remains anchored on `Aegaeon v0.1.0`
- event participation is treated as an amplification point for the first
  launch, not as a separate large release milestone
- event execution copy should be reusable for the first suitable exhibitable
  event without changing the core launch narrative
- the release narrative should progress from core platform, to integration, to vertical fit, to
  enterprise legacy integration
- exact publication dates must be refreshed against release evidence before
  external publication

## Core narrative

The outward-facing Aegaeon story for 2026 is built in this order:

1. `Secure Defaults`: avoid dangerous configurations by default and place exceptions under control
2. `Verified Core`: apply high-assurance techniques to security-critical OAuth/OIDC surfaces
3. `Operational Controls`: keep configuration changes, key operations, and exceptions auditable and
   governable

This narrative remains the default booth and event message for reusable
exhibition material.

## Release Sequence

| Sequence | Milestone | Primary purpose | Public deliverables |
| --- | --- | --- | --- |
| 1 | Aegaeon v0.1.0 release | first public launch | press release, product page, whitepaper, Spec Sheet, evaluation CTA |
| 2 | Event announcement and exhibition package | event traffic capture | event announcement, demo outline, meeting CTA |
| 3 | Aegaeon SDK v0.1.0 release | integration acceleration | press release, integration guide, updated Spec Sheet |
| 4 | Aegaeon v0.2.0 "Education Ready" release | vertical expansion for education | press release, education integration guide, updated Spec Sheet |
| 5 | Aegaeon SAML Facade v0.1.0 release | enterprise legacy integration story | press release, enterprise integration guide, updated Spec Sheet |

## Channel strategy

### Phase 1: first launch

- Focus all attention on `Aegaeon v0.1.0`
- Publish the whitepaper and Spec Sheet on the same day as the launch release
- Do not fragment the first message with education- or SAML-specific positioning

### Phase 2: Interop amplification

- Use Interop Tokyo 2026 to demonstrate what is already public and available
- Keep the booth message to three pillars: `Secure Defaults`, `Verified Core`,
  `Operational Controls`
- Use `SDK`, `Education Ready`, and `SAML Facade` as `Next` / `Later` story elements, not the main
  show-floor headline

### Phase 3: follow-on launches

- Use the SDK release to convert evaluation interest into implementation work
- Use the education release to open the initial target vertical explicitly
- Use the SAML Facade release to expand into enterprise migration and legacy integration

## Publication package checklist

### Aegaeon v0.1.0

- Press release
- Product landing page
- Whitepaper PDF
- Spec Sheet PDF
- Evaluation / PoC contact path

Working drafts for these assets live under `../drafts/v0.1.0/`.

### Event announcement

- Event announcement post
- Demo summary
- Meeting booking link
- One-page booth handout

Working drafts for reusable event assets live under `../drafts/event/`.

### Aegaeon SDK v0.1.0

- Press release
- Integration guide
- Updated Spec Sheet
- SDK quickstart

### Education Ready

- Press release
- Education integration guide
- Updated Spec Sheet

### SAML Facade

- Press release
- Enterprise integration guide
- Updated Spec Sheet

## Event Announcement Outline

### Working headline

Aegaeon to exhibit at the selected launch-amplification event

### Working subheadline

Demonstrating a high-assurance OAuth/OIDC platform built around Secure Defaults, Verified Core,
and Operational Controls

### Event announcement body points

- Aegaeon will exhibit after the initial public release of `v0.1.0`
- The booth will focus on deployable OAuth/OIDC runtime controls, not just protocol compliance
- Demonstrations will cover the Secure Defaults posture, control-plane auditability, and
  high-assurance handling of security-critical protocol surfaces
- Evaluation and partnership meetings will be available during the event

## Launch asset working set

For the first public launch, use these working drafts as the execution pack:

- `../drafts/v0.1.0/aegaeon-v0.1.0-asset-status.md`
- `../drafts/v0.1.0/aegaeon-v0.1.0-press-release-draft.md`
- `../drafts/v0.1.0/aegaeon-v0.1.0-landing-page-copy.md`
- `../drafts/v0.1.0/aegaeon-v0.1.0-spec-sheet-draft.md`
- `../drafts/v0.1.0/aegaeon-v0.1.0-whitepaper-outline.md`
- `../drafts/v0.1.0/aegaeon-v0.1.0-preview-request-flow.md`
- `../drafts/v0.1.0/aegaeon-v0.1.0-design-asset-brief.md`
- `../drafts/v0.1.0/aegaeon-v0.1.0-github-public-readiness.md`

These materials are execution drafts. If any wording conflict appears, `docs/product-positioning.md`
remains the claim boundary authority.

For event execution beyond the Interop-specific schedule, use
`../drafts/event/aegaeon-event-exhibition-plan.md` as the reusable exhibition pack.

## Press Release Draft References

- First launch wording:
  `../drafts/v0.1.0/aegaeon-v0.1.0-press-release-draft.md`
- Follow-on SDK, education, and SAML wording:
  `../drafts/follow-on/aegaeon-2026-follow-on-press-release-drafts.md`

These draft files are not approved publication copy. Before reuse, refresh the
release date, verify the claim boundary, and check product positioning.
