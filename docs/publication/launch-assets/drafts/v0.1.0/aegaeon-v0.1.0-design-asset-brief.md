# Aegaeon v0.1.0 Design Asset Brief

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This brief defines the minimum visual assets needed for the first public launch.

## Creative direction

- tone: technical, trustworthy, modern
- avoid stock-security imagery
- emphasize structure, control, and clarity rather than "cyber" aesthetics
- make the relationship between server core and operational controls visually legible

## Required assets

### 1. Hero visual

- Usage:
  - product landing page hero
  - social / announcement image derivative
- Message:
  - Aegaeon combines protocol core and operational control
- Preferred treatment:
  - abstract system / control-plane composition, not a lock icon

### 2. Product architecture diagram

- Usage:
  - landing page section
  - whitepaper
- Must show:
  - data plane
  - control plane
  - admin console
  - management API
  - explicit separation from external assumptions / infrastructure

### 3. Three-pillar diagram

- Usage:
  - landing page
  - whitepaper
  - handout
- Content:
  - Secure Defaults
  - Verified Core
  - Operational Controls

### 4. Admin Console screenshots

- Usage:
  - landing page
  - Spec Sheet
  - media background deck
- Recommended screens:
  - environment overview
  - configuration / policy view
  - audit or key-management related screen

### 5. Open Graph / social card

- Usage:
  - launch post
  - press release links
  - GitHub social preview if needed

## Copy guardrails for visuals

- do not put "formally verified UI" on screenshots or captions
- keep "Verified Core" visually anchored to the server side
- if a diagram shows the admin console, label it as control plane

## Recommended source materials

- `docs/product-positioning.md`
- `docs/development/current-delivery-context.md`
- `docs/specs/management-plane/README.md`
- actual product screenshots from local/staging environment

## Delivery checklist

- hero visual exported for web
- OG image exported
- architecture diagram exported as SVG and PNG
- three-pillar diagram exported as SVG and PNG
- 2 to 3 approved screenshots with consistent dummy data
