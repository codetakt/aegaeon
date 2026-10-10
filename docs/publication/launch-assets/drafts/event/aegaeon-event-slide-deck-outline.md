# Aegaeon Event Slide Deck Outline

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This document defines a reusable slide structure for event talks, booth-side mini-presentations,
or partner sessions. It should work as an 8 to 10 slide deck.

## Deck objective

- explain the product clearly in under 5 minutes
- support a 10-minute presentation with light expansion
- keep the message consistent with the LP, handout, and event talk track

## Recommended deck lengths

- short version: 6 slides
- standard version: 8 slides
- extended version: 10 slides

Use the 8-slide version as the default.

## Slide 1: Title

### Purpose

- establish category and thesis immediately

### Title options

- `Make authentication and authorization more resilient, from implementation through operations`
- `An OAuth/OIDC platform with a high-assurance core and operational controls`

### Subtitle

- `Aegaeon`

### Visual

- hero visual or architecture motif

## Slide 2: Problem

### Purpose

- frame the operational problem, not just protocol implementation

### Key message

- `After implementation, OAuth/OIDC is often fragile around exception settings, key operations, change management, and audits.`

### Suggested bullets

- dangerous exceptions become permanent
- key operations become person-dependent
- configuration changes are hard to audit
- protocol compliance alone does not solve operations

## Slide 3: What Aegaeon is

### Purpose

- define the product simply

### Key message

- `Aegaeon is an OAuth/OIDC platform that can be embedded in existing services and enterprise infrastructure.`

### Suggested bullets

- server-side OAuth/OIDC platform
- control-plane operations through Aegaeon Admin Console
- OSS / Self-hosted evaluation path for the first release

## Slide 4: Three pillars

### Purpose

- anchor the story in a memorable structure

### Content

- Secure Defaults
- Verified Core
- Operational Controls

### Visual

- 3-column or triangular pillar graphic

## Slide 5: Architecture / control plane

### Purpose

- make the product shape concrete

### Content

- data plane
- control plane
- admin console
- management API

### Speaker note

- `The claim centers on the server side. Admin Console is a first-party control-plane UI.`

## Slide 6: What ships now

### Purpose

- prevent ambiguity about release scope

### Suggested bullets

- OAuth 2.0 / 2.1 server
- OpenID Connect 1.0 provider
- OpenID Connect Federation runtime support
- control-plane operations via Admin Console

### Boundary note

- `Current public wording about high assurance concerns the security-critical server-side OAuth/OIDC core.`

## Slide 7: Example use cases

### Purpose

- help the audience map the product to their environment

### Suggested blocks

- embedded identity foundation
- shared authentication / API protection platform
- stricter governance and auditability

## Slide 8: Next step

### Purpose

- create a concrete action

### Suggested CTA

- whitepaper
- Spec Sheet
- preview / PoC discussion

### Closing line

- `Start by reviewing the materials, then discuss a PoC if you have concrete adoption requirements.`

## Optional slide 9: Technical credibility

Use only for technical sessions or qualified meetings.

### Content

- standards coverage
- compliance matrix
- assurance-case and assumptions references

### Warning

- do not overload this slide with proof terminology

## Optional slide 10: Event-specific close

### Content

- booth location
- meeting-booking QR
- contact path

## Visual guidance

- one message per slide
- avoid dense standards tables
- use diagrams over screenshots until the story is anchored
- keep one or two screenshots only where they support the operations narrative

## Speaker pacing

### 5-minute version

- slide 1: 20 sec
- slide 2: 40 sec
- slide 3: 30 sec
- slide 4: 45 sec
- slide 5: 60 sec
- slide 6: 40 sec
- slide 7: 40 sec
- slide 8: 25 sec

### 10-minute version

- expand slides 2, 5, 6, and 9

## Copy guardrails

- do not say the full product is formally verified
- keep `Verified Core` visually and verbally tied to the server side
- describe the Admin Console as a control-plane UI
- avoid mixing SDK launch language into the first-release deck
