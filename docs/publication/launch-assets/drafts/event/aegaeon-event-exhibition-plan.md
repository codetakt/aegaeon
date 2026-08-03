# Aegaeon Event Exhibition Plan

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This document defines a reusable exhibition plan for any 2026 event where Aegaeon can exhibit.
It is intentionally not tied to a single conference. If Interop Tokyo is confirmed, this plan can
be applied there. If not, the same package should be reusable for the first suitable event.

## Purpose

The event program should do four things:

1. turn launch messaging into a live conversation
2. make Aegaeon legible in under one minute to visitors
3. generate qualified follow-up meetings, not just booth traffic
4. reinforce the first-release story without widening the current claim boundary

## Event selection criteria

Prioritize events that satisfy most of the following:

- visitors include platform engineers, security architects, enterprise architects, or product teams
- booth traffic is likely to contain self-hosted / infrastructure buyers or evaluators
- the event allows demos, handouts, and meeting booking
- the audience can understand the value of OAuth/OIDC infrastructure beyond consumer login UX
- the booth cost and staffing load are proportionate to expected pipeline value

Deprioritize events where:

- the audience is too broad and non-technical
- the event mainly rewards consumer-brand awareness rather than technical evaluation
- there is no practical way to demo, collect leads, or book follow-up meetings

## Core event message

At any event, Aegaeon should be described in this order:

1. Secure Defaults
2. Verified Core
3. Operational Controls

Short booth message:

- `認証認可を、実装だけでなく運用まで壊れにくくする OAuth/OIDC 基盤`

Expanded booth message:

- `Aegaeon は、サーバ側の高保証コア、Secure Defaults、運用統制を一体で整備した OAuth/OIDC 基盤です。`

## Boundary guardrails

At event booths, staff and printed materials must not imply:

- the entire product, including the UI, is formally verified
- the admin console itself is a formally verified UI
- the SDK / WASM client track is already released as part of the first launch

Safe wording:

- `サーバ側の security-critical な OAuth/OIDC コアに高保証アプローチを適用`
- `Aegaeon Admin Console は first-party control-plane UI`

## Exhibition formats

Prepare for three event shapes.

### Format A: Standard booth

Use when:

- there is a dedicated booth space
- at least 2 staff can rotate continuously
- demo monitors and printed material are available

Bring:

- one hero board
- one architecture board
- one live demo screen
- one one-page handout
- one QR code for preview / PoC request

### Format B: Shared booth / partner area

Use when:

- there is limited wall space
- the team is participating through a partner or consortium
- visitors need a fast, compact explanation

Bring:

- one concise messaging board
- one tablet / laptop demo
- one QR card
- one short leave-behind handout

### Format C: Session / meeting-centric presence

Use when:

- there is no formal booth
- the event allows side meetings, lightning talks, or sponsor sessions

Bring:

- one short slide deck
- one demo laptop
- one downloadable asset pack
- one meeting booking path

## What to exhibit

Every event package should include the following content layers.

### Layer 1: Instant understanding

For visitors who stop for 10 to 20 seconds:

- what Aegaeon is
- who it is for
- why it is different

Recommended visible line:

- `高保証コアと運用統制を備えた OAuth/OIDC 基盤`

### Layer 2: Technical differentiation

For visitors who stay 1 to 3 minutes:

- Secure Defaults
- server-side high-assurance core
- control-plane auditability and change control

### Layer 3: Evaluation conversion

For visitors who show real interest:

- whitepaper
- Spec Sheet
- preview / PoC request
- meeting booking

## Recommended demo set

### Demo 1: Product overview

Purpose:

- explain the product in less than 2 minutes

Flow:

1. show the product thesis
2. show server and control plane roles
3. show how the admin console supports operational control

### Demo 2: Admin Console walkthrough

Purpose:

- make the operational-control story concrete

Focus:

- configuration view
- policy or client-management view
- audit or key-management related screen

### Demo 3: Technical credibility path

Purpose:

- give technical buyers a deeper route without forcing proof details on every visitor

Focus:

- standards coverage
- compliance matrix
- assurance-case and assumptions links

## Physical / visual asset list

### Mandatory

- event headline banner
- 1 architecture diagram
- 1 three-pillar visual
- 1 to 2 admin-console screenshots
- QR code for preview / PoC request
- QR code for whitepaper / Spec Sheet

### Recommended

- social-card style event image
- short demo loop on screen
- printed one-page handout

## Handout structure

The one-page event handout should contain:

- one-line product definition
- three pillars
- what ships now
- what it is for
- QR to whitepaper
- QR to preview / PoC request

Do not overfill it with standards lists.

## Event page / announcement asset set

For any confirmed event, prepare:

- one event announcement post
- one short event page / section on the site
- one meeting-booking CTA
- one event-specific social image

## Lead capture design

### Primary path

- preview / PoC request form

### Secondary path

- direct meeting booking for qualified prospects

### Triage questions for booth staff

- Are you evaluating a new identity platform or improving an existing one?
- Is the main need embedded identity, shared platform, or governance / audit control?
- Are you looking for OSS / self-hosted evaluation now?

### Recommended lead labels

- `evaluation`
- `PoC`
- `partner`
- `media`
- `student / research`

## Staffing plan

### Minimum staffing

- 2 people for a booth event

Roles:

- one primary explainer / closer
- one demo and technical deep-dive owner

### Preferred staffing

- 3 people

Roles:

- greeter / traffic capture
- product explainer
- technical deep-dive / meeting qualification

## Talk track by visitor type

### Engineering leader

- emphasize implementation risk and operational debt reduction

### Security architect

- emphasize secure defaults, explicit boundary, and control-plane auditability

### Product / business lead

- emphasize faster, safer adoption of OAuth/OIDC without long-term operational fragility

### Partner / integrator

- emphasize self-hosted evaluation, documentation, and roadmap visibility

## Pre-event deliverables timeline

### T-6 weeks

- confirm event format
- select staff
- confirm demo scope
- start visual asset production

### T-4 weeks

- freeze event message
- finalize handout draft
- confirm QR destinations
- rehearse 2-minute demo

### T-2 weeks

- freeze visuals
- print handouts
- verify form and booking flow
- prepare FAQ / objection handling notes

### T-1 week

- dry run demos end-to-end
- confirm staffing schedule
- confirm transport and hardware
- prepare follow-up templates

### Event day

- track meaningful conversations, not only scans
- tag leads immediately
- schedule follow-ups while context is fresh

### T+3 business days

- send follow-up to all qualified leads
- log learnings on message fit, objections, and missing assets
- update LP / FAQ / deck based on real questions

## Success metrics

Track:

- total qualified conversations
- number of preview / PoC requests
- number of booked follow-up meetings
- number of whitepaper downloads from event traffic
- recurring objections or misunderstandings

Do not treat raw booth scans as the main KPI.

## Open production checklist

- create event-specific handout draft
- create short slide deck
- create event signage copy
- prepare QR destinations and tracking
- prepare event-specific FAQ / objection handling sheet

Working drafts for these now exist under:

- `aegaeon-event-announcement-draft.md`
- `aegaeon-event-one-page-handout.md`
- `aegaeon-event-faq-and-objection-handling.md`
- `aegaeon-event-demo-runbook.md`
- `aegaeon-event-slide-deck-outline.md`

## Dependencies

This plan depends on:

- `../v0.1.0/aegaeon-v0.1.0-landing-page-structure.md`
- `../v0.1.0/aegaeon-v0.1.0-landing-page-copy.md`
- `../v0.1.0/aegaeon-v0.1.0-press-release-draft.md`
- `../v0.1.0/aegaeon-v0.1.0-preview-request-flow.md`
- `../v0.1.0/aegaeon-v0.1.0-design-asset-brief.md`
- `../../../../product-positioning.md`
