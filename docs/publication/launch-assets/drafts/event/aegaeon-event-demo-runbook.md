# Aegaeon Event Demo Runbook

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This runbook defines how to demonstrate Aegaeon consistently at events.
It is written so booth staff, presenters, and partner staff can all use the same flow.

## Demo goals

- explain Aegaeon in under 2 minutes for casual visitors
- provide a deeper 5-minute path for qualified prospects
- show operational-control value, not only protocol feature lists
- stay inside the released claim boundary

## Demo modes

Prepare two default modes.

### Mode A: 90-second booth demo

Use when:

- the visitor is browsing quickly
- the area is noisy or crowded
- the goal is to qualify whether a follow-up is worth it

### Mode B: 5-minute qualified demo

Use when:

- the visitor is technical
- the visitor has a concrete identity-platform problem
- the conversation can continue without blocking traffic

## Mandatory demo ingredients

Every demo should include:

- what Aegaeon is
- why it exists
- the three pillars
- one concrete control-plane view
- one clear next step

## Demo environment recommendation

- use a stable local or staging environment with fixed sample data
- avoid live environments with changing tenant or audit data
- pre-load the browser tabs needed for the demo
- keep one fallback screenshot deck in case the live demo fails

## Suggested browser tabs

- landing page or overview slide
- architecture diagram
- Admin Console environment or configuration view
- audit / key-management or policy-related screen
- whitepaper / preview request page

## Mode A: 90-second booth demo

### Objective

- help the visitor understand the product and decide whether to continue

### Script

#### Step 1: Opening

Say:

- `Aegaeon is an OAuth/OIDC platform that can be embedded in existing services and enterprise infrastructure.`

#### Step 2: Why it matters

Say:

- `Even after OAuth/OIDC is implemented, some areas remain fragile in operation. Aegaeon emphasizes addressing those areas as well.`

#### Step 3: Three pillars

Point to the visual and say:

- `There are three guiding ideas: Secure Defaults, Verified Core, and Operational Controls.`

#### Step 4: One concrete screen

Show one Admin Console screen and say:

- `Alongside standards support, we enable configuration changes, audits, and key operations to be handled through the control plane.`

#### Step 5: Close

Say:

- `If you are interested, we can point you straight to the whitepaper or a PoC discussion.`

### Success signal

The visitor asks one of:

- `What is covered?`
- `What makes it different?`
- `How would we get started with adoption?`

## Mode B: 5-minute qualified demo

### Objective

- move a serious visitor from curiosity to a concrete follow-up

### Script

#### Step 1: Problem statement

Say:

- `Authentication and authorization problems do not end at implementation. Operational debt often arises around exception settings, key operations, change management, and audits.`

#### Step 2: Product definition

Say:

- `Aegaeon is an OAuth/OIDC platform that brings together a high-assurance server-side core, Secure Defaults, and operational controls.`

#### Step 3: Architecture view

Show the architecture diagram and explain:

- data plane
- control plane
- admin console as first-party control-plane UI

Say:

- `The claim centers on the server side. Admin Console is a control-plane UI, but we do not describe the UI itself as formally verified.`

#### Step 4: Product screen walkthrough

Show a control-plane screen and explain:

- environment or client-management view
- policy or configuration view
- audit or key-management related view

Anchor the explanation in:

- change control
- auditability
- operational repeatability

#### Step 5: Technical credibility route

Only if the visitor asks, show:

- compliance matrix
- assurance-case or assumptions links

Say:

- `Our current public wording concerns the security-critical server-side OAuth/OIDC core.`

#### Step 6: Close

Ask:

- `Would you like to start your evaluation by reviewing the materials, or proceed to a discussion about a PoC?`

## Recommended demo stories by visitor type

### Engineering leader

Emphasize:

- implementation risk reduction
- operational debt reduction
- standardization across teams

### Security architect

Emphasize:

- explicit claim boundary
- secure defaults
- control-plane auditability

### Product / business lead

Emphasize:

- faster adoption of OAuth/OIDC
- reduced long-term operational fragility
- clearer governance story

## Demo do and don't

### Do

- start from the problem, not the acronym list
- show one screen with operational meaning
- repeat the next step clearly
- use the same vocabulary as the LP and handout

### Do not

- start with formal-methods jargon
- over-index on proof details for casual visitors
- imply the UI is formally verified
- imply the first launch includes released SDK / WASM

## Fallback plan if live demo fails

If the live environment is unavailable:

- switch immediately to screenshots or slides
- keep the same story order
- offer to continue the technical walkthrough in a follow-up meeting

## Pre-event demo checklist

- sample environment is populated
- tabs are pre-opened
- screenshots are exported as backup
- QR links are tested
- 90-second and 5-minute talk tracks are rehearsed

## Post-demo CTA mapping

- casual interest -> whitepaper
- evaluation interest -> preview / PoC form
- strong fit -> direct follow-up meeting
