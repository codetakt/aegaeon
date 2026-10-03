# Aegaeon v0.1.0 Landing Page Copy Draft

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This draft is for the first public product page / launch LP.
The copy intentionally stays inside the current server-side claim boundary.

For the page-level information architecture and CTA design, see
`aegaeon-v0.1.0-landing-page-structure.md`.

## Page goal

- Explain what Aegaeon is in one screen
- Show why it is different from a generic OAuth/OIDC server
- Convert interest into preview / PoC inquiries

## Hero

### Eyebrow

High-assurance OAuth/OIDC platform

### Headline

Make authentication and authorization more resilient, from implementation through operations

### Subheadline

Aegaeon is an OAuth/OIDC platform that can be embedded in existing services and enterprise infrastructure.
It brings together a high-assurance server-side core, Secure Defaults, and operational controls
to help reduce both implementation risks during adoption and incidents during operations.

### Primary CTA

Request a preview

### Secondary CTA

Read the whitepaper

### Support copy

Planned for OSS / Self-hosted delivery.
The initial release will focus on Aegaeon Server and Aegaeon Admin Console.

## Section 1: Why Aegaeon

### Heading

Even after implementation, OAuth/OIDC can be fragile in operation

### Body

Authentication and authorization problems do not end with protocol implementation.
Operational risks accumulate in production: exceptions for dangerous settings,
key operations dependent on individuals, incidents during changes, and audit gaps.

By treating OAuth/OIDC implementation and operational controls together,
Aegaeon aims to provide an authentication and authorization foundation that stands up to long-term operation.

## Section 2: Three pillars

### Heading

Three pillars for a more resilient authentication and authorization foundation

### Pillar 1

#### Title

Secure Defaults

#### Description

Defaults avoid dangerous configurations and make it easier to keep exception settings under control.

### Pillar 2

#### Title

Verified Core

#### Description

We apply a high-assurance approach to security-critical server-side OAuth/OIDC core areas
such as PKCE, DPoP, and JOSE.

### Pillar 3

#### Title

Operational Controls

#### Description

Configuration changes, audits, RBAC, and key / secret lifecycle management
can be handled together in a way that is easy for operators to track.

## Section 3: What ships in v0.1.0

### Heading

What the first release provides

### Body

- OAuth 2.0 / OAuth 2.1 server
- OpenID Connect 1.0 server
- OpenID Connect Federation runtime support
- Control-plane operations through Aegaeon Admin Console
- Adoption and evaluation flow for self-hosted use

### Note

Aegaeon Admin Console is a first-party control-plane UI,
but we do not position the UI itself as formally verified.
The formal claims center on the server side.

## Section 4: Evidence / trust section

### Heading

Claims and evidence at release

### Body

Aegaeon's current public wording is based on the server-side claim:
"An assumption-qualified, formally verified and security-tested
OIDC 1.0 / OAuth 2.0/2.1 identity provider server."

This wording rests on verification and testing results from F*, Tamarin, Kani,
JOSE / conformance / security-suite, and other work, together with explicit assumptions.

### Evidence links

- Assumption Register
- Assurance Case
- Compliance Matrix
- Security review summary

## Section 5: Use cases

### Heading

Intended deployment scenarios

### Use case 1

Embed an authentication foundation into an existing product

### Use case 2

Standardize a shared authentication and API protection foundation across multiple services

### Use case 3

Establish controls covering key operations, audits, and change management

## Section 6: Call to action

### Heading

Start with the evaluation materials

### Body

The whitepaper and Spec Sheet are available.
We also welcome preview and PoC inquiries.

### CTA buttons

- Download the whitepaper
- Download the Spec Sheet
- Request a preview

## FAQ draft

### Q. What will Aegaeon release?

The release will focus on Aegaeon Server and Aegaeon Admin Console for operating it.

### Q. Is the entire product formally verified?

The current claim concerns the security-critical server-side OAuth/OIDC core.
Admin Console is a first-party control-plane UI, but we do not describe the UI itself
as formally verified.

### Q. Is it SaaS or self-hosted?

For the first release, we will focus on evaluation paths for OSS / Self-hosted use.

## Copy to avoid

- "The entire product is formally verified"
- "The admin UI is also formally verified"
- "SDK / WASM have also been released at the same time"
- "All cryptography and all client surfaces have been verified"
