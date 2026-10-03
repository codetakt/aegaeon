# Aegaeon Event One-Page Handout

Last updated: 2026-07-08

Status: draft

Owner: Product / Publication

Audience: publication contributors, maintainers

> **Status note (2026-07-08):** Draft publication collateral; do not treat this as approved release wording, and check `docs/product-positioning.md` before reuse.

This file is the content draft for a one-page printed handout or downloadable event leave-behind.
It is designed for a single A4 page, portrait or landscape.

## Primary objective

- help visitors remember what Aegaeon is after leaving the booth
- make it easy to share internally with engineering / security stakeholders
- drive readers to the whitepaper and preview / PoC request

## Layout recommendation

Use a simple 5-block structure:

1. headline and one-line definition
2. three pillars
3. what ships now
4. use cases
5. QR codes and CTA

## Draft content

### Header

#### Product name

Aegaeon

#### Tagline

An OAuth/OIDC platform with a high-assurance core and operational controls

#### One-line definition

A platform that brings together an OAuth/OIDC server for embedding in existing services
and enterprise infrastructure, and the control plane that supports it.

### Three pillars

#### Secure Defaults

We support defaults that help avoid dangerous configurations and operations that keep exception settings under control.

#### Verified Core

We apply a high-assurance approach to security-critical server-side OAuth/OIDC core areas
such as PKCE, DPoP, and JOSE.

#### Operational Controls

We enable change management, audits, RBAC, and key / secret lifecycle management
in a form that is easy for operators to track.

### What ships now

- OAuth 2.0 / OAuth 2.1 server
- OpenID Connect 1.0 provider
- OpenID Connect Federation runtime support
- Control-plane operations through Aegaeon Admin Console
- OSS / Self-hosted evaluation path

### Use cases

- Embedding an authentication foundation into existing products
- Establishing a shared authentication and API protection foundation across multiple services
- Strengthening operational controls, including key operations, audits, and configuration changes

### Boundary note

Current public wording about high assurance concerns the security-critical server-side
OAuth/OIDC core. Aegaeon Admin Console is a first-party control-plane UI,
but we do not describe the UI itself as formally verified.

### CTA block

Materials and evaluation paths:

- Whitepaper
- Spec Sheet
- Preview / PoC consultation

### QR labels

- `Whitepaper`
- `Spec Sheet`
- `Preview / PoC`

## Design notes

- keep the page easy to scan in under 30 seconds
- avoid long standards lists
- use one diagram at most
- prioritize one QR for conversion and one QR for content

## Optional back-side content

If a two-sided version is needed, add:

- simple architecture diagram
- short demo flow
- contact or meeting-booking URL
