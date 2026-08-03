# Security Review

Last updated: 2026-07-08

Status: snapshot

Owner: Security

Audience: security reviewers, maintainers

> **Status note (2026-07-08):** Snapshot security review; refresh evidence before using it for a new release decision.

This compatibility entrypoint preserves the historical `docs/security/security-review.md` path. The maintained security-review snapshot now lives in `security-review/`.

Retained for: temporary compatibility with historical links, generated evidence, and release artifacts that still reference this moved path.

Review after: 2026-10-08

## Scope

- compatibility pointer for the security-review snapshot
- navigation to threat, hardening, testing, risk, certification, and appendix details

## Canonical Documents

- `[index]` [Security review details](security-review/README.md)
- `[snapshot]` [Threat, vulnerability, and formal review](security-review/threat-vulnerability-and-formal-review.md)
- `[snapshot]` [Runtime hardening and testing](security-review/runtime-hardening-and-testing.md)
- `[snapshot]` [Risk, certification, and appendices](security-review/risk-certification-and-appendices.md)

## Reading Rule of Thumb

1. Use [security-review/README.md](security-review/README.md) as the maintained map.
2. Update the split files directly; do not add new review content to this compatibility page.
