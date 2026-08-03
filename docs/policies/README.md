# Policies Overview

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

This index summarizes the normative policy documents, their ownership, and their
review expectations.

## Scope

- normative security / compliance / operator posture
- ownership and review expectations for long-lived policies
- policy references used by operations, verification, and release work

## Interim Reviewer (Initial Rollout)

- Codex (automated): initial review support until team ownership is fully staffed
- This does not replace the designated `Review by` team in each policy

## Canonical Documents

| Policy | Owner | Review by | Summary |
| --- | --- | --- | --- |
| `docs/policies/audit-policy.md` | Security/Verification | Platform/Operations | Audit-required operations, storage baseline, and fail-closed rules. |
| `docs/policies/branch-protection.md` | Platform/CI | Security/Verification | Branch protection rules and required CI checks. |
| `docs/policies/dcr-everparse-self-check.md` | Security/Verification | Core/Server | EverParse DCR self-check posture and gating. |
| `docs/policies/dcr-policy.md` | Security/Verification | Core/Server | DCR BCP gates for grant types, PKCE, and sender constraints. |
| `docs/policies/dependency-policy.md` | Security/Verification | Platform/CI | Supply-chain gates: deny, audit, vet, geiger. |
| `docs/policies/jose-header-policy.md` | Crypto/FFI | Security/Verification | JOSE protected header length limits and policy context. |
| `docs/policies/jwt-bearer-policy.md` | Security/Verification | Core/Server | JWT bearer grant posture and client-subject toggle. |
| `docs/policies/management-platform-quality-profile.md` | Platform/CI | SDK/Admin Console | Shared quality profile and drift policy for backend, SDK, and admin-console repositories. |
| `docs/policies/oauth-doc-only-rfcs.md` | Security/Verification | Core/Server | Doc-only RFC posture and expectations. |
| `docs/policies/saml-facade-policy.md` | Security/Verification | Core/Server | SAML termination via Aegaeon Facade; RFC 7522 not applicable in core. |
| `docs/policies/unsafe-code-policy.md` | Security/Verification | Core/Server | Unsafe usage restrictions and geiger policy. |
| `docs/policies/verified-crypto-policy.md` | Security/Verification | Crypto/FFI | Verified crypto definition, coverage, and exceptions. |

## Reading Rule of Thumb

1. Start here when you need the normative posture for a feature or operational decision.
2. Jump to `docs/operations/` for runbooks and to `docs/configurations/` for environment variables.
3. Jump to `docs/verification/` when policy language touches the formal claim boundary.
