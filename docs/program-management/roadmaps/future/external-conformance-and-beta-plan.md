# Post-Beta External Conformance Plan

Last updated: 2026-07-07

Status: future plan

Owner: Program Management

Audience: maintainers, planning contributors

This document tracks external conformance work that remains after the completed OSS publication and
minimum beta baseline. It is not a release-readiness checklist for already shipped work.

Authoritative requirement status remains in `spec/compliance-matrix.yaml`; conformance exports are
runtime interoperability evidence, not automatic formal-claim expansion.

## Current Baseline

- The initial OSS publication baseline is complete.
- The OIDC configuration certification plan has passing evidence.
- OIDF tooling and Docker/nginx/TLS harnesses live under `scripts/oidf_conformance/`.
- Accepted exports should be archived under `artifacts/conformance/<plan>/` and indexed from
  `docs/releases/`.

## Target Plans

### OIDC Basic

Goal: complete the OIDC Basic certification plan with both automated and manual evidence.

Remaining work:

- run the plan with the current conformance harness
- resolve manual evidence modules with retained screenshots / attestations
- re-export machine-readable results after manual evidence is accepted
- link the accepted export from release docs

### OAuth Code + PKCE

Goal: archive conformance evidence for the standard authorization-code + PKCE path.

Scope:

- authorization endpoint
- token endpoint
- PKCE S256
- supported client-authentication methods
- negative-path evidence for rejected weak or inconsistent inputs

### DPoP

Goal: validate DPoP proof, token binding, and nonce behaviour against the external suite.

Scope:

- DPoP proof validation
- `token_type: DPoP`
- access-token `cnf.jkt`
- nonce challenge / retry behaviour
- introspection `cnf` exposure where applicable

### PAR And JAR

Goal: validate pushed and signed request handling as external interoperability evidence.

Scope:

- PAR endpoint discovery and request-uri handling
- single-use and expiry semantics
- signed Request Object handling
- PAR + JAR combinations where the suite supports them

### Lower-Priority Plans

Run when suite support and operator time are available:

- Token Exchange
- Device Authorization
- Back-Channel Logout
- FAPI Baseline / Advanced
- JARM variants

## Execution Pattern

1. Prepare conformance environment from `scripts/oidf_conformance/.env.example`.
2. Build or select the Aegaeon image.
3. Start the Docker/nginx/TLS stack.
4. Run the selected plan.
5. Archive the suite export, result JSON, plan config, suite commit, and diagnostics.
6. Add a short release-doc index entry for accepted evidence.

Expected archive shape:

```text
artifacts/conformance/<plan-name>/
  plan-export/
    results.json
    export.zip
    plan.json
    suite_commit.txt
    latest_run_id.txt
  manual-evidence/
```

## Acceptance Criteria

A plan is accepted only when:

- automated modules pass or have documented suite limitations
- manual modules have retained operator evidence
- exports are machine-readable and reproducible enough for review
- regressions from prior accepted runs are triaged
- release docs link the retained evidence

## Certification Decision

Formal OIDF certification is deferred until targeted plans pass with stable evidence and the fee /
legal process is justified. Self-published exports are the preferred intermediate trust-building
step.

## References

- Future backlog: `future-projects.md`
- Current execution: `../active/current-execution-plan.md`
- Conformance release evidence: `docs/releases/evidence/beta-conformance.md`
- OIDF harness: `scripts/oidf_conformance/`
