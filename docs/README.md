# Aegaeon Documentation Hub

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Documentation

Audience: contributors, maintainers

Aegaeon is an assumption-qualified formally verified and security-tested
OIDC 1.0 / OAuth 2.0/2.1 identity-provider server with OpenID Connect
Federation runtime support. Use
[Product positioning](product-positioning.md) for outward-facing wording,
[Formal claim overview](verification/claims/formal-claim-overview.md) for claim
orientation, and [Assurance case details](verification/claims/assurance-case/README.md)
for formal claim scope, assumptions, and boundary conditions.

This directory collects the living documentation for the project. Keep this hub
thin: section `README.md` files are the entrypoints, program history belongs in
`docs/program-management/historical/`, and completed historical material should
remain only when it has explicit audit or traceability value.

## Start Here

- [Product positioning](product-positioning.md) — what the project can safely call itself today
  vs planned future positions
- [Verification overview](verification/README.md) — claim scope, assumptions, verification status,
  and proof entrypoints
- [Specifications overview](specs/README.md) — canonical product/API/runtime artefact specs
- [Design overview](design/README.md) — runtime, Verified Core, and platform-boundary designs
- [Program management overview](program-management/README.md) — active plans, historical delivery
  records, and roadmaps
- [SDK initiative](program-management/initiatives/sdk/README.md) — SDK handoff,
  repository-boundary, and client-claim planning
- [Releases overview](releases/README.md) — release runbooks and evidence pointers

## Reader Paths

- **Operators**: start with [Operations](operations/README.md), then
  [Configuration](configurations/README.md), [Security](security/README.md), and
  [Releases](releases/README.md).
- **Contributors**: start with [Development](development/README.md),
  [Automation](automation/README.md), [Policies](policies/README.md), and the
  [Documentation style guide](documentation-style-guide.md).
- **Verification reviewers**: start with [Verification](verification/README.md),
  then [Verification claims](verification/claims/README.md),
  [Verification runbooks](verification/runbooks/README.md), and
  `spec/compliance-matrix.yaml`.
- **SDK maintainers**: start with the
  [SDK initiative](program-management/initiatives/sdk/README.md),
  [SDK release runbook](operations/sdk-release.md), and the separate
  `aegaeon-sdk` repository.
- **Maintainers / release managers**: start with
  [Program management](program-management/README.md),
  [Roadmaps](program-management/roadmaps/README.md),
  [Releases](releases/README.md), and [Publication](publication/README.md).

## Section Index

- [Architecture](architecture/README.md)
- [Specifications](specs/README.md)
- [Design](design/README.md)
- [Configuration](configurations/README.md)
- [Policies](policies/README.md)
- [Automation](automation/README.md)
- [Program management](program-management/README.md)
- [Publication](publication/README.md)
- [Releases](releases/README.md)
- [Performance](performance/README.md)
- [Verification](verification/README.md)
- [Operations](operations/README.md)
- [Security](security/README.md)
- [Development](development/README.md)

## Historical / Archived Material

- [Program-management historical records](program-management/historical/README.md)

## Quick Links

- [Changelog](../CHANGELOG.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Agent guide (Claude)](development/claude-agent-guide.md)
- [Documentation style guide](documentation-style-guide.md)
- [Generated documentation index](index.md)
- [`scripts/README.md`](../scripts/README.md)

## Core Commands

```bash
# Main merge guard
nix flake check

# Release build artefact
nix build .#server

# Security suite (deny/audit/vet + fuzz/sanitizers/SBOM/geiger/udeps)
nix run .#security-suite

# Performance smoke
nix run .#perf-bench

# Documentation structure audit
python3 scripts/validation/check_docs_structure.py

# Generated documentation index
python3 scripts/validation/check_docs_structure.py --print-index

# Refresh committed documentation index
python3 scripts/validation/check_docs_structure.py --write-index
```

For the full command set, use [Automation](automation/README.md),
[Verification runbooks](verification/runbooks/README.md), and
[Performance](performance/README.md).

If a document goes stale, update it, promote its durable content, or remove it.
