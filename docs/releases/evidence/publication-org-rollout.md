# Publication Organization Rollout Evidence

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

## Scope

This document defines the evidence required by the `publication-org-rollout`
enterprise-readiness gate in `spec/enterprise-readiness-claim.current.json`.

It records the release-organization controls needed before released-client or
enterprise-ready wording can rely on SDK/package publication custody.

## Canonical schema and validator

The source-managed report schema is:

- `spec/publication-org-rollout.schema.json`

Validate reports with:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_publication_org_rollout.py <publication-org-rollout-report.json>'
```

Require activation-ready evidence with:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_publication_org_rollout.py --require-ready <publication-org-rollout-report.json>'
```

## Required tasks

The report must include exactly the publication controls that currently block
released-client and enterprise-readiness wording:

- `publication_org_branch_protection`
- `publication_org_secret_rollout`

`ready=true` is accepted only when all required tasks are `done`, each done task
has a non-empty `detail`, and no blockers remain. `--require-ready` also
requires a concrete target repository owner and repository name.

## Evidence source

The SDK publication workflow produces the rollout report through:

- `publication-org-rollout.yml`
- `release:publication-org-rollout-report`
- `.artifacts/release/publication-org-rollout-report.json`

When importing the evidence into the server release archive, keep the report
with the release-candidate evidence bundle and link it from
`docs/releases/evidence/release-security-evidence.md` / the release manifest when the
enterprise-readiness claim is being evaluated.

## Completion criteria

Before marking `publication-org-rollout` complete:

1. Generate a rollout report against the real publication organization.
2. Validate it with `--require-ready`.
3. Archive the report with the release-candidate evidence bundle.
4. Confirm released-client claim readiness uses the same report.
5. Keep the enterprise-readiness claim inactive unless all other required
   evidence is complete.

## Related documents

- `spec/publication-org-rollout.schema.json`
- `spec/released-client-claim.current.json`
- `spec/enterprise-readiness-claim.current.json`
- `docs/releases/evidence/release-security-evidence.md`
