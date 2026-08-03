# Managed Provider Evidence

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

## Scope

This document defines the hosted managed-provider evidence required by the
`managed-provider-evidence` enterprise-readiness gate in
`spec/enterprise-readiness-claim.current.json`.

It is separate from local Dex / Keycloak interop evidence. Enterprise-readiness
activation requires at least one real commercial or enterprise provider tenant
run.

## Canonical schema and validator

The source-managed evidence schema is:

- `spec/managed-provider-evidence.schema.json`

Validate basic evidence shape with:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_managed_provider_evidence.py <managed-provider-evidence.json>'
```

Require enterprise-readiness suitable evidence with:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_managed_provider_evidence.py --require-enterprise-ready <managed-provider-evidence.json>'
```

## Enterprise-readiness requirements

The stricter validator mode requires:

- `provider.class` is `commercial` or `enterprise`
- `lane.hosted` is `true`
- `lane.status` is `passed`
- `provider.issuer` uses `https://`
- GitHub source metadata is present:
  - `github_run_id`
  - `github_workflow`
  - `github_repository`
  - `github_ref`
  - `github_sha`
- GitHub source metadata is shape-checked:
  - `github_run_id` is numeric
  - `github_repository` is `owner/repo`
  - `github_ref` is a full `refs/*` value
  - `github_sha` is a 40-hex commit SHA
- `generated_at` is no older than 168 hours at the source-evidence or
  archive-collection reference time
- `runtime.claim_phase` is `released-client-claim`
- `runtime.default_profile` is not `compat-interop`
- `runtime.promoted_client_slices` is non-empty
- `runtime.compat_only_surfaces` is a list of recorded compatibility surfaces
  that remain outside the released-client formal claim

Sandbox, self-hosted, local-only, failed, or manually imported evidence can
remain useful for debugging, but it must not close the enterprise-readiness
managed-provider gate.

## Evidence source

The SDK managed-provider workflow produces the evidence through:

- `managed-provider-evidence.yml`
- `build:managed-provider-evidence`
- `.artifacts/managed-provider/managed-provider-evidence.json`

When importing the evidence into the server release archive, keep the JSON with
the release-candidate evidence bundle and link it from the release manifest.

## Completion criteria

Before marking `managed-provider-evidence` complete:

1. Run the hosted managed-provider lane against a provisioned real tenant.
2. Validate the evidence with `--require-enterprise-ready`.
3. Archive the evidence with the release-candidate evidence bundle.
4. Confirm released-client readiness consumes the same evidence or a fresher
   equivalent.
5. Keep the enterprise-readiness claim inactive unless all other required
   evidence is complete.

## Related documents

- `spec/managed-provider-evidence.schema.json`
- `spec/released-client-claim.current.json`
- `spec/enterprise-readiness-claim.current.json`
- `docs/releases/evidence/release-security-evidence.md`
