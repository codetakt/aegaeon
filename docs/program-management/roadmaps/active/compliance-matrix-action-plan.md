# Compliance Matrix Hardening Notes

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

The single source of truth for RFC requirement status is `spec/compliance-matrix.yaml`, validated by
`scripts/validation/validate_compliance_matrix.py`.

For open remediation work, use issues/PRs and link back to matrix row IDs and evidence paths. For
sprint-level planning, use:

- Current execution plan: `docs/program-management/roadmaps/active/current-execution-plan.md`
- Prioritised backlog: `docs/program-management/roadmaps/future/future-projects.md`
- Historical sprint records:
  - `docs/program-management/historical/roadmaps/oauth2-execution-plan.md`
  - `docs/program-management/historical/roadmaps/oidc-execution-plan.md`
- Verification posture and runbooks: `docs/verification/README.md`

## Validate matrix correctness

```bash
python3 scripts/validation/validate_compliance_matrix.py --check
```

## Generate a current compliance report (local)

```bash
./scripts/validation/run_compliance_check.sh
```

Outputs are written under `artifacts/compliance/` and are intended to be uploaded as CI artefacts.

## Lifting a row to `verified`

1. Implement the requirement and add tests/proofs.
2. Ensure evidence artefacts exist and are referenced by path from `spec/compliance-matrix.yaml`.
3. Run the relevant verification suite locally:
   - `nix flake check -L` (or service-specific targets such as `nix build .#verify-fstar -L`,
     `nix build .#verify-tamarin -L`, `nix build .#verify-kani -L`, `nix run .#security-suite`).
4. Re-run matrix validation and commit the updated matrix plus any referenced artefacts.

## Policy

Do not maintain separate spreadsheets or “shadow” status lists in-tree. If additional tracking is
needed, use issues/PRs and link back to matrix row IDs and evidence paths.
