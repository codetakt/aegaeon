# Branch Protection Rules

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Platform/CI
- Review by: Security/Verification

## Main Branch Protection

To keep `main` healthy, configure GitHub branch protection with the following settings.

### Required Status Checks

| Status check | Why it matters |
| --- | --- |
| `PR Validation / Required checks` | Requires successful classification and success of every selected check or reusable workflow in the current PR run |

Configure the job named **Required checks** from the **PR Validation** workflow.
Confirm the displayed name in a completed hosted run when selecting the check in
GitHub settings. This document specifies the intended configuration; editing it
does not enable repository protection.

The aggregate runs for documentation-only PRs as well as implementation changes.
See [PR validation](../automation/pr-validation.md) for selection and failure rules.
Individual conditional lanes should not be required independently, because an
intentional skip must remain acceptable. The historical `verify-all` / **Unified
Verification** and **F* Verification** compatibility jobs are passthroughs and do
not establish that any verification succeeded.

### GitHub Settings

1. **Settings → Branches → Branch protection rules**
2. Add a rule for `main`
3. Enable:
   - Require a pull request before merging
   - Require status checks to pass before merging
   - Require branches to be up to date before merging
4. Require the aggregate check above after its first successful hosted run

### Local Verification Before Pushing

```bash
# Core checks selected for implementation/shared-infrastructure changes
nix flake check --print-build-logs

# Formal checks selected by the full PR scope
nix build .#verify-fstar
nix build .#verify-tamarin
nix build .#verify-kani
nix build .#verify-jose
nix build .#verify-dudect
```

### Failure Recovery

1. Open the failing job log in GitHub Actions and inspect the artefacts if provided.
2. Reproduce locally with the commands above (or use `nix run .#security-suite` for the security smoke).
3. Fix the issue and push; the PR will re-run the required checks automatically.

Keeping the branch protection configuration aligned with the current workflows prevents accidental merges that skip verification.
