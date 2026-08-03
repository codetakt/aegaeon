# Branch Protection Rules

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Platform/CI
- Review by: Security/Verification

## Main Branch Protection

To keep `main` healthy, configure GitHub branch protection with the following settings.

### Required Status Checks

| Status Check | Why it matters |
|--------------|----------------|
| `verify-all` | Runs `nix flake check --print-build-logs` (covers workspace fmt/clippy/tests + merge guard) |
| `fstar` | Containerised F* proof verification |
| `tamarin` | Protocol proof suite |
| `kani` | Bounded model checking harnesses |
| `jose-vectors` | JOSE / RFC conformance vectors |
| `dudect` | Constant-time statistical analysis |

Only `verify-all` is strictly required, but enabling the additional checks keeps regressions visible to reviewers.

### GitHub Settings

1. **Settings → Branches → Branch protection rules**
2. Add a rule for `main`
3. Enable:
   - Require a pull request before merging
   - Require status checks to pass before merging
   - Require branches to be up to date before merging
4. Add the checks from the table above in the desired order

### Local Verification Before Pushing

```bash
# Core checks run by verify-all
nix flake check --print-build-logs

# Optional deeper verification (matches individual jobs)
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
