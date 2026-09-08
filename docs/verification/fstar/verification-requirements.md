# F* Verification Requirements

Last updated: 2026-09-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This note captures the infrastructure expectations and quick diagnostics needed
before running `bash scripts/verify/verify_fstar_ci.sh` or
`nix build .#verify-fstar -L`. Keep this nearby when debugging CI parity issues or preparing a new
workstation.

## 1. Nix Infrastructure

- **Daemon socket access**: The user invoking the script must be able to talk to
  `/nix/var/nix/daemon-socket/socket`. A quick check is:

  ```bash
  ls -la /nix/var/nix/daemon-socket/socket
  ```

  Expected mode is `srw-rw-rw-` (world-writeable) or equivalent group access.
  If the command fails with “Operation not permitted”, request daemon access on
  the host before retrying the F* run.

- **Fetcher cache write access**: Verify that the local user owns and can write
  to `~/.cache/nix/fetcher-cache-v3.sqlite` (and the parent directory). Errors
  such as `attempt to write a readonly database` indicate this file or directory
  is read-only. Reassign ownership or adjust permissions, then rerun the script.

- **Git worktree hygiene**: Use an isolated worktree for a reviewable source
  baseline. Include new implementation files in Git's index before invoking the
  Git-backed flake; otherwise Nix will not see them. Preserve unrelated work.

## 2. F* Runtime Layer

- The `verify-fstar` derivation sets `HOME="$TMPDIR"` and copies the source tree
  into a writable build directory. The hosted wrapper invokes that derivation.
  Direct use of `scripts/flake/verify_fstar.sh` requires the documented provider
  environment and a writable source copy; it can create `fstar/C.Loops.fst`.

## 3. Required Invocations and Evidence

The production target requires all five ordered invocations: `1` (policy), `1b`
(federation), `2a-1` (LowStar JSON specification), `2a-2` (LowStar JSON runtime),
and `2b` (remaining selected modules). Any unsuccessful invocation, signal,
missing selected file/tool, or evidence-write failure makes the target fail.
Failed production invocations also print a `[FAIL] Pass <id>` diagnostic with
the runner's exit status, while preserving the structured completion record.
The target runs `tests/ci/test_fstar_runner.py` and `tests/ci/test_fstar_admission.py`
before invoking the real verifier; the same controlled-tool and fixture tests
run in the PR documentation lane.

The build output contains `verify.log` and, under `invocations/<pass-id>/`:

- `inputs.json`: requested and resolved executable argv, working directory,
  selected source paths and SHA-256 digests, tool and available solver identity, ordered includes,
  provider paths, and the available local sources/interfaces/hints/caches.
- `output.log`: the verifier's combined stdout and stderr for that invocation.
- `result.json`: completion state, actual process return code (negative for
  signals), and the input-record/output digests. An incomplete or missing record
  is never a successful invocation. Runs require fresh evidence directories.

Each input and completion record is also emitted with the `FSTAR-EVIDENCE`
prefix. Failed Nix builds have no successful output store path, so these records
and the verifier output survive in the captured build log. The hosted wrapper
saves `build.log` and both Nix/tee statuses under a fresh run directory in
`$FSTAR_CI_ARTIFACT_DIR` (default `artifacts/fstar/ci`), copying successful output
only from that run's dedicated result link. CI uploads these diagnostics on
failure as well as success. The upload excludes the `result` symlink's contents;
the copied `verified-output` tree supplies one copy of the successful evidence.
Preserve failed/incomplete logs during investigation;
a cancellation or early infrastructure failure may leave no completion record.

The dependency snapshot describes available context, not the effective import
or assumption graph. Nix provider paths and the pinned flake identify immutable
external inputs; a direct non-Nix run must retain its external provider trees
separately. The existing generated `C.Loops.fst` assumptions are explicitly
identified as `builder-generated-assumptions` and included in the source snapshot.
Neither their presence nor a zero exit status proves their soundness. This gate
does not establish complete module/lemma coverage, model adequacy, implementation
refinement, or release assurance.

After the fifth invocation the target runs `scripts/validation/admit_fstar_modules.py`,
which binds every requested implementation and interface to exactly one result
under the pinned output contract and rejects missing, duplicate, contradictory
or unclassified results, reported errors, denied cache options and changed
source digests, even when the process exited 0 and printed `Verified module`
lines. It writes `invocations/<pass-id>/modules.json` and, only when all five
passes are accepted, `admission.json`; the hosted wrapper replays those records
before it reports success. See [F\* per-module admission](module-admission.md)
for the contract, dispositions, cache policy and record formats.

`nix build .#verify-abstract` is a separate exploratory target. Its five generated
PAR experiments retain individual results and return failure if any experiment
fails; they are not production proof evidence. A direct run of
`scripts/verify/verify_fstar_abstract.sh` without `OUT_DIR` writes each run to a
fresh `artifacts/fstar/abstract/run.*` directory, because invocation records are
never reused or overwritten. Fixing result propagation does
not establish the validity of those experimental models.

## 4. Troubleshooting Cheatsheet

| Symptom | Likely Cause | Quick Fix |
| --- | --- | --- |
| `cannot connect to socket /nix/var/nix/daemon-socket/socket` | Missing daemon access | Ensure user can read/write the socket; restart daemon if needed |
| `attempt to write a readonly database` | `~/.cache/nix` is read-only | `chown -R <user> ~/.cache/nix` or adjust permissions |
| F* run hangs waiting for cache | Worktree has large untracked changes | Clean/stage files to avoid hashing huge inputs |

Document any additional environmental constraints alongside this page so F*
contributors have a single reference when onboarding.
