# F* Verification Requirements

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This note captures the infrastructure expectations and quick diagnostics needed
before running `./scripts/verify_fstar_ci.sh` (or any of the Flake targets that
wrap it). Keep this nearby when debugging CI parity issues or preparing a new
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

- **Git worktree hygiene (recommended)**: While not strictly required, keeping
  the worktree clean reduces spurious rebuilds because Nix hashes the flake
  input. Stage or stash unrelated edits before running the verification script
  when possible.

## 2. F* Runtime Layer

- `./scripts/verify_fstar_ci.sh` already exports `HOME="$TMPDIR"` while
  invoking F*, so `.checked` and `.hints` files land in a temporary, writable
  directory. No additional action is needed unless the host constrains `/tmp`.

## 3. Troubleshooting Cheatsheet

| Symptom | Likely Cause | Quick Fix |
| --- | --- | --- |
| `cannot connect to socket /nix/var/nix/daemon-socket/socket` | Missing daemon access | Ensure user can read/write the socket; restart daemon if needed |
| `attempt to write a readonly database` | `~/.cache/nix` is read-only | `chown -R <user> ~/.cache/nix` or adjust permissions |
| F* run hangs waiting for cache | Worktree has large untracked changes | Clean/stage files to avoid hashing huge inputs |

Document any additional environmental constraints alongside this page so F*
contributors have a single reference when onboarding.
