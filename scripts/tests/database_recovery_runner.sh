#!/usr/bin/env bash
set -euo pipefail

runner=$(nix build .#organizations-recovery-integration --no-link --print-out-paths)
test -n "$runner"
"$runner/bin/aegaeon-organizations-recovery-integration" \
	"$RUNNER_TEMP/aegaeon-recovery-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
