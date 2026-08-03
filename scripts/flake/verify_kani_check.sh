#!/usr/bin/env bash
set -euo pipefail

export HOME="$TMPDIR"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$TMPDIR/xdg/state}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$TMPDIR/xdg/cache}"

# Run the thicker regression harness suite in Nix CI by default.
export AEG_KANI_SUITE="${AEG_KANI_SUITE:-regression}"
export AEG_KANI_RUN_SERVER="${AEG_KANI_RUN_SERVER:-1}"

chmod +x scripts/kani/run_kani.sh
exec bash ./scripts/kani/run_kani.sh
