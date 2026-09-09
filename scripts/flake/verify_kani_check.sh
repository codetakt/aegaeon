#!/usr/bin/env bash
# Nix gate for Kani evidence: run the admitted selection (required + diagnostic) in full
# scope, then re-decide the retained records. The legacy suite wrapper is not part of the
# gate; a required rejection or a runner fault fails this derivation.
set -euo pipefail

# Outside a Nix build sandbox (nix run .#verify-kani) TMPDIR may be unset: use a private
# temporary directory so the gate never touches the caller's home or caches.
: "${TMPDIR:=$(mktemp -d)}"
export TMPDIR
export HOME="$TMPDIR"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$TMPDIR/xdg/state}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$TMPDIR/xdg/cache}"
OUTPUT="${AEG_KANI_EVIDENCE_DIR:-artifacts/kani-evidence}"

status=0
python3 scripts/validation/run_kani_evidence.py --scope full --output "$OUTPUT" || status=$?
if [ "$status" -ne 0 ]; then
	echo "KANI-ADMISSION {\"event\":\"gate\",\"status\":\"rejected\",\"exit\":$status}"
	exit "$status"
fi
run_dir="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["run"])' "$OUTPUT/gate.json")"
python3 scripts/validation/run_kani_evidence.py --verify-records "$OUTPUT/$run_dir"
python3 scripts/validation/check_kani_citations.py --gate "$OUTPUT/gate.json"
echo "KANI-ADMISSION {\"event\":\"gate\",\"status\":\"accepted\",\"run\":\"$run_dir\"}"
