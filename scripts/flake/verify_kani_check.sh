#!/usr/bin/env bash
# Nix gate for Kani evidence: run the admitted selection (required + diagnostic) in full
# scope, then re-decide the retained records. The legacy suite wrapper is not part of the
# gate; a required rejection or a runner fault fails this derivation.
set -euo pipefail

# A private per-run temporary directory (under the caller's TMPDIR when set) keeps HOME
# and the XDG state/cache away from shared locations, inside and outside a Nix build
# sandbox; it is removed on exit. The evidence itself is written under OUTPUT.
GATE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/aegaeon-kani-gate.XXXXXX")"
trap 'rm -rf "$GATE_TMP"' EXIT
export TMPDIR="$GATE_TMP"
export HOME="$GATE_TMP"
export XDG_STATE_HOME="$GATE_TMP/xdg/state"
export XDG_CACHE_HOME="$GATE_TMP/xdg/cache"
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
