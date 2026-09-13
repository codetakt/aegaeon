#!/usr/bin/env bash
# Preserve diagnostic evidence even when Nix cannot produce a successful output.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$(dirname "$SCRIPT_DIR")")
artifact_base="${FSTAR_CI_ARTIFACT_DIR:-artifacts/fstar/ci}"
mkdir -p "$artifact_base"
artifact_base="$(realpath "$artifact_base")"
evidence_dir="$(mktemp -d "$artifact_base/run.XXXXXX")"
echo "F* build evidence: $evidence_dir"

if nix build .#verify-fstar -L --out-link "$evidence_dir/result" 2>&1 |
	tee "$evidence_dir/build.log"; then
	statuses=("${PIPESTATUS[@]}")
else
	statuses=("${PIPESTATUS[@]}")
fi
printf '{"build_status":%d,"log_status":%d}\n' "${statuses[0]}" "${statuses[1]}" \
	>"$evidence_dir/build-result.json"
if ((statuses[0] != 0 || statuses[1] != 0)); then
	echo "[FAIL] F* build or log capture failed; see $evidence_dir/build.log" >&2
	exit 1
fi

# Use only this invocation's output link. Never collect an old ./result.
cp -R "$evidence_dir/result/." "$evidence_dir/verified-output"
# A substituted or cached build output is accepted only if its per-module
# admission records are present, bound to the invocation digests and replayable.
python3 "$REPO_ROOT/scripts/validation/admit_fstar_modules.py" \
	--verify-records "$evidence_dir/verified-output"
# The effective-assumption graph shipped with the output must be reconstructible
# from its own records and this checkout; consistency is not qualification.
python3 "$REPO_ROOT/scripts/validation/assumption_graph.py" check \
	--evidence "$evidence_dir/verified-output" \
	--source-root "$REPO_ROOT" \
	--graph "$evidence_dir/verified-output/assumption-graph.json"
cat "$evidence_dir/verified-output/verify.log"
echo "[OK] F* build and evidence capture succeeded"
