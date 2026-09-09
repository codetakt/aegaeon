#!/usr/bin/env bash
# Hosted Tamarin wrapper: preserve build diagnostics even when Nix produces no
# output, and accept a (possibly substituted) output only after replaying its
# retained admission records.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$(dirname "$SCRIPT_DIR")")
artifact_base="${TAMARIN_CI_ARTIFACT_DIR:-artifacts/tamarin/ci}"
mkdir -p "$artifact_base"
artifact_base="$(realpath "$artifact_base")"
evidence_dir="$(mktemp -d "$artifact_base/run.XXXXXX")"
echo "Tamarin build evidence: $evidence_dir"

if nix build .#verify-tamarin -L --out-link "$evidence_dir/result" 2>&1 |
	tee "$evidence_dir/build.log"; then
	statuses=("${PIPESTATUS[@]}")
else
	statuses=("${PIPESTATUS[@]}")
fi
printf '{"build_status":%d,"log_status":%d}\n' "${statuses[0]}" "${statuses[1]}" \
	>"$evidence_dir/build-result.json"
if ((statuses[0] != 0 || statuses[1] != 0)); then
	echo "[FAIL] Tamarin build or log capture failed; see $evidence_dir/build.log" >&2
	exit 1
fi

# Use only this invocation's output link. Never collect an old ./result.
cp -R "$evidence_dir/result/." "$evidence_dir/verified-output"
python3 "$REPO_ROOT/scripts/validation/admit_tamarin_lemmas.py" verify-records \
	"$evidence_dir/verified-output" --registry "$REPO_ROOT/spec/tamarin-evidence.json"
tail -n 5 "$evidence_dir/verified-output/verify-tamarin.log"
echo "[OK] Tamarin build and evidence capture succeeded"
