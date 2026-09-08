#!/usr/bin/env bash
# Preserve diagnostic evidence even when Nix cannot produce a successful output.
set -euo pipefail

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
cat "$evidence_dir/verified-output/verify.log"
echo "[OK] F* build and evidence capture succeeded"
