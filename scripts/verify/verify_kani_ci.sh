#!/usr/bin/env bash
# Consume the same full-scope Nix gate as local flake checks. Cached outputs are
# accepted only after current-source record reconstruction and citation admission.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(dirname "$(dirname "$SCRIPT_DIR")")
cd "$REPO_ROOT"
artifact_base="${KANI_CI_ARTIFACT_DIR:-artifacts/kani/ci}"
mkdir -p "$artifact_base"
artifact_base="$(realpath "$artifact_base")"
evidence_dir="$(mktemp -d "$artifact_base/run.XXXXXX")"
echo "Kani build evidence: $evidence_dir"
nix --version >"$evidence_dir/nix-version"
nix config show build-dir >"$evidence_dir/nix-configured-build-dir"
nix eval --raw .#verify-kani.drvPath >"$evidence_dir/requested-drv"
requested_drv="$(cat "$evidence_dir/requested-drv")"

# The Nix build user may not traverse runner.temp. Use only the daemon's fixed
# build parent; keep uploaded artifacts separate from the retained build tree.
python3 "$REPO_ROOT/scripts/ci/collect_kani_failure.py" --prepare-build "$evidence_dir"
build_root="$(cat "$evidence_dir/build-root")"
if nix build "$requested_drv^*" --keep-failed --log-format internal-json -L \
	--option build-dir "$build_root" \
	--out-link "$evidence_dir/result" 2>&1 |
	tee "$evidence_dir/build.log" >/dev/null; then
	statuses=("${PIPESTATUS[@]}")
else
	statuses=("${PIPESTATUS[@]}")
fi
printf '{"build_status":%d,"log_status":%d}\n' "${statuses[0]}" "${statuses[1]}" \
	>"$evidence_dir/build-result.json"
if ((statuses[0] != 0 || statuses[1] != 0)); then
	python3 "$REPO_ROOT/scripts/ci/collect_kani_failure.py" "$evidence_dir" || true
	echo "[FAIL] Kani build or log capture failed; see $evidence_dir/build.log" >&2
	exit 1
fi

# A fresh invocation directory prevents an earlier output from being adopted.
output="$evidence_dir/verified-output"
cp -R "$evidence_dir/result/evidence/." "$output"
run_name="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["run"])' "$output/gate.json")"
if [[ ! $run_name =~ ^run-[a-zA-Z0-9_-]+$ ]]; then
	echo "[FAIL] Kani gate names an invalid retained run" >&2
	exit 1
fi
nix develop .#verification --command python3 \
	"$REPO_ROOT/scripts/validation/run_kani_evidence.py" \
	--root "$REPO_ROOT" --verify-records "$output/$run_name" 2>&1 |
	tee "$evidence_dir/replay.log"
nix develop .#verification --command python3 \
	"$REPO_ROOT/scripts/validation/check_kani_citations.py" \
	--root "$REPO_ROOT" --gate "$output/gate.json" 2>&1 |
	tee "$evidence_dir/citations.log"
echo "[OK] Full-scope Kani output replays against the current source"
