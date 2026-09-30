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
nix eval --raw .#verify-kani.drvPath >"$evidence_dir/requested-drv"
requested_drv="$(cat "$evidence_dir/requested-drv")"

# Nix creates this fresh root beneath a traversable, secure parent. The default
# works with a local daemon; hosted runners provide RUNNER_TEMP. Do not derive
# capture bounds from builder-controlled log messages or upload the build tree.
build_root="$(python3 - "${RUNNER_TEMP:-/nix/var/nix/builds}" <<'PY'
import pathlib
import sys
import uuid

parent = pathlib.Path(sys.argv[1])
if (
    not parent.is_absolute()
    or parent.resolve(strict=True) != parent
    or not parent.is_dir()
    or parent.stat().st_mode & 0o022
):
    raise SystemExit("Kani build parent must be a secure canonical absolute directory")
root = parent / ("aegaeon-kani-" + uuid.uuid4().hex)
if root.exists() or root.is_symlink():
    raise SystemExit("Kani build root must be fresh")
print(root)
PY
)"
printf '%s\n' "$build_root" >"$evidence_dir/build-root"
if nix build "$requested_drv^*" --keep-failed --log-format internal-json -L \
	--option build-dir "$build_root" \
	--out-link "$evidence_dir/result" 2>&1 |
	tee "$evidence_dir/build.log"; then
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
if [[ ! "$run_name" =~ ^run-[a-zA-Z0-9_-]+$ ]]; then
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
