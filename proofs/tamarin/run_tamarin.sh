#!/usr/bin/env bash
set -euo pipefail

# Run the CI Tamarin selection through the same admission as the Nix gate and
# retain per-request records.
# Usage: ./run_tamarin.sh [--docker] [theory-path-relative-to-proofs/tamarin ...]
#
# Only requests admitted from this run's own records are reported as verified.
# The Docker image ships tamarin-prover 1.8.0, whose output is not the
# supported contract; the admission rejects it explicitly.

cd "$(dirname "$0")"
PROOFS_ROOT="$(pwd -P)"
ROOT_DIR="$(cd ../.. && pwd -P)"
ARTIFACT_BASE="${AEG_TAMARIN_ARTIFACT_DIR:-$ROOT_DIR/artifacts/tamarin/manual}"
PROOFS_FILE="$ROOT_DIR/ci/tamarin_proofs.sh"
REGISTRY="$ROOT_DIR/spec/tamarin-evidence.json"
ADMIT="$ROOT_DIR/scripts/validation/admit_tamarin_lemmas.py"

USE_DOCKER=false
if [[ ${1:-} == "--docker" ]]; then
	USE_DOCKER=true
	shift
fi

# Serialise words for shlex.split: single-quote each, escaping embedded quotes.
shell_join() {
	local word out=""
	for word in "$@"; do
		out+="'${word//\'/\'\\\'\'}' "
	done
	printf '%s' "${out% }"
}

echo "=== Tamarin Proof Verification ==="
echo "Date: $(date -u +%FT%TZ)"

if [[ $USE_DOCKER == true ]]; then
	if ! command -v docker >/dev/null 2>&1; then
		echo "ERROR: Docker is not installed" >&2
		exit 1
	fi
	IMAGE="darrenldl/tamarin-prover:1.8.0"
	if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
		echo "Pulling Tamarin Prover Docker image..."
		docker pull "$IMAGE"
	fi
	# The tool string is split with Python's shlex; quote every word so a
	# checkout path with spaces or quotes survives the round trip.
	TOOL="$(shell_join docker run --rm -v "$PROOFS_ROOT:/workspace" -w /workspace "$IMAGE" tamarin-prover)"
	echo "Using Docker image: $IMAGE (its output contract is not supported; expect rejection)"
else
	if ! command -v tamarin-prover >/dev/null 2>&1; then
		echo "ERROR: tamarin-prover not found in PATH" >&2
		echo "Use the pinned tool: nix develop .#verification" >&2
		exit 1
	fi
	TOOL="tamarin-prover"
	echo "Using native tamarin-prover"
fi

# shellcheck source=/dev/null
source "$PROOFS_FILE"
normalize_tamarin_proofs

declare -a SELECTED
if [[ $# -gt 0 ]]; then
	for target in "$@"; do
		target="${target#./}"
		found=false
		for spec in "${TAMARIN_PROOF_SPECS[@]}"; do
			if [[ ${spec%%:*} == "$target" ]]; then
				SELECTED+=("$spec")
				found=true
			fi
		done
		if [[ $found == false ]]; then
			echo "ERROR: '$target' is not in the CI selection (ci/tamarin_proofs.sh)" >&2
			exit 1
		fi
	done
else
	SELECTED=("${TAMARIN_PROOF_SPECS[@]}")
fi

mkdir -p "$ARTIFACT_BASE"
OUT_DIR="$(mktemp -d "$ARTIFACT_BASE/run.XXXXXX")"
echo "Evidence directory: $OUT_DIR"
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

python3 "$ADMIT" run \
	--out-dir "$OUT_DIR" \
	--proofs-root "$PROOFS_ROOT" \
	--registry "$REGISTRY" \
	--tool "$TOOL" \
	-- "${SELECTED[@]}"
