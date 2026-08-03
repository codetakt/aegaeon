#!/usr/bin/env bash
set -euo pipefail

# Run all Tamarin proofs (natively or via Docker) and collect results.
# Usage: ./run_tamarin.sh [--docker]

cd "$(dirname "$0")"
ROOT_DIR="$(cd ../.. && pwd)"
ARTIFACT_DIR="${AEG_TAMARIN_ARTIFACT_DIR:-$ROOT_DIR/artifacts/tamarin/manual}"

USE_DOCKER=false
if [[ ${1:-} == "--docker" ]]; then
	USE_DOCKER=true
	shift
fi

echo "=== Tamarin Proof Verification ==="
echo "Date: $(date)"
echo ""

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
	TAMARIN_CMD=(docker run --rm -v "$PWD:/workspace" -w /workspace "$IMAGE" tamarin-prover)
	echo "Using Docker image: $IMAGE"
else
	if ! command -v tamarin-prover >/dev/null 2>&1; then
		echo "ERROR: tamarin-prover not found in PATH" >&2
		echo "Install Tamarin from: https://tamarin-prover.github.io/" >&2
		echo "Or re-run with --docker" >&2
		exit 1
	fi
	TAMARIN_CMD=(tamarin-prover)
	echo "Using native tamarin-prover"
fi

echo ""

TIMEOUT=${TAMARIN_TIMEOUT:-600}
echo "Timeout per file: ${TIMEOUT}s"

declare -a PROOF_FILES
if [[ $# -gt 0 ]]; then
	for target in "$@"; do
		if [[ -f $target ]]; then
			PROOF_FILES+=("$target")
		else
			echo "WARNING: target '$target' not found" >&2
		fi
	done
else
	readarray -d '' PROOF_FILES < <(find . -type f -name '*.spthy' ! -name 'common.spthy' -print0 | sort -z)
fi

if [[ ${#PROOF_FILES[@]} -eq 0 ]]; then
	echo "No .spthy files to verify."
	exit 1
fi

mkdir -p "$ARTIFACT_DIR"

FAILED=0
SUCCESS=0
declare -A FILE_STATUS

for file in "${PROOF_FILES[@]}"; do
	display_name="${file#./}"
	log_name="${display_name%.spthy}"
	log_name="${log_name//\//_}"
	log_file="${ARTIFACT_DIR}/${log_name}.log"

	echo "→ Proving ${display_name}"
	if timeout "$TIMEOUT" "${TAMARIN_CMD[@]}" --prove "$file" >"$log_file" 2>&1; then
		if grep -q " falsified" "$log_file" || grep -q "analysis incomplete" "$log_file"; then
			echo "   ✗ Lemma not fully verified (see $log_file)"
			FILE_STATUS["$display_name"]="✗ FAILED"
			FAILED=$((FAILED + 1))
		else
			echo "   ✓ Verified (log: $log_file)"
			FILE_STATUS["$display_name"]="✓ VERIFIED"
			SUCCESS=$((SUCCESS + 1))
		fi
	else
		echo "   ✗ Command failed (see $log_file)"
		FILE_STATUS["$display_name"]="✗ ERROR"
		FAILED=$((FAILED + 1))
	fi
done

echo ""
echo "Summary: $SUCCESS succeeded, $FAILED failed"

if [[ $FAILED -eq 0 ]]; then
	exit 0
else
	exit 1
fi
