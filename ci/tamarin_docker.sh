#!/usr/bin/env bash
# This script is meant to be run INSIDE the Tamarin Docker container
# It's called from GitHub Actions CI
set -euo pipefail

# We're mounted at /workspace in the container
cd /workspace/proofs/tamarin

echo "=== Tamarin Proof Verification (Docker mode) ==="
echo "Date: $(date)"
echo ""

source /workspace/ci/tamarin_proofs.sh
normalize_tamarin_proofs

PASSED=0
FAILED=0
TOTAL=0

# Use temp directory inside container for intermediate files
TEMP_DIR="/tmp/tamarin_proofs"
mkdir -p "$TEMP_DIR"

echo "Starting proof verification..."
echo ""

for PROOF_SPEC in "${TAMARIN_PROOF_SPECS[@]}"; do
	IFS=':' read -r FILE LEMMAS <<<"$PROOF_SPEC"

	if [ ! -f "$FILE" ]; then
		echo "  ✗ File $FILE not found"
		FAILED=$((FAILED + 1))
		TOTAL=$((TOTAL + 1))
		continue
	fi

	echo "Processing $FILE..."

	# Get directory of the file for include path
	FILE_DIR=$(dirname "$FILE")

	# Parse lemmas
	IFS=',' read -ra LEMMA_LIST <<<"$LEMMAS"

	for LEMMA in "${LEMMA_LIST[@]}"; do
		TOTAL=$((TOTAL + 1))
		echo -n "  Proving lemma '$LEMMA'... "

		# Run Tamarin on the specific lemma
		# Replace slashes in filename for log file
		LOG_NAME=$(echo "$FILE" | sed 's|/|_|g' | sed 's|\.spthy||')
		PROOF_LOG="$TEMP_DIR/${LOG_NAME}_${LEMMA}.log"

		# Run tamarin-prover (without --include which is not supported in 1.8.0)
		if tamarin-prover --prove="$LEMMA" "$FILE" >"$PROOF_LOG" 2>&1; then
			# Check if proof was successful
			if grep -q "verified" "$PROOF_LOG"; then
				echo "✓ VERIFIED"
				PASSED=$((PASSED + 1))
			elif grep -q "falsified" "$PROOF_LOG"; then
				echo "✗ FALSIFIED"
				FAILED=$((FAILED + 1))
				# Output the proof log for debugging
				echo "    --- Begin proof log for $LEMMA ---"
				cat "$PROOF_LOG" | head -50
				echo "    --- End proof log ---"
			else
				echo "? INCONCLUSIVE"
				FAILED=$((FAILED + 1))
				# Output the proof log for debugging
				echo "    --- Begin proof log for $LEMMA ---"
				cat "$PROOF_LOG" | head -50
				echo "    --- End proof log ---"
			fi
		else
			echo "✗ ERROR"
			FAILED=$((FAILED + 1))
			# Output the error log
			echo "    --- Begin error log for $LEMMA ---"
			cat "$PROOF_LOG" | head -50
			echo "    --- End error log ---"
		fi
	done

	echo ""
done

echo "=== Summary ==="
echo "Lemmas verified: $PASSED/$TOTAL"
echo "Lemmas failed: $FAILED/$TOTAL"

if [ "$FAILED" -eq 0 ] && [ "$TOTAL" -gt 0 ]; then
	echo "Status: SUCCESS - All security properties verified"
	exit 0
else
	echo "Status: FAILURE - Some lemmas could not be verified"
	exit 1
fi
