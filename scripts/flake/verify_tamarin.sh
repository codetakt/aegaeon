#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"

ROOT_DIR="$(pwd -P)"
PROOFS_ROOT="$ROOT_DIR/proofs/tamarin"
PROOFS_FILE="$ROOT_DIR/ci/tamarin_proofs.sh"

if [ ! -d "$PROOFS_ROOT" ]; then
	echo "proofs/tamarin directory not found" >&2
	exit 1
fi

if [ ! -f "$PROOFS_FILE" ]; then
	echo "Tamarin proof list not found: $PROOFS_FILE" >&2
	exit 1
fi

# shellcheck source=/dev/null
source "$PROOFS_FILE"
normalize_tamarin_proofs

export LANG=C.UTF-8
export LC_ALL=C.UTF-8

TAMARIN_TIMEOUT_DEFAULT=600
TAMARIN_DERIVCHECK_TIMEOUT_DEFAULT=180

tamarin_timeout="${TAMARIN_TIMEOUT:-$TAMARIN_TIMEOUT_DEFAULT}"
tamarin_deriv_timeout="${TAMARIN_DERIVCHECK_TIMEOUT:-$TAMARIN_DERIVCHECK_TIMEOUT_DEFAULT}"

log="$OUT_DIR/verify-tamarin.log"
rm -f "$log"

TEMP_DIR="$OUT_DIR/tamarin_proofs"
mkdir -p "$TEMP_DIR"

PASSED=0
FAILED=0
TOTAL=0

for PROOF_SPEC in "${TAMARIN_PROOF_SPECS[@]}"; do
	IFS=':' read -r FILE LEMMAS <<<"$PROOF_SPEC"
	PROOF_PATH="$PROOFS_ROOT/$FILE"

	if [ ! -f "$PROOF_PATH" ]; then
		echo "[FAIL] Missing proof file: $FILE" | tee -a "$log"
		FAILED=$((FAILED + 1))
		TOTAL=$((TOTAL + 1))
		continue
	fi

	IFS=',' read -ra LEMMA_LIST <<<"$LEMMAS"
	for LEMMA in "${LEMMA_LIST[@]}"; do
		TOTAL=$((TOTAL + 1))
		echo "=> Proving $FILE:$LEMMA" | tee -a "$log"
		LOG_NAME=$(echo "$FILE" | sed 's|/|_|g' | sed 's|\.spthy||')
		PROOF_LOG="$TEMP_DIR/${LOG_NAME}_${LEMMA}.log"

		if timeout "$tamarin_timeout" \
			tamarin-prover \
			--prove="$LEMMA" \
			--derivcheck-timeout="$tamarin_deriv_timeout" \
			"$PROOF_PATH" >"$PROOF_LOG" 2>&1; then
			if grep -q "verified" "$PROOF_LOG"; then
				echo "[OK] $FILE:$LEMMA" | tee -a "$log"
				PASSED=$((PASSED + 1))
			elif grep -q "falsified" "$PROOF_LOG"; then
				echo "[FAIL] $FILE:$LEMMA (falsified)" | tee -a "$log"
				FAILED=$((FAILED + 1))
				cat "$PROOF_LOG" | head -50 >>"$log"
			else
				echo "[FAIL] $FILE:$LEMMA (inconclusive)" | tee -a "$log"
				FAILED=$((FAILED + 1))
				cat "$PROOF_LOG" | head -50 >>"$log"
			fi
		else
			echo "[FAIL] $FILE:$LEMMA (error/timeout)" | tee -a "$log"
			FAILED=$((FAILED + 1))
			cat "$PROOF_LOG" | head -50 >>"$log"
		fi
	done

done

echo "=== Summary ===" | tee -a "$log"
echo "Lemmas verified: $PASSED/$TOTAL" | tee -a "$log"
echo "Lemmas failed: $FAILED/$TOTAL" | tee -a "$log"

if [ "$FAILED" -ne 0 ]; then
	exit 1
fi
