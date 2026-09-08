#!/usr/bin/env bash
# Required Tamarin gate: every selected (theory, lemma) must be admitted by
# scripts/validation/admit_tamarin_lemmas.py from this run's own records.
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"

ROOT_DIR="$(pwd -P)"
PROOFS_ROOT="$ROOT_DIR/proofs/tamarin"
# The override exists for controlled-tool regression tests only; the Nix and
# hosted paths always use the shared CI selection.
PROOFS_FILE="${TAMARIN_PROOFS_FILE:-$ROOT_DIR/ci/tamarin_proofs.sh}"
REGISTRY="$ROOT_DIR/spec/tamarin-evidence.json"
ADMIT="$ROOT_DIR/scripts/validation/admit_tamarin_lemmas.py"

for required in "$PROOFS_ROOT" "$PROOFS_FILE" "$REGISTRY" "$ADMIT"; do
	if [ ! -e "$required" ]; then
		echo "[FAIL] required input not found: $required" >&2
		exit 1
	fi
done

# shellcheck source=/dev/null
source "$PROOFS_FILE"
normalize_tamarin_proofs
if [ "${#TAMARIN_PROOF_SPECS[@]}" -eq 0 ]; then
	echo "[FAIL] the Tamarin selection is empty" >&2
	exit 1
fi

# The admission regressions run before the real prover; tests that drive this
# script with a controlled tool set AEG_TAMARIN_SELFTEST=0 to avoid recursion.
if [ "${AEG_TAMARIN_SELFTEST:-1}" != "0" ]; then
	(cd "$ROOT_DIR" && python3 -m unittest discover -s tests/ci -p 'test_tamarin_admission.py')
fi

export LANG=C.UTF-8
export LC_ALL=C.UTF-8

python3 "$ADMIT" run \
	--out-dir "$OUT_DIR" \
	--proofs-root "$PROOFS_ROOT" \
	--registry "$REGISTRY" \
	--tool "${TAMARIN_TOOL:-tamarin-prover}" \
	-- "${TAMARIN_PROOF_SPECS[@]}"
