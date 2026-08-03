#!/usr/bin/env bash
set -euo pipefail

: "${OUT_DIR:?OUT_DIR not set}"

log="$OUT_DIR/verify-fstar-abstract.log"
rm -f "$log"

echo "=> Verifying F* abstract modules" | tee -a "$log"
if bash scripts/verify/verify_fstar_abstract.sh 2>&1 | tee -a "$log"; then
	echo "[OK] F* abstract verification succeeded" | tee -a "$log"
else
	echo "[FAIL] F* abstract verification failed" | tee -a "$log"
	exit 1
fi
