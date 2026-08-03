#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)/.."

mkdir -p artifacts
chmod 777 artifacts
LOG="artifacts/hacl.log"

ensure_docker() {
	if ! command -v docker >/dev/null 2>&1; then
		sudo apt-get update
		sudo apt-get install -y docker.io
	fi
}

ensure_docker

# Pull image only if not present
# NOTE: Docker usage is planned for future HACL*/EverCrypt verification
if ! docker image inspect projecteverest/everest-linux:latest >/dev/null 2>&1; then
	echo "Pulling Project Everest image..."
	docker pull projecteverest/everest-linux:latest
fi

# Check for HACL*/EverCrypt usage in the codebase
echo "=== HACL*/EverCrypt CI Check ===" | tee "$LOG"
echo "" | tee -a "$LOG"

# Check for HACL*/EverCrypt references in our code
CRYPTO_REFS=$(
	find fstar \( -name '*.fst' -o -name '*.fsti' \) 2>/dev/null |
		xargs -r grep -l 'HACL\|EverCrypt' 2>/dev/null || true
)

if [ -n "$CRYPTO_REFS" ]; then
	echo "Found HACL*/EverCrypt references in:" | tee -a "$LOG"
	echo "$CRYPTO_REFS" | tee -a "$LOG"
	echo "" | tee -a "$LOG"

	# Count the references
	HACL_COUNT=$(echo "$CRYPTO_REFS" | xargs grep -h "HACL" 2>/dev/null | wc -l || echo "0")
	EVERCRYPT_COUNT=$(echo "$CRYPTO_REFS" | xargs grep -h "EverCrypt" 2>/dev/null | wc -l || echo "0")

	echo "Statistics:" | tee -a "$LOG"
	echo "  - HACL* references: $HACL_COUNT" | tee -a "$LOG"
	echo "  - EverCrypt references: $EVERCRYPT_COUNT" | tee -a "$LOG"
else
	echo "No HACL*/EverCrypt references found in F* code" | tee -a "$LOG"
	echo "" | tee -a "$LOG"
	echo "Note: HACL*/EverCrypt will provide:" | tee -a "$LOG"
	echo "  - Verified cryptographic primitives" | tee -a "$LOG"
	echo "  - Constant-time implementations" | tee -a "$LOG"
	echo "  - High-performance crypto operations" | tee -a "$LOG"
fi

# Check C stubs that reference EverCrypt
C_CRYPTO_REFS=$(
	find c include \( -name '*.c' -o -name '*.h' \) 2>/dev/null |
		xargs -r grep -l 'EverCrypt' 2>/dev/null || true
)
if [ -n "$C_CRYPTO_REFS" ]; then
	echo "" | tee -a "$LOG"
	echo "Found EverCrypt references in C code:" | tee -a "$LOG"
	echo "$C_CRYPTO_REFS" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "✅ HACL*/EverCrypt check completed" | tee -a "$LOG"
