#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)/.."

mkdir -p artifacts
chmod 777 artifacts
LOG="artifacts/everparse.log"

ensure_docker() {
	if ! command -v docker >/dev/null 2>&1; then
		sudo apt-get update
		sudo apt-get install -y docker.io
	fi
}

ensure_docker

# Pull image only if not present
# NOTE: Docker usage is planned for future EverParse generation
if ! docker image inspect projecteverest/everest-linux:latest >/dev/null 2>&1; then
	echo "Pulling Project Everest image..."
	docker pull projecteverest/everest-linux:latest
fi

# For now, just verify schema files exist and the generated parsers are present
echo "=== EverParse CI Check ===" | tee "$LOG"
echo "" | tee -a "$LOG"

# Check for schema specification files
SCHEMA_FILES=$(find fstar/lowparse \( -name "*.3d" -o -name "*.evr" \) 2>/dev/null || true)
if [ -z "$SCHEMA_FILES" ]; then
	echo "ERROR: No EverParse schema files (*.3d or *.evr) found in fstar/lowparse/" | tee -a "$LOG"
	exit 1
fi

echo "Found EverParse schemas:" | tee -a "$LOG"
echo "$SCHEMA_FILES" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Check if generated parsers exist
if [ -d "generated/everparse" ]; then
	echo "Generated parsers directory exists" | tee -a "$LOG"
	GENERATED_FILES=$(find generated/everparse -name "*.fst" -o -name "*.fsti" 2>/dev/null || true)
	if [ -n "$GENERATED_FILES" ]; then
		echo "Found generated parser files:" | tee -a "$LOG"
		echo "$GENERATED_FILES" | tee -a "$LOG"
	else
		echo "Warning: No generated parser files found" | tee -a "$LOG"
	fi
else
	echo "Note: Generated parsers directory not found (will be created during build)" | tee -a "$LOG"
fi

echo "" | tee -a "$LOG"
echo "✅ EverParse schema files are present" | tee -a "$LOG"
