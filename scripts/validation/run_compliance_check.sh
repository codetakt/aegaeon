#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACT_DIR="$REPO_ROOT/artifacts/compliance"
mkdir -p "$ARTIFACT_DIR"

timestamp="$(date +%Y%m%dT%H%M%S)"
log_path="$ARTIFACT_DIR/validate_${timestamp}.log"

(
	cd "$REPO_ROOT"
	python scripts/validation/validate_compliance_matrix.py --check
) | tee "$log_path"

echo "Compliance matrix validation log written to ${log_path#$REPO_ROOT/}"
