#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

export RUN_TRIVY="${RUN_TRIVY:-1}"
export GRYPE_FAIL_ON="${GRYPE_FAIL_ON:-medium}"

exec "$ROOT/scripts/security/run_sbom_scan.sh" "$@"
