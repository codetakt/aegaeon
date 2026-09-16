#!/usr/bin/env bash
# Generate a source dependency SBOM from a fresh, recorded input snapshot.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$SCRIPT_DIR/generate_sbom.py" "$@"
