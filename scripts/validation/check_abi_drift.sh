#!/usr/bin/env bash
# check_abi_drift.sh - Detect drift between ABI template and committed ABI JSON
#
# This script ensures the committed verified_core.abi.json stays in sync with
# the canonical template in generate_verified_core_abi.js. Run this in CI to
# prevent ABI drift that would cause external host implementers to build
# incorrect WASM import implementations.
#
# Usage:
#   ./scripts/validation/check_abi_drift.sh
#
# Exit codes:
#   0 - ABI is in sync
#   1 - ABI drift detected (regenerate with: node scripts/sdk/generate_verified_core_abi.js)
#   2 - Script error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

ABI_GENERATOR="$ROOT_DIR/scripts/sdk/generate_verified_core_abi.js"
COMMITTED_ABI="$ROOT_DIR/generated/lowstar/verified-core/verified_core.abi.json"

# Verify required files exist
if [[ ! -f $ABI_GENERATOR ]]; then
	echo "ERROR: ABI generator not found: $ABI_GENERATOR" >&2
	exit 2
fi

if [[ ! -f $COMMITTED_ABI ]]; then
	echo "ERROR: Committed ABI not found: $COMMITTED_ABI" >&2
	exit 2
fi

echo "[check-abi-drift] Checking ABI drift..."

# Create temp file for regenerated ABI (non-destructive approach)
# Use portable mktemp syntax (macOS doesn't support --suffix)
TEMP_ABI=$(mktemp "${TMPDIR:-/tmp}/abi-check-XXXXXX.json")
trap 'rm -f "$TEMP_ABI"' EXIT

# Regenerate ABI to temp file
echo "[check-abi-drift] Regenerating ABI from template to temp file..."
if ! node "$ABI_GENERATOR" --out "$TEMP_ABI" >/dev/null 2>&1; then
	echo "ERROR: ABI generator failed" >&2
	exit 2
fi

# Compare (normalize by parsing as JSON to ignore whitespace and timestamp differences)
# Use node for reliable JSON comparison, excluding generatedAt timestamps
DIFF_RESULT=$(node -e "
const fs = require('fs');
function normalizeForComparison(obj) {
  if (typeof obj !== 'object' || obj === null) return obj;
  if (Array.isArray(obj)) return obj.map(normalizeForComparison);
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    // Skip timestamp fields that change on every generation
    if (key === 'generatedAt') continue;
    result[key] = normalizeForComparison(value);
  }
  return result;
}
const committed = normalizeForComparison(JSON.parse(fs.readFileSync(process.argv[1], 'utf8')));
const regenerated = normalizeForComparison(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')));
const equal = JSON.stringify(committed) === JSON.stringify(regenerated);
process.exit(equal ? 0 : 1);
" "$COMMITTED_ABI" "$TEMP_ABI" 2>/dev/null && echo "equal" || echo "different")

if [[ $DIFF_RESULT == "equal" ]]; then
	echo "[check-abi-drift] ABI is in sync with template"
	exit 0
else
	echo ""
	echo "============================================================"
	echo "ERROR: ABI drift detected!"
	echo "============================================================"
	echo ""
	echo "The committed verified_core.abi.json differs from what the"
	echo "template in generate_verified_core_abi.js produces."
	echo ""
	echo "This can happen when:"
	echo "  - The ABI template was updated but the JSON wasn't regenerated"
	echo "  - The JSON was manually edited (don't do this!)"
	echo ""
	echo "To fix, regenerate and commit the ABI:"
	echo "  node scripts/sdk/generate_verified_core_abi.js"
	echo "  git add generated/lowstar/verified-core/verified_core.abi.json"
	echo "  git commit -m 'chore: regenerate verified_core.abi.json'"
	echo ""

	# Show a text diff for debugging (excluding generatedAt)
	echo "Diff preview (first 30 lines, excluding timestamps):"
	diff <(jq -S 'del(.generatedAt)' "$COMMITTED_ABI") \
		<(jq -S 'del(.generatedAt)' "$TEMP_ABI") 2>/dev/null | head -30 || true
	echo ""
	exit 1
fi
