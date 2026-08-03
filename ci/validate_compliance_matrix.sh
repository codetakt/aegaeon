#!/usr/bin/env bash
set -euo pipefail

# Validate compliance matrix exists and is valid YAML
if [ ! -f "spec/compliance-matrix.yaml" ]; then
	echo "✅ Compliance matrix not yet created (spec/compliance-matrix.yaml)"
	exit 0
fi

# Check if the file is valid YAML
if command -v yq &>/dev/null; then
	yq '.' spec/compliance-matrix.yaml >/dev/null 2>&1 || {
		echo "❌ Compliance matrix is not valid YAML"
		exit 1
	}
	echo "✅ Compliance matrix is valid YAML"
else
	echo "⚠️ yq not installed, skipping YAML validation"
fi

# Ensure no items remain in an implemented state
pending=$(grep -c '^\s*status:\s*implemented\s*$' spec/compliance-matrix.yaml || true)
if [ "$pending" -gt 0 ]; then
	echo "❌ Compliance matrix has $pending pending item(s) with status: implemented"
	exit 1
fi

echo "✅ Compliance matrix validation passed"
