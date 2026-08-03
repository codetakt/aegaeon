#!/usr/bin/env bash
# CI-friendly F* verification script

set -e
set -o pipefail

echo "=== Starting F* Verification ==="

# Build with log output, capture result
if nix build .#verify-fstar -L 2>&1 | tee /tmp/fstar-build.log; then
	echo ""
	echo "=== ✓ F* Verification SUCCEEDED ==="

	# Show summary from result
	if [ -L result ]; then
		echo "Full log available at: result/verify.log"
		echo ""
		echo "=== Last 20 lines of verification ==="
		tail -20 result/verify.log
	fi
	exit 0
else
	echo ""
	echo "=== ✗ F* Verification FAILED ==="
	echo ""
	echo "Build log saved to: /tmp/fstar-build.log"

	# Nix already showed last 25 lines, but we can show more if needed
	echo "For full logs, check the 'nix log' command shown above"
	exit 1
fi
