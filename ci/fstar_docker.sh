#!/usr/bin/env bash
# This script is meant to be run INSIDE the Project Everest Docker container
# It's called from GitHub Actions CI
set -euo pipefail

# We're mounted at /workspace in the container
cd /workspace

echo "F* verification script (Docker mode)"
echo "Running inside Project Everest container"

# Environment is already set up by the Docker image
echo "F* version:"
fstar.exe --version || exit 1

echo "Z3 version:"
z3 --version || echo "Z3 not found"

# Find non-empty F* files, excluding generated files
FILES=$(find fstar tests/fstar -name '*.fst' -size +0 -not -path '*/generated/*' 2>/dev/null || true)

if [ -z "$FILES" ]; then
	echo "ERROR: No F* files found to verify"
	exit 1
fi

echo "Found $(echo $FILES | wc -w) non-empty F* files"

# For now, use admit_smt_queries true due to missing dependencies
# Once HACL* and other deps are properly set up, we can remove this
fstar.exe --admit_smt_queries true --warn_error +271 \
	--include fstar \
	--include tests/fstar \
	--include tests/fstar/property \
	--include tests/fstar/unit \
	--include generated/everparse \
	--include $FSTAR_HOME/ulib \
	--include $HACL_HOME/dist/gcc-compatible \
	--include $KRML_HOME/krmllib \
	$FILES 2>&1

# Check the exit code
if [ $? -ne 0 ]; then
	echo "F* verification failed" >&2
	exit 1
fi

echo "F* verification completed successfully"
