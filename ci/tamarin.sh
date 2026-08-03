#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)/.."

# This script is now deprecated in favor of direct installation in CI workflow
# For local development, use:
#   nix build .#verify-tamarin -L
# Or:
#   proofs/tamarin/run_tamarin.sh --docker

echo "Note: ci/tamarin.sh is deprecated. Tamarin is now installed directly in CI workflow."
echo "Delegating to proofs/tamarin/run_tamarin.sh..."

pushd proofs/tamarin >/dev/null
./run_tamarin.sh
popd >/dev/null
