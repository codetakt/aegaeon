#!/usr/bin/env bash
# Detect and select appropriate build environment
# Priority: 1. Nix, 2. Local
#
# Note: Most checks are Nix-first (flakes). Some workflows/scripts may still use
# Docker for pinned images, but local reproduction should prefer the Nix shells.

set -euo pipefail

# Check for Nix
if command -v nix &>/dev/null && [ -f flake.nix ]; then
	echo "Nix environment available" >&2
	echo "nix"
	exit 0
fi

# Fallback to local environment
echo "Using local environment (manual setup required)" >&2
echo "local"
