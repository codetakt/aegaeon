#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"

# Traverse the repository with the pinned nixfmt-tree wrapper.
treefmt --ci

# Static analysis
statix check .

# Dead code (strict)
deadnix \
	--fail \
	--no-lambda-arg \
	--no-lambda-pattern-names \
	--no-underscore \
	.
