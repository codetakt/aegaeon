#!/usr/bin/env bash
# Run command with appropriate environment based on hierarchy
# Usage: ./run-with-environment.sh <command>

set -euo pipefail

if [ $# -eq 0 ]; then
	echo "Usage: $0 <command>" >&2
	exit 1
fi

COMMAND="$*"
ENV_TYPE=$(./ci/detect-environment.sh)

case "$ENV_TYPE" in
nix)
	echo "Running with Nix: $COMMAND" >&2
	exec nix develop -c bash -c "$COMMAND"
	;;
local)
	echo "Running with local environment: $COMMAND" >&2
	exec bash -c "$COMMAND"
	;;
*)
	echo "Unknown environment type: $ENV_TYPE" >&2
	exit 1
	;;
esac
