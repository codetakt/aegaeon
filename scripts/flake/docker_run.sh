#!/usr/bin/env bash
set -euo pipefail

IMAGE="${DOCKER_IMAGE:-aegaeon}"
PORTS="${DOCKER_PORTS:-8080:8080}"

exec docker run --rm -p "$PORTS" "$IMAGE" "$@"
