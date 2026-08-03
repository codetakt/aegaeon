#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT"

IMAGE="${DOCKER_IMAGE:-aegaeon}"
IMAGE_TAR="${AEGAEON_DOCKER_IMAGE:-}"

if [[ -z $IMAGE_TAR ]]; then
	if command -v nix >/dev/null 2>&1; then
		IMAGE_TAR="$(nix build .#docker-image --no-link --print-out-paths 2>/dev/null | tail -n1 || true)"
	fi
fi

if [[ -z $IMAGE_TAR ]]; then
	echo "AEGAEON_DOCKER_IMAGE not set and nix build did not return a path" >&2
	exit 1
fi

if gzip -t "$IMAGE_TAR" >/dev/null 2>&1; then
	gzip -dc "$IMAGE_TAR" | docker load
else
	docker load -i "$IMAGE_TAR"
fi

if [ "$IMAGE" != "aegaeon" ]; then
	docker tag aegaeon:latest "$IMAGE:latest"
fi
