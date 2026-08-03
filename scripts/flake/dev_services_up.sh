#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
COMPOSE_FILE="${DEV_COMPOSE_FILE:-$ROOT/tests/docker/docker-compose.yml}"
if command -v docker >/dev/null 2>&1; then
	if docker compose version >/dev/null 2>&1; then
		docker compose -f "$COMPOSE_FILE" up -d "$@"
	elif command -v docker-compose >/dev/null 2>&1; then
		docker-compose -f "$COMPOSE_FILE" up -d "$@"
	else
		echo "docker compose plugin not available" >&2
		exit 1
	fi
else
	echo "docker command not available in PATH" >&2
	exit 1
fi
