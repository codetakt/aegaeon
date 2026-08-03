#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
COMPOSE_FILE="${DEV_COMPOSE_FILE:-$ROOT/tests/docker/docker-compose.yml}"
POSTGRES_PORT="${AEGAEON_POSTGRES_PORT:-5432}"
DEFAULT_AEGAEON_DATABASE_URL="postgres://aegaeon:aegaeon@localhost:${POSTGRES_PORT}/aegaeon?sslmode=disable"
AEGAEON_DATABASE_URL="${AEGAEON_DATABASE_URL:-$DEFAULT_AEGAEON_DATABASE_URL}"
AEGAEON_TEST_REDIS_URL="${AEGAEON_TEST_REDIS_URL:-redis://localhost:6379/0}"
SCOPE="${1:-${AEGAEON_SERVER_CONTAINER_TEST_SCOPE:-all}}"

usage() {
	cat <<'USAGE'
usage: run_server_container_integration.sh [all|redis|postgres]

Runs ignored aegaeon-server Redis/Postgres integration tests against the
repository Docker Compose services. The positional scope overrides
AEGAEON_SERVER_CONTAINER_TEST_SCOPE when both are set.
USAGE
}

if [[ $# -gt 1 || $SCOPE == "-h" || $SCOPE == "--help" ]]; then
	usage
	if [[ $# -gt 1 ]]; then
		exit 2
	fi
	exit 0
fi

case "$SCOPE" in
all | redis | postgres) ;;
pg)
	SCOPE="postgres"
	;;
*)
	echo "unknown server container integration scope: $SCOPE" >&2
	echo "expected all, redis, or postgres" >&2
	exit 2
	;;
esac

export AEGAEON_DATABASE_URL
export DATABASE_URL="${AEGAEON_DATABASE_URL}"
export AEGAEON_TEST_REDIS_URL
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CC_x86_64_unknown_linux_gnu="${CC_x86_64_unknown_linux_gnu:-clang}"
export CXX_x86_64_unknown_linux_gnu="${CXX_x86_64_unknown_linux_gnu:-clang++}"

compose() {
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		docker compose -f "$COMPOSE_FILE" "$@"
	elif command -v docker-compose >/dev/null 2>&1; then
		docker-compose -f "$COMPOSE_FILE" "$@"
	else
		echo "docker compose is required for server container integration tests" >&2
		exit 1
	fi
}

wait_for_postgres() {
	for _ in $(seq 1 60); do
		if compose exec -T postgres pg_isready -U aegaeon -d aegaeon >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	compose logs postgres >&2 || true
	echo "postgres did not become ready" >&2
	exit 1
}

wait_for_redis() {
	for _ in $(seq 1 60); do
		if compose exec -T redis redis-cli ping 2>/dev/null | grep -q '^PONG$'; then
			return 0
		fi
		sleep 1
	done
	compose logs redis >&2 || true
	echo "redis did not become ready" >&2
	exit 1
}

run_redis_tests() {
	echo "running Redis-backed aegaeon-server ignored tests"
	cargo test -p aegaeon-server redis_ --lib -- --ignored --test-threads=1
}

run_postgres_tests() {
	echo "applying database migrations"
	atlas migrate apply --env local

	# Run the full ignored sweep (minus Redis-backed tests) instead of a
	# name-prefix filter: prefix filtering silently skipped DB-gated tests
	# that were not named pg_* (e.g. the dcr_configuration_* RFC 7592 tests).
	echo "running Postgres-backed aegaeon-server ignored lib tests"
	cargo test -p aegaeon-server --lib -- --ignored --test-threads=1 --skip redis_

	echo "running Postgres-backed dynamic client registration integration test"
	cargo test -p aegaeon-server --test dcr_database_test -- --ignored --test-threads=1
}

compose_services_for_scope() {
	case "$SCOPE" in
	all)
		printf '%s\n' postgres redis
		;;
	redis)
		printf '%s\n' redis
		;;
	postgres)
		printf '%s\n' postgres
		;;
	*)
		echo "invalid normalized server container integration scope: $SCOPE" >&2
		return 2
		;;
	esac
}

cd "$ROOT"

mapfile -t COMPOSE_SERVICES < <(compose_services_for_scope)

if [[ ${AEGAEON_SERVER_CONTAINER_SKIP_UP:-0} != "1" ]]; then
	compose up -d "${COMPOSE_SERVICES[@]}"
fi

case "$SCOPE" in
all)
	wait_for_postgres
	wait_for_redis
	;;
redis)
	wait_for_redis
	;;
postgres)
	wait_for_postgres
	;;
esac

case "$SCOPE" in
all)
	run_redis_tests
	run_postgres_tests
	;;
redis)
	run_redis_tests
	;;
postgres)
	run_postgres_tests
	;;
esac

if [[ ${AEGAEON_SERVER_CONTAINER_DOWN:-0} == "1" ]]; then
	compose down
fi
