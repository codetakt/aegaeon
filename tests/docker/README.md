# Test Infrastructure

This directory contains Docker Compose configurations for local testing and development.

## Usage

Preferred (Nix):

```bash
nix run .#dev-services-up
```

Stop services:

```bash
nix run .#dev-services-down
```

Manual (without Nix):

```bash
docker compose -f tests/docker/docker-compose.yml up -d
docker compose -f tests/docker/docker-compose.yml down
```

## Management UI integration

For UI ↔ management-API integration tests (separate UI repository), this repo provides a minimal
stack with Postgres + `aegaeon-server`:

```bash
# Build/load the Docker image (Nix).
nix run .#docker-build

# Start Postgres first.
docker compose -f tests/docker/docker-compose.management-ui.yml up -d postgres

# Apply migrations (from the repo root).
export AEGAEON_DATABASE_URL='postgres://aegaeon:aegaeon@localhost:5432/aegaeon?sslmode=disable'
export DATABASE_URL="$AEGAEON_DATABASE_URL"
atlas migrate apply --env local

# Before starting aegaeon-server, seed an ACTIVE management Environment/configuration
# whose issuer_host matches AEGAEON_RUNTIME_ISSUER_HOST. For hosted-style initialization,
# use the aegaeon-hosted-bootstrap utility.

# Start the server after the active runtime environment exists.
docker compose -f tests/docker/docker-compose.management-ui.yml up -d aegaeon
```

Notes:

- The management API uses cookie sessions + CSRF tokens; the browser Origin must be allowlisted via
  `aegaeon.control_plane_policies.management_allowed_origins`; this is database policy, not a
  startup environment variable.
- Use a consistent host (`localhost` vs `127.0.0.1`) because the Origin check is exact-match.
- To protect first-owner provisioning, set `AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN` before starting the
  stack and include `bootstrapToken` in the bootstrap request.

## Management API DB tests

To run DB/Redis-backed `aegaeon-server` ignored integration tests against local containers:

```bash
nix run .#server-container-integration
```

The runner starts the `postgres` and `redis` compose services, waits for readiness, applies Atlas
migrations, and then runs the targeted ignored server tests for Redis shared stores, Postgres
repositories, management runtime keys, and dynamic client registration. It intentionally avoids
unrelated ignored tests such as timing-sensitive or external-network scenarios.

Useful overrides:

```bash
# Run only one backing store family.
AEGAEON_SERVER_CONTAINER_TEST_SCOPE=redis nix run .#server-container-integration
AEGAEON_SERVER_CONTAINER_TEST_SCOPE=postgres nix run .#server-container-integration

# Stop the compose stack after the run.
AEGAEON_SERVER_CONTAINER_DOWN=1 nix run .#server-container-integration

# Use already-running services.
AEGAEON_SERVER_CONTAINER_SKIP_UP=1 nix run .#server-container-integration
```

Manual equivalent:

```bash
# Start services (Postgres + dependencies).
nix run .#dev-services-up

# Apply migrations (from the repo root).
export AEGAEON_DATABASE_URL='postgres://aegaeon:aegaeon@localhost:5432/aegaeon?sslmode=disable'
export DATABASE_URL="$AEGAEON_DATABASE_URL"
atlas migrate apply --env local

# Run specific tests that need a live DB.
nix develop .#default --command bash -c \
  'export CC_x86_64_unknown_linux_gnu=clang
   export CXX_x86_64_unknown_linux_gnu=clang++
   cargo test -p aegaeon-server --test <test_name>'

# Stop services when done.
nix run .#dev-services-down
```

## Services

- **Jaeger**: Distributed tracing UI at `http://localhost:16686`
- **Prometheus**: Metrics collection at `http://localhost:9090`
- **Grafana**: Metrics visualization at `http://localhost:3000`
- **MockServer** (optional): Generic HTTP mock server at `http://localhost:18080`
- **Redis** (optional): Local cache/session testing at `redis://localhost:6379`

## Integration

The main application can connect to these services using:

- OTLP endpoint: `http://localhost:4317` (gRPC) or `http://localhost:4318` (HTTP)
- Prometheus scrape endpoint: Configure in `prometheus.yml`
