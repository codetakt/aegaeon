# Aegaeon

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![F*](https://img.shields.io/badge/F%2A-verification%20assets-blueviolet.svg)](fstar/)
[![Tamarin](https://img.shields.io/badge/Tamarin-protocol%20models-blueviolet.svg)](proofs/tamarin/)

Aegaeon is an OAuth/OIDC identity-provider server with formal-verification
assets and security-test tooling. Completion of its published
[server assurance contract](docs/verification/claims/assurance-case/assurance-contract.md)
is pending; see the [activation backlog](docs/verification/claims/assurance-case/contract-status.md).
The project prioritizes security posture (OAuth 2.0 Security BCP / sender-constrained
tokens) and maintains formal verification artefacts (F*, Tamarin, Kani) alongside
the Rust implementation.
The official claim definition and boundary conditions are specified in the
[claim definition](docs/verification/claims/assurance-case/claim-definition.md).
The first-party admin console uses `@aegaeon/management-client`. Browser rendering
has a separate assurance boundary; server-side management and session operations
that affect foundation guarantees are included in the contract.
Public wording is indexed in
[`docs/product-positioning.md`](docs/product-positioning.md); its scope, finalized
public wording and release-record requirements are fixed by the
[assurance statement specification](docs/verification/claims/assurance-statement.md).
Standalone SDK packages have a separate
[SDK assurance contract](docs/verification/claims/sdk-assurance/assurance-contract.md)
covering client/RP behavior and distributed JavaScript/WASM implementations.
Its [qualified claim remains inactive](docs/verification/claims/sdk-assurance/contract-status.md).

The contract fixes obligations before proof completion. Matrix `verified` rows
are an evidence inventory, not a complete server or release attestation. External
cryptography, entropy, toolchain and platform assumptions must be disclosed;
own-code input validation, state transitions and adapter behavior remain
verification obligations. The [standards baseline](docs/verification/claims/assurance-case/standards-baseline.md)
pins specification editions and distinguishes mandatory, conditional and deferred
capabilities. Adopting that baseline does not assert current conformance to it.

## Scope

- OAuth 2.0/2.1 Authorization Server with PKCE (S256), PAR (RFC 9126), DPoP (RFC 9449)
- OpenID Connect Provider: ID Token, discovery, userinfo, back-channel logout
- Dynamic Client Registration (RFC 7591) and Management (RFC 7592)
- Device Authorization (RFC 8628), Token Revocation (RFC 7009), Introspection (RFC 7662)
- OpenID Federation trust-chain consumer and upstream brokering; public OP publication is deferred
- Authorization Server Metadata (RFC 8414) and Security BCP guidance (RFC 9700)

For detailed coverage and evidence, see `spec/compliance-matrix.yaml` and `docs/`.

## 5-Minute Demo

Start the server and run the sample RP to see a complete Authorization Code + PKCE flow:

```bash
# Terminal 1: Start local PostgreSQL/Redis services and apply schema migrations.
nix run .#dev-services-up
export AEGAEON_DATABASE_URL='postgres://aegaeon:aegaeon@localhost:5432/aegaeon?sslmode=disable'
export DATABASE_URL="$AEGAEON_DATABASE_URL"
atlas migrate apply --env local

# Use the local Redis service for every fail-closed runtime-state surface.
export AEGAEON_LOCAL_REDIS_URL='redis://localhost:6379/0'
for key in \
  AEGAEON_AUTH_CODE_REDIS_URL \
  AEGAEON_AUTH_SESSION_REDIS_URL \
  AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL \
  AEGAEON_DEVICE_CODE_REDIS_URL \
  AEGAEON_DEVICE_CSRF_REDIS_URL \
  AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL \
  AEGAEON_DPOP_NONCE_REDIS_URL \
  AEGAEON_DPOP_REDIS_URL \
  AEGAEON_JWKS_REDIS_URL \
  AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL \
  AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL \
  AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL \
  AEGAEON_MANAGEMENT_SESSION_REDIS_URL \
  AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL \
  AEGAEON_PAR_REDIS_URL \
  AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL \
  AEGAEON_STEPUP_REDIS_URL \
  AEGAEON_TOKEN_STORE_REDIS_URL \
  AEGAEON_UPSTREAM_AUTH_REDIS_URL \
  AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL
do
  export "$key=$AEGAEON_LOCAL_REDIS_URL"
done

# Create an active management Environment whose issuer host is 127.0.0.1:8080
# and whose issuer URL is http://localhost:8080. Enable OIDC in that Environment
# policy, and create an ACTIVE
# OIDC_ID_TOKEN_SIGNING runtime key through the management API or admin console.
# See docs/operations/runtime-configuration.md for the runtime authority checklist.

# Terminal 2: Start the DB/Redis-backed server after repeating the AEGAEON_* exports above.
AEGAEON_RUNTIME_ISSUER_HOST=127.0.0.1:8080 \
  nix run .#dev-server

# Terminal 3: Run the sample Relying Party.
cd examples/minimal-rp
pip install -r requirements.txt
python app.py
```

Open <http://localhost:5000> and click **Login with Aegaeon**. The sample RP will:
1. Discover the server via `/.well-known/openid-configuration`
2. Register itself via Dynamic Client Registration (RFC 7591)
3. Redirect you to `/authorize` with PKCE S256 + state
4. Exchange the authorization code for tokens
5. Display the decoded ID token claims

The former `AEGAEON_OIDC_*` startup-environment shortcut is removed from supported server runtime.
Debug/test fixtures seed equivalent policy and key rows directly into PostgreSQL instead. Supported
server runtime loads issuer policy and OIDC signing material from the active PostgreSQL-backed
management snapshot. See
[`examples/minimal-rp/README.md`](examples/minimal-rp/README.md) for RP options and
[`docs/operations/runtime-configuration.md`](docs/operations/runtime-configuration.md) for
runtime configuration operations.

## Quick Start

```bash
# Hook baseline (mirrors CI pre-commit gate)
PRE_COMMIT_HOME=/tmp/pre-commit-aegaeon nix develop . --command bash -lc 'pre-commit run --all-files'

# Workflow inventory audit (mirrors CI)
nix develop .#default --command node --experimental-strip-types tests/verified_core_wasm/workflow_inventory_policy_test.ts

# Core checks (fmt/clippy/tests + verification checks)
nix flake check --print-build-logs

# Run aggregate security checks (deny/audit/vet)
nix run .#security-suite

# Dev server (cargo run; requires PostgreSQL and an active management runtime configuration)
nix run .#dev-server

# Release build artefact
nix build .#server -o result-server
./result-server/bin/aegaeon-server --host 127.0.0.1 --port 8080
```

Server system/bootstrap configuration is driven by environment variables; issuer-scoped runtime
policy is loaded from PostgreSQL by default. See `docs/configurations/environment/README.md`.

## Documentation

- [`docs/README.md`](docs/README.md): documentation hub
- [`docs/configurations/environment/README.md`](docs/configurations/environment/README.md): server environment reference
- [`CHANGELOG.md`](CHANGELOG.md): release notes
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution guidelines
- [`SECURITY.md`](SECURITY.md): vulnerability reporting and security posture
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md): community standards

## Standards

See the [standards baseline](docs/verification/claims/assurance-case/standards-baseline.md)
for pinned editions and role applicability, `spec/compliance-matrix.yaml` for
existing evidence, and `nix flake check` for current gates. Contract completion
requires all applicable clauses, including those not yet individually indexed.

## Development Environment

This project uses [Nix Flakes](https://nixos.wiki/wiki/Flakes) for reproducible development environments.

### Prerequisites
- Nix with flakes enabled (`nix >= 2.4`)
- Enable flakes: Add `experimental-features = nix-command flakes` to `~/.config/nix/nix.conf`

### Setup
```bash
# Enter the development environment
nix develop

# Or run one-off commands inside the dev environment
nix develop -c cargo test --workspace
```

**Important:** The supported local workflow is `nix develop` / `direnv`-managed
dev shells. Running `cargo` directly from an arbitrary host shell is not
supported, because the repository expects the pinned Rust toolchain and native
linker/binutils wiring from the Nix dev shell.

**Note:** Historical `just` recipes have been retired. All workflows are exposed
either as `nix run .#<task>` apps or as standard `nix build` /
`nix flake check` targets.

The development environment includes:
- Rust toolchain (pinned nightly; mirrored by `rust-toolchain.toml` for rustup users)
- Verification tooling (F*, KaRaMeL, EverParse, Z3, Tamarin)
- CI tooling (deny/audit/vet, fuzzing, sanitizers, Python helpers)

## Verification

```bash
nix build .#verify-fstar -L
nix build .#verify-tamarin -L
nix build .#verify-kani -L
nix build .#verify-jose -L
```

## OCI Image with Nix

```bash
# Build the OCI image tarball (dockerTools)
nix build .#docker-image

# Load it into Docker as `aegaeon:latest`
nix run .#docker-build

docker run --rm -p 8080:8080 aegaeon:latest
```

OIDF conformance: see `scripts/oidf_conformance/README.md`.

## Regenerating Extracted Artefacts

Some verification/extraction outputs are committed under `generated/` and `artifacts/` and are checked in CI.

```bash
nix develop .#verification
scripts/extraction/run_jose_lowstar.sh
git diff -- generated/everparse generated/lowstar artifacts/karamel
```

## Repository Layout

- `crates/`: Rust crates (server, JOSE, observability, FFI, ...)
- `examples/`: sample applications (minimal RP)
- `fstar/`: F* specifications, implementations, and proof sources
- `generated/`: committed generated artefacts (EverParse wrappers, extracted Low* C, ...)
- `proofs/`: protocol-level models and their verification tooling
- `nix/`: pinned toolchains and packaging (incl. OCI image)
- `scripts/`: verification runners and local tooling
- `spec/`: compliance matrix, assurance contracts, and schemas
- `tests/`: integration and conformance harnesses

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
