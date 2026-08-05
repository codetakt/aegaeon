# Aegaeon

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-1151%2B%20passing-brightgreen.svg)](spec/compliance-matrix.yaml)
[![F*](https://img.shields.io/badge/F%2A-155%20modules%20%7C%200%20admit-blueviolet.svg)](fstar/)
[![Tamarin](https://img.shields.io/badge/Tamarin-248%20lemmas%20verified-blueviolet.svg)](proofs/tamarin/)

Aegaeon is an assumption-qualified formally verified and security-tested
OIDC 1.0 / OAuth 2.0/2.1 identity-provider server, with OpenID Connect Federation
runtime support. See the [Assumption Boundary Overview](docs/verification/claims/assumption-boundary-overview.md)
for the explicit trust boundary.
The project prioritizes security posture (OAuth 2.0 Security BCP / sender-constrained
tokens) and maintains formal verification artefacts (F*, Tamarin, Kani) alongside
the Rust implementation.
The official claim definition and boundary conditions are specified in the
[claim definition](docs/verification/claims/assurance-case/claim-definition.md).
The first-party admin console is a constrained control-plane UI built on
`@aegaeon/management-client`; it is intentionally outside the released formal claim.
Canonical outward-facing wording lives in
[`docs/product-positioning.md`](docs/product-positioning.md).

**Formal boundary note:** In realistic von Neumann systems with I/O, the
following cannot be proven inside the project’s formal system and are treated
as explicit assumptions outside the formal claim: (1) computational hardness
(EUF‑CMA, collision resistance) stated as theorem premises, (2) OS/device
entropy sources modeled as external contracts (e.g., min‑entropy), and (3)
external host/storage behaviour modeled as explicit interface contracts or
TCB boundaries.

Formal claim (short): the verification covers **VerifiedReqs** — the subset of
`spec/compliance-matrix.yaml` entries with `status: verified` and a formal proof reference
(F\*/Low\*/HACL\*, Tamarin, Kani, or EverParse) — guaranteed **in their respective
models** under the 12 documented [assumptions](docs/verification/claims/assumptions/current-register.md)
(6 crypto hardness, 2 HACL* linkage, 2 OIDC hash runtime linkage,
1 EverParse linkage, 1 WASM host), for binaries
produced by the pinned Nix toolchain and configured per the documented `AEGAEON_*` policy gates.
Everything else is outside the claim.
See [Assurance Case §0.2](docs/verification/claims/assurance-case/claim-definition.md#02-claim-scope) for the full definition.

## Scope

- OAuth 2.0/2.1 Authorization Server with PKCE (S256), PAR (RFC 9126), DPoP (RFC 9449)
- OpenID Connect Provider: ID Token, discovery, userinfo, back-channel logout
- Dynamic Client Registration (RFC 7591) and Management (RFC 7592)
- Device Authorization (RFC 8628), Token Revocation (RFC 7009), Introspection (RFC 7662)
- OpenID Connect Federation 1.0: Entity Configuration, Subordinate Statements, Trust Marks
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

See `spec/compliance-matrix.yaml` for 308 tracked requirements across 48+ RFC/OIDC specifications, and `nix flake check` for current gates.

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

## OCI Image (No Dockerfile)

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
- `fstar/`: F* sources (155 modules, 0 admit, 12 assume vals across 8 files)
- `generated/`: committed generated artefacts (EverParse wrappers, extracted Low* C, ...)
- `proofs/`: protocol-level models (54 Tamarin files, 248 lemmas)
- `nix/`: pinned toolchains and packaging (incl. OCI image)
- `scripts/`: verification runners and local tooling
- `spec/`: compliance matrix + schema (308 entries)
- `tests/`: integration and conformance harnesses

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
