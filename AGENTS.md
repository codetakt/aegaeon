# Repository Guidelines

## Project Structure & Module Organization

Aegaeon is a Rust/Nix workspace for an OAuth/OIDC identity provider with formal verification assets. Rust crates live in `crates/`; key modules include `server`, `client`, `crypto`, `jose`, `ffi`, `observability`, and `loadtest`. Database migrations are in `db/migrations/`. Verification sources live in `fstar/`, `proofs/`, `c/`, and generated outputs under `generated/`. Repository tests and fixtures are in `tests/`; crate integration tests are under `crates/*/tests/`. Use `docs/` for documentation, `spec/` for compliance data, `scripts/` for helpers, and `nix/` plus `flake.nix` for reproducible tooling.

## Build, Test, and Development Commands

- `nix develop`: enter the supported pinned toolchain shell.
- `nix flake check --print-build-logs`: run the main CI-style gates.
- `nix develop -c cargo test --workspace`: run Rust workspace tests.
- `nix build .#server -o result-server`: build the release server artifact.
- `nix run .#dev-services-up`: start local PostgreSQL/Redis services for development.
- `nix run .#dev-server`: run the local server; requires documented `AEGAEON_*` configuration.
- `nix run .#security-suite`: run dependency, audit, fuzz-smoke, SBOM, and security checks.
- `nix run .#server-container-integration`: run the DB/Redis-gated ignored integration tests against local containers (also enforced by the `db-integration` CI job).
- `npm run lint:ts` and `npm run typecheck:ts`: check TypeScript scripts.

## Coding Style & Naming Conventions

Rust uses edition 2021 and the pinned nightly from `rust-toolchain.toml`. Format with `cargo fmt --all`; lint with `cargo clippy --workspace --all-targets -- -D warnings`. Keep protocol and security code fail-closed. Avoid `unsafe` unless isolated and justified. Prefer `snake_case` for Rust modules, functions, migrations, and tests. TypeScript uses ESLint and strict type checking; prefer explicit type imports. Do not hand-edit generated artifacts in `generated/` or verification outputs in `artifacts/`.

## Testing Guidelines

Name integration tests by behavior, usually `*_test.rs`, under the relevant crate or `tests/`. Add conformance or compliance-matrix updates when protocol behavior changes. Heavier lanes include `nix build .#verify-fstar -L`, `nix build .#verify-tamarin -L`, `nix build .#verify-kani -L`, and `nix run .#verify-lowstar`.

## Verification Claim Discipline

For any `status: verified` compliance-matrix row, every formal `proof[]` block must be grounded by `python3 scripts/validation/verify_verified_reqs.py --strict`. Do not cite `F*` modules classified as `toy-stub` from verified rows. When adding or recategorizing `F*` modules, update `docs/verification/claims/model-fidelity.yaml` and, for material model changes, `docs/verification/claims/model-fidelity-register.md` in the same change.

## Commit & Pull Request Guidelines

Commits follow Conventional Commits enforced by `commitlint.config.cjs`, for example `fix(server): reject invalid DPoP nonce`. Use lowercase types such as `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, and `chore`; keep headers at 72 characters or less. Pull requests should describe behavior changes, link issues, list commands run, include tests or proof evidence, cite RFCs for protocol changes, and update `docs/` or `spec/compliance-matrix.yaml` when needed.

## Security & Configuration Tips

Never commit secrets, private keys, or local service credentials. Keep runtime settings in documented `AEGAEON_*` environment variables, and consult `docs/configurations/environment/README.md` before adding or removing configuration.
