# Polyglot Quality Profile Rollout

Last updated: 2026-05-12

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

## Goal

Bring the three first-party repositories below onto one auditable polyglot quality profile:

- `aegaeon`
- `../aegaeon-sdk`
- `../aegaeon-admin-console`

The target state is:

1. language-agnostic repository rules are aligned
2. each real language surface has an always-on strict lint/typecheck path
3. workflow names and required-check names are stable enough for branch protection

This document tracks the shared contract and the remaining rollout work. It is not the product
specification; it is the quality-governance execution record.

## Shared baseline contract

The following rules must stay aligned across all three repositories:

- Conventional Commit enforcement via `commitlint`
- repo-wide `CI - Lint` workflow name
- `CI - Lint / Lint` as the stable branch-protection surface for low-cost governance checks
- `pre-commit` as the language-agnostic hook entrypoint
- shared file hygiene (`editorconfig`, EOF, whitespace, line endings, JSON/TOML/YAML validation)
- Markdown linting and typo detection
- workflow inventory policy checks
- minimal GitHub workflow permissions (`contents: read`) unless a workflow proves it needs more

## Language surfaces

### `aegaeon`

- Rust:
  - target profile: `cargo fmt --all -- --check`
  - target profile: `cargo clippy --workspace --all-targets --all-features`
  - target profile: `-D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented`
  - status: partial; green on selected crates, not yet green workspace-wide
- TypeScript:
  - `npm run lint:ts`
  - `npm run typecheck:ts`
  - owned by `CI - Lint / TypeScript Lint`
- Python:
  - `ruff check scripts/validation ci/validate_slos.py`
  - `mypy`
  - owned by `CI - Lint / Python Lint`

### `../aegaeon-sdk`

- TypeScript:
  - `pnpm run lint`
  - `pnpm run typecheck`
  - `pnpm run audit:strict-types`
  - owned by `CI - Lint / TypeScript Lint`

### `../aegaeon-admin-console`

- TypeScript:
  - `pnpm run test:repo`
  - `pnpm run tokens:check`
  - `pnpm run lint`
  - `pnpm run typecheck`
  - owned by `CI - Lint / TypeScript Lint`

## Workflow naming contract

The active naming target is:

- `aegaeon`
  - `CI - Lint`
  - `CI - Core`
- `../aegaeon-sdk`
  - `CI - Lint`
  - `CI - SDK`
- `../aegaeon-admin-console`
  - `CI - Lint`
  - `CI - Admin Console`

The stable required-check baseline is:

- `CI - Lint / Lint`
- repo-local typed lint lanes such as `CI - Lint / TypeScript Lint` or `CI - Lint / Python Lint`

Repo-specific build/test lanes remain separate and may be required in branch protection when the
repository policy says so.

## 2026-05-12 implementation state

Completed in this rollout batch:

- aligned `CI - Lint` naming across all three repositories
- renamed main CI workflows to `CI - Core`, `CI - SDK`, and `CI - Admin Console`
- aligned workflow inventory policies with the new names
- moved admin-console low-cost governance checks out of the main build workflow and into `CI - Lint`
- added dedicated TypeScript lint jobs for the SDK and admin console
- added dedicated TypeScript and Python lint jobs for the server repo
- aligned `.editorconfig` defaults across all three repositories

Still open:

- server Rust strict rollout is not yet complete across the entire workspace
- some historical/internal scaffolding and generated-doc surfaces still need periodic re-audit when
  workflow contracts change

## Rust strict rollout plan for `aegaeon`

The Rust surface is the only remaining material gap against the full strict target.

### Batch R1

- keep already-clean crates green under strict clippy
- treat `aegaeon-jose-tlv` and `aegaeon-observability` as the baseline examples

### Batch R2

- clean `crates/crypto`
- remove avoidable `expect`/`unwrap`
- add missing `# Errors`, `# Panics`, and `#[must_use]` annotations where pedantic/cargo require them
- collapse style-only clippy issues after the semantic ones are fixed

### Batch R3

- clean `crates/ffi`
- decide which raw-pointer patterns deserve wrapper refactors versus narrow, documented allows
- keep the FFI safety story explicit in docs and comments

### Batch R4

- enable strict clippy on the workspace path used in CI
- make the strict Rust lane branch-protection eligible

## Done criteria

This initiative is complete only when all of the following are true:

- all three repositories expose `CI - Lint / Lint`
- all real TypeScript surfaces expose `CI - Lint / TypeScript Lint`
- the server Python surface exposes `CI - Lint / Python Lint`
- the workflow inventory policies match the checked-in workflows in all three repositories
- `.editorconfig`, Markdown lint, typo policy, and commitlint remain aligned
- the server Rust workspace reaches the strict clippy target without ad hoc fail-open exceptions
