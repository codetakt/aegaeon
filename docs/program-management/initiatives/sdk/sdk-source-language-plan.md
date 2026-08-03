# SDK Source Language Plan

Last updated: 2026-07-07

Status: active plan

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-03-16):** This is a backend companion plan for the SDK source-language migration. Keep it synchronized with the separate `aegaeon-sdk` repository. It does not widen the current verified claim by itself.

## Purpose

This document records the target state and execution order for the SDK source-language migration.

The goal is to converge on:

- **WASM** for the formally verified core
- **TypeScript source** for SDK logic
- **generated JavaScript** as the only runtime/distribution artefact
- **no handwritten JavaScript** in the SDK implementation track

## Non-goals

- This plan does **not** move the verified claim boundary above the existing WASM core.
- This plan does **not** require HTML, Nix, YAML, shell, or Docker definitions to move into TypeScript.
- This plan does **not** by itself activate released client wording.

## Target State

1. The Verified Core remains `verified_core.wasm`.
2. SDK packages use **TypeScript as the only handwritten source language**.
3. Runtime loaders, release gates, and repository automation execute **built JavaScript artefacts**, not `ts-node` / `tsx` / ad-hoc transpilation.
4. Consumers such as `../aegaeon-admin-console` depend on package exports only and do not reach into SDK internals.
5. JSON Schema and other machine-readable contracts remain authoritative; TypeScript types and generated JavaScript follow those contracts.

## Repository Responsibilities

- **`aegaeon`**
  - source of truth for scaffold generation
  - source of truth for backend companion docs and release handoff contracts
  - must stay layout-compatible with the separate SDK repository
- **`aegaeon-sdk`**
  - operational implementation of the SDK workspace
  - canonical build, publish, and client-readiness workflow execution
- **`aegaeon-admin-console`**
  - consumer of `@aegaeon/management-client`
  - must remain insulated from SDK internal file layout and source-language changes

## Execution Order

### Phase 0 — Freeze the Policy

- record the target state and sequencing in source-managed docs
- keep the verified-claim boundary unchanged
- keep admin-console on `@aegaeon/management-client` only

### Phase 1 — Build Substrate First

- add a stable TypeScript build pipeline for SDK packages and repository tooling
- separate **source** from **runtime artefacts** (`src/` → `dist/`)
- make release/verification workflows consume built JavaScript, not raw TypeScript
- keep release-critical workflows free of `tsx` / `ts-node`

#### Current status

- complete
- `aegaeon-sdk/sdk` now has `tsconfig.json`, `tsconfig.tools.json`, project references, stricter compiler options, and a built-tool wrapper under `dist-tools/exec-tool.js`
- `verify-core`, `released-client-readiness`, and `publish` wiring consume built JavaScript helpers for dispatch/payload/public-key handling instead of direct source-script execution
- package exports can now resolve built artefacts from `dist/`, so the next step is migrating package source one package at a time while keeping runtime artefacts stable

### Phase 2 — Migrate the Lowest Layer First

- migrate `@aegaeon/verified-core`
- migrate `@aegaeon/runtime-web`
- migrate `@aegaeon/runtime-node`

#### Current status

- complete
- `@aegaeon/verified-core` now keeps handwritten source under `src/*.ts`, emits `dist/index.js`, `dist/node.js`, `dist/web.js`, and publishes `dist/*.d.ts`
- `@aegaeon/runtime-web` and `@aegaeon/runtime-node` now keep handwritten source under `src/*.ts`, emit `dist/index.js` / `dist/reference.js` (plus `dist/browser-smoke.js` for `runtime-web`), and publish `dist/*.d.ts`
- browser import maps, staged workspace smoke tests, package-publish smoke tests, and SDK browser smoke wiring now consume `dist/*` outputs rather than handwritten runtime `.mjs`

### Phase 3 — Migrate Domain SDK Packages

- migrate `@aegaeon/management-client`
- migrate `@aegaeon/rp-core`
- migrate `@aegaeon/issuer-spa`

#### Current status

- complete
- `@aegaeon/management-client` now keeps handwritten implementation under `src/index.ts`, emits `dist/index.js`, and consumes the built output in package tests
- the public management-client type contract is intentionally still carried by the hand-authored `index.d.ts` during this phase so the admin-console boundary stays stable while the implementation source moves to TypeScript
- `@aegaeon/rp-core` now keeps handwritten implementation under `src/index.ts`, emits `dist/index.js`, and publishes `dist/index.d.ts`; browser import maps and the local-provider E2E now consume the built output
- `@aegaeon/issuer-spa` now keeps handwritten implementation under `src/index.ts`, emits `dist/index.js`, and publishes `dist/index.d.ts`; browser import maps and the local/external-provider E2E lanes now consume the built output
- the backend `scripts/sdk/stage_reference_sdk_workspace.ts` and `scripts/sdk/scaffold_sdk_repo_workspace.ts` generators now mirror the `src/` + `dist/` layout across the Phase 3 package set so staged/scaffolded workspaces keep a stable package surface during migration

### Phase 4 — Migrate Repository Scripts and Validators

- migrate repository logic in `sdk/tools-src/` to TypeScript source
- replace handwritten JavaScript verification/build scripts with generated JavaScript outputs under `sdk/dist-tools/`
- converge schema validation and release/report tooling on the same source-language discipline where practical

#### Current status

- complete
- the companion scaffold now mirrors the SDK repo layout with `sdk/tools-src/*.ts` source and runtime execution through `sdk/dist-tools/*.js`
- SDK repository tools now execute from built JavaScript under `dist-tools/*.js`, and the legacy handwritten `.mjs` tool files are removed
- scaffold/source-of-truth tests cover the built-tool layout so generated repositories validate the same execution path as the operational SDK repo

### Phase 5 — Keep Consumers Stable

- keep `aegaeon-admin-console` on package exports only
- do not let consumer repositories depend on SDK source layout
- preserve the current admin-console boundary contract while SDK internals change

### Phase 6 — Migrate Tests and Support Code

- migrate Node tests to TypeScript source
- migrate Playwright tests and browser support code to TypeScript source where practical
- keep minimal shell orchestration only where it is operationally justified

#### Current status

- complete
- `sdk/tests/node/*.ts` is now the handwritten source-of-truth for repository and local-provider Node tests, and `sdk/dist-tests/node/*.js` is the runtime path executed by `test:repo` and `test:provider-local`
- `sdk/tests/browser/*.ts`, `sdk/tests/providers/**/*.ts`, and `sdk/tests/playwright.config.ts` now carry the handwritten browser/playwright/provider source, and `sdk/dist-tests/browser/*.js`, `sdk/dist-tests/providers/**/*.js`, and `sdk/dist-tests/playwright.config.js` are the runtime paths executed by `test:browser-smoke`, `test:playwright`, and the provider browser lanes
- the companion scaffold now mirrors the same `tests/node/*.ts`, `tests/browser/*.ts`, `tests/providers/**/*.ts`, and preseeded `dist-tests/**/*.js` layout so generated repositories validate the same execution path as the operational SDK repo

### Phase 7 — Enforce the New Rule

- disable `allowJs`
- prohibit handwritten JavaScript in SDK packages and SDK repo tooling
- keep generated JavaScript as the only runtime artefact

#### Current status

- complete
- `aegaeon-sdk/sdk/tsconfig.base.json` now sets `allowJs: false` and `checkJs: false`
- package-local TypeScript test configs now build `test/*.ts` into `dist-test/*.js` for the remaining package-level test entrypoints
- the SDK workspace now runs `audit:no-js-source` before `test:repo`, and the audit fails closed if handwritten `.js` / `.mjs` / `.cjs` files appear in protected SDK directories
- the backend scaffold/source-of-truth mirrors the same no-handwritten-JavaScript policy, package test layout, and runtime `dist-test/*.js` execution path so generated repositories enforce the same rule as the operational SDK repo

### Phase 8 — Re-run Product Gates After Migration

- re-run client promotion and released-client readiness gates after the migration stabilizes
- confirm that source-language cleanup did not widen or blur the claim boundary

#### Current status

- complete
- a fresh local rerun now reproduces the expected post-migration gate shape:
  - `client-claim-promotion-report.json` is `ready: true`
  - `released-client-claim-report.json` remains `ready: false`
- the current blocker set is unchanged by the TypeScript migration:
  - hosted provenance is still missing from the local managed-provider evidence
  - hosted provenance is still missing from the local admin-console evidence
  - publication-org rollout tasks remain pending
- the release-publication bundle now records the same outcome together with the fresh signed attestation, SBOM, promotion report, and admin/managed evidence inputs, which confirms the migration did not widen the released-client claim boundary

## Guardrails

- Do not re-implement cryptography in TypeScript.
- Do not treat TypeScript migration as proof promotion.
- Keep release and verification paths fail-closed.
- Prefer one source language for SDK logic, but keep machine-readable contracts as the controlling surface.

## Post-convergence language rollout

After TypeScript source convergence, language expansion should proceed in this order:

1. **Rust**
   - expected publish target: crates.io
   - rationale: closest follow-on to the current WASM/runtime boundary and release-attestation flow
2. **Ruby**
   - begins only after Rust package boundaries and release custody are stable
   - expected publish target: RubyGems
3. **PHP**
   - begins only after Ruby package boundaries and release custody are stable
   - expected publish target: Packagist / Composer

This rollout order does **not** widen the current formal claim boundary by itself. Any claim change still requires explicit policy promotion and evidence updates.
