# Aegaeon SDK CI Companion Plan

Last updated: 2026-03-15

Status: active plan

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-03-15):** The active SDK CI workflows now live in the separate `aegaeon-sdk` repository. This backend document records only the **backend-owned inputs** that feed those workflows: the `release-core` producer path, the scaffolded workflow sources under `scripts/sdk/`, and the machine-readable handoff contracts. It should be read as a companion to the SDK repository's canonical CI plan, not as a second operational source of truth.

## 1. Purpose

Define the backend-side CI and handoff responsibilities that support the `aegaeon-sdk` repository.

This document does **not** redefine how the SDK repository runs package CI, browser lanes, or publish. Those details are canonical in `aegaeon-sdk`.

## 2. Canonical workflow names

The current canonical SDK check names are:

- `SDK Verify Core / Verify Core`
- `SDK CI / Packages`
- `SDK CI / Browser Smoke`
- `SDK Browser E2E / Core Playwright`
- `SDK Browser E2E / External Provider (Dex)`
- optional hosted lanes:
  - `SDK Browser E2E / External Provider (Keycloak)`
  - `SDK Browser E2E / External Provider (Managed)`

When these names change, update the backend scaffold generators and tests in the same workstream.

## 3. Backend-owned CI inputs

The backend repository owns the following sources that feed SDK CI:

| Input | Purpose |
|-------|---------|
| `release-core.yml` | builds Verified Core artefacts and emits the SDK handoff bundle |
| `scripts/sdk/scaffold_sdk_repo_workspace.mjs` | source-managed workflow/template generator for the SDK repository |
| `scripts/sdk/build_sdk_repository_dispatch_payload.mjs` | canonical `repository_dispatch` payload builder |
| `scripts/sdk/build_verified_core_handoff_manifest.mjs` | canonical handoff-manifest builder |
| `spec/sdk-repository-dispatch.schema.json` | dispatch payload contract |
| `spec/verified-core-handoff-manifest.schema.json` | handoff bundle contract |
| `scripts/validation/validate_*` helpers | fail-closed validation for those contracts |

## 4. Backend release-core responsibilities

The backend `release-core` path is responsible for producing and validating:

- Verified Core artefacts (`verified_core.wasm`, manifest, integrity sidecars, optional signature)
- Verified Core SBOM
- `sdk-repository-dispatch.json`
- `verified-core-handoff-manifest.json`

It must validate machine-readable handoff payloads before:

- uploading them as artefacts
- attaching them to releases
- sending optional `repository_dispatch` events

## 5. Backend-side validation commands

Use these commands in the backend repository when touching SDK handoff logic:

```bash
nix develop .
node tests/verified_core_wasm/scaffold_sdk_repo_test.mjs
node tests/verified_core_wasm/sdk_repository_dispatch_payload_test.mjs
node tests/verified_core_wasm/verified_core_handoff_manifest_test.mjs
node tests/verified_core_wasm/branch_protection_policy_test.mjs
nix flake check --print-build-logs
```

These checks confirm that the backend-owned scaffold and handoff contracts still match the current SDK workflow boundary.

## 6. Change discipline

If any of the following change, update backend and SDK repository assets together:

- workflow names
- required check names
- dispatch payload fields
- handoff-manifest fields
- public-key / signature handling rules
- repository-settings or release-custody inputs expected by the SDK workflows

Do not allow the backend scaffold to drift from the active SDK repository.

## 7. Publication-org tasks (deferred)

The following are intentionally **not** treated as complete in the backend repository:

- hosted branch-protection rollout
- publication-org secrets and custody enforcement
- final required-check application in the target org
- commercial-tenant managed-provider steady-state evidence

Track those as publication-org rollout tasks rather than backend CI tasks.
