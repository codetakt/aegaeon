# Aegaeon SDK Repository Boundary Plan

Last updated: 2026-03-15

Status: active plan

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-03-15):** The separate `aegaeon-sdk` repository now exists and is the canonical home for publishable SDK packages, active SDK workflows, and package-release operations. This backend repository remains the source-managed home for Verified Core extraction, proof-backed artefact generation, the `release-core` handoff workflow, the SDK scaffold generators under `scripts/sdk/`, and the source-of-truth reference implementations that are copied or synchronized into `aegaeon-sdk`. Publication-org rollout items such as hosted branch protection and final release-secret custody remain deferred operational tasks.

## 1. Purpose

This document defines the **repository boundary** between:

- `aegaeon` — the backend / proof / Verified Core repository
- `aegaeon-sdk` — the SDK packaging and delivery repository
- `aegaeon-admin-console` — the management UI that consumes the SDK

This document is intentionally backend-side and companion-oriented. It does **not** restate the full SDK repository CI or publish runbooks. Those operational details are canonical in the `aegaeon-sdk` repository.

## 2. Responsibility Split

| Repository | Canonical responsibilities |
|------------|----------------------------|
| `aegaeon` | Verified Core source, proofs, extraction, `release-core`, handoff schemas, scaffold generators, reference adapters, backend-side management-client source-of-truth, backend-side admin/SDK integration docs |
| `aegaeon-sdk` | Publishable SDK workspace (`sdk/`), active GitHub workflows, package release operations, client/runtime/browser E2E lanes, release manifests / attestations / publication bundles |
| `aegaeon-admin-console` | Management UI built on `@aegaeon/management-client`; compose-backed end-to-end evidence against sibling `aegaeon` images |

### 2.1 Package boundary

The current SDK package split is:

- **Verified Core / runtime**
  - `@aegaeon/verified-core`
  - `@aegaeon/runtime-node`
  - `@aegaeon/runtime-web`
- **Domain SDKs**
  - `@aegaeon/management-client`
  - `@aegaeon/issuer-spa`
  - `@aegaeon/rp-core`

Post-TypeScript language expansion remains follow-on work and must proceed in the order **Rust → Ruby → PHP**.

### 2.2 Admin-console dependency rule

Admin UIs should depend on `@aegaeon/management-client` only unless the management-plane login flow itself is explicitly moved onto OIDC client surfaces. The sibling `aegaeon-admin-console` now source-manages this rule in `spec/admin-sdk-boundary.current.json`.

## 3. Backend-owned source of truth

The backend repository continues to own the following inputs that feed the SDK repository:

- `scripts/sdk/runtime_node_reference.ts`
- `scripts/sdk/runtime_web_reference.ts`
- `scripts/sdk/management_client_reference.ts`
- `scripts/sdk/stage_reference_sdk_workspace.ts`
- `scripts/sdk/scaffold_sdk_repo_workspace.ts`
- `scripts/sdk/build_sdk_repository_dispatch_payload.ts`
- `scripts/sdk/build_verified_core_handoff_manifest.ts`
- `spec/sdk-repository-dispatch.schema.json`
- `spec/verified-core-handoff-manifest.schema.json`

The backend repository also owns the proof-backed Verified Core build/release path and its release artefacts.

## 4. Handoff contracts

### 4.1 Verified Core release bundle

The backend `release-core` workflow is the canonical producer of:

- `verified_core.wasm`
- `manifest.json`
- optional `verified_core.wasm.sig`
- checksum / integrity sidecars
- Verified Core SBOM
- `sdk-repository-dispatch.json`
- `verified-core-handoff-manifest.json`

The machine-readable contracts are:

- `spec/sdk-repository-dispatch.schema.json`
- `spec/verified-core-handoff-manifest.schema.json`

Validation helpers are source-managed in this repository and must stay in lock-step with the schemas.

### 4.2 SDK-side release artefacts

The SDK repository is the canonical producer of:

- `publish-manifest.json`
- `sdk-workspace-sbom.cdx.json`
- `release-attestation.json`
- optional detached release-attestation signature
- optional client-claim promotion report
- `release-publication-bundle.json`

This backend repository may carry generator or scaffold copies of those assets, but the operational release boundary is the SDK repository.

## 5. Synchronization rule

Whenever one of the following changes, update the backend scaffold, the backend tests, and the SDK repository in the same workstream:

- workflow names / required check names
- handoff payload fields
- handoff manifest fields
- public-key materialization rules
- repository-settings / release-custody contracts
- client-claim boundary or promotion gates

The backend repository is allowed to remain a **source-managed generator** for those contracts, but it must not drift from the active `aegaeon-sdk` repository.

## 6. Current validation baseline

Backend-side validation that protects the repository boundary currently includes:

```bash
nix develop .
node tests/verified_core_wasm/scaffold_sdk_repo_test.mjs
node tests/verified_core_wasm/sdk_repository_dispatch_payload_test.mjs
node tests/verified_core_wasm/verified_core_handoff_manifest_test.mjs
node scripts/sdk/management_client_reference_test.mjs
nix flake check --print-build-logs
```

These checks validate the backend-owned source-of-truth and handoff contracts. They do not replace the SDK repository's own CI or publish workflows.

## 7. Deferred publication-org work

The following remain intentionally outside the current sandbox boundary and are tracked as publication-org tasks:

- hosted branch-protection rollout
- final release-secret custody
- final npm / provenance / signing enforcement in the publication org
- commercial-tenant managed-provider steady-state evidence

These items should not be reintroduced into backend-side docs as if they were already operational here.
