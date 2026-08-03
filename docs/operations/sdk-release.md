# SDK Release Handoff Runbook (Backend Companion)

Last updated: 2026-03-15

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

> **Status note (2026-03-15):** Package publish, provenance enforcement, and release-publication bundles are now operational concerns of the separate `aegaeon-sdk` repository. This backend runbook covers only the **Verified Core producer side**: what `aegaeon` must build, validate, and hand off so that the SDK repository can verify and publish against a stable input contract.

## 1. Scope

This runbook applies to the backend repository only.

It covers:

- building Verified Core release artefacts
- validating the SDK handoff contracts
- optionally notifying the SDK repository via `repository_dispatch`

It does **not** cover npm publish, client-claim promotion, SDK release attestation publication, or publication-org branch protection. Those are SDK-repository responsibilities.

## 2. Required outputs

A backend-side SDK handoff must produce:

- `verified_core.wasm`
- `manifest.json`
- checksum / integrity sidecars
- optional `verified_core.wasm.sig`
- Verified Core SBOM
- `sdk-repository-dispatch.json`
- `verified-core-handoff-manifest.json`

The machine-readable contracts are:

- `spec/sdk-repository-dispatch.schema.json`
- `spec/verified-core-handoff-manifest.schema.json`

## 3. Preconditions

Before creating a handoff bundle:

1. `nix flake check --print-build-logs` is green.
2. Any touched SDK handoff generators or schemas have passed their focused tests.
3. If emitting signed Verified Core artefacts, the signing-key path is available to the build.
4. If sending a `repository_dispatch`, the target SDK repo slug and token are available.

Focused backend-side checks:

```bash
nix develop .
node tests/verified_core_wasm/scaffold_sdk_repo_test.mjs
node tests/verified_core_wasm/sdk_repository_dispatch_payload_test.mjs
node tests/verified_core_wasm/verified_core_handoff_manifest_test.mjs
node scripts/sdk/management_client_reference_test.mjs
```

## 4. Local handoff build

A typical local handoff refresh is:

```bash
nix develop .
bash scripts/flake/build_verified_core.sh
node tests/verified_core_wasm/scaffold_sdk_repo_test.mjs
```

To emit a signed Verified Core artefact locally, provide:

```bash
AEG_VERIFIED_CORE_SIGNING_KEY_PATH=/path/to/key.pem \
  bash scripts/flake/build_verified_core.sh
```

## 5. Release-core workflow responsibilities

The backend `release-core` workflow must:

1. build the Verified Core artefact bundle
2. validate `sdk-repository-dispatch.json`
3. validate `verified-core-handoff-manifest.json`
4. upload the handoff bundle as artefacts
5. optionally attach the bundle to a GitHub release
6. optionally send `repository_dispatch` to the SDK repository

A handoff must fail closed if:

- dispatch payload validation fails
- handoff-manifest validation fails
- signing is requested but required signing inputs are absent

## 6. Handoff consumers

The intended consumer of this bundle is the separate `aegaeon-sdk` repository, which verifies and ingests the handoff via its own `verify-core` workflow.

This backend repository may continue to carry scaffold copies of SDK release scripts and workflow templates, but the operational release boundary is the SDK repository.

## 7. Synchronization rule

When the backend changes any of the following, the SDK repository must be updated in the same workstream:

- dispatch payload fields
- handoff-manifest fields
- public-key materialization rules expected by SDK verification
- workflow/check names embedded in scaffolded assets
- management-client source-of-truth used to feed the SDK package

## 8. Deferred publication-org work

The following remain outside this backend runbook:

- npm publish and npm provenance enforcement
- SDK release attestation publication
- client-claim promotion and released client wording
- hosted branch protection in the final org
- publication-org release-secret custody

Those items should be tracked and executed in the SDK repository and final publication org.
