# SDK Implementation Guide

Last updated: 2026-03-11

Status: active plan

Owner: Engineering

Audience: implementation contributors, maintainers

## 1. Purpose

This document provides implementation guidance for the TypeScript SDK layers. **Phase 1 (Verified Core Loader) is available, and the P1 client-core blocker is now closed in the backend repository.** This repository currently carries Node and browser reference adapters plus focused WASM tests; the publishable `@aegaeon/runtime-*` packages still belong to the separate `aegaeon-sdk` delivery track. The intended pre-release client-claim boundary is now source-managed in `spec/client-claim-boundary.current.json`, the promotion gate is frozen in `spec/client-claim-promotion.current.json`, the released-client wording target is frozen in `spec/released-client-claim.current.json`, managed commercial-provider evidence is modeled in `spec/managed-provider-evidence.schema.json`, admin-console SDK evidence is modeled in `spec/admin-sdk-evidence.schema.json`, the admin-console management-auth posture is source-managed in `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`, hosted workflow presence/default references are frozen in `scripts/sdk/sdk_workflow_inventory.current.json`, hosted evidence-source selection is frozen in `scripts/sdk/sdk_hosted_evidence_sources.current.json`, and the SDK release path now has machine-readable release scaffolds via `scripts/sdk/tools-src/*.ts`, with runtime execution through generated JavaScript under `dist-tools/*.js`. Managed-provider evidence is expected to flow artifact-first through the hosted `managed-provider-evidence.yml` workflow artifact, with `AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON` retained only as an explicit override when a hosted artifact cannot be wired directly; admin-console evidence is expected to flow artifact-first through the dedicated hosted `admin-sdk-evidence` artifact, with `AEGAEON_ADMIN_SDK_EVIDENCE_JSON` retained only as an explicit override. That admin evidence is only meaningful when it comes from an admin-console build that still passes the source-managed management-session boundary. `managed-provider-evidence.yml`, `client-claim-promotion.yml`, `released-client-readiness.yml`, `publication-org-rollout.yml`, and `publish.yml` now accept `workflow_dispatch` input overrides for inline evidence JSON, publication-org blocker status, and optional hosted self-dispatch (`dispatch_hosted=true`) where applicable, while hosted artifact source selection remains source-managed through repository variables, workflow inventory policy, and the hosted evidence-source policy. The released-client policy now also requires both hosted evidence bundles to be no older than 168 hours and to come from the expected hosted workflow/lane pairs. The separate SDK repository now also carries dedicated hosted `managed-provider-evidence.yml`, `client-claim-promotion.yml`, `released-client-readiness.yml`, and `publication-org-rollout.yml` lanes so evidence capture, promotion, readiness, and publication-org rollout auditing stay separated from the broader Playwright diagnostics lane. When managed-provider evidence and admin-console SDK evidence exist, the hosted promotion lane writes `.artifacts/release/client-claim-promotion-report.json`, while the hosted readiness lane, publication-org rollout lane, and publish path can write `.artifacts/release/released-client-claim-report.json`, `.artifacts/release/publication-org-rollout-report.json`, and `.artifacts/release/release-publication-bundle.json` in fail-closed passes. The source-language convergence target and sequencing are now recorded in `sdk-source-language-plan.md`.

Related documents:
- `client-sdk-architecture.md`
- `sdk-repository-plan.md`
- `sdk-ci-plan.md`
- `../../../operations/sdk-release.md`

## 2. Current SDK Structure

```text
aegaeon-sdk/
  package.json                  # pnpm workspace root
  pnpm-workspace.yaml
  README.md                     # Quick start and API documentation
  e2e/                          # Playwright browser tests
    secure-context.spec.ts      # SecureContext enforcement
    crypto.spec.ts              # ES256 signature tests
    public/                     # Test fixtures
      index.html
      crypto-test.html
      verified-core/            # WASM artifact for tests
  packages/
    runtime-shared/             # @aegaeon/runtime-shared
      src/
        handle.ts               # RuntimeHandle creation
        imports.ts              # WASM host imports (sha256, verify_signature, etc.)
        memory.ts               # WASM memory management
        types.ts                # TypeScript interfaces
    verified-core-loader/       # @aegaeon/verified-core-loader
      src/index.ts              # initCore() entry point
    verified-core/              # @aegaeon/verified-core
      dist/                     # WASM artifact + manifest
        verified_core.wasm
        manifest.json
        verified_core.abi.json  # ABI specification
        types.d.ts              # Generated TypeScript types
      INTEGRATION.md            # Integration guide
    runtime-web/                # @aegaeon/runtime-web
      src/index.ts              # initRuntimeWeb() / initCore()
    runtime-node/               # @aegaeon/runtime-node
      src/index.ts              # initRuntimeNode() / initCore()
    management-client/          # @aegaeon/management-client (alpha)
    issuer-spa/                 # @aegaeon/issuer-spa (alpha)
    rp-core/                    # @aegaeon/rp-core (alpha)
```

- Use pnpm v9+ and Node.js 22+ (provided by `nix develop`).
- Each package has `README.md`, `tsconfig.json`, and `package.json`.
- Higher-level language expansion beyond the current TypeScript alpha surfaces is still pending. The required order is **Rust first, then Ruby, then PHP**.

## 3. Pre-implementation Checklist

1. Core artefact available under `artifacts/verified-core/` (`verified_core.wasm`, `manifest.json`, `*.sig`, `integrity.txt`).
2. Node.js 22+ と Rust toolchain (Rust 1.77+) を準備（`nix develop` で満たされる）。
3. `pnpm install --frozen-lockfile` runs without errors.
4. `scripts/sdk/fetch_core_artifact.js` accessible (copy into `aegaeon-sdk/scripts/` or reference via relative path).
5. Confirm definitions in `client-sdk-architecture.md` (layer responsibilities, package names).

## 4. Implementation Phases

### Phase 1 — Verified Core Loader ✅ COMPLETE

**Implemented packages:**
- `@aegaeon/verified-core-loader` - WASM loading and integrity verification
- `@aegaeon/runtime-shared` - Memory management and host imports
- `@aegaeon/verified-core` - WASM artifact distribution

**Key features:**
- `initCore(opts)` entry point that loads WASM + verifies manifest
- SHA-256 integrity verification
- Optional Ed25519 signature verification
- Memory management for WASM linear memory
- Current backend-repo reference boundary: replay store, byte-handle registration/release, compact parsing, and handle resolution (7 imports in the minimal WASM build).

**API:**
```typescript
import { initCore } from "@aegaeon/verified-core-loader";

const { instance, handle } = await initCore({
  manifest: manifestJson,
  wasm: wasmBytes,
  signature: signatureBytes,     // optional
  publicKeyPem: publicKeyPem,    // optional
  createHandle: (ctx) => createRuntimeHandle(ctx, hostCrypto, replayStore),
});
```

### Phase 2 — Runtime Adapters 🚧 IN PROGRESS

**Current implementation in this repository:**
- `scripts/sdk/runtime_node_reference.ts` - Node reference adapter for the current Verified Core WASM artefact
- `scripts/sdk/runtime_web_reference.ts` - browser-facing reference adapter with SecureContext enforcement and WebCrypto artefact verification
- `tests/verified_core_wasm/runtime_node_reference_test.ts` - focused end-to-end coverage for the Node adapter
- `tests/verified_core_wasm/runtime_web_reference_test.ts` - focused WebCrypto coverage for the browser-facing adapter
- `tests/verified_core_wasm/runtime_web_reference.html` - secure-context browser smoke harness served by `runtime_web_reference_server.ts`
- `tests/verified_core_wasm/runtime_web_browser_smoke_test.ts` - headless-browser smoke runner with localhost-first / file-fallback execution
- `scripts/sdk/stage_reference_sdk_workspace.ts` - local staging generator for package-shaped `@aegaeon/verified-core`, `@aegaeon/runtime-node`, `@aegaeon/runtime-web`, and alpha `@aegaeon/management-client` / `@aegaeon/issuer-spa` / `@aegaeon/rp-core` surfaces
- `scripts/sdk/scaffold_sdk_repo_workspace.ts` - generator for a pnpm-based `aegaeon-sdk` repository skeleton that carries the staged package surfaces forward
- `scripts/sdk/build_sdk_repository_dispatch_payload.ts` - backend-side helper that builds the `verified-core-release` `repository_dispatch` payload for the separate SDK repository
- `scripts/sdk/build_sdk_release_attestation.mjs` - backend-side helper that builds the release-attestation scaffold from `.artifacts/release/publish-manifest.json` plus `spec/client-claim-boundary.current.json` and can optionally emit a detached signature descriptor when release custody enables signed attestations
- `scripts/sdk/build_sdk_managed_provider_evidence.mjs` - backend-side helper that materializes `.artifacts/managed-provider/managed-provider-evidence.json` after a successful managed commercial-provider lane
- `scripts/sdk/download_managed_provider_evidence.mjs` - backend-side helper that materializes `.artifacts/managed-provider/managed-provider-evidence.json` from a hosted `managed-provider-evidence` artifact
- `scripts/sdk/tools-src/run-hosted-evidence.ts` - backend/source-of-truth helper mirrored into the SDK repo to dispatch hosted admin / managed-provider evidence workflows and download their dedicated artifacts into `.artifacts/*`
- `scripts/sdk/tools-src/build-hosted-release-readiness-report.ts` - backend/source-of-truth helper that inspects remote SDK/admin state, hosted workflow presence, and the most recent successful hosted evidence runs, then writes `.artifacts/release/hosted-release-readiness-report.json`
- `scripts/sdk/check_sdk_client_claim_promotion.mjs` - backend-side helper that audits `spec/client-claim-promotion.current.json` against the frozen client boundary, release attestation, required lanes, and managed-provider evidence
- `scripts/sdk/build_sdk_released_client_claim_report.mjs` - backend-side helper that turns the frozen released-client wording policy plus current evidence into a machine-readable `ready / blockers` report
- `scripts/sdk/check_sdk_released_client_readiness.mjs` - backend-side helper that validates managed-provider evidence, validates admin-console evidence, runs the promotion gate, builds the released-client report, audits the activation gate, and writes the release-publication bundle
- `scripts/sdk/tools-src/build-hosted-release-readiness-report.ts` - companion report generator used before publication-org rollout so remote drift and hosted evidence gaps are machine-readable
- `tests/verified_core_wasm/staged_sdk_workspace_test.ts` - package-resolution smoke test for the staged workspace
- `tests/verified_core_wasm/publishable_sdk_package_test.ts` - `npm pack` / tarball-install smoke test for the staged package surfaces
- `tests/verified_core_wasm/scaffold_sdk_repo_test.ts` - repository-scaffold smoke test for the generated pnpm workspace / workflow skeleton, including local `download-core:release` + `verify-core` execution against the backend artefact bundle
- `tests/verified_core_wasm/sdk_repository_dispatch_payload_test.ts` - dispatch payload smoke test for the backend `release-core` → SDK repository handoff

**Current features in the reference adapters:**
- Manifest / SRI verification before instantiation
- Optional Ed25519 artefact-signature verification in both Node and browser-facing loaders
- Packaged distribution outputs (`manifest.json`, `verified_core.wasm.sha256`, `verified_core.wasm.sha512`, `verified_core.wasm.sri`, `verified-core-sbom.json`, `types.d.ts`) available from `scripts/sdk/package_verified_core_dist.js`
- PKCE S256 generation and verification (`pkceGenerate`, `pkceVerify`)
- JWT verification for compact and claims inputs (`jwtVerify`, `jwtVerifyClaims`)
- DPoP verification for compact and claims inputs (`dpopVerify`, `dpopVerifyClaims`)
- In-memory replay-store hook for DPoP replay semantics
- SecureContext enforcement plus browser smoke coverage via `runtime_web_reference.html` and `runtime_web_browser_smoke_test.mjs`
- Publishable package metadata on the staged surfaces (`license`, `engines`, `publishConfig`, bundled `LICENSE`)
- Separate-repository scaffold generation (`pnpm-workspace.yaml`, `.changeset/config.json`, `.npmrc`, `tsconfig.base.json`, `tools-src/download-core-release.ts`, `tools-src/verify-core.ts`, `tools-src/check-repository-settings.ts`, `tools-src/check-release-custody.ts`, `tools-src/check-managed-provider-readiness.ts`, `scripts/validation/validate_managed_external_provider_config.py`, `spec/repository-settings.current.json`, `spec/release-custody.current.json`, `spec/managed-external-provider.schema.json`, generated `dist-tools/*.js`, workflow scaffolding, copied packages, browser-smoke assets)
- Source-managed claim / release contracts (`spec/client-claim-boundary.current.json`, `spec/client-claim-boundary.schema.json`, `spec/sdk-release-attestation.schema.json`, `scripts/validation/validate_client_claim_boundary.py`, `scripts/validation/validate_sdk_release_attestation.py`, `tools-src/build-release-attestation.ts`, generated `dist-tools/build-release-attestation.js`)
- Source-managed promotion / released-client / commercial-provider contracts (`spec/client-claim-promotion.current.json`, `spec/client-claim-promotion.schema.json`, `spec/released-client-claim.current.json`, `spec/released-client-claim.schema.json`, `spec/released-client-claim-report.schema.json`, `spec/managed-provider-evidence.schema.json`, `scripts/validation/validate_client_claim_promotion.py`, `scripts/validation/validate_released_client_claim.py`, `scripts/validation/validate_released_client_claim_report.py`, `scripts/validation/validate_managed_provider_evidence.py`, `tools-src/build-managed-provider-evidence.ts`, `tools-src/check-client-claim-promotion.ts`, `tools-src/build-released-client-claim-report.ts`, generated `dist-tools/*.js`)
- Current signature-verification scope: **EdDSA inside the WASM path**, plus adapter-side `ES256` / `RS256` preverification in the Node/browser reference adapters before claims / time / replay enforcement returns to Verified Core

**Remaining package work in `aegaeon-sdk`:**
- Keep `sdk/spec/repository-settings.current.json`, `sdk/spec/release-custody.current.json`, and `sdk/spec/branch-protection.main.json` aligned with the active root-level workflows and carry them forward into the final publication-org repository
- Keep `sdk/spec/client-claim-boundary.current.json` aligned with runtime defaults and do not widen released wording until it is explicitly promoted from its current pre-release state
- Keep `sdk/spec/client-claim-promotion.current.json` and `sdk/spec/released-client-claim.current.json` aligned with the intended released client wording; do not claim a released client boundary until the managed-provider evidence bundle, admin-console evidence bundle, release attestation, released-client report, and required lanes satisfy that gate
- Keep `.artifacts/release/publish-manifest.json`, `.artifacts/release/release-attestation.json`, npm provenance, and `sdk/spec/release-custody.current.json` aligned for every real publish; add signed attestations / SBOM publication on top of that baseline
- Keep `.artifacts/managed-provider/managed-provider-evidence.json` aligned with `sdk/spec/managed-provider-evidence.schema.json` after every hosted commercial-provider pass and treat it as an input to client-claim promotion rather than as release marketing evidence by itself
- Browser bundler integration plus provisioned credential-backed upstream IdP coverage beyond the current Dex + Keycloak baselines around the reference web adapter, keeping the managed-provider lane aligned with `sdk/spec/managed-external-provider.schema.json` and fronted by a fail-closed readiness audit
- Higher-level domain SDKs layered on top of the runtime adapters

**Implementation snapshot:**

| Feature | backend-repo reference | publishable SDK package |
|---------|------------------------|-------------------------|
| PKCE S256 | ✅ reference + staged tarball smoke + scaffold | pending separate repo activation |
| JWT compact / claims | ✅ EdDSA reference | pending separate repo |
| DPoP compact / claims | ✅ EdDSA reference | pending separate repo |
| ES256 / RS256 runtime support | ✅ reference adapters via adapter-side preverification; full promoted client claim still pending | pending separate repo / claim |
| Browser SecureContext adapter | ✅ reference in backend repo | pending separate repo |

**Reference API in this repository:**
```javascript
import { initCore as initNodeCore } from "../../scripts/sdk/runtime_node_reference.ts";
import { initCore as initWebCore } from "../../scripts/sdk/runtime_web_reference.ts";

const { handle: nodeHandle } = await initNodeCore();
const { handle: webHandle } = await initWebCore({ secureContext: true, manifest, wasmBytes });
const pkce = await webHandle.pkceGenerate({ verifier });
const valid = await nodeHandle.pkceVerify({ verifier, challenge });
const jwt = await webHandle.jwtVerify({ jwt: compactJwt, publicKey });
```

### Phase 3 — Domain SDKs (Alpha Started)

**Planned packages:**

- `@aegaeon/management-client`
  - Current alpha helpers: `createManagementClient`, `createInMemoryManagementSessionStore`, `createInMemoryCookieJar`, CSRF priming, Origin injection, automatic `teamId` path insertion, and the current admin-console control-plane surface (team / tenant / environment / client / client-secret / configuration-version / policy / key-store / signing-key / user / audit helpers)
  - Intended consumers: admin UIs and automation clients
  - Remaining work: wider OpenAPI code generation, richer session lifecycle helpers, and React/UI bindings

- `@aegaeon/issuer-spa`
  - Current alpha helpers: `createInMemoryTransactionStore`, `createSessionStorageTransactionStore`, `createInMemorySessionStore`, `createSessionStorageSessionStore`, `fetchIssuerMetadata`, `startLogin`, `startLoginFromIssuerMetadata`, `startLoginWithDiscovery`, `finishLogin`, `persistLoginSession`, `completeLogin`, `restoreLoginTransaction`, `restoreLoginSession`, `clearLoginTransaction`, `clearLoginSession`, `buildLogoutUrl`, `buildLogoutUrlFromIssuerMetadata`, and `initIssuerSpaRuntime`
  - Intended consumers: first-party browser login flows, not management UIs
  - Current local provider E2E: `pnpm run test:provider-local` in `../aegaeon-sdk/sdk` (after `nix develop .`) exercises discovery, Authorization Code + PKCE, token exchange, RS256 ID Token verification through `@aegaeon/runtime-node`, session persistence, and logout URL derivation against a sibling real `../aegaeon` OP
  - Current third-party non-mock browser E2E baselines: `../aegaeon-sdk/sdk/tests/providers/dex/run_dex_browser_e2e.mjs` and `../aegaeon-sdk/sdk/tests/providers/keycloak/run_keycloak_browser_e2e.mjs`
  - Remaining work: Trusted Types support, richer browser/session lifecycle helpers, framework bindings, and provisioning real commercial upstream tenants on top of the new scripted `test:provider-managed-browser` lane beyond the current Dex + Keycloak baselines
  - Promotion note: successful managed-provider runs should now also emit `.artifacts/managed-provider/managed-provider-evidence.json`, upload a dedicated `managed-provider-evidence` artifact, and pass the frozen client-claim promotion gate before any release wording changes
  - One-shot readiness helper in the separate SDK repo: `cd ../aegaeon-sdk/sdk && pnpm run run:real-tenant-readiness -- --managed-provider-config tests/providers/managed/managed-provider.example.json --mode readiness --claim-active "${AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE:-false}"`
  - Example Next.js integration in `packages/examples/issuer-next-app`

- `@aegaeon/rp-core`
  - Authorization Code with external IdP
  - Attribute mapping DSL executed via WASM (when available)
  - Current alpha helpers: `normalizeIssuerMetadata`, `fetchIssuerMetadata`, `buildAuthorizationUrlFromIssuerMetadata`, `buildPkceAuthorizationRequest`, `buildPkceAuthorizationTransaction`, `buildPkceAuthorizationTransactionFromIssuerMetadata`, `validateAuthorizationResponse`, `buildTokenRequestFromAuthorizationResponse`, `buildEndSessionUrl`, `buildEndSessionUrlFromIssuerMetadata`, `createInMemoryAuthorizationTransactionStore`, `createInMemoryFederatedSessionStore`, `startFederatedLogin`, `startFederatedLoginFromIssuerMetadata`, `finishFederatedLogin`, `buildFederatedSessionRecord`
  - Intended consumers: OIDC / federation RP flows under `issuer-spa` or server-side adapters
  - Current local provider E2E: `pnpm run test:provider-local` in `../aegaeon-sdk/sdk` (after `nix develop .`) covers the `rp-core` discovery → authorize → token → session path against a real Aegaeon OP
  - Remaining work: browser-native session persistence, richer token/session lifecycle helpers, and third-party upstream-IdP oriented E2E flows

### Phase 4 — Post-TypeScript language expansion (Pending)

#### Phase 4A — Rust adapters

**Planned crates:**

- `aegaeon-sdk/crates/aegaeon-core`
  - WASM loader with `wasmtime`
  - `no_std` optional feature (fallback to `wee_alloc`)
  - Safe wrappers for PKCE/DPoP verification

- `aegaeon-sdk/crates/aegaeon-management`
  - OpenAPI client generated via `oapi-codegen` or `swagger-codegen`
  - `ManagementClient::new(base_url, session)` with CSRF support

**Exit conditions:**

- Rust package boundaries are stable.
- Release custody for crates.io is defined.
- The Rust track does **not** widen the current client claim boundary by itself.

#### Phase 4B — Ruby adapters

- publish Ruby wrappers to RubyGems after the Rust package boundary and release discipline are stable
- keep the Ruby track outside the formal claim boundary unless separately promoted

#### Phase 4C — PHP adapters

- publish PHP wrappers to Packagist / Composer after the Ruby package boundary and release discipline are stable
- keep the PHP track outside the formal claim boundary unless separately promoted

## 5. Verification Commands

```bash
# Enter Nix dev shell
nix develop

# Install dependencies
cd sdk && pnpm install

# Build all packages
pnpm -r run build

# Type checking
pnpm -r run lint

# Run unit tests
pnpm test

# Run E2E browser tests
pnpm test:e2e
```

Automated via CI when the SDK is moved to a separate repository.

## 6. Migration Plan to Separate Repository

When ready to publish the SDK packages:

1. Ensure each package has `.gitignore`, `README.md`, and licensing headers
2. Use `git subtree split` or `rsync` to transfer the SDK workspace to the `aegaeon-sdk` repo
3. Run `pnpm install && pnpm -r build && pnpm test` to confirm parity
4. Apply release workflow (`publish.yml`) from `sdk-ci-plan.md`

## 7. Maintenance Notes

- **Constant-time operations**: `host_bytes_eq` and `Host_verify_ath_binding` use XOR accumulator pattern to prevent timing attacks
- **Claims-based API**: Use `dpopVerifyClaims`/`jwtVerifyClaims` when the caller has already parsed the JWS
- **Platform limitations**: Current verified browser-facing path is EdDSA-only; document any ES256 / RS256 compatibility or promotion step explicitly when adding algorithms
- **ABI updates**: When modifying WASM exports, run `node scripts/sdk/generate_verified_core_abi.js` to regenerate types
- **Distribution**: Run `node scripts/sdk/package_verified_core_dist.js --out packages/verified-core/dist` to update WASM artifact
