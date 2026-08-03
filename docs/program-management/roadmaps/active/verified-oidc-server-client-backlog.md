# Verified OIDC Server / Client Implementation Backlog

Last updated: 2026-03-16

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

## Purpose

This document turns the current product-positioning and verification-gap analysis into an
implementation-ordered backlog.

It is a delivery aid, not a new claim document. For claim scope and released wording, use:

- `docs/product-positioning.md`
- `docs/verification/claims/assurance-case/README.md`
- `docs/verification/claims/crypto-allowlist.md`
- `docs/verification/workplans/verification-boundary-roadmap.md`

## Priority Order

### P0 — Verified OIDC Server Claim Blockers

1. **Carve out the OIDC `RS256 Required Slice` in code**
   - isolate OP ID Token `RS256` issuance, `at_hash` / `c_hash`, and `RS256` verification helpers
   - remove stringly-typed duplication across OIDC issuance and RP/brokering paths
   - status: complete
2. **Route OP-required `RS256` verification through the carved-out path**
   - upstream / brokering ID Token verification should use the dedicated `RS256` helper where applicable
   - status: complete
3. **Add `RS256 Required Slice` implementation tests**
   - ID Token sign/verify round-trip
   - tamper rejection
   - OIDC hash vectors for `RS256`
   - status: complete
4. **Close the proof / boundary evidence for the Required Slice**
   - replace compat-only posture with explicit boundary promotion backed by non-doc-only evidence
   - evidence bundle: `artifacts/verification/oidc-rs256-required-slice/20260309T014321Z`
   - status: complete

### P1 — Verified OIDC Client Core Blockers

1. **Make Verified Core claims APIs non-stub for claimable client usage**
   - remove `UNSUPPORTED` claims-path behaviour where the client track depends on it
   - progress: `VerifiedCore_jwt_verify_claims_v1` and `VerifiedCore_dpop_verify_claims_v1` now provide claimable client behaviour; EdDSA remains inside the current verified WASM path, while the Node/Web reference adapters preverify `ES256` / `RS256` signatures and then call the claims exports with explicit `SIGNATURE_PREVERIFIED` flags so Verified Core still enforces claims, time, and replay semantics; `tests/verified_core_wasm/test_instantiate.mjs` now proves both the accepted preverified path and the rejected non-preverified path
   - released-claim note: this closes the client-core blocker but does **not** yet create a released standalone client-product claim
   - status: complete
1. **Reduce WASM host-stub dependence**
   - eliminate Warning 15 hot spots and `FStar_String_uppercase` / math-int host callbacks
   - progress: `Dpop.Htm_validation` no longer imports `FStar_String_uppercase`, JWT audience membership / `ath` binding / Low* compat math shims now live inside the WASM binary, and the default fixture import table dropped from 67 → 64 → 7 imports
   - closed boundary: the remaining runtime boundary is now limited to replay-store I/O, compact parsing, handle registration, and handle resolution; no additional crypto host imports were added for the `ES256` / `RS256` client path
   - status: complete
1. **Add real-crypto WASM tests**
   - avoid mock-host-only confidence for JWT / DPoP verification
   - progress: `tests/verified_core_wasm/test_instantiate.mjs` now drives direct WASM claims coverage, `tests/verified_core_wasm/runtime_node_reference_test.mjs` covers Node adapter PKCE/JWT/DPoP with `RS256` / `ES256` adapter-side preverification, and `tests/verified_core_wasm/runtime_web_reference_test.mjs` provides the parallel browser-facing WebCrypto coverage
   - remaining gap moved to P2: browser-required CI lanes and real-upstream IdP end-to-end coverage
   - status: complete
1. **Ship signed / attestable Verified Core artefacts**
   - `verified_core.wasm.sig`, SBOM, manifest discipline, generated ABI header
   - progress: `scripts/sdk/package_verified_core_dist.js` now emits packaged `manifest.json`, `verified_core.wasm.sha256`, `verified_core.wasm.sha512`, `verified_core.wasm.sri`, `verified-core-sbom.json`, `types.d.ts`, and optional Ed25519 signatures; the refreshed fixture bundle is consumed by the current Node/Web reference adapters; `tests/verified_core_wasm/package_dist_test.mjs` exercises sign → package → fetch verification end-to-end
   - P1 closure note: this closes the SDK handoff artefact discipline required for client-core work; production key custody, CI/publish attestation, and release-time signature policy stay tracked under P2 productization
   - status: complete

### P2 — Client / SDK Productization

1. **Implement runtime adapters**
   - `@aegaeon/verified-core`, `@aegaeon/runtime-web`, `@aegaeon/runtime-node`, `aegaeon-core`
   - progress: this repository now ships a Node reference adapter at `scripts/sdk/runtime_node_reference.ts`, a browser-facing reference adapter at `scripts/sdk/runtime_web_reference.ts`, explicit client crypto profiles (`verified-core`, `aegaeon-rs256`, `compat-interop`) with `aegaeon-rs256` as the default, `scripts/sdk/stage_reference_sdk_workspace.ts` for staged package surfaces, and `scripts/sdk/scaffold_sdk_repo_workspace.ts` for generating a pnpm-based `aegaeon-sdk` repository skeleton; both generators now emit `@aegaeon/verified-core`, `@aegaeon/runtime-node`, `@aegaeon/runtime-web`, and alpha `@aegaeon/management-client` / `@aegaeon/issuer-spa` / `@aegaeon/rp-core` surfaces. The staged packages now carry publishable metadata (`license`, `engines`, `publishConfig`, bundled `LICENSE`), publishable versioned package dependencies for tarball smoke tests, scaffold-local `workspace:*` package wiring, root `nix develop`-first scripts, `.changeset/config.json`, `.npmrc`, `tsconfig.base.json`, package-level `tsconfig.json`, `tsconfig.tests.browser.json`, `tools-src/download-core-release.ts`, `tools-src/verify-core.ts`, `tools-src/check-repository-settings.ts`, `tools-src/check-managed-provider-readiness.ts`, `tools-src/materialize-sdk-dispatch-payload.ts`, `tools-src/export-sdk-dispatch-env.ts`, `tools-src/materialize-verified-core-public-key.ts`, receiver-side `scripts/validation/validate_sdk_repository_dispatch_payload.py`, receiver-side `scripts/validation/validate_verified_core_handoff_manifest.py`, `scripts/validation/validate_managed_external_provider_config.py`, generated `dist-tools/*.js`, `spec/repository-settings.current.json` / `spec/branch-protection.main.json` / `spec/managed-external-provider.schema.json` policy files, a generated MIGRATION cutover checklist, Playwright scaffold files (`tests/playwright.config.ts`, `tests/browser/*.ts`, `tests/providers/**/*.ts`, preseeded `dist-tests/browser/*.js`, `.github/workflows/playwright.yml`), and workflow scaffolding for `verify-core`, `ci`, `playwright`, `managed-provider-evidence`, `client-claim-promotion`, `released-client-readiness`, and `publish`; the backend repo now also ships `scripts/sdk/build_sdk_repository_dispatch_payload.ts`, `scripts/sdk/build_verified_core_handoff_manifest.ts`, `scripts/sdk/materialize_verified_core_public_key.ts`, the canonical payload contract at `spec/sdk-repository-dispatch.schema.json`, the canonical handoff contract at `spec/verified-core-handoff-manifest.schema.json`, and validators for all three contracts; `release-core.yml` now validates the generated payload and handoff manifest before upload/dispatch and can emit / optionally send the `verified-core-release` `repository_dispatch` payload that the scaffold expects; the receiver flow now fail-closes when a signed artefact arrives without an explicit public-key path, `VERIFIED_CORE_PUBKEY`, or `VERIFIED_CORE_PUBKEY_OP_REF` secret, validates `verified-core-handoff-manifest.json` when it is present, source-manages the current sandbox repository settings contract via `audit:repo-settings`, and adds a dedicated `audit:managed-provider` gate that validates config shape, auth-method-dependent secrets, and browser availability before a tenant-backed lane runs; the real separate SDK repository at `../aegaeon-sdk` is now initialized as Git, has active root-level workflows under `/.github/workflows/`, passes `actionlint`, and completes `nix develop . --command bash -lc 'cd sdk && pnpm run test:repo'`; hosted check names are now fixed as `SDK Verify Core / Verify Core`, `SDK CI / Packages`, `SDK CI / Browser Smoke`, `SDK Browser E2E / Core Playwright`, `SDK Browser E2E / External Provider (Dex)`, the hosted `SDK Client Claim Promotion / Client Claim Promotion`, and the hosted `SDK Claim Readiness / Released Client Readiness`
   - remaining gap: hosted secret provisioning remains an operations step, the pre-release client-claim boundary is now frozen in `spec/client-claim-boundary.current.json`, the promotion gate is now frozen in `spec/client-claim-promotion.current.json`, the released-client wording target is now frozen in `spec/released-client-claim.current.json`, managed commercial-provider evidence is now modeled by `spec/managed-provider-evidence.schema.json`, and publication-time custody is frozen in `spec/release-custody.current.json`, but none of that has been promoted into a released client claim yet; the scaffold now emits a CycloneDX workspace SBOM, a machine-readable release-publication bundle, an optional detached signed release-attestation descriptor, a `client-claim-promotion-report.json` whenever managed-provider evidence is available, and a `released-client-claim-report.json` that records the remaining publication-org blockers, evidence freshness, and hosted provenance, while the release-publication bundle records managed-provider evidence, admin-console evidence, and the released-client report when present, on top of the current npm-provenance + publish-manifest + release-attestation flow; the separate SDK repository now also carries dedicated hosted `SDK Client Claim Promotion / Client Claim Promotion` and `SDK Claim Readiness / Released Client Readiness` lanes that download hosted admin and managed-provider evidence artifacts before running the gates, and the hosted/manual gates (`client-claim-promotion.yml`, `released-client-readiness.yml`, `publish.yml`) now accept `workflow_dispatch` overrides for inline evidence JSON, publication-org blocker status, and optional `dispatch_hosted=true` self-dispatch so one-off real-tenant runs do not require persistent repo-var edits; hosted artifact source selection remains source-managed through repository variables, workflow inventory policy, and the hosted evidence-source policy; as of `2026-03-18`, the generated hosted readiness report is green with both hosted evidence bundles present/fresh, and the remaining activation blockers are only the deferred publication-org tasks (`publication_org_branch_protection`, `publication_org_secret_rollout`); release-grade browser-capable CI runners plus real-upstream IdP coverage remain open; hosted branch-protection rollout is now a deferred publication-org task because the final released SDK will ship from a different organization
   - status: in_progress
1. **Implement claimable SDK surfaces**
    - `@aegaeon/management-client`
    - `@aegaeon/issuer-spa`
    - `@aegaeon/rp-core`
    - progress: the backend `scripts/sdk/stage_reference_sdk_workspace.ts` and `scripts/sdk/scaffold_sdk_repo_workspace.ts` generators now both emit alpha `@aegaeon/management-client` / `@aegaeon/issuer-spa` / `@aegaeon/rp-core` packages that keep cryptographic verification delegated to the runtime packages. `@aegaeon/management-client` currently covers selected OpenAPI-backed control-plane operations plus auth/session helpers (`createManagementClient`, `createInMemoryManagementSessionStore`, `createInMemoryCookieJar`, CSRF priming, Origin injection, automatic `teamId` path insertion, and selected team / tenant / environment / oauth-profile / connection / configuration-version / signing-key / key-store / client / client-secret / policy / user / audit helpers, including environment/team-audit JSON/CSV export and query-string-backed audit filters). `@aegaeon/rp-core` now covers both low-level Authorization Code + PKCE helpers (`normalizeIssuerMetadata`, `fetchIssuerMetadata`, `buildAuthorizationUrlFromIssuerMetadata`, `buildPkceAuthorizationRequest`, `buildPkceAuthorizationTransaction`, `buildPkceAuthorizationTransactionFromIssuerMetadata`, callback parsing/state validation, callback→token-request derivation, and RP-initiated logout URL construction) and higher-level orchestration (`createInMemoryAuthorizationTransactionStore`, `createInMemoryFederatedSessionStore`, `startFederatedLogin`, `startFederatedLoginFromIssuerMetadata`, `finishFederatedLogin`, `buildFederatedSessionRecord`, and restore/clear helpers for transaction + session state). `@aegaeon/issuer-spa` now layers browser transaction storage, browser-native session persistence, discovery-driven callback completion, and logout orchestration on top (`createInMemoryTransactionStore`, `createSessionStorageTransactionStore`, `createInMemorySessionStore`, `createSessionStorageSessionStore`, `fetchIssuerMetadata`, `startLogin`, `startLoginFromIssuerMetadata`, `startLoginWithDiscovery`, `finishLogin`, `persistLoginSession`, `completeLogin`, `restoreLoginTransaction`, `restoreLoginSession`, `clearLoginTransaction`, `clearLoginSession`, `buildLogoutUrl`, `buildLogoutUrlFromIssuerMetadata`, and `initIssuerSpaRuntime`). The sibling `../aegaeon-admin-console` is now wired through `@aegaeon/management-client` only, its package/import/env boundary is source-managed in `../aegaeon-admin-console/spec/admin-sdk-boundary.current.json`, its management-auth posture is source-managed in `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`, its hosted workflow inventory is source-managed in `../aegaeon-admin-console/spec/workflow-inventory.current.json`, its compose-backed browser lane emits `.artifacts/admin-sdk/admin-sdk-evidence.json` validated against `spec/admin-sdk-evidence.schema.json`, and a hosted `Admin Console Stack E2E / Stack E2E` workflow now checks out sibling `aegaeon` / `aegaeon-sdk` repositories and uploads the same admin evidence plus Playwright diagnostics as CI artifacts after exercising bootstrap, login, dashboard rendering, create team/tenant/environment, list/create/update/delete oauth profiles, list/create/update/delete connections, update environment policy, create/activate configuration version, rotate/activate-next/revoke signing key, update key store, list/block/unblock users, invalidate user sessions, revoke user refresh tokens, environment/team audit reads, query-string-backed audit filtering, environment/team-audit JSON/CSV export, audit-event detail, create/update/delete client, issue/revoke/revoke-all client secrets, and logout against a sibling `../aegaeon` stack. Focused tests live at `tests/verified_core_wasm/staged_sdk_workspace_test.ts`, `tests/verified_core_wasm/publishable_sdk_package_test.ts`, `../aegaeon-sdk/sdk/packages/management-client/test/management_client_test.ts`, `../aegaeon-sdk/sdk/packages/issuer-spa/test/issuer_spa_test.ts`, and `../aegaeon-sdk/sdk/packages/rp-core/test/rp_core_test.ts`
    - remaining gap: React/UI bindings for the management SDK, Trusted Types / framework bindings for issuer-spa, publication-org release wiring, and promotion of the current source-managed client-claim boundary through `spec/client-claim-promotion.current.json` and `spec/released-client-claim.current.json` remain open
    - status: in_progress
1. **Add browser / node / real-upstream end-to-end coverage**
    - Playwright, Vitest, Rust, and real upstream IdP integration runs
    - progress: `tests/verified_core_wasm/runtime_node_reference_test.mjs` and `runtime_web_reference_test.mjs` now cover the Node and browser-facing reference adapters for PKCE plus JWT/DPoP compact and claims paths; `tests/verified_core_wasm/run_all.sh` includes both in the standard WASM suite, `tests/verified_core_wasm/runtime_web_reference.html` provides a browser smoke harness, and `tests/verified_core_wasm/runtime_web_browser_smoke_test.mjs` drives headless Chrome with localhost→file fallback so supported CI runners can execute a real browser smoke. The real separate SDK repository at `../aegaeon-sdk/sdk` now also carries TypeScript browser/playwright/provider sources under `tests/playwright.config.ts`, `tests/browser/*.ts`, and `tests/providers/**/*.ts`, and runs the built outputs under `dist-tests/` for both the packaged `runtime-web` harness and a local mock-upstream OIDC discovery → Authorization Code + PKCE redirect/token-exchange → logout flow for `issuer-spa`; `nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-local'` exercises `@aegaeon/runtime-node`, `@aegaeon/rp-core`, and the promoted `RS256` client slice against a sibling real `../aegaeon` OP built via `nix build .#server`; `nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-dex-browser -- --required'` stands up a local Dex container as a third-party non-mock upstream for the browser stack, `nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-keycloak-browser -- --required'` adds the same discovery/login/token/userinfo/logout orchestration against a local Keycloak container, and the new `nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-managed-browser -- --required --config <file>'` lane accepts a credential-backed scripted commercial-provider login contract through `tests/providers/managed/run_managed_browser_e2e.ts`, with the hosted `AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON` payload now required to validate against the source-managed `spec/managed-external-provider.schema.json` and to pass `pnpm run audit:managed-provider -- --config <file>` before browser execution; the hosted SDK repo now separates managed evidence capture into dedicated `managed-provider-evidence.yml`, while `playwright.yml` remains the broader browser E2E lane for core, Dex, Keycloak, and optional managed diagnostics
    - remaining gap: diagnostics retention policy and the actual provisioning of credential-backed commercial test tenants beyond the current Dex + Keycloak baselines are still pending; once a hosted commercial-provider lane passes, the resulting managed-provider evidence still has to satisfy the frozen promotion gate before any client wording changes; hosted branch-protection enforcement remains deferred to the final publication-org repository
    - status: in_progress
1. **Define a separate client / RP assurance case**
    - current claim remains server-side until this exists
    - progress: `docs/verification/claims/client-rp-assurance-case.md` now records the completed P1 client-core boundary, the adapter-side `RS256` / `ES256` preverification model, and the remaining blockers before any released client / RP product claim; `spec/client-claim-boundary.current.json` source-manages the frozen pre-release client-claim boundary, `spec/client-claim-promotion.current.json` source-manages the promotion gate, `spec/released-client-claim.current.json` source-manages the final released wording target, `spec/managed-provider-evidence.schema.json` records the hosted commercial-provider evidence expected before any released client-claim decision, `spec/admin-sdk-evidence.schema.json` records the admin-console SDK evidence expected before any released client-claim decision, the publish lane now ingests managed-provider evidence artifact-first through the dedicated hosted `managed-provider-evidence` artifact or the explicit `AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON` override, ingests admin evidence artifact-first through the dedicated hosted `admin-sdk-evidence` artifact or the explicit JSON override, and the SDK publish path now writes `.artifacts/release/client-claim-promotion-report.json` plus `.artifacts/release/released-client-claim-report.json` while also binding those inputs into `.artifacts/release/release-publication-bundle.json`
    - status: complete

### P2.5 — SDK TypeScript Source Convergence

1. **Freeze the SDK TypeScript-source target**
    - record the target state as `WASM core + TypeScript source + generated JavaScript artefacts only`
    - keep the verified claim boundary unchanged
    - keep admin-console on `@aegaeon/management-client` only during the migration
    - status: complete
1. **Build a TypeScript-first SDK substrate**
    - move package and tool execution toward `src/` → `dist/`
    - make release/verification workflows consume built JavaScript artefacts rather than handwritten source files
    - keep release-critical lanes free of `tsx` / `ts-node`
    - current snapshot:
      - `aegaeon-sdk/sdk` has `tsconfig.json`, `tsconfig.tools.json`, project references, stricter compiler options, and `dist-tools/exec-tool.js`
      - `verify-core`, `released-client-readiness`, and `publish` now run built JavaScript helper entrypoints rather than direct source scripts
      - package exports are now allowed to resolve built artefacts from `dist/`, so low-level package migration can proceed without changing workflow execution
    - status: complete
1. **Migrate low-level SDK packages first**
    - `@aegaeon/verified-core`
    - `@aegaeon/runtime-web`
    - `@aegaeon/runtime-node`
    - current snapshot:
      - `@aegaeon/verified-core` now keeps handwritten source in `src/index.ts`, `src/node.ts`, and `src/web.ts`, emits `dist/index.js`, `dist/node.js`, `dist/web.js`, and ships `dist/*.d.ts`
      - `@aegaeon/runtime-web` and `@aegaeon/runtime-node` now keep handwritten source under `src/*.ts`, emit `dist/index.js` / `dist/reference.js` (plus `dist/browser-smoke.js` for `runtime-web`), and publish `dist/*.d.ts`
      - browser import maps, staged workspace smoke tests, package-publish smoke tests, and SDK browser smoke wiring now consume `dist/*` outputs across the low-level package set
    - status: complete
1. **Migrate domain SDK packages second**
    - `@aegaeon/management-client`
    - `@aegaeon/rp-core`
    - `@aegaeon/issuer-spa`
    - current snapshot:
      - `@aegaeon/management-client` now keeps handwritten implementation under `src/index.ts`, emits `dist/index.js`, and uses built-output package tests while preserving the hand-authored `index.d.ts` as the stable public type contract for admin-console
      - `@aegaeon/rp-core` now keeps handwritten implementation under `src/index.ts`, emits `dist/index.js`, and publishes `dist/index.d.ts`; browser import maps and the local-provider lane now consume the built output
      - `@aegaeon/issuer-spa` now keeps handwritten implementation under `src/index.ts`, emits `dist/index.js`, and publishes `dist/index.d.ts`; browser import maps and the local/external-provider lanes now consume the built output
      - the backend `scripts/sdk/stage_reference_sdk_workspace.ts` and `scripts/sdk/scaffold_sdk_repo_workspace.ts` generators now mirror the `src/` + `dist/` layout across all Phase 3 packages
    - status: complete
1. **Migrate SDK repo scripts and validators**
    - move repository tooling to TypeScript source while keeping build/runtime outputs as plain JavaScript
    - keep machine-readable contracts authoritative
    - current snapshot:
      - `aegaeon-sdk/sdk/tools-src/*.ts` now holds the repository toolchain source
      - runtime execution goes through `sdk/dist-tools/*.js`
      - the legacy handwritten `.mjs` tool files are removed from the SDK repo
      - scaffold/source-of-truth tests now cover the built-tool layout used by the generated SDK repository
      - companion docs and SDK docs are synchronized on the `tools-src/*.ts` + `dist-tools/*.js` layout
    - status: complete
1. **Migrate SDK tests and support code**
    - move Node tests and browser support code to TypeScript source
    - keep stack/browser lanes green throughout
    - current snapshot:
      - `aegaeon-sdk/sdk/tests/node/*.ts` now carries the handwritten Node test source, including the local-provider E2E
      - `test:repo` and `test:provider-local` now execute built outputs from `sdk/dist-tests/node/*.js`
      - `aegaeon-sdk/sdk/tests/browser/*.ts`, `sdk/tests/providers/**/*.ts`, and `sdk/tests/playwright.config.ts` now carry the handwritten browser/playwright/provider source, while `test:browser-smoke`, `test:playwright`, `test:provider-dex-browser`, `test:provider-keycloak-browser`, and `test:provider-managed-browser` execute built outputs from `sdk/dist-tests/browser/*.js`, `sdk/dist-tests/providers/**/*.js`, and `sdk/dist-tests/playwright.config.js`
      - the backend scaffold mirrors the same `tests/node/*.ts`, `tests/browser/*.ts`, `tests/providers/**/*.ts`, and preseeded `dist-tests/**/*.js` layout so generated repositories exercise the same runtime path
    - status: complete
1. **Enforce no handwritten JavaScript in the SDK track**
    - disable `allowJs` after package, script, and test migration is complete
    - add CI guards for protected directories
    - current snapshot:
      - `aegaeon-sdk/sdk/tsconfig.base.json` now disables `allowJs` / `checkJs`
      - package-level tests for `management-client`, `rp-core`, and `issuer-spa` now build `test/*.ts` into `dist-test/*.js`
      - `pnpm run audit:no-js-source` is wired into `test:repo` and fails closed if handwritten `.js` / `.mjs` / `.cjs` source appears under the protected SDK directories
      - the backend scaffold/source-of-truth mirrors the same policy so generated repositories enforce the no-handwritten-JavaScript rule immediately
    - status: complete
1. **Re-run readiness and activation gates after migration**
    - refresh client-claim promotion / readiness evidence after the source-language migration stabilizes
    - current snapshot:
      - a fresh local rerun after the TypeScript migration now reproduces the expected gate shape without widening the claim boundary
      - `.artifacts/release/client-claim-promotion-report.json` is `ready: true` when fed fresh local admin-console evidence plus the managed-provider evidence fixture and the required lane set
      - `.artifacts/release/released-client-claim-report.json` remains `ready: false` because hosted provenance is still absent from the local admin/managed evidence and the publication-org rollout tasks remain pending
      - `.artifacts/release/release-publication-bundle.json` records the same result together with the fresh signed release attestation and workspace SBOM, so the post-migration release gate remains fail-closed
    - status: complete
1. **Keep post-TypeScript language rollout ordered**
    - expand beyond TypeScript only in the order **Rust → Ruby → PHP**
    - Rust is the first non-TypeScript target because it is the closest follow-on to the current WASM/runtime boundary
    - Ruby starts only after Rust package boundaries and release custody stabilize
    - PHP starts only after Ruby package boundaries and release custody stabilize
    - adding a new language track does not widen the current formal claim boundary by itself
    - status: planned

### P3 — Optional Interoperability Expansion

1. **Close the `RS256 Interop Slice`**
    - signed Request Objects / `request_uri`
    - `private_key_jwt`
    - status: planned
1. **Decide whether broader JOSE algorithms deserve promotion**
    - `ES256` / federation and other compat algorithms stay out unless explicitly promoted
    - status: planned

## Immediate Next Steps

1. Use `docs/program-management/roadmaps/active/verified-server-client-formal-claim-roadmap.md`
   and `spec/server-client-formal-assurance-claim.current.json` as the Phase 5
   gate before changing any public `formally verified server and client`
   wording.
2. Provision and run credential-backed real-upstream IdP end-to-end coverage through the new managed commercial-provider lane on top of the current Dex + Keycloak baselines, and emit `.artifacts/managed-provider/managed-provider-evidence.json`.
3. Run `scripts/sdk/check_sdk_released_client_readiness.mjs` against the managed-provider evidence bundle, the admin-console SDK evidence bundle, and the hosted lane set before widening any client wording; retain `.artifacts/release/client-claim-promotion-report.json`, `.artifacts/release/released-client-claim-report.json`, and `.artifacts/release/release-publication-bundle.json` as the machine-readable gate record.
   - Use `pnpm run release:hosted-readiness-report` in `aegaeon-sdk/sdk` when publication-org rollout is still pending; it writes `.artifacts/release/hosted-release-readiness-report.json` and surfaces remote drift, missing hosted workflows, and missing successful hosted evidence runs before the readiness gate is expected to pass.
4. Clear the publication-org blockers recorded in `.artifacts/release/released-client-claim-report.json` before enabling any released client wording.
5. Promote the detached signed release-attestation scaffold from source-managed preflight into the final publication-org custody flow, alongside npm provenance, the publish manifest, the workspace SBOM, the release attestation, the released-client report, and the release-publication bundle.
