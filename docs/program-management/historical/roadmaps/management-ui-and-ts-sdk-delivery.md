# Management UI & TypeScript SDK Delivery Record

Last updated: 2026-05-14

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

> **Status note (2026-05-14):** This historical record captures the backend-side coordination
> assumptions for the initial SDK / control-plane implementation track. The sibling
> `../aegaeon-sdk` and `../aegaeon-admin-console` repositories now carry the active SDK /
> control-plane implementation and hosted workflow inventory. The remaining cross-repository
> execution sequence is tracked in `../../roadmaps/active/management-platform-follow-on-plan.md`, and the
> shared quality baseline / drift policy are tracked in
> `../../../policies/management-platform-quality-profile.md`. This record does not redefine the
> released product statement or formal claim; use `../../../product-positioning.md` and
> `../../../verification/claims/assurance-case.md` for those.
> **Implementation snapshot (2026-05-14):**
>
> - `../aegaeon-sdk` now carries the package workspaces for `@aegaeon/verified-core`, `@aegaeon/runtime-node`, `@aegaeon/runtime-web`, `@aegaeon/management-client`, `@aegaeon/issuer-spa`, and `@aegaeon/rp-core`.
> - `../aegaeon-sdk/.github/workflows/` currently carries `verify-core.yml`, `ci.yml`, `lint.yml`, `playwright.yml`, `managed-provider-evidence.yml`, `client-claim-promotion.yml`, `released-client-readiness.yml`, and `publish.yml`.
> - `../aegaeon-sdk/sdk/spec/` now carries the source-managed workflow / evidence / custody / claim contracts needed for hosted promotion and readiness gates.
> - `../aegaeon-admin-console` now consumes `@aegaeon/management-client` as its only SDK dependency, source-manages the current SDK/auth boundary in `spec/admin-sdk-boundary.current.json` and `spec/admin-auth-boundary.current.json`, and currently carries hosted workflows `ci.yml`, `lint.yml`, and `stack-e2e.yml`.
> - The compose-backed admin-console lane and hosted stack lane exist; what remains is not “build the first UI/SDK surface” but “promote the existing surfaces through publication custody, hosted evidence, and final operational hardening”.

## 0. Current execution delta

The original sequence in this document assumed the backend repository would first emit a reference
scaffold and that the actual SDK / UI work would happen later. That assumption is now outdated.

What is already materially present in sibling repositories:

- `@aegaeon/management-client` exists and is the enforced dependency boundary for the admin console.
- `@aegaeon/issuer-spa` and `@aegaeon/rp-core` alpha packages exist in the SDK repository.
- Hosted workflow inventories and source-managed evidence contracts exist in both the SDK and
  admin-console repositories.
- The admin console already has a stack-backed browser lane that drives a sibling backend and SDK
  workspace together.

Therefore the active remaining work for the broad management-platform track is:

1. apply the source-managed branch-protection / repository-settings / release-custody contracts in
   the real publication organization
2. run the managed-provider evidence lane against provisioned commercial tenants and feed those
   artifacts into the hosted promotion/readiness gates
3. publish the SDK packages and activate the released client claim only after the hosted evidence
   and custody gates are satisfied
4. complete regulated-environment operational runbooks and the remaining KMS/HSM-backed OIDC
   signing-key work on the backend side

## 1. Background and Purpose

- The OAuth/OIDC server-side sprints (OAuth 0–7, OIDC-1…5) are complete.
- Management Console and SDK implementation is progressing in separate repositories, and alpha package/workflow
  baselines already exist. The current focus is on fixing boundaries,
  hosted evidence, release custody, and publication readiness, rather than initial implementation itself.
- Publish Verified Core (based on EverCrypt/HACL\*) as WASM so that the management UI, external SPA
  clients, and RP SDKs can use a shared foundation.
- FIPS support may be an option in the future; for now, assume EverCrypt/HACL\* and record FIPS as follow-up work.

## 2. Dependencies (Logical Order)

```text
Verified Core (F*/Low*/KaRaMeL → WASM)
        │
        ▼
Runtime Adapters (TypeScript Web/Node, Rust FFI)
        │
        ├── Management API Client SDK (@aegaeon/management-client)
        ├── Issuer SPA SDK (@aegaeon/issuer-spa)
        └── RP/External Client SDK (@aegaeon/rp-core)
             │
             ▼
      Management UI Implementation (Separate Repository)
```

- Note on repository separation:
  - Separate repositories (such as `aegaeon-sdk`) are the authoritative sources for TypeScript SDK / Management UI implementation.
  - This repository provides Verified Core extraction artefacts (for example, `artifacts/verified-core/`) and the server implementation;
    the SDK fetches and consumes those artefacts.
  - `pnpm ...` commands in this document refer to execution in the SDK repository (this repository's `package.json` is not for SDK development).

- All SDKs use Verified Core. The artifact/handoff and package boundaries
  are now in place; the remaining issues are publication custody and promotion of hosted evidence.
- The Management UI MVP requires `@aegaeon/management-client`. SPA authentication flows (PKCE/DPoP/state/nonce) must also be provided through Verified Core.

### Definition of Ready (Cross-Cutting)

Confirm the following prerequisites before starting each sprint:

1. `docs/specs/management-plane-phase1.md` and `docs/program-management/initiatives/sdk/client-sdk-architecture.md` reflect the latest decisions (EverCrypt/HACL\* cryptographic policy, FIPS considerations, and federation requirements).
2. The F\*/Rust/TypeScript modules affected by the sprint can be built and tested on the main branch, with no unresolved blocker issues (check Zulip/Issue tracker).
3. The generation procedures for dependent artefacts (WASM, npm/crates packages, OpenAPI schemas) are documented in `docs/` or `scripts/`, and `nix flake check` currently passes.
4. Security and product reviewers (security architect / product owner) have approved the Definition of Ready checklist before kickoff.

## 3. Planned Sprints and Deliverables (Dependency Order)

### Sprint A — Verified Core Extraction & WASM Foundation

Current status (2026-05-12):

- backend-side extraction / packaging baseline is present
- sibling SDK repository now consumes the resulting verified-core artifact shape
- remaining work is publication custody and final released-package rollout, not initial scaffolding

#### Definition of Ready

- The list and dependency graph of F\* modules to include in Verified Core are documented in `docs/specs/verified-core-wasm.md`, and `fstar --verify_all` passes locally.
- A scaffold for `scripts/extraction/run_verified_core_lowstar.sh` exists, and the source retrieval path for EverCrypt/HACL\* has been confirmed from `nix develop`.
- `docs/program-management/initiatives/sdk/sdk-repository-plan.md` contains the proposed SDK repository structure (fetch procedure, CI policy).
- The SDK CI policy is documented in `docs/program-management/initiatives/sdk/sdk-ci-plan.md`.
- Detailed SDK implementation steps are documented in `docs/program-management/initiatives/sdk/sdk-implementation-guide.md`.

**Goal**: Extract F\* Verified Core as wasm32-wasi and provide signed artefacts.

Scope:

- Organize F\* modules (PKCE, DPoP, nonce/state, JWK/JWT verification, request normalization).
- KaRaMeL → C → wasm32-wasi build pipeline (`scripts/extraction/run_verified_core_lowstar.sh` + `scripts/extraction/package_verified_core.sh`).
  - Current state: the packaging script places `verified_core.wasm` / `*.sha256` / `*.sri` / `manifest.json` in `artifacts/verified-core/`.
  - Next stage: add WASM artefact signing (Ed25519), SBOM generation, C ABI (thin wrapper), and smoke tests.
- Document the policy of managing Verified Core artefacts in this repository and moving upper layers (Runtime Adapter / Domain SDK) into the dedicated `aegaeon-sdk` repository.
- Reflect the three-layer architecture (Core Loader → Runtime Adapter → Domain SDK) and repository separation rules in `docs/program-management/initiatives/sdk/client-sdk-architecture.md`.
- Implement `scripts/extraction/run_verified_core_lowstar.sh` and automate generation through `.krml` for the PKCE/DPoP/JWT modules.

DoD:

1. `scripts/extraction/package_verified_core.sh` passes in the `nix develop` environment, and artefacts include hashes/manifests.
2. Rust: `cargo test -p aegaeon-core` (Rust FFI smoke) passes. TypeScript: WASM loading smoke tests pass in the SDK repository (for example, `pnpm test --filter @aegaeon/verified-core`).
3. Build procedures, signature/SBOM policy, and repository separation are added to `docs/program-management/initiatives/sdk/client-sdk-architecture.md` and `docs/specs/verified-core-wasm.md`.
4. Artefacts (WASM, hash manifest, sig) are stored in `artifacts/verified-core/`, and fetch procedures are provided for the SDK repository (for example, `pnpm run fetch-core`).

> **Current state (2026-02-17)**
> WASM extraction pipeline functional: `package_verified_core.sh` generates `verified_core.wasm` + hash/manifest in `artifacts/verified-core/`.
> Phase 9 Sprint A in progress:
>
> - C ABI thin wrapper (`verified_core_shim.c`) under implementation — defines FFI entry points for KaRaMeL output.
> - WASM smoke tests under development — PKCE challenge generate/verify and DPoP header generation round trips.
> - Artifact manifest (`manifest.json`) complete; signing flow under development — Ed25519 signatures + SBOM generation.
> - Remaining tasks: decide how to resolve Low\* Warning 15, confirm Token/PkJWT module extraction, add Rust/TypeScript smoke tests, and establish signing/SBOM/delivery flows.

### Sprint B — Runtime Adapters (TS/Rust)

Current status (2026-05-12):

- sibling SDK repository now carries active `runtime-node` / `runtime-web` packages and hosted
  browser lanes
- remaining work is package publication, provenance/custody promotion, and post-TypeScript
  language rollout

#### Definition of Ready

- Sprint A artefacts (`verified_core.wasm` + hash/manifest; signatures/SBOM to follow) are committed to `artifacts/verified-core/`, and verification instructions exist.
- Readiness of npm/crates publishing tokens has been confirmed in the TypeScript/Rust repositories, and publish flows to the internal registry / crates.io are established.
- Example API specifications for Web/Node/Rust are reflected in `docs/program-management/initiatives/sdk/client-sdk-architecture.md`, and security review (CSP, SecureContext assumptions) is complete.

**Goal**: Provide thin TypeScript (Web/Node) and Rust FFI adapters that call WASM Core.

Scope:

- `@aegaeon/verified-core` package: WASM loader, JSON Schema Validation, and both Web/Node support.
- `aegaeon-core` Rust crate: `no_std` support and `zeroize`-based secret management.
- Unify SecureContext checks, SRI/integrity verification, and error propagation (`Result`, `ErrorCode`).
- Browser/E2E smoke: PKCE challenge generation → verification, DPoP header generation, and JWK signature verification round trips.

DoD:

1. TypeScript packages in the SDK repository can be published to the npm private registry (`pnpm publish --dry-run` passes).
2. The Rust crate passes `cargo publish --dry-run` and clears `cargo audit`.
3. Runtime adapter APIs are documented in `docs/program-management/initiatives/sdk/client-sdk-architecture.md` and the API Reference (README).
4. Browser (Playwright), Node (Vitest), and Rust (unit test) CI jobs pass.

### Sprint C — Management API Client SDK

Current status (2026-05-12):

- sibling SDK repository now carries an active alpha `@aegaeon/management-client`
- sibling admin-console repository now consumes that package as its only SDK dependency and audits
  the boundary fail-closed
- remaining work is publication hardening, not first implementation

#### Definition of Ready

- The OpenAPI v1 schema (`generated/openapi/aegaeon-management-api.v1.json`) is current, and product/security have approved the version bump policy.
- Session management and CSRF policies are defined in `docs/specs/management-plane-phase1.md`, and the backend implementation provides at least API stubs.
- The management UI repository has feature flags / DI structures for incorporating the SDK beta, and joint development arrangements are in place.

**Goal**: Provide the REST client (`@aegaeon/management-client`) used by the management UI.

Scope:

- Type generation from OpenAPI (management API v1) + runtime validation (`zod` or `valibot`).
- Shared helpers for CSRF tokens, Origin checks, and teamId injection.
- Server-side cookie session integration (SameSite=Lax, double-submit token).
- `ManagementSession` wrapper and rotation support.
- Error handling (`errorCode`, retry policy) and audit log integration.

DoD:

1. `pnpm lint && pnpm test` passes for generated code + handlers in the SDK repository.
2. End-to-end smoke tests in `examples/management-console` (mock server) run in CI.
3. The README documents integration steps (Bootstrapping → Login → API calls).
4. Configuration flags usable in both OSS and Enterprise are documented.

### Sprint D — SPA / Issuer SDK

Current status (2026-05-12):

- sibling SDK repository now carries an active alpha `@aegaeon/issuer-spa`
- local mock-upstream, local Aegaeon-provider, Dex, Keycloak, and optional managed-provider lanes
  are represented in the current repository/workflow layout
- remaining work is hosted managed-provider evidence, released wording activation, and publication

#### Definition of Ready

- The Web Adapter provided in Sprint B passes Playwright smoke tests, and error patterns under CSP/Trusted Types assumptions have been identified.
- SPA requirements (authentication UX, session persistence, DPoP header generation) are documented in `docs/program-management/initiatives/sdk/client-sdk-architecture.md` and agreed with the UI team.
- An E2E mock environment for the management plane `/authorize` → `/token` flow is running and available to the SDK.

**Goal**: Build an SPA Auth client (`@aegaeon/issuer-spa`) on Verified Core.

Scope:

- Provide PKCE/DPoP/State/Nonce issuance and verification through Core.
- Redirect handling, session storage (Web Crypto + Credential Management API).
- Error boundaries and hooks/components designed for CSP/Trusted Types.
- Example: Next.js/React integration sample.

DoD:

1. The Auth Code flow round trip passes browser E2E (Playwright) tests.
2. Complete tests for token/refresh handling and storage fallback (guarded IndexedDB/localStorage).
3. Update the relevant section of `docs/program-management/initiatives/sdk/client-sdk-architecture.md`.

### Sprint E — RP Core SDK & Federation Wiring

Current status (2026-05-12):

- sibling SDK repository now carries an active alpha `@aegaeon/rp-core`
- higher-level federated login orchestration exists at the package/layout level
- remaining work is promotion from alpha/runtime-readiness into published/released status, plus
  any additional backend KMS/HSM integration needed for the broader management-platform story

#### Definition of Ready

- External IdP (such as Google Workspace) test accounts and a mock IdP are ready, and JWKS caching / attribute mapping specifications are finalized in `docs/program-management/initiatives/sdk/client-sdk-architecture.md`.
- Draft DB Schema / Migration for federation configuration (the `federation` block) has been added to `docs/specs/management-plane-phase1.md`.
- The security team has prepared a draft Federation Threat Model (STRIDE), and mitigations for the main risks have been agreed.

**Goal**: Provide `@aegaeon/rp-core` and server configuration to support RP flows with external IdPs (for example, Google Workplace).

Scope:

- Authorization Code + PKCE, ID Token/JWK verification, attribute mapping DSL (WASM sandbox).
- Management API CRUD for the `federation` block and audit event support.
- Update documentation for the server-side RP mode path and monitoring (metrics/logging).
- Example integration test with mock IdP (conformance-like harness).

DoD:

1. Automated tests pass from federation configuration change → RP flow → session issuance.
2. Configuration forms work in the Management UI, and audit events are recorded.
3. Update the relevant rows in `spec/compliance-matrix.yaml` from `planned` → `verified`.

## 4. Definition of Done (Cross-Cutting)

Conditions that every sprint must meet:

1. `nix flake check --print-build-logs` passes.
2. Tests/linters pass (Rust: `cargo test`, `cargo clippy`; TypeScript: `pnpm lint`, `pnpm test` in the SDK repository).
3. Documentation updates: reflect status in `docs/program-management/initiatives/sdk/client-sdk-architecture.md` and `docs/program-management/roadmaps/...`.
4. SBOM and signed artefacts (`cosign`, `sbom.json`) are generated and stored in `artifacts/`.
5. Security posture: introduce no new fail-open behavior; handle secrets through SecureContext / keystore.

## 5. Risks and Mitigations

| Risk | Mitigation |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Verified Core WASM does not work in SPAs | Implement smoke tests early for both Web and Node. |
| Frontend work starts late | After Sprint B, the management UI team incorporates the alpha `@aegaeon/management-client` and develops in parallel. |
| Differences in third-party IdP specifications | Add nightly tests with a mock IdP + real IdPs (Google/TBD). |
| FIPS requirements arise | Design a cryptographic provider abstraction in Sprint B. Record FIPS as future work as described in section 8.1 of `docs/program-management/initiatives/sdk/client-sdk-architecture.md`. |

## 6. References

- `docs/program-management/initiatives/sdk/client-sdk-architecture.md`
- `docs/specs/management-plane-phase1.md`
- `docs/program-management/roadmaps/active/current-execution-plan.md`
- `spec/compliance-matrix.yaml`

This record preserves the history of initial SDK / UI delivery; current remaining work is consolidated in
`docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`.
