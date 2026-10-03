# Aegaeon Client & Federation Architecture (Draft)

Last updated: 2026-07-08

Status: draft

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-07-08):** Draft client architecture; it does not activate released client wording or formal claim scope.

## Status

- **Author**: Codex (assistant)
- **Date**: 2026-03-10
- **Version**: 0.2 (draft)
- **Scope**: Includes Verified Core-based client SDKs, WASM compilation, and federation RP functionality.
  The server implementation **natively links the same C code extracted by KaRaMeL**; WASM is exclusively for client distribution.
- **Security posture**: Confidentiality and integrity take priority. Fail-closed behavior and verifiability are prerequisites.
- **Claim boundary**: This draft describes future client-side packaging and runtime surfaces. It must not be read as a released client-product claim; use `../../../product-positioning.md` and `../../../verification/claims/assurance-case/README.md` for the current claim boundary.
- **Implementation snapshot (2026-03-13)**: this repository now contains a Node reference adapter at `scripts/sdk/runtime_node_reference.ts`, a browser reference adapter at `scripts/sdk/runtime_web_reference.ts`, focused Node/WebCrypto tests at `tests/verified_core_wasm/runtime_{node,web}_reference_test.ts`, and a browser smoke harness at `tests/verified_core_wasm/runtime_web_reference.html`. The current client-core baseline supports PKCE plus JWT / DPoP compact and claims flows; EdDSA remains inside the current WASM verification path, while `RS256` / `ES256` are presently handled by adapter-side preverification before Verified Core enforces claims / time / replay semantics. The current SDK scaffold also emits alpha `@aegaeon/management-client`, `@aegaeon/issuer-spa`, and `@aegaeon/rp-core` packages: `management-client` covers selected OpenAPI-backed control-plane operations plus session / CSRF / Origin / `teamId` helpers, including oauth-profile CRUD, connection CRUD, environment/team-audit JSON/CSV export, and query-string-backed audit filters, `issuer-spa` now covers browser transaction persistence, browser-native session persistence, discovery-driven callback completion, and logout orchestration, and `rp-core` now covers both low-level Authorization Code + PKCE helpers and higher-level federated-login orchestration via in-memory transaction/session stores plus issuer metadata / discovery helpers and `startFederatedLogin` / `finishFederatedLogin`. The sibling `../aegaeon-admin-console` now uses `@aegaeon/management-client` as its only SDK dependency, emits `.artifacts/admin-sdk/admin-sdk-evidence.json` against `spec/admin-sdk-evidence.schema.json`, and now has both a compose-backed local browser lane and a hosted `Admin Console Stack E2E / Stack E2E` workflow that exercise bootstrap, login, dashboard rendering, create team/tenant/environment, list/create/update/delete oauth profiles, list/create/update/delete connections, update environment policy, create/activate configuration version, rotate/activate-next/revoke signing key, update key store, list/block/unblock users, invalidate user sessions, revoke user refresh tokens, environment/team audit reads, query-string-backed audit filtering, environment/team-audit JSON/CSV export, audit-event detail, create/update/delete client, issue/revoke/revoke-all client secrets, and logout against a sibling `../aegaeon` stack, while uploading admin evidence and Playwright diagnostics as CI artifacts; the hosted workflow name, lane name, and artifact names are now source-managed in `../aegaeon-admin-console/spec/workflow-inventory.current.json` and audited fail-closed by the console repo itself. Published `@aegaeon/runtime-node` / `@aegaeon/runtime-web` packages remain future deliverables in the separate SDK repository.

## 1. Purpose and Background

- Aegaeon formally verifies the VerifiedReqs scope of its OAuth/OIDC server implementation under qualified assumptions (F\*/Low\*/KaRaMeL; see `../../../verification/claims/assurance-case/claim-definition.md` for the boundary), providing high assurance for the data plane.
- As a next step, Aegaeon will provide secure **client SDKs** and add RP functionality for **federation with existing IdPs (for example, Google Workspace)**.
- Design goals:
  - Share Verified Core as WASM, establish the TypeScript SDK first, then use it as the SDK foundation for language expansion in the order **Rust → Ruby → PHP**.
  - Manage federation configuration per Environment on the server and integrate securely with external IdPs.
  - Handle secrets, sessions, and attribute transformations within minimal boundaries and always fail closed.

## 2. Architecture

> See `sdk-repository-plan.md` for the detailed repository layout and CI flow.
> See `sdk-implementation-guide.md` for implementation steps.

### 2.1 Verified Core (WASM)

- **Implementation**: F\* → KaRaMeL → C → wasm32-wasi.
- **Responsibilities**:
  - PKCE (S256), DPoP, State/Nonce normalization, and Redirect URI normalization.
  - Authorization Code flow verification (at_hash, c_hash, nonce).
  - JWK/JWT verification (signature, iss/aud/exp) and replay prevention.
  - Implement state machines as pure functions, with only serialized buffers for input/output.
- **Constraints**:
  - No dynamic memory allocation (fixed arenas or caller-provided buffers).
  - `wasi_snapshot_preview1` only. No I/O capabilities.
  - Errors only through `Result<Success, ErrorCode>` (for example, `INVALID_TOKEN`, `PKCE_MISMATCH`, `SECURITY_LEDGER_CONFLICT`).

### 2.2 Runtime Adapters

| Layer | npm/crate Name | Role | Main Constraints |
|----|-------------|------|-----------|
| **Core Loader** | `@aegaeon/verified-core` / `aegaeon-core` | Fetch WASM artefacts, verify signatures, and abstract core entry points. | Web: SecureContext + SRI + streaming instantiation. Node/Rust: load a selected `wasmtime` / `wasmer` / `wasm3` backend after Ed25519 signature verification. |
| **Runtime Adapter** | `@aegaeon/runtime-web` / `@aegaeon/runtime-node` | Thin layer that makes the binary boundary with Core type-safe. Input/output validation, buffer management, and synchronization waits. | No WASM memory reallocation. All APIs support cancellation with `AbortSignal`. |
| **Domain SDK** | `@aegaeon/management-client`, `@aegaeon/issuer-spa`, `@aegaeon/rp-core` | Business logic for the management API, Issuer SPA, and external RP. | Delegate protocol state machines to Core. Implement UI/HTTP here. |
| **Integration Helpers** | (Separate repository: `@aegaeon/next`, `@aegaeon/remix`) | Framework integration, DI, and React hooks. | Optional. Wrappers around Core/API SDKs only. |

- Layered distribution uses three layers as the baseline, or four with Integration Helpers. WASM Core is always the lowest layer.
- Adapters keep a thin boundary with WASM and do not reimplement state machines or signature verification.
- Package boundary normalization:
  - `@aegaeon/management-client` is the canonical management-plane package for admin UIs and automation.
  - `@aegaeon/issuer-spa` and `@aegaeon/rp-core` are the canonical OIDC client / RP packages.
  - Admin consoles should depend on `@aegaeon/management-client` only unless the management-plane login flow itself moves onto OIDC.
  - The sibling `../aegaeon-admin-console` now source-manages that rule in `spec/admin-sdk-boundary.current.json` and audits it with `pnpm test:repo`.
  - The sibling `../aegaeon-admin-console` also source-manages the current management-auth posture in `spec/admin-auth-boundary.current.json`: admin login stays on the cookie-based management-session flow, and app sources must not hand-roll cookie / CSRF / bearer-token auth logic.
- Initialization flow:
  1. Core Loader fetches `verified_core.wasm` + `manifest.json` and verifies signatures/SRI/hashes.
  2. Runtime Adapter validates input/output with JSON Schema (`zod` / `serde_with`).
  3. Domain SDK implements HTTP/Storage/UI logic.

### 2.2.2 Post-TypeScript language rollout

Post-TypeScript language expansion is planned in this order:

1. **Rust**
2. **Ruby**
3. **PHP**

- Rust comes first because it is the closest follow-on to the current WASM/runtime boundary and release-attestation flow.
- Ruby starts only after the Rust package boundary and release discipline are stable.
- PHP starts only after the Ruby package boundary and release discipline are stable.
- Adding a new language track does **not** widen the current formal claim boundary by itself; any claim change still requires explicit evidence and policy promotion.

### 2.3 SDK Layers

1. `@aegaeon/verified-core` (WASM + TypeScript bindings)
   - WASM module and `initCore()` helper.
   - Validate Core input/output with JSON Schema.
   - Include the following in `packages/verified-core/`:
     - `dist/verified_core.wasm` (covered by SRI)
     - `dist/verified_core.manifest.json` (sha256, sha512, size, build number)
     - `dist/verified_core.wasm.sig` (Ed25519)
     - `loader.ts` (signature verification and the `WebAssembly.instantiateStreaming` call)
   - Check the manifest in a postinstall hook during `npm install`; treat hash mismatches as fatal errors when `NODE_ENV=production`.
2. `@aegaeon/management-client`
   - Current alpha: a control-plane package covering the current admin-console surface of the Aegaeon management API.
   - Current helpers automatically inject CSRF / Origin / teamId and provide an in-memory session / cookie surface usable in both Node and browsers.
   - The current alpha combines surfaces equivalent to `core` / `auth` in one package; React hooks are not implemented yet.
   - Future: add `react/` (hooks/UI integration), E2EE options (environment snapshots, audit logs), and broader OpenAPI codegen.
3. `@aegaeon/issuer-spa`
   - Delegate authentication UI, session management, and PKCE/DPoP to Core.
   - Enforce XSS protections (CSP, Trusted Types).
   - Current alpha: provides browser transaction/session stores and callback-driven completion.
   - Build on `runtime-web`; support frameworks such as Next.js/Remix through Integration Helpers.
4. `@aegaeon/rp-core` (for external IdP RP use)
   - Delegate Authorization Code + PKCE exchange and ID Token/JWK verification to Core.
   - Support an attribute mapping DSL and SAML/OIDC event handling.
   - Current alpha: provides in-memory transaction/session stores and `startFederatedLogin` / `finishFederatedLogin` in addition to low-level PKCE/callback helpers.
   - Support live reload of federation configuration (Management API Webhook → SDK Cache invalidation).

Post-TypeScript language expansion is planned in this order:

- **Rust**: `aegaeon-management` (OpenAPI wrapper) and `aegaeon-core` (WASM FFI)
- **Ruby**: wrappers distributed through RubyGems
- **PHP**: wrappers distributed through Composer / Packagist

### 2.4 Package Layout and Build Strategy

```text
packages/
  verified-core/          # npm foundation package (WASM + loader)
  runtime-web/            # Wraps Core Loader for browsers
  runtime-node/           # For Node/Edge (Deno, Bun)
  management-client/      # Management API SDK (core/auth/react)
  issuer-spa/             # Authentication UI SDK
  rp-core/                # Federation RP SDK
  next/                   # Next.js helpers (optional)
crates/
  aegaeon-core/           # Rust Loader + FFI
  aegaeon-management/     # OpenAPI client
gems/                     # Ruby language track (planned)
php/                      # PHP language track (planned)
```

- Use `pnpm` workspaces. Build all packages with `pnpm recursive run build`.
- Do not track WASM artefacts in git; `pnpm run fetch-core` fetches them from `artifacts/verified-core/` and places them in `dist/`.
  - Reference: `scripts/sdk/fetch_core_artifact.js` in this repository is the CLI scaffold (Node 22+ / Ed25519 verification).
- CI:
  - Step1: run `scripts/extraction/package_verified_core.sh` to generate artefacts.
  - Step2: `pnpm run fetch-core && pnpm run lint && pnpm run test`.
  - Step3: run dry-run checks with `pnpm publish --dry-run` / `cargo publish --dry-run`.
- Browser bundle: load `verified_core.wasm` via dynamic import (ESM) and disable `asset/inline` in `vite/webpack` to preserve integrity checks.
- Node: `runtime-node` reads WASM through `fs/promises`, verifies the hash against the manifest, then calls `WebAssembly.instantiate`. Override with the `AEGAEON_CORE_WASM_PATH` environment variable (for tests).

### 2.5 Repository Split Policy

- **This repository (aegaeon)**: Verified Core (F*/C/WASM), `scripts/extraction/*`, `artifacts/verified-core/`, and core specification documents.
- **New repository (tentatively aegaeon-sdk)**: pnpm workspace containing upper layers such as `packages/` / `crates/`. Fetch Core artefacts from GitHub releases or internal S3 and synchronize them with `pnpm run fetch-core`.
- Core update flow:
  1. In this repository: `package_verified_core.sh` → artefact publication → release tag.
  2. The SDK repository reads the manifest and imports artefacts while verifying hashes/signatures (`pnpm update-core --version <tag>` is envisaged).
  3. SDK CI performs lint/test/publish.
- This split separates the Verified Core proof artefact lifecycle from frontend SDK distribution, clarifying the audit trail and supply-chain controls.

## 3. Federation (RP) Functionality

### 3.1 Environment Snapshot Extension

Add a `federation` block to `configurationDocument`:

```json
"federation": {
  "upstreamIssuer": "https://accounts.google.com",
  "clientId": "uuid",
  "redirectUri": "https://env.example/oauth2/callback",
  "jwksCache": {
    "jwksUri": "https://www.googleapis.com/oauth2/v3/certs",
    "maxAgeSeconds": 3600
  },
  "attributeMapping": [
    { "from": "google.groups", "to": "aegaeon.roles", "rule": "mapGroups" }
  ],
  "logout": {
    "backChannel": true,
    "sessionHintClaim": "sid"
  }
}
```

- Do not include secrets. Store only reference IDs for external IdP client secrets/private keys through the keystore.
- Make changes through Config Transaction and require audit logs.

### 3.2 Flow Overview

1. At Aegaeon `/authorize`, prompt=login ⇒ transition to RP mode.
2. Pass the `state`/`nonce`/PKCE generated by Verified Core to the external IdP.
3. Core verifies the code returned by the external IdP (PKCE, nonce, signature, alg).
4. Execute attribute mapping in a sandboxed DSL (WASM). Errors return `invalid_token`.
5. On success, issue a session within the Environment and record the `FEDERATION.LOGIN.SUCCEEDED.v1` audit event.

### 3.3 Security Controls

- External IdP JWK fetching: TLS pinning + ETag + max-age monitoring. On failure, use last-known-good + alerts.
- Attribute mapping: the DSL is declarative. Execute it in a WebAssembly sandbox with no network capabilities.
- Session integration: handle external IdP cookies only through the front channel, not on the server. Back-channel logout invalidates the session store through a webhook.
- Auditing: record successes/failures as `management.federation.*` / `security.federation.*` events. Include requestId/traceId.

## 4. Security Design

### 4.1 Fail-Closed Behavior and Duplicate Prevention

- Verified Core returns errors as explicit codes such as `SECURITY_LEDGER_CONFLICT`, `PKCE_MISMATCH`, and `TOKEN_VALIDATION_FAILED`.
- JavaScript/Rust propagates these to callers without wrapping them.
- The browser SDK prohibits operation outside HTTP (file://). The Node SDK allows keystore unpacking only when `NODE_ENV=production`.

### 4.2 Secret Management

- TypeScript: use Web Crypto API `CryptoKey`/`PasswordCredential`. Prohibit console.log.
- Rust: `secrecy::Secret` + `zeroize`. Zero on drop even on panic paths.
- Server: store external IdP client secrets in HSM/KMS (keystore). The Configuration Document contains reference IDs only.

### 4.3 WASM Distribution and Signatures

- Sign WASM binaries with Ed25519 and attach signature files to release artefacts.
- Require SRI (integrity) on `<script type="module">` for the browser version. Node/Rust versions must also pass signature verification before startup.
- Supply chain: attach an SBOM with `cosign attest --predicate sbom.json`.

### 4.4 Hardening

- Design the runtime assuming CSP (`default-src 'none'`, `script-src 'self' 'wasm-unsafe-eval'`) and Trusted Types.
- SDK fetches use `same-origin` or an explicit allowlist. XSRF protection: cookie + header double submit.
- Record all runtime exceptions as structured logs (`SECURITY.*`), excluding PII.

## 5. Testing and Verification

| Category | Coverage |
|------|------|
| F\* | RP flows, PKCE, nonce, DPoP, JWK signature verification, and attribute mapping DSL safety. |
| WASM | `wasm-bindgen-test` + fuzz (`cargo fuzz`). Side-channel detection with dudect. |
| SDK | CSP/XSS/Token leakage tests with Playwright (browser) / Vitest (Node). Prepare Rust harnesses with `cargo kani`. |
| Protocol | OIDC Conformance (RP), Google Workspace validation, and OIDF RP certification. |
| Audit | Document the STRIDE model and Red Team guidelines in docs/security. |

## 6. Deployment and Distribution

- npm: `@aegaeon/verified-core`, `@aegaeon/management-client`, `@aegaeon/issuer-spa`, `@aegaeon/rp-core`. SLSA Level 2 provenance.
- crates.io: `aegaeon-core` (WASM FFI), `aegaeon-management` (API client).
- RubyGems: Ruby wrappers (planned after Rust).
- Packagist / Composer: PHP wrappers (planned after Ruby).
- OSS and SaaS share the same codebase. Feature flags control functionality.
- Do not distribute WASM binaries through a CDN; provide signed tarballs. Browser SDKs must perform integrity checks.

## 7. Roadmap

1. Extend Verified Core F\* proofs and establish the WASM build pipeline (dudect, KaRaMeL extraction).
2. Implement TypeScript adapters and a secure initialization path.
3. Add federation configuration (the `federation` block) to Environment snapshots and support it in the Management API/UI.
4. Release SDKs (management/issuer/rp) incrementally, with RP E2E tests in real environments → beta → GA.
5. Expand beyond TypeScript in the order **Rust → Ruby → PHP**.
6. Conduct external audits (such as Cure53) and security reviews, with vulnerability assessment before release.

The management-plane follow-on work for these two deployment postures is tracked separately:

- primary-authority local IAM: `../../../specs/primary-authority-user-management.md`
- upstream-authority broker / downstream-IdP: `../../../specs/oidc-rp-brokering-spec.md`

## 8. Risks and Responses

| Risk | Mitigation |
|--------|--------|
| WASM binary tampering | Ed25519 signatures + SRI + signature verification in Node/Rust. |
| Incorrect attribute mapping implementation | Implement the DSL in Verified Core and execute it in a sandbox. Provide validation and dry-run functionality in the UI. |
| External IdP JWK changes | Monitor `jwksCache` expiration and consult last-known-good; fail closed + alert on anomalies. |
| Secret leakage during SDK use | Depend on SecureContext, use `secrecy::Secret`, prohibit logging, and zero on exceptions. |
| Supply-chain attacks | SBOM + sigstore/cosign + reproducible builds. |

### 8.1 FIPS Support Considerations (Future Work)

- At present (Phases 1–2), EverCrypt/HACL\* is the assumed cryptographic foundation; FIPS certification has not been obtained.
- If FIPS 140-3 certification becomes necessary as of 2026-xx, consider the following:
  1. Introduce a cryptographic provider abstraction layer and switch to the OpenSSL FIPS Provider or an AWS-LC FIPS build in FIPS mode.
  2. Implement self-tests (KAT), DRBG initialization, and disabling of prohibited algorithms when entering FIPS mode.
  3. Define how Verified Core (EverCrypt) coexists with FIPS mode, continuing to use the existing Verified Core in non-FIPS mode.
- Keep this policy synchronized with “Cryptography posture and future FIPS track” in the management-plane specification, and track it as future work in
  `../../roadmaps/future/future-projects.md`.
- Reassess these options in response to future requirements. At this stage, EverCrypt/HACL\* remains the baseline, and FIPS support is recorded only as a roadmap candidate.

---

This document is a draft and will be updated to align with subsequent specifications/implementations. Reviews take place in the security/architecture channel, and the version is finalized after approval.
