# Runtime Adapter Design (Draft)

Last updated: 2026-07-07

Status: draft

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-03-08):** Adapter-level support for `RS256` / `ES256` describes runtime capability and portability goals. It must not be read as expanding the current strong-constraint claim, which still follows the verified allowlist unless an explicit boundary-closure exception is documented.

This memo captures the executable design for the Runtime Adapter layer that sits on top of the Verified Core
WASM artefact. It is the primary blueprint for **Sprint A / Step 2** and is referenced by the implementation
plan. The **server runtime links the native C output directly**; this document focuses on the **client-side
WASM adapters**. Use `docs/program-management/initiatives/sdk/sdk-implementation-guide.md` for SDK implementation sequencing.

## 1. Goals & Constraints

- Provide thin adapters for Web (browser / edge runtimes) and Node.js that expose the Verified Core entry
  points with type-safe inputs/outputs and deterministic error handling.
- Do **not** re-implement protocol logic; all security decisions remain inside the Verified Core WASM.
- Enforce supply-chain guarantees established in Step 1:
  - Ed25519 signature + SHA-256/SHA-512 hash checks (reuse `scripts/sdk/fetch_core_artifact.js` logic).
  - For browsers, require SecureContext + Subresource Integrity (SRI) metadata.
- Ensure adapters can be moved to the dedicated SDK repository (`aegaeon-sdk`) without changes.
- Keep module boundaries small so that Domain SDKs (`@aegaeon/management-client`, `@aegaeon/issuer-spa`,
  `@aegaeon/rp-core`) depend only on the adapters, not directly on the WASM loader.

## 2. Shared Runtime Model

### 2.1 Core Bindings Shape

All runtimes expose a `RuntimeHandle` with the same shape:

```ts
interface RuntimeHandle {
  /** Release WASM resources (idempotent). */
  dispose(): void;

  /** Generate a PKCE verifier/challenge pair in constant time. */
  pkceGenerate(opts: { verifierLength?: number }): Promise<{ verifier: string; challenge: string }>;

  /** Verify PKCE pair; returns `true` only on success. */
  pkceVerify(input: { verifier: string; challenge: string }): Promise<boolean>;

  /** Validate a DPoP proof and return replay ticket data for the host store. */
  dpopVerify(input: {
    proof: string;
    method: string;
    htu: string;
    namespace: string;
    nowSeconds: number | bigint;
    accessToken?: string;
    maxAgeSeconds?: number;
    maxFutureSkewSeconds?: number;
    requireAccessTokenHash?: boolean;
    requireJti?: boolean;
    allowedAlgorithms?: ("ES256" | "RS256" | "EdDSA")[];
  }): Promise<{
    jktHash: Uint8Array;
    replayKeyHash: Uint8Array;
    jtiHash?: Uint8Array;
    issuedAtSeconds: number;
    hasAccessTokenHash: boolean;
  }>;

  /** Verify JWT/JWK combinations (used by RP / management). */
  jwtVerify(input: {
    token: string;
    publicKey: Uint8Array;
    publicKeyFormat: "JWK_JSON_UTF8" | "SPKI_DER" | "RAW_EC_P256_UNCOMPRESSED";
    nowSeconds?: number | bigint;
    issuer?: string;
    audience?: string[];
    allowedAlgorithms?: ("ES256" | "RS256" | "EdDSA")[];
    requireExp?: boolean;
    requireIat?: boolean;
    requireNbf?: boolean;
  }): Promise<{
    header: unknown;
    claims: unknown;
    payloadHash: Uint8Array;
    kidHash?: Uint8Array;
  }>;
}
```

> _Note_: The exact function list will be aligned with the Verified Core exports delivered in Sprint A.
> Placeholders above reflect the target scope (PKCE/DPoP/JWT). All functions **must return promises** so
> adapters can support cancellation through `AbortSignal`.

### 2.2 Error Surface

- WASM returns structuredエラーコード (`VerifiedCoreStatusCode`)。アダプタはこれを `CoreError` にマッピングし、protocol-aware なコードを公開する:

```ts
class CoreError extends Error {
  readonly code:
    | "CORE_FAILURE"
    | "NOT_IMPLEMENTED"
    | "DPoP_INVALID_ARGUMENT"
    | "DPoP_INVALID_SIGNATURE"
    | "DPoP_INVALID_CLAIMS"
    | "DPoP_REPLAY"
    | "DPoP_REPLAY_STORE_UNAVAILABLE"
    | "DPoP_UNSUPPORTED_ALGORITHM"
    | "DPoP_INTERNAL"
    | "JWT_INVALID_TOKEN"
    | "JWT_INVALID_ARGUMENT"
    | "JWT_INVALID_SIGNATURE"
    | "JWT_INVALID_CLAIMS"
    | "JWT_UNSUPPORTED_ALGORITHM"
    | "JWT_INTERNAL"
    | "JWT_INVALID_FORMAT";
  readonly detail?: unknown;
}
```

- Transport / loader failures are surfaced as `LoaderError` with codes:
  - `MANIFEST_MISSING`, `HASH_MISMATCH`, `SIGNATURE_INVALID`
  - `UNSUPPORTED_ENVIRONMENT` (e.g., not a SecureContext)
  - `ABORTED` (AbortSignal triggered)

Errors are never swallowed; callers must decide whether to retry or fail the user journey.

### 2.3 Memory Interaction

- WASM allocators return pointers + lengths. Adapters use a unified helper:

```ts
interface WasiBindings {
  memory: WebAssembly.Memory;
  alloc(size: number): number;
  dealloc(ptr: number, size: number): void;
}
```

- `runtime-web` and `runtime-node` each implement:
  - `writeUtf8(ptr, string)` / `readUtf8(ptr, len)`
  - `writeBytes(ptr, Uint8Array)` / `readBytes`

All buffers are zeroed (via WASM function) after use to avoid leaking secrets.

## 3. `@aegaeon/runtime-web`

### 3.1 Public API

```ts
export interface InitOptions {
  fetch?: typeof fetch;
  manifestUrl: string;
  wasmUrl: string;
  signatureUrl?: string;
  publicKeyPem?: string; // optional; if omitted, rely on pre-verified fetch-core step
  integrity?: string;    // SRI string, e.g. "sha256-..."
  abortSignal?: AbortSignal;
  cache?: Cache | false; // default: use Cache API for manifest
}

export interface RuntimeWeb {
  readonly manifest: VerifiedCoreManifest;
  readonly handle: RuntimeHandle;
}

export async function initRuntimeWeb(options: InitOptions): Promise<RuntimeWeb>;
```

- `manifestUrl` / `wasmUrl` default to `/verified-core/manifest.json` etc., but callers can override (CDN / release asset).
- SecureContext guard: throw `LoaderError("UNSUPPORTED_ENVIRONMENT")` when `typeof window === "undefined"` or
  `window.isSecureContext === false`.
- Fetch logic:
  - Use `fetch` streaming + `WebAssembly.instantiateStreaming` when possible.
  - If SRI is provided, set the `integrity` attribute (callers must also set it on `<script type="module">` when bundling).
- Signature verification paths:
  - If `publicKeyPem` is provided, run `SubtleCrypto.verify` (Ed25519; Web Crypto in secure contexts).
  - If not provided, assume artefact was verified offline via `fetch_core_artifact.js` (documented requirement).
- Cache strategy: optional `Cache` instance to store manifest and WASM; default is `cache = false` to avoid storing secrets by default.
  When caching is enabled, set `Cache-Control: immutable` semantics.
- Abort handling: wrap all fetch and instantiate calls to respect `AbortSignal`. If aborted, throw `LoaderError("ABORTED")`.

### 3.2 Internal Structure

```text
packages/runtime-web/
  src/
    init.ts              # implements initRuntimeWeb
    loader.ts            # fetch + verify + instantiate
    bindings.ts          # WASM memory helpers
    errors.ts            # CoreError / LoaderError definitions
    schema.ts            # zod schemas for inputs/outputs
```

- Input/Output validation uses `zod`. Example: `PkceGenerateInputSchema`, `DpopVerifyInputSchema`.
- Align logging with SDK policy: no `console.log`; provide optional hook `onEvent?(event: CoreEvent)` for structured logs.
- Provide `dispose()` that calls into WASM deallocator (`vc_free_slice`) and drops references to `WebAssembly.Instance`.

### 3.3 Testing

- Vitest unit tests mocking `fetch` and manual byte arrays (manifest mismatch, signature invalid, abort).
- Playwright E2E:
  - Loads sample page under `https://localhost` (SecureContext) and runs `initRuntimeWeb`.
  - Negative test: run under `http://localhost` to assert `UNSUPPORTED_ENVIRONMENT`.
- Additional regression: inject tampered WASM and ensure loader rejects before instantiate.

#### Execution Order / Dependencies

1. Ensure Phase 1 Verified Core loader is complete and exposes `RuntimeHandle`.
2. Implement memory bindings + loader helpers (`loader.ts`, `bindings.ts`).
3. Build Vitest unit tests (mock fetch) → integrate with `pnpm test`.
4. Add Playwright smoke tests once Vitest passes.
5. Update docs (`../../../aegaeon-sdk/README.md`, adapter README).
6. Gate via CI (`aegaeon-sdk/.github/workflows/verify-core.yml`).

## 4. `@aegaeon/runtime-node`

### 4.1 Public API

```ts
export interface InitNodeOptions {
  wasmPath?: string;
  manifestPath?: string;
  signaturePath?: string;
  publicKeyPem?: string;
  disableSignatureCheck?: boolean; // only for development; default false
  abortSignal?: AbortSignal;
  wasi?: { args?: string[]; env?: Record<string, string>; preopens?: Record<string, string> };
  fs?: typeof import("node:fs/promises"); // dependency injection for tests
}

export interface RuntimeNode {
  readonly manifest: VerifiedCoreManifest;
  readonly handle: RuntimeHandle;
}

export async function initRuntimeNode(options?: InitNodeOptions): Promise<RuntimeNode>;
```

- Default paths (relative to process CWD):
  - `wasmPath`: `process.env.AEG_CORE_WASM_PATH ?? "artifacts/verified-core/verified_core.wasm"`
  - `manifestPath`: `process.env.AEG_CORE_MANIFEST_PATH ?? "artifacts/verified-core/manifest.json"`
  - `signaturePath`: `process.env.AEG_CORE_SIGNATURE_PATH ?? "artifacts/verified-core/verified_core.wasm.sig"`
- Signature verification:
  - Always required unless `disableSignatureCheck === true`. When disabled, log structured warning (`severity=warn`, `code="SIGNATURE_DISABLED"`).
  - Use Node `crypto.verify` (Ed25519). Public key can be provided via `publicKeyPem` option or `AEG_CORE_PUBLIC_KEY`.
- Instantiation strategy:
  - Use `WebAssembly.instantiate` with `fs.readFile`.
  - WASI support: if Verified Core exposes WASI imports, create minimal WASI instance via `@wasmer/wasi` (configured through `options.wasi`).
- Abort handling: wrap file reads and instantiation in abort-aware helpers:

```ts
await withAbort(options.abortSignal, () => fs.readFile(wasmPath));
```

### 4.2 Optional features

#### Execution Order / Dependencies

1. Consume Phase 1 loader artefacts (`initCore`, shared types).
2. Implement file IO + signature verification (Node `crypto`).
3. Add WASI support (optional, behind feature flag).
4. Create Vitest tests for happy path / hash mismatch / signature mismatch / env overrides.
5. Document environment variables (`AEG_CORE_*`) and update security guidance.
6. Hook tests into `pnpm test` / CI.

- `edge` builds (Cloudflare Workers, Deno, Bun) will reuse `runtime-web` entry point because those environments expose Web streams.
- Provide experimental `initRuntimeNodeRaw` that accepts pre-loaded buffers (used by tests to bypass filesystem).

### 4.3 Testing

- Vitest unit tests:
  - fixture manifest/wasm/signature under `aegaeon-sdk/test-fixtures/`.
  - tampered wasm → verify that `LoaderError("HASH_MISMATCH")` is thrown.
  - environment overrides (`AEG_CORE_WASM_PATH`) and `disableSignatureCheck`.
- Integration test using `wasmtime` (optional):
  - Runs a real Verified Core wasm (once available) and executes PKCE/DPoP functions.

## 5. Shared Utilities

- `packages/runtime-shared/` (optional workspace) containing:
  - Manifest types (`VerifiedCoreManifest`).
  - Error classes.
  - Input/output zod schemas.
  - Buffer helpers (encode/decode).
  - Logging/event emitter interface.
- `scripts/sdk/fetch_core_artifact.js` remains the CLI to pre-fetch artefacts; runtime adapters should reuse the helper functions (`computeIntegrity`, `verifySignature`) by extracting them into TypeScript modules when the code migrates to the SDK repo.

## 6. Testing Matrix & CI Hooks

| Scenario | Runtime | Command |
|----------|---------|---------|
| Unit tests | Node 22+ | `pnpm test --filter runtime-*` |
| Type checks | Node 22+ | `pnpm run lint` (tsc + eslint) |
| Browser smoke | Chromium (Playwright) | `pnpm run test:e2e --filter runtime-web` |
| WASM integration | Node 22+ | `pnpm run test:wasm` (when Verified Core exports ready) |
| Supply-chain | Node 22+ | `pnpm run verify-core -- --version <tag>` (calls fetch-core + manifest check) |

CI should run Node 22 LTS and optional Node 20 to check compatibility. For browsers, limit to Chromium headless to keep jobs fast; expand to WebKit/Firefox later if needed.

## 7. Follow-up Tasks

1. Scaffold `packages/runtime-web` and `packages/runtime-node` with the structure above.
2. Extract shared helpers (manifest parsing, error types, buffer utilities) into `packages/runtime-shared`.
3. Implement Vitest test suites with fixtures under `aegaeon-sdk/test-fixtures/verified-core/`.
4. Prepare Playwright harness for SecureContext detection (use self-signed cert via `mkcert` in dev).
5. Update `docs/program-management/initiatives/sdk/sdk-implementation-guide.md` Phase 2 once APIs harden.
6. Coordinate with Verified Core team to confirm exported function names/ABI before finalizing TypeScript bindings.

This document should be updated as implementation progresses (record deviations, additional constraints, or new APIs). Once the adapters are feature-complete, migrate content into the SDK repository documentation.
