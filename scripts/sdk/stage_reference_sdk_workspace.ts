#!/usr/bin/env node
import { promises as fs } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..", "..");
const LICENSE_PATH = path.join(ROOT_DIR, "LICENSE");
const MANAGEMENT_CLIENT_INDEX_SOURCE = path.join(MODULE_DIR, "management_client_reference.ts");
const MANAGEMENT_CLIENT_TYPES_SOURCE = path.join(MODULE_DIR, "management_client_reference.d.ts");
const MANAGEMENT_CLIENT_README_SOURCE = path.join(MODULE_DIR, "management_client_reference_readme.txt");
const MANAGEMENT_CLIENT_TEST_SOURCE = path.join(MODULE_DIR, "management_client_reference_test.ts");
const RUNTIME_NODE_REFERENCE_SOURCE = path.join(MODULE_DIR, "runtime_node_reference.ts");
const RUNTIME_WEB_REFERENCE_SOURCE = path.join(MODULE_DIR, "runtime_web_reference.ts");
const ISSUER_SPA_INDEX_SOURCE = path.join(MODULE_DIR, "issuer_spa_reference.ts");
const ISSUER_SPA_README_SOURCE = path.join(MODULE_DIR, "issuer_spa_reference_readme.txt");
const ISSUER_SPA_TEST_SOURCE = path.join(MODULE_DIR, "issuer_spa_reference_test.ts");
const RP_CORE_INDEX_SOURCE = path.join(MODULE_DIR, "rp_core_reference.ts");
const RP_CORE_README_SOURCE = path.join(MODULE_DIR, "rp_core_reference_readme.txt");
const RP_CORE_TEST_SOURCE = path.join(MODULE_DIR, "rp_core_reference_test.ts");
const DEFAULT_DIST_DIR = path.join(ROOT_DIR, "artifacts", "verified-core");
const DEFAULT_OUT_DIR = path.join(ROOT_DIR, "artifacts", "sdk-staging");
const OPTIONAL_DIST_FILES = new Set(["verified_core.wasm.sig"]);
const REQUIRED_DIST_FILES = [
  "manifest.json",
  "verified_core.wasm",
  "verified_core.abi.json",
  "verified_core.wasm.sha256",
  "verified_core.wasm.sha512",
  "verified_core.wasm.sri",
  "verified-core-sbom.json",
  "types.d.ts",
  "integrity.txt",
];

function parseArgs(argv) {
  const options = {
    distDir: DEFAULT_DIST_DIR,
    outDir: DEFAULT_OUT_DIR,
    version: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      continue;
    }
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    switch (key) {
      case "dist-dir":
        options.distDir = path.resolve(value);
        break;
      case "out-dir":
        options.outDir = path.resolve(value);
        break;
      case "version":
        options.version = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  return options;
}

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

async function removeDir(dirPath) {
  await fs.rm(dirPath, { recursive: true, force: true });
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function writeJson(filePath, value) {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeText(filePath, text) {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, text, "utf8");
}

async function copyFileIfPresent(sourcePath, destinationPath) {
  try {
    await ensureDir(path.dirname(destinationPath));
    await fs.copyFile(sourcePath, destinationPath);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

async function copyRequiredDistFiles(distDir, packageDistDir) {
  for (const fileName of REQUIRED_DIST_FILES) {
    const sourcePath = path.join(distDir, fileName);
    const destinationPath = path.join(packageDistDir, fileName);
    await ensureDir(path.dirname(destinationPath));
    await fs.copyFile(sourcePath, destinationPath);
  }

  for (const fileName of OPTIONAL_DIST_FILES) {
    await copyFileIfPresent(path.join(distDir, fileName), path.join(packageDistDir, fileName));
  }
}

function rootPackageJson(version) {
  return {
    name: "aegaeon-sdk-reference-workspace",
    private: true,
    version,
    type: "module",
    description: "Local staging workspace for Aegaeon SDK reference package surfaces.",
    workspaces: ["packages/*"],
  };
}

function verifiedCorePackageJson(version) {
  return {
    name: "@aegaeon/verified-core",
    version,
    private: false,
    type: "module",
    description: "Bundled Verified Core artifact package staged from the backend repository.",
    license: "Apache-2.0",
    types: "./dist/index.d.ts",
    sideEffects: false,
    publishConfig: {
      access: "public",
    },
    engines: {
      node: ">=24",
    },
    keywords: ["oidc", "oauth", "wasm", "verification", "sdk"],
    exports: {
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
      },
      "./node": {
        types: "./dist/node.d.ts",
        import: "./dist/node.js",
      },
      "./web": {
        types: "./dist/web.d.ts",
        import: "./dist/web.js",
      },
      "./package.json": "./package.json"
    },
    files: ["dist", "README.md", "LICENSE"],
  };
}

function runtimePackageJson(name, version) {
  const exports = {
    ".": {
      types: "./dist/index.d.ts",
      import: "./dist/index.js",
    },
    "./package.json": "./package.json",
  };
  if (name === "@aegaeon/runtime-web") {
    exports["./browser-smoke"] = {
      types: "./dist/browser-smoke.d.ts",
      import: "./dist/browser-smoke.js",
    };
  }
  return {
    name,
    version,
    private: false,
    type: "module",
    description: `${name} reference adapter staged from the backend repository.`,
    license: "Apache-2.0",
    types: "./dist/index.d.ts",
    sideEffects: false,
    publishConfig: {
      access: "public",
    },
    engines: {
      node: ">=24",
    },
    keywords: ["oidc", "oauth", "wasm", "verification", "sdk"],
    dependencies: {
      "@aegaeon/verified-core": version,
    },
    exports,
    files: ["dist", "README.md", "LICENSE"],
  };
}

function managementClientPackageJson(version) {
  return {
    name: "@aegaeon/management-client",
    version,
    private: false,
    type: "module",
    types: "./index.d.ts",
    description: "Alpha management-plane SDK for the Aegaeon control-plane API.",
    license: "Apache-2.0",
    sideEffects: false,
    publishConfig: {
      access: "public",
    },
    engines: {
      node: ">=24",
    },
    keywords: ["management", "openapi", "csrf", "sdk", "admin"],
    exports: {
      ".": {
        types: "./index.d.ts",
        import: "./dist/index.js",
      },
      "./package.json": "./package.json",
    },
    files: ["dist", "index.d.ts", "README.md", "LICENSE"],
  };
}

function rpCorePackageJson(version) {
  return {
    name: "@aegaeon/rp-core",
    version,
    private: false,
    type: "module",
    types: "./dist/index.d.ts",
    description: "Thin RP orchestration helpers for Authorization Code + PKCE against Aegaeon-compatible OIDC issuers.",
    license: "Apache-2.0",
    sideEffects: false,
    publishConfig: {
      access: "public",
    },
    engines: {
      node: ">=24",
    },
    keywords: ["oidc", "oauth", "pkce", "rp", "sdk"],
    exports: {
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
      },
      "./package.json": "./package.json",
    },
    files: ["dist", "README.md", "LICENSE"],
  };
}

function issuerSpaPackageJson(version) {
  return {
    name: "@aegaeon/issuer-spa",
    version,
    private: false,
    type: "module",
    description: "Browser-facing login orchestration helpers for Aegaeon-compatible issuers.",
    license: "Apache-2.0",
    types: "./dist/index.d.ts",
    sideEffects: false,
    publishConfig: {
      access: "public",
    },
    engines: {
      node: ">=24",
    },
    keywords: ["oidc", "oauth", "pkce", "spa", "sdk"],
    dependencies: {
      "@aegaeon/runtime-web": version,
      "@aegaeon/rp-core": version,
    },
    exports: {
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
      },
      "./package.json": "./package.json",
    },
    files: ["dist", "README.md", "LICENSE"],
  };
}

function verifiedCoreIndex(version) {
  return `export const packageName = "@aegaeon/verified-core";\nexport const packageVersion = ${JSON.stringify(version)};\nexport const bundledFiles = Object.freeze([\n  "manifest.json",\n  "verified_core.wasm",\n  "verified_core.abi.json",\n  "verified_core.wasm.sha256",\n  "verified_core.wasm.sha512",\n  "verified_core.wasm.sri",\n  "verified-core-sbom.json",\n  "types.d.ts",\n  "integrity.txt",\n  "verified_core.wasm.sig",\n]);\n`;
}

function verifiedCoreIndexSource(version) {
  return `export const packageName = "@aegaeon/verified-core";\nexport const packageVersion = ${JSON.stringify(version)};\nexport const bundledFiles = Object.freeze([\n  "manifest.json",\n  "verified_core.wasm",\n  "verified_core.abi.json",\n  "verified_core.wasm.sha256",\n  "verified_core.wasm.sha512",\n  "verified_core.wasm.sri",\n  "verified-core-sbom.json",\n  "types.d.ts",\n  "integrity.txt",\n  "verified_core.wasm.sig",\n]);\n`;
}

function verifiedCoreNodeModule() {
  return `import { promises as fs } from "node:fs";\nimport path from "node:path";\nimport { fileURLToPath } from "node:url";\n\nconst DIST_DIR = path.dirname(fileURLToPath(import.meta.url));\nconst PACKAGE_DIR = path.dirname(DIST_DIR);\n\nexport function resolveBundledArtifactPaths() {\n  return {\n    packageDir: PACKAGE_DIR,\n    distDir: DIST_DIR,\n    manifestPath: path.join(DIST_DIR, "manifest.json"),\n    wasmPath: path.join(DIST_DIR, "verified_core.wasm"),\n    signaturePath: path.join(DIST_DIR, "verified_core.wasm.sig"),\n    abiPath: path.join(DIST_DIR, "verified_core.abi.json"),\n    typesPath: path.join(DIST_DIR, "types.d.ts"),\n    integrityPath: path.join(DIST_DIR, "integrity.txt"),\n  };\n}\n\nexport async function readBundledManifest() {\n  const { manifestPath } = resolveBundledArtifactPaths();\n  return JSON.parse(await fs.readFile(manifestPath, "utf8"));\n}\n\nexport async function readBundledWasm() {\n  const { wasmPath } = resolveBundledArtifactPaths();\n  return fs.readFile(wasmPath);\n}\n\nexport async function readBundledSignature() {\n  const { signaturePath } = resolveBundledArtifactPaths();\n  try {\n    return await fs.readFile(signaturePath);\n  } catch (error) {\n    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {\n      return null;\n    }\n    throw error;\n  }\n}\n\nexport async function loadBundledArtifact() {\n  const paths = resolveBundledArtifactPaths();\n  const [manifest, wasmBytes, signatureBytes] = await Promise.all([\n    readBundledManifest(),\n    readBundledWasm(),\n    readBundledSignature(),\n  ]);\n  return { manifest, wasmBytes, signatureBytes, paths };\n}\n`;
}

function verifiedCoreNodeSource() {
  return `import { promises as fs } from "node:fs";\nimport path from "node:path";\nimport { fileURLToPath } from "node:url";\n\nconst DIST_DIR = path.dirname(fileURLToPath(import.meta.url));\nconst PACKAGE_DIR = path.dirname(DIST_DIR);\n\nexport function resolveBundledArtifactPaths() {\n  return {\n    packageDir: PACKAGE_DIR,\n    distDir: DIST_DIR,\n    manifestPath: path.join(DIST_DIR, "manifest.json"),\n    wasmPath: path.join(DIST_DIR, "verified_core.wasm"),\n    signaturePath: path.join(DIST_DIR, "verified_core.wasm.sig"),\n    abiPath: path.join(DIST_DIR, "verified_core.abi.json"),\n    typesPath: path.join(DIST_DIR, "types.d.ts"),\n    integrityPath: path.join(DIST_DIR, "integrity.txt"),\n  };\n}\n\nexport async function readBundledManifest() {\n  const { manifestPath } = resolveBundledArtifactPaths();\n  return JSON.parse(await fs.readFile(manifestPath, "utf8"));\n}\n\nexport async function readBundledWasm() {\n  const { wasmPath } = resolveBundledArtifactPaths();\n  return fs.readFile(wasmPath);\n}\n\nexport async function readBundledSignature() {\n  const { signaturePath } = resolveBundledArtifactPaths();\n  try {\n    return await fs.readFile(signaturePath);\n  } catch (error) {\n    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {\n      return null;\n    }\n    throw error;\n  }\n}\n\nexport async function loadBundledArtifact() {\n  const paths = resolveBundledArtifactPaths();\n  const [manifest, wasmBytes, signatureBytes] = await Promise.all([\n    readBundledManifest(),\n    readBundledWasm(),\n    readBundledSignature(),\n  ]);\n  return { manifest, wasmBytes, signatureBytes, paths };\n}\n`;
}

function verifiedCoreWebModule() {
  return `const DIST_URL = new URL("./", import.meta.url);\nconst PACKAGE_URL = new URL("../", DIST_URL);\n\nexport function resolveBundledArtifactUrls() {\n  return {\n    packageUrl: PACKAGE_URL.toString(),\n    distUrl: DIST_URL.toString(),\n    manifestUrl: new URL("./manifest.json", DIST_URL).toString(),\n    wasmUrl: new URL("./verified_core.wasm", DIST_URL).toString(),\n    signatureUrl: new URL("./verified_core.wasm.sig", DIST_URL).toString(),\n    abiUrl: new URL("./verified_core.abi.json", DIST_URL).toString(),\n    typesUrl: new URL("./types.d.ts", DIST_URL).toString(),\n  };\n}\n\nasync function fetchText(url, fetchImpl) {\n  const response = await fetchImpl(url);\n  if (!response.ok) {\n    throw new Error(\`failed to fetch \${url}: \${response.status}\`);\n  }\n  return response.text();\n}\n\nasync function fetchBytes(url, fetchImpl) {\n  const response = await fetchImpl(url);\n  if (!response.ok) {\n    throw new Error(\`failed to fetch \${url}: \${response.status}\`);\n  }\n  return new Uint8Array(await response.arrayBuffer());\n}\n\nexport async function readBundledManifest({ fetchImpl = globalThis.fetch?.bind(globalThis) } = {}) {\n  if (!fetchImpl) {\n    throw new Error(\"fetch implementation is required to load the bundled manifest\");\n  }\n  const { manifestUrl } = resolveBundledArtifactUrls();\n  return JSON.parse(await fetchText(manifestUrl, fetchImpl));\n}\n\nexport async function readBundledWasm({ fetchImpl = globalThis.fetch?.bind(globalThis) } = {}) {\n  if (!fetchImpl) {\n    throw new Error(\"fetch implementation is required to load the bundled wasm\");\n  }\n  const { wasmUrl } = resolveBundledArtifactUrls();\n  return fetchBytes(wasmUrl, fetchImpl);\n}\n\nexport async function readBundledSignature({ fetchImpl = globalThis.fetch?.bind(globalThis) } = {}) {\n  if (!fetchImpl) {\n    throw new Error(\"fetch implementation is required to load the bundled signature\");\n  }\n  const { signatureUrl } = resolveBundledArtifactUrls();\n  try {\n    return await fetchBytes(signatureUrl, fetchImpl);\n  } catch (error) {\n    if (error instanceof Error) {\n      const message = error.message;\n      if (message.includes(\": 404\") || message.includes(\"ENOENT\") || message.includes(\"not found\")) {\n        return null;\n      }\n    }\n    throw error;\n  }\n}\n\nexport async function loadBundledArtifact({ fetchImpl = globalThis.fetch?.bind(globalThis) } = {}) {\n  const urls = resolveBundledArtifactUrls();\n  const [manifest, wasmBytes, signatureBytes] = await Promise.all([\n    readBundledManifest({ fetchImpl }),\n    readBundledWasm({ fetchImpl }),\n    readBundledSignature({ fetchImpl }),\n  ]);\n  return { manifest, wasmBytes, signatureBytes, urls };\n}\n`;
}

function verifiedCoreWebSource() {
  return `const DIST_URL = new URL("./", import.meta.url);\nconst PACKAGE_URL = new URL("../", DIST_URL);\n\nexport function resolveBundledArtifactUrls() {\n  return {\n    packageUrl: PACKAGE_URL.toString(),\n    distUrl: DIST_URL.toString(),\n    manifestUrl: new URL("./manifest.json", DIST_URL).toString(),\n    wasmUrl: new URL("./verified_core.wasm", DIST_URL).toString(),\n    signatureUrl: new URL("./verified_core.wasm.sig", DIST_URL).toString(),\n    abiUrl: new URL("./verified_core.abi.json", DIST_URL).toString(),\n    typesUrl: new URL("./types.d.ts", DIST_URL).toString(),\n  };\n}\n\nasync function fetchText(url: string, fetchImpl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {\n  const response = await fetchImpl(url);\n  if (!response.ok) {\n    throw new Error(\`failed to fetch \${url}: \${response.status}\`);\n  }\n  return response.text();\n}\n\nasync function fetchBytes(url: string, fetchImpl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {\n  const response = await fetchImpl(url);\n  if (!response.ok) {\n    throw new Error(\`failed to fetch \${url}: \${response.status}\`);\n  }\n  return new Uint8Array(await response.arrayBuffer());\n}\n\nexport async function readBundledManifest({ fetchImpl = globalThis.fetch?.bind(globalThis) }: { fetchImpl?: ((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | undefined } = {}) {\n  if (!fetchImpl) {\n    throw new Error(\"fetch implementation is required to load the bundled manifest\");\n  }\n  const { manifestUrl } = resolveBundledArtifactUrls();\n  return JSON.parse(await fetchText(manifestUrl, fetchImpl));\n}\n\nexport async function readBundledWasm({ fetchImpl = globalThis.fetch?.bind(globalThis) }: { fetchImpl?: ((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | undefined } = {}) {\n  if (!fetchImpl) {\n    throw new Error(\"fetch implementation is required to load the bundled wasm\");\n  }\n  const { wasmUrl } = resolveBundledArtifactUrls();\n  return fetchBytes(wasmUrl, fetchImpl);\n}\n\nexport async function readBundledSignature({ fetchImpl = globalThis.fetch?.bind(globalThis) }: { fetchImpl?: ((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | undefined } = {}) {\n  if (!fetchImpl) {\n    throw new Error(\"fetch implementation is required to load the bundled signature\");\n  }\n  const { signatureUrl } = resolveBundledArtifactUrls();\n  try {\n    return await fetchBytes(signatureUrl, fetchImpl);\n  } catch (error) {\n    if (error instanceof Error) {\n      const message = error.message;\n      if (message.includes(\": 404\") || message.includes(\"ENOENT\") || message.includes(\"not found\")) {\n        return null;\n      }\n    }\n    throw error;\n  }\n}\n\nexport async function loadBundledArtifact({ fetchImpl = globalThis.fetch?.bind(globalThis) }: { fetchImpl?: ((input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) | undefined } = {}) {\n  const urls = resolveBundledArtifactUrls();\n  const [manifest, wasmBytes, signatureBytes] = await Promise.all([\n    readBundledManifest({ fetchImpl }),\n    readBundledWasm({ fetchImpl }),\n    readBundledSignature({ fetchImpl }),\n  ]);\n  return { manifest, wasmBytes, signatureBytes, urls };\n}\n`;
}

function runtimeNodeIndex() {
  return `import * as reference from "./reference.js";\nimport { loadBundledArtifact, resolveBundledArtifactPaths as resolveBundledPaths } from "@aegaeon/verified-core/node";\nimport type { NodeInitOptions } from "./reference.js";\n\nexport const VC_STATUS = reference.VC_STATUS;\nexport const VC_ALG = reference.VC_ALG;\nexport const VC_DPOP_FLAGS = reference.VC_DPOP_FLAGS;\nexport const VC_JWT_FLAGS = reference.VC_JWT_FLAGS;\nexport const CLIENT_CRYPTO_PROFILES = reference.CLIENT_CRYPTO_PROFILES;\nexport const DEFAULT_CLIENT_CRYPTO_PROFILE = reference.DEFAULT_CLIENT_CRYPTO_PROFILE;\nexport const createInMemoryReplayStore = reference.createInMemoryReplayStore;\nexport const resolveJwtAllowedAlgorithmsBitmaskForProfile = reference.resolveJwtAllowedAlgorithmsBitmaskForProfile;\nexport const resolveDpopAllowedAlgorithmsBitmaskForProfile = reference.resolveDpopAllowedAlgorithmsBitmaskForProfile;\n\nexport function resolveBundledArtifactPaths() {\n  return resolveBundledPaths();\n}\n\nexport async function initCore(options: NodeInitOptions = {}) {\n  const hasExplicitArtifact = Boolean(\n    options.manifest || options.manifestPath || options.wasmBytes || options.wasmPath || options.signaturePath\n  );\n  if (hasExplicitArtifact) {\n    return reference.initCore(options);\n  }\n  const { manifest, wasmBytes, signatureBytes } = await loadBundledArtifact();\n  return reference.initCore({ ...options, manifest, wasmBytes, ...(signatureBytes ? { signatureBytes } : {}) });\n}\n`;
}

function runtimeWebIndex() {
  return `import * as reference from "./reference.js";\nimport { loadBundledArtifact, resolveBundledArtifactUrls as resolveBundledUrls } from "@aegaeon/verified-core/web";\nimport type { WebInitOptions } from "./reference.js";\n\nexport const VC_STATUS = reference.VC_STATUS;\nexport const VC_ALG = reference.VC_ALG;\nexport const VC_DPOP_FLAGS = reference.VC_DPOP_FLAGS;\nexport const VC_JWT_FLAGS = reference.VC_JWT_FLAGS;\nexport const CLIENT_CRYPTO_PROFILES = reference.CLIENT_CRYPTO_PROFILES;\nexport const DEFAULT_CLIENT_CRYPTO_PROFILE = reference.DEFAULT_CLIENT_CRYPTO_PROFILE;\nexport const createInMemoryReplayStore = reference.createInMemoryReplayStore;\nexport const resolveJwtAllowedAlgorithmsBitmaskForProfile = reference.resolveJwtAllowedAlgorithmsBitmaskForProfile;\nexport const resolveDpopAllowedAlgorithmsBitmaskForProfile = reference.resolveDpopAllowedAlgorithmsBitmaskForProfile;\n\nexport function resolveBundledArtifactUrls() {\n  return resolveBundledUrls();\n}\n\nexport async function initCore(options: WebInitOptions = {}) {\n  const hasExplicitArtifact = Boolean(options.manifest || options.manifestUrl || options.wasmBytes || options.wasmUrl);\n  if (hasExplicitArtifact) {\n    return reference.initCore(options);\n  }\n  const { manifest, wasmBytes, signatureBytes } = await loadBundledArtifact({ fetchImpl: options.fetchImpl });\n  return reference.initCore({\n    ...options,\n    manifest,\n    wasmBytes,\n    ...(signatureBytes ? { signatureBytes } : {}),\n  });\n}\n`;
}

function runtimeWebBrowserSmoke() {
  return `import * as reference from "./reference.js";\nimport { loadBundledArtifact, resolveBundledArtifactUrls as resolveBundledUrls } from "../../verified-core/dist/web.js";\nimport type { WebInitOptions } from "./reference.js";\n\nexport const VC_STATUS = reference.VC_STATUS;\nexport const VC_ALG = reference.VC_ALG;\nexport const VC_DPOP_FLAGS = reference.VC_DPOP_FLAGS;\nexport const VC_JWT_FLAGS = reference.VC_JWT_FLAGS;\nexport const CLIENT_CRYPTO_PROFILES = reference.CLIENT_CRYPTO_PROFILES;\nexport const DEFAULT_CLIENT_CRYPTO_PROFILE = reference.DEFAULT_CLIENT_CRYPTO_PROFILE;\nexport const createInMemoryReplayStore = reference.createInMemoryReplayStore;\nexport const resolveJwtAllowedAlgorithmsBitmaskForProfile = reference.resolveJwtAllowedAlgorithmsBitmaskForProfile;\nexport const resolveDpopAllowedAlgorithmsBitmaskForProfile = reference.resolveDpopAllowedAlgorithmsBitmaskForProfile;\n\nexport function resolveBundledArtifactUrls() {\n  return resolveBundledUrls();\n}\n\nexport async function initCore(options: WebInitOptions = {}) {\n  const hasExplicitArtifact = Boolean(options.manifest || options.manifestUrl || options.wasmBytes || options.wasmUrl);\n  if (hasExplicitArtifact) {\n    return reference.initCore(options);\n  }\n  const { manifest, wasmBytes, signatureBytes } = await loadBundledArtifact({ fetchImpl: options.fetchImpl });\n  return reference.initCore({\n    ...options,\n    manifest,\n    wasmBytes,\n    ...(signatureBytes ? { signatureBytes } : {}),\n  });\n}\n`;
}

function runtimeDistJavaScript(source) {
  return stripTypeScriptTypes(source);
}

function verifiedCoreReadme() {
  return `# @aegaeon/verified-core\n\nLocal staging package for the bundled Verified Core artefacts.\n\nThis package is generated from \`artifacts/verified-core/\` in the backend repository and mirrors the intended package surface for the separate \`aegaeon-sdk\` repository.\n\nEnvironment-specific helpers:\n- \`@aegaeon/verified-core/node\` for Node.js / bundling-time file access\n- \`@aegaeon/verified-core/web\` for browser-friendly URL resolution and fetch-based loading\n`;
}

function runtimeReadme(packageName, environment) {
  return `# ${packageName}\n\nLocal staging package for the ${environment} reference adapter.\n\nThe adapter wraps the current reference implementation from the backend repository and defaults to the bundled artefacts from \`@aegaeon/verified-core\`.\n\nClient crypto profiles:\n- \`verified-core\` — EdDSA-only verified core profile\n- \`aegaeon-rs256\` — default first-party profile; JWT accepts \`EdDSA|RS256\`, DPoP stays \`EdDSA\`\n- \`compat-interop\` — interoperability profile; JWT accepts \`EdDSA|RS256|ES256\`, DPoP accepts \`EdDSA|ES256\`\n`;
}

async function createSymlink(targetPath, linkPath) {
  await ensureDir(path.dirname(linkPath));
  try {
    await fs.symlink(targetPath, linkPath, "junction");
  } catch (error) {
    if (error && error.code === "EEXIST") {
      return;
    }
    throw error;
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = await readJson(path.join(options.distDir, "manifest.json"));
  const version = options.version ?? manifest.version ?? "0.0.0-reference";

  await removeDir(options.outDir);
  const packagesDir = path.join(options.outDir, "packages");
  const verifiedCoreDir = path.join(packagesDir, "verified-core");
  const runtimeNodeDir = path.join(packagesDir, "runtime-node");
  const runtimeWebDir = path.join(packagesDir, "runtime-web");
  const managementClientDir = path.join(packagesDir, "management-client");
  const issuerSpaDir = path.join(packagesDir, "issuer-spa");
  const rpCoreDir = path.join(packagesDir, "rp-core");

  await ensureDir(packagesDir);
  await writeJson(path.join(options.outDir, "package.json"), rootPackageJson(version));
  await writeText(path.join(options.outDir, "README.md"), "# Aegaeon SDK reference workspace\n\nGenerated from the backend repository to exercise package-shaped SDK surfaces locally.\n");

  await writeJson(path.join(verifiedCoreDir, "package.json"), verifiedCorePackageJson(version));
  await ensureDir(path.join(verifiedCoreDir, "src"));
  await ensureDir(path.join(verifiedCoreDir, "dist"));
  await writeText(path.join(verifiedCoreDir, "src", "index.ts"), verifiedCoreIndexSource(version));
  await writeText(path.join(verifiedCoreDir, "src", "node.ts"), verifiedCoreNodeSource());
  await writeText(path.join(verifiedCoreDir, "src", "web.ts"), verifiedCoreWebSource());
  await writeText(path.join(verifiedCoreDir, "dist", "index.js"), verifiedCoreIndex(version));
  await writeText(path.join(verifiedCoreDir, "dist", "node.js"), verifiedCoreNodeModule());
  await writeText(path.join(verifiedCoreDir, "dist", "web.js"), verifiedCoreWebModule());
  await writeText(path.join(verifiedCoreDir, "README.md"), verifiedCoreReadme());
  await fs.copyFile(LICENSE_PATH, path.join(verifiedCoreDir, "LICENSE"));
  await copyRequiredDistFiles(options.distDir, path.join(verifiedCoreDir, "dist"));

  await writeJson(path.join(runtimeNodeDir, "package.json"), runtimePackageJson("@aegaeon/runtime-node", version));
  await ensureDir(path.join(runtimeNodeDir, "src"));
  await ensureDir(path.join(runtimeNodeDir, "dist"));
  const runtimeNodeIndexSource = runtimeNodeIndex();
  await writeText(path.join(runtimeNodeDir, "src", "index.ts"), runtimeNodeIndexSource);
  await writeText(path.join(runtimeNodeDir, "dist", "index.js"), runtimeDistJavaScript(runtimeNodeIndexSource));
  await writeText(path.join(runtimeNodeDir, "README.md"), runtimeReadme("@aegaeon/runtime-node", "Node.js"));
  await fs.copyFile(LICENSE_PATH, path.join(runtimeNodeDir, "LICENSE"));
  const runtimeNodeReference = (await fs.readFile(RUNTIME_NODE_REFERENCE_SOURCE, "utf8"))
    .replace('const ROOT_DIR = path.resolve(MODULE_DIR, "..", "..");', 'const ROOT_DIR = path.resolve(MODULE_DIR, "..", "..", "..");');
  await writeText(path.join(runtimeNodeDir, "src", "reference.ts"), runtimeNodeReference);
  await writeText(path.join(runtimeNodeDir, "dist", "reference.js"), runtimeDistJavaScript(runtimeNodeReference));

  await writeJson(path.join(runtimeWebDir, "package.json"), runtimePackageJson("@aegaeon/runtime-web", version));
  await ensureDir(path.join(runtimeWebDir, "src"));
  await ensureDir(path.join(runtimeWebDir, "dist"));
  const runtimeWebIndexSource = runtimeWebIndex();
  await writeText(path.join(runtimeWebDir, "src", "index.ts"), runtimeWebIndexSource);
  await writeText(path.join(runtimeWebDir, "dist", "index.js"), runtimeDistJavaScript(runtimeWebIndexSource));
  await writeText(path.join(runtimeWebDir, "README.md"), runtimeReadme("@aegaeon/runtime-web", "browser / WebCrypto"));
  await fs.copyFile(LICENSE_PATH, path.join(runtimeWebDir, "LICENSE"));
  const runtimeWebReference = (await fs.readFile(RUNTIME_WEB_REFERENCE_SOURCE, "utf8"))
    .replaceAll('../../artifacts/verified-core/', '../../../artifacts/verified-core/');
  await writeText(path.join(runtimeWebDir, "src", "reference.ts"), runtimeWebReference);
  await writeText(path.join(runtimeWebDir, "dist", "reference.js"), runtimeDistJavaScript(runtimeWebReference));
  const runtimeWebBrowserSmokeSource = runtimeWebBrowserSmoke();
  await writeText(path.join(runtimeWebDir, "src", "browser-smoke.ts"), runtimeWebBrowserSmokeSource);
  await writeText(path.join(runtimeWebDir, "dist", "browser-smoke.js"), runtimeDistJavaScript(runtimeWebBrowserSmokeSource));

  await writeJson(path.join(managementClientDir, "package.json"), managementClientPackageJson(version));
  await ensureDir(path.join(managementClientDir, "src"));
  await ensureDir(path.join(managementClientDir, "dist"));
  await ensureDir(path.join(managementClientDir, "test"));
  await ensureDir(path.join(managementClientDir, "dist-test"));
  const managementClientSource = await fs.readFile(MANAGEMENT_CLIENT_INDEX_SOURCE, "utf8");
  const managementClientTestSource = await fs.readFile(MANAGEMENT_CLIENT_TEST_SOURCE, "utf8");
  await writeText(path.join(managementClientDir, "src", "index.ts"), managementClientSource);
  await writeText(path.join(managementClientDir, "dist", "index.js"), runtimeDistJavaScript(managementClientSource));
  await fs.copyFile(MANAGEMENT_CLIENT_TYPES_SOURCE, path.join(managementClientDir, "index.d.ts"));
  await fs.copyFile(MANAGEMENT_CLIENT_README_SOURCE, path.join(managementClientDir, "README.md"));
  await writeText(path.join(managementClientDir, "test", "management_client_test.ts"), managementClientTestSource);
  await writeText(path.join(managementClientDir, "dist-test", "management_client_test.js"), runtimeDistJavaScript(managementClientTestSource));
  await fs.copyFile(LICENSE_PATH, path.join(managementClientDir, "LICENSE"));

  await writeJson(path.join(issuerSpaDir, "package.json"), issuerSpaPackageJson(version));
  await ensureDir(path.join(issuerSpaDir, "src"));
  await ensureDir(path.join(issuerSpaDir, "dist"));
  await ensureDir(path.join(issuerSpaDir, "test"));
  await ensureDir(path.join(issuerSpaDir, "dist-test"));
  const issuerSpaSource = await fs.readFile(ISSUER_SPA_INDEX_SOURCE, "utf8");
  const issuerSpaTestSource = await fs.readFile(ISSUER_SPA_TEST_SOURCE, "utf8");
  await writeText(path.join(issuerSpaDir, "src", "index.ts"), issuerSpaSource);
  await writeText(path.join(issuerSpaDir, "dist", "index.js"), runtimeDistJavaScript(issuerSpaSource));
  await fs.copyFile(ISSUER_SPA_README_SOURCE, path.join(issuerSpaDir, "README.md"));
  await writeText(path.join(issuerSpaDir, "test", "issuer_spa_test.ts"), issuerSpaTestSource);
  await writeText(path.join(issuerSpaDir, "dist-test", "issuer_spa_test.js"), runtimeDistJavaScript(issuerSpaTestSource));
  await fs.copyFile(LICENSE_PATH, path.join(issuerSpaDir, "LICENSE"));

  await writeJson(path.join(rpCoreDir, "package.json"), rpCorePackageJson(version));
  await ensureDir(path.join(rpCoreDir, "src"));
  await ensureDir(path.join(rpCoreDir, "dist"));
  await ensureDir(path.join(rpCoreDir, "test"));
  await ensureDir(path.join(rpCoreDir, "dist-test"));
  const rpCoreSource = await fs.readFile(RP_CORE_INDEX_SOURCE, "utf8");
  const rpCoreTestSource = await fs.readFile(RP_CORE_TEST_SOURCE, "utf8");
  await writeText(path.join(rpCoreDir, "src", "index.ts"), rpCoreSource);
  await writeText(path.join(rpCoreDir, "dist", "index.js"), runtimeDistJavaScript(rpCoreSource));
  await fs.copyFile(RP_CORE_README_SOURCE, path.join(rpCoreDir, "README.md"));
  await writeText(path.join(rpCoreDir, "test", "rp_core_test.ts"), rpCoreTestSource);
  await writeText(path.join(rpCoreDir, "dist-test", "rp_core_test.js"), runtimeDistJavaScript(rpCoreTestSource));
  await fs.copyFile(LICENSE_PATH, path.join(rpCoreDir, "LICENSE"));

  const scopedNodeModulesDir = path.join(options.outDir, "node_modules", "@aegaeon");
  await ensureDir(scopedNodeModulesDir);
  await createSymlink(path.relative(scopedNodeModulesDir, verifiedCoreDir), path.join(scopedNodeModulesDir, "verified-core"));
  await createSymlink(path.relative(scopedNodeModulesDir, runtimeNodeDir), path.join(scopedNodeModulesDir, "runtime-node"));
  await createSymlink(path.relative(scopedNodeModulesDir, runtimeWebDir), path.join(scopedNodeModulesDir, "runtime-web"));
  await createSymlink(path.relative(scopedNodeModulesDir, managementClientDir), path.join(scopedNodeModulesDir, "management-client"));
  await createSymlink(path.relative(scopedNodeModulesDir, issuerSpaDir), path.join(scopedNodeModulesDir, "issuer-spa"));
  await createSymlink(path.relative(scopedNodeModulesDir, rpCoreDir), path.join(scopedNodeModulesDir, "rp-core"));

  console.log("[stage-sdk] staged reference workspace:", options.outDir);
  console.log("[stage-sdk] package version:", version);
  console.log("[stage-sdk] packages:");
  console.log(`  - ${verifiedCoreDir}`);
  console.log(`  - ${runtimeNodeDir}`);
  console.log(`  - ${runtimeWebDir}`);
  console.log(`  - ${managementClientDir}`);
  console.log(`  - ${issuerSpaDir}`);
  console.log(`  - ${rpCoreDir}`);
}

main().catch((error) => {
  console.error("[stage-sdk] error:", error);
  process.exitCode = 1;
});
