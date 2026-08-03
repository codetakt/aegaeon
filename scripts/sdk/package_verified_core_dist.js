#!/usr/bin/env node
/**
 * Package Verified Core for distribution to external SDK repositories.
 *
 * This script creates a complete distribution bundle containing:
 * - verified_core.wasm (the compiled WASM binary)
 * - manifest.json (integrity metadata with SHA-256, SRI)
 * - verified_core.abi.json (ABI specification for type generation)
 * - verified-core-sbom.json (CycloneDX SBOM)
 * - Optional: signature file if signing key is provided
 *
 * Usage:
 *   node scripts/sdk/package_verified_core_dist.js \
 *     --out dist/verified-core \
 *     [--wasm artifacts/verified-core/verified_core.wasm] \
 *     [--abi generated/lowstar/verified-core/verified_core.abi.json] \
 *     [--version 1.0.0] \
 *     [--private-key signing.pem]
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash, sign, createPrivateKey, createPublicKey } from "node:crypto";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, "../..");

/**
 * @typedef {Object} CliOptions
 * @property {string} out
 * @property {string | undefined} wasm
 * @property {string | undefined} abi
 * @property {string | undefined} version
 * @property {string | undefined} privateKey
 */

/**
 * @typedef {Object} AbiEnum
 * @property {string} repr
 * @property {Record<string, number>} variants
 */

/**
 * @typedef {Object} AbiStructField
 * @property {string} name
 * @property {string} type
 * @property {number} offsetBytes
 * @property {string | undefined} description
 */

/**
 * @typedef {Object} AbiStruct
 * @property {string} repr
 * @property {number} sizeBytes
 * @property {AbiStructField[]} fields
 */

/**
 * @typedef {Object} AbiExportParam
 * @property {string} name
 * @property {string} type
 * @property {string | undefined} pointsTo
 */

/**
 * @typedef {Object} AbiResult
 * @property {string} type
 */

/**
 * @typedef {Object} AbiExportEntry
 * @property {string} name
 * @property {AbiExportParam[]} params
 * @property {AbiResult[]} results
 * @property {string | undefined} description
 */

/**
 * @typedef {Object} AbiImportParam
 * @property {string} name
 * @property {string} type
 */

/**
 * @typedef {Object} AbiImportEntry
 * @property {string} module
 * @property {string} name
 * @property {AbiImportParam[]} params
 * @property {AbiResult[]} results
 * @property {string | undefined} description
 */

/**
 * @typedef {Object} AbiBitmask
 * @property {string} repr
 * @property {Record<string, number>} bits
 */

/**
 * @param {string[]} argv
 * @returns {CliOptions}
 */
function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    args.set(key, value);
    i += 1;
  }

  const out = args.get("out");
  if (!out) {
    throw new Error("Required option: --out <directory>");
  }

  return {
    out,
    wasm: args.get("wasm"),
    abi: args.get("abi"),
    version: args.get("version"),
    privateKey: args.get("private-key")
  };
}

/**
 * Get current git commit hash.
 * @returns {Promise<string>}
 */
async function getGitCommit() {
  try {
    const { execSync } = await import("node:child_process");
    return execSync("git rev-parse HEAD", { encoding: "utf8", cwd: ROOT_DIR }).trim();
  } catch {
    return "unknown";
  }
}

/**
 * Compute SHA-256 or SHA-512 hash of data.
 * @param {Buffer} data
 * @param {"sha256" | "sha512"} algorithm
 * @returns {string}
 */
function digestHex(data, algorithm) {
  return createHash(algorithm).update(data).digest("hex");
}

/**
 * Compute SRI hash (base64 SHA-256).
 * @param {Buffer} data
 * @returns {string}
 */
function computeSri(data) {
  const hash = createHash("sha256").update(data).digest("base64");
  return `sha256-${hash}`;
}

/**
 * Sign data with Ed25519 private key.
 * @param {Buffer} data
 * @param {string} privateKeyPem
 * @returns {{ signature: Buffer, publicKeyFingerprint: string }}
 */
function signData(data, privateKeyPem) {
  const privateKey = createPrivateKey(privateKeyPem);
  const signature = sign(null, data, privateKey);

  // Derive public key and compute fingerprint
  const publicKey = createPublicKey(privateKey);
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const fingerprint = createHash("sha256").update(publicKeyDer).digest("hex").slice(0, 16);

  return { signature, publicKeyFingerprint: fingerprint };
}

/**
 * @template T
 * @param {string} filePath
 * @returns {Promise<T>}
 */
async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const timestamp = new Date().toISOString();

  console.log("[package-dist] Starting verified-core distribution packaging...\n");

  // Source paths
  const wasmPath =
    options.wasm ||
    path.join(ROOT_DIR, "artifacts/verified-core/verified_core.wasm");
  const abiPath =
    options.abi ||
    path.join(
      ROOT_DIR,
      "generated/lowstar/verified-core/verified_core.abi.json",
    );

  // Read WASM binary
  console.log("[package-dist] Reading WASM binary...");
  const wasmBytes = await fs.readFile(wasmPath);
  const wasmHash = digestHex(wasmBytes, "sha256");
  const wasmSha512 = digestHex(wasmBytes, "sha512");
  const wasmSri = computeSri(wasmBytes);
  console.log(`  Size: ${wasmBytes.length} bytes`);
  console.log(`  SHA-256: ${wasmHash}`);
  console.log(`  SRI: ${wasmSri}`);

  // Read ABI
  console.log("\n[package-dist] Reading ABI specification...");
  const abi = await readJson(abiPath);
  console.log(`  ABI Version: ${abi.abiVersion}`);

  // Get git commit
  const sourceCommit = await getGitCommit();
  console.log(`\n[package-dist] Source commit: ${sourceCommit.slice(0, 12)}`);

  // Determine version
  const version = options.version || "1.0.0";
  console.log(`[package-dist] Package version: ${version}`);

  // Create output directory
  await fs.mkdir(options.out, { recursive: true });
  console.log(`\n[package-dist] Output directory: ${options.out}`);

  // Copy WASM
  const outWasmPath = path.join(options.out, "verified_core.wasm");
  await fs.writeFile(outWasmPath, wasmBytes);
  console.log("  - verified_core.wasm");

  // Copy ABI
  const outAbiPath = path.join(options.out, "verified_core.abi.json");
  await fs.writeFile(outAbiPath, JSON.stringify(abi, null, 2) + "\n", "utf8");
  console.log("  - verified_core.abi.json");

  // Build manifest
  /** @type {Record<string, unknown>} */
  const manifest = {
    artifact: "verified_core.wasm",
    version,
    size_bytes: wasmBytes.length,
    sha256: wasmHash,
    sha512: wasmSha512,
    sri: wasmSri,
    generated_at: timestamp,
    source_commit: sourceCommit,
    abi_version: abi.abiVersion
  };

  // Sign if private key provided
  if (options.privateKey) {
    console.log("\n[package-dist] Signing artifact...");
    const privateKeyPem = await fs.readFile(options.privateKey, "utf8");
    const { signature, publicKeyFingerprint } = signData(wasmBytes, privateKeyPem);

    // Write signature file
    const outSigPath = path.join(options.out, "verified_core.wasm.sig");
    await fs.writeFile(outSigPath, signature);
    console.log("  - verified_core.wasm.sig");

    // Add signature metadata to manifest
    manifest.signature = {
      algorithm: "Ed25519",
      file: "verified_core.wasm.sig",
      format: "raw",
      public_key_fingerprint: publicKeyFingerprint,
      signed_at: timestamp
    };
    console.log(`  Fingerprint: ${publicKeyFingerprint}`);
  }

  // Write manifest
  const outManifestPath = path.join(options.out, "manifest.json");
  await fs.writeFile(outManifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  console.log("  - manifest.json");

  // Write hash helper files
  const outSha256Path = path.join(options.out, "verified_core.wasm.sha256");
  await fs.writeFile(outSha256Path, `${wasmHash}  verified_core.wasm\n`, "utf8");
  console.log("  - verified_core.wasm.sha256");

  const outSha512Path = path.join(options.out, "verified_core.wasm.sha512");
  await fs.writeFile(outSha512Path, `${wasmSha512}  verified_core.wasm\n`, "utf8");
  console.log("  - verified_core.wasm.sha512");

  const outSriPath = path.join(options.out, "verified_core.wasm.sri");
  await fs.writeFile(outSriPath, `${wasmSri}\n`, "utf8");
  console.log("  - verified_core.wasm.sri");

  // Generate SBOM
  console.log("\n[package-dist] Generating SBOM...");
  const sbom = generateSbom(manifest, abi);
  const outSbomPath = path.join(options.out, "verified-core-sbom.json");
  await fs.writeFile(outSbomPath, JSON.stringify(sbom, null, 2) + "\n", "utf8");
  console.log("  - verified-core-sbom.json");

  // Generate TypeScript types
  console.log("\n[package-dist] Generating TypeScript definitions...");
  const typeDefs = generateTypeDefs(abi);
  const outTypesPath = path.join(options.out, "types.d.ts");
  await fs.writeFile(outTypesPath, typeDefs, "utf8");
  console.log("  - types.d.ts");

  // Write integrity file (for quick verification)
  const integrityContent = [
    `# Verified Core Integrity`,
    `# Generated: ${timestamp}`,
    `# Version: ${version}`,
    ``,
    `SHA-256: ${wasmHash}`,
    `SRI: ${wasmSri}`,
    `Size: ${wasmBytes.length} bytes`,
    `Commit: ${sourceCommit}`,
    ``
  ].join("\n");
  const outIntegrityPath = path.join(options.out, "integrity.txt");
  await fs.writeFile(outIntegrityPath, integrityContent, "utf8");
  console.log("  - integrity.txt");

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("[package-dist] Distribution package created successfully!");
  console.log("=".repeat(60));
  console.log(`\nContents of ${options.out}:`);

  const files = await fs.readdir(options.out);
  for (const file of files.sort()) {
    const stat = await fs.stat(path.join(options.out, file));
    console.log(`  ${file.padEnd(30)} ${stat.size.toString().padStart(8)} bytes`);
  }

  console.log(`\nTo use in SDK repository:`);
  console.log(`  1. Copy ${options.out}/ to your SDK's artifacts/ directory`);
  console.log(`  2. Install @aegaeon/verified-core (or copy the loader code)`);
  console.log(`  3. See INTEGRATION.md for usage examples`);
}

/**
 * Generate UUID v4.
 * @returns {string}
 */
function generateUuid() {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32)
  ].join("-");
}

/**
 * Generate CycloneDX SBOM.
 * @param {Record<string, unknown>} manifest
 * @param {Record<string, unknown>} abi
 * @returns {Record<string, unknown>}
 */
function generateSbom(manifest, abi) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${generateUuid()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: "application",
            name: "package_verified_core_dist.js",
            version: "1.0.0",
            description: "Aegaeon Verified Core distribution packager"
          }
        ]
      },
      component: {
        type: "library",
        "bom-ref": "verified-core-wasm",
        name: "verified_core.wasm",
        version: manifest.version,
        description: "Formally verified cryptographic core compiled to WebAssembly",
        hashes: [
          { alg: "SHA-256", content: manifest.sha256 }
        ],
        licenses: [{ license: { id: "Apache-2.0" } }],
        purl:
          `pkg:generic/aegaeon/verified-core@${manifest.version}` +
          `?source_commit=${manifest.source_commit}`,
        properties: [
          { name: "cdx:verified-core:sri", value: manifest.sri },
          {
            name: "cdx:security:formal-verification",
            value: "F* (proofs checked by Z3 SMT solver)"
          },
          { name: "cdx:security:tcb", value: "F* type system, KaRaMeL extraction, WASI libc" },
          { name: "cdx:abi:version", value: abi.abiVersion }
        ]
      }
    },
    components: [
      {
        type: "library",
        "bom-ref": "fstar-pkce",
        name: "Pkce.fst",
        version: "1.0.0",
        description: "PKCE (RFC 7636) S256 challenge verification",
        properties: [
          { name: "cdx:source:language", value: "F*" },
          { name: "cdx:verification:status", value: "verified" }
        ]
      },
      {
        type: "library",
        "bom-ref": "fstar-dpop",
        name: "Dpop.fst",
        version: "1.0.0",
        description: "DPoP (RFC 9449) proof validation",
        properties: [
          { name: "cdx:source:language", value: "F*" },
          { name: "cdx:verification:status", value: "verified" }
        ]
      },
      {
        type: "library",
        "bom-ref": "fstar-claims-runtime",
        name: "VerifiedCore_Api_Claims_Runtime.fst",
        version: "1.0.0",
        description: "Claims-based JWT/DPoP verification runtime",
        properties: [
          { name: "cdx:source:language", value: "F*" },
          { name: "cdx:verification:status", value: "verified" }
        ]
      }
    ],
    dependencies: [
      {
        ref: "verified-core-wasm",
        dependsOn: ["fstar-pkce", "fstar-dpop", "fstar-claims-runtime"]
      }
    ]
  };
}

/**
 * Generate TypeScript type definitions from ABI.
 * @param {Record<string, unknown>} abi
 * @returns {string}
 */
function generateTypeDefs(abi) {
  const lines = [
    "/**",
    " * Verified Core TypeScript Definitions",
    " * Auto-generated from ABI specification",
    ` * ABI Version: ${abi.abiVersion}`,
    " */",
    "",
    "// ============================================================",
    "// Enums",
    "// ============================================================",
    ""
  ];

  // Get types from the correct location in ABI schema
  const types = /** @type {Record<string, unknown>} */ (abi.types || {});
  const enumsObj = /** @type {Record<string, AbiEnum>} */ (
    types.enums || {}
  );

  // Generate enum types
  for (const [enumName, enumDef] of Object.entries(enumsObj)) {
    const variants = Object.entries(enumDef.variants || {});
    lines.push(`/** ${enumName} enum (${enumDef.repr}) */`);
    lines.push(`export type ${enumName} =`);
    for (let i = 0; i < variants.length; i++) {
      const [name, value] = variants[i];
      const suffix = i === variants.length - 1 ? ";" : "";
      lines.push(`  | ${value} // ${name}${suffix}`);
    }
    lines.push("");
  }

  // Generate constants for enum values
  lines.push("// ============================================================");
  lines.push("// Enum Constants");
  lines.push("// ============================================================");
  lines.push("");

  for (const [enumName, enumDef] of Object.entries(enumsObj)) {
    lines.push(`export const ${enumName} = {`);
    for (const [name, value] of Object.entries(enumDef.variants || {})) {
      lines.push(`  ${name}: ${value},`);
    }
    lines.push("} as const;");
    lines.push("");
  }

  // Generate struct interfaces
  lines.push("// ============================================================");
  lines.push("// Structs (for reference - actual memory layout in ABI JSON)");
  lines.push("// ============================================================");
  lines.push("");

  const structsObj = /** @type {Record<string, AbiStruct>} */ (
    types.structs || {}
  );
  for (const [structName, structDef] of Object.entries(structsObj)) {
    lines.push(`/** ${structName} (${structDef.sizeBytes} bytes) */`);
    lines.push(`export interface ${structName} {`);
    for (const field of structDef.fields || []) {
      const desc = field.description ? ` - ${field.description}` : "";
      lines.push(`  /** Offset: ${field.offsetBytes}${desc} */`);
      lines.push(`  ${field.name}: ${mapAbiTypeToTs(field.type)};`);
    }
    lines.push("}");
    lines.push("");
  }

  // Export info
  lines.push("// ============================================================");
  lines.push("// WASM Exports");
  lines.push("// ============================================================");
  lines.push("");

  const exports_ = /** @type {AbiExportEntry[]} */ (abi.exports || []);
  lines.push("export interface VerifiedCoreExports {");
  for (const exp of exports_) {
    const params = exp.params || [];
    const paramStr = params.map(p => `${p.name}: number`).join(", ");
    // Get return type from results array
    const results = exp.results || [];
    const returnType = results.length > 0 ? "number" : "void";
    lines.push(`  /** ${exp.description || exp.name} */`);
    lines.push(`  ${exp.name}(${paramStr}): ${returnType};`);
  }
  lines.push("}");
  lines.push("");

  // Import info - group by module
  lines.push("// ============================================================");
  lines.push("// WASM Imports (host must provide)");
  lines.push("// ============================================================");
  lines.push("");

  const imports = /** @type {AbiImportEntry[]} */ (abi.imports || []);

  // Group imports by module
  /** @type {Map<string, typeof imports>} */
  const importsByModule = new Map();
  for (const imp of imports) {
    const mod = imp.module || "env";
    if (!importsByModule.has(mod)) {
      importsByModule.set(mod, []);
    }
    importsByModule.get(mod).push(imp);
  }

  for (const [moduleName, moduleImports] of importsByModule) {
    const interfaceName = moduleName.replace(/[^a-zA-Z0-9]/g, "_");
    lines.push(`export interface ${interfaceName}Imports {`);
    for (const fn of moduleImports) {
      const params = fn.params || [];
      const paramStr = params.map(p => `${p.name}: number`).join(", ");
      const results = fn.results || [];
      const returnType = results.length > 0 ? "number" : "void";
      if (fn.description) {
        lines.push(`  /** ${fn.description} */`);
      }
      lines.push(`  ${fn.name}(${paramStr}): ${returnType};`);
    }
    lines.push("}");
    lines.push("");
  }

  // Generate bitmask constants
  const bitmasks = /** @type {Record<string, AbiBitmask>} */ (
    types.bitmasks || {}
  );
  if (Object.keys(bitmasks).length > 0) {
    lines.push("// ============================================================");
    lines.push("// Bitmask Constants");
    lines.push("// ============================================================");
    lines.push("");

    for (const [bitmaskName, bitmaskDef] of Object.entries(bitmasks)) {
      lines.push(`export const ${bitmaskName} = {`);
      for (const [bitName, bitIndex] of Object.entries(bitmaskDef.bits || {})) {
        lines.push(`  ${bitName}: 1 << ${bitIndex}, // bit ${bitIndex}`);
      }
      lines.push("} as const;");
      lines.push("");
    }
  }

  return lines.join("\n");
}

/**
 * Map ABI type to TypeScript type.
 * @param {string} abiType
 * @returns {string}
 */
function mapAbiTypeToTs(abiType) {
  const mapping = {
    u8: "number",
    u16: "number",
    u32: "number",
    u64: "bigint",
    i8: "number",
    i16: "number",
    i32: "number",
    i64: "bigint",
    ptr: "number",
    bool: "boolean"
  };
  return mapping[abiType] || "unknown";
}

/**
 * Map WASM type to TypeScript type.
 * @param {string} wasmType
 * @returns {string}
 */
function mapWasmTypeToTs(wasmType) {
  const mapping = {
    i32: "number",
    i64: "bigint",
    f32: "number",
    f64: "number",
    void: "void"
  };
  return mapping[wasmType] || "number";
}

main().catch((error) => {
  console.error("[package-dist] Error:", error.message);
  process.exitCode = 1;
});
