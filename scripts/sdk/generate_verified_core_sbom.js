#!/usr/bin/env node
/**
 * Generate a CycloneDX SBOM for the Verified Core WASM artifact.
 *
 * This SBOM documents the provenance and components of the formally verified
 * cryptographic core, including:
 * - F* source files and their verification status
 * - KaRaMeL extraction toolchain
 * - C-to-WASM compilation chain
 * - Host environment dependencies
 *
 * Usage:
 *   node scripts/sdk/generate_verified_core_sbom.js \
 *     --manifest artifacts/verified-core/manifest.json \
 *     --out artifacts/verified-core/verified-core-sbom.json
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

/**
 * @typedef {Object} CliOptions
 * @property {string} manifest
 * @property {string} out
 * @property {string | undefined} wasmPath
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

  const manifest = args.get("manifest");
  const out = args.get("out");
  if (!manifest || !out) {
    throw new Error("Required options: --manifest, --out");
  }

  return {
    manifest,
    out,
    wasmPath: args.get("wasm")
  };
}

/**
 * Generate a UUID v4 (random).
 * @returns {string}
 */
function generateUuid() {
  const bytes = new Uint8Array(16);
  globalThis.crypto?.getRandomValues?.(bytes) ??
    (() => {
      for (let i = 0; i < 16; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    })();
  // Set version (4) and variant (RFC 4122)
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
 * @template T
 * @param {string} filePath
 * @returns {Promise<T>}
 */
async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

/**
 * Generate the CycloneDX SBOM for Verified Core.
 * @param {Record<string, unknown>} manifest
 * @param {string | undefined} wasmPath
 * @returns {Promise<Record<string, unknown>>}
 */
async function generateSbom(manifest, wasmPath) {
  const timestamp = new Date().toISOString();
  const serialNumber = `urn:uuid:${generateUuid()}`;

  // Compute WASM hash if path is provided
  let wasmHash = manifest.sha256;
  if (wasmPath) {
    try {
      const wasmBytes = await fs.readFile(wasmPath);
      wasmHash = createHash("sha256").update(wasmBytes).digest("hex");
    } catch {
      // Use manifest hash as fallback
    }
  }

  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [
          {
            type: "application",
            name: "generate_verified_core_sbom.js",
            version: "1.0.0",
            description: "Aegaeon Verified Core SBOM generator"
          }
        ]
      },
      authors: [
        {
          name: "Aegaeon Development Team",
          email: "security@aegaeon.example"
        }
      ],
      component: {
        type: "library",
        "bom-ref": "verified-core-wasm",
        name: "verified_core.wasm",
        version: manifest.version ?? "1.0.0",
        description: "Formally verified cryptographic core compiled to WebAssembly",
        hashes: [
          {
            alg: "SHA-256",
            content: wasmHash
          }
        ],
        licenses: [
          {
            license: {
              id: "Apache-2.0"
            }
          }
        ],
        purl:
          `pkg:generic/aegaeon/verified-core@${manifest.version ?? "1.0.0"}` +
          `?source_commit=${manifest.source_commit}`,
        externalReferences: [
          {
            type: "vcs",
            url: "https://github.com/cariandrum22/aegaeon",
            comment: "Source repository"
          },
          {
            type: "build-meta",
            url: `git:${manifest.source_commit}`,
            comment: "Build source commit"
          }
        ],
        properties: [
          {
            name: "cdx:verified-core:generated_at",
            value: manifest.generated_at ?? timestamp
          },
          {
            name: "cdx:verified-core:sri",
            value: manifest.sri ?? ""
          },
          {
            name: "cdx:security:formal-verification",
            value: "F* (proofs checked by Z3 SMT solver)"
          },
          {
            name: "cdx:security:tcb",
            value: "F* type system, KaRaMeL extraction, WASI libc"
          }
        ]
      }
    },
    components: [
      // F* source modules
      {
        type: "library",
        "bom-ref": "fstar-pkce",
        name: "Pkce.fst",
        version: "1.0.0",
        description: "PKCE (RFC 7636) S256 challenge verification",
        purl: "pkg:generic/aegaeon/fstar-pkce@1.0.0",
        properties: [
          { name: "cdx:source:language", value: "F*" },
          { name: "cdx:verification:status", value: "verified" },
          { name: "cdx:verification:prover", value: "Z3" }
        ]
      },
      {
        type: "library",
        "bom-ref": "fstar-dpop",
        name: "Dpop.fst",
        version: "1.0.0",
        description: "DPoP (RFC 9449) proof validation",
        purl: "pkg:generic/aegaeon/fstar-dpop@1.0.0",
        properties: [
          { name: "cdx:source:language", value: "F*" },
          { name: "cdx:verification:status", value: "verified" },
          { name: "cdx:verification:prover", value: "Z3" }
        ]
      },
      {
        type: "library",
        "bom-ref": "fstar-claims-runtime",
        name: "VerifiedCore_Api_Claims_Runtime.fst",
        version: "1.0.0",
        description: "Claims-based JWT/DPoP verification runtime",
        purl: "pkg:generic/aegaeon/fstar-claims-runtime@1.0.0",
        properties: [
          { name: "cdx:source:language", value: "F*" },
          { name: "cdx:verification:status", value: "verified" },
          { name: "cdx:verification:prover", value: "Z3" }
        ]
      },
      // Build toolchain components
      {
        type: "application",
        "bom-ref": "fstar-compiler",
        name: "F* (FStar)",
        version: "2024.01.13",
        description: "Proof-oriented programming language and compiler",
        purl: "pkg:generic/fstar@2024.01.13",
        externalReferences: [
          { type: "website", url: "https://www.fstar-lang.org/" }
        ]
      },
      {
        type: "application",
        "bom-ref": "karamel",
        name: "KaRaMeL",
        version: "1.0.0",
        description: "F* to C extraction tool",
        purl: "pkg:generic/karamel@1.0.0",
        externalReferences: [
          { type: "vcs", url: "https://github.com/FStarLang/karamel" }
        ]
      },
      {
        type: "application",
        "bom-ref": "wasi-sdk",
        name: "WASI SDK",
        version: "21.0",
        description: "WebAssembly System Interface SDK (wasm32-wasi target)",
        purl: "pkg:generic/wasi-sdk@21.0",
        externalReferences: [
          { type: "vcs", url: "https://github.com/WebAssembly/wasi-sdk" }
        ]
      },
      // Host dependencies (provided at runtime)
      {
        type: "library",
        "bom-ref": "host-crypto-sha256",
        name: "Host SHA-256",
        version: "1.0.0",
        description: "Host-provided SHA-256 implementation (Node.js crypto or Web Crypto API)",
        purl: "pkg:generic/aegaeon/host-crypto-sha256@1.0.0",
        scope: "optional",
        properties: [
          { name: "cdx:runtime:provided-by", value: "host" },
          { name: "cdx:crypto:algorithm", value: "SHA-256" }
        ]
      },
      {
        type: "library",
        "bom-ref": "host-crypto-ed25519",
        name: "Host Ed25519",
        version: "1.0.0",
        description: "Host-provided Ed25519 signature verification",
        purl: "pkg:generic/aegaeon/host-crypto-ed25519@1.0.0",
        scope: "optional",
        properties: [
          { name: "cdx:runtime:provided-by", value: "host" },
          { name: "cdx:crypto:algorithm", value: "Ed25519" }
        ]
      },
      {
        type: "library",
        "bom-ref": "host-crypto-es256",
        name: "Host ES256",
        version: "1.0.0",
        description: "Host-provided ES256 (P-256/secp256r1 + SHA-256) signature verification",
        purl: "pkg:generic/aegaeon/host-crypto-es256@1.0.0",
        scope: "optional",
        properties: [
          { name: "cdx:runtime:provided-by", value: "host" },
          { name: "cdx:crypto:algorithm", value: "ES256 (ECDSA P-256 + SHA-256)" }
        ]
      }
    ],
    dependencies: [
      {
        ref: "verified-core-wasm",
        dependsOn: [
          "fstar-pkce",
          "fstar-dpop",
          "fstar-claims-runtime",
          "fstar-compiler",
          "karamel",
          "wasi-sdk"
        ]
      },
      {
        ref: "fstar-pkce",
        dependsOn: ["host-crypto-sha256"]
      },
      {
        ref: "fstar-dpop",
        dependsOn: ["host-crypto-sha256", "host-crypto-ed25519", "host-crypto-es256"]
      },
      {
        ref: "fstar-claims-runtime",
        dependsOn: ["host-crypto-sha256", "host-crypto-ed25519", "host-crypto-es256"]
      }
    ],
    formulation: [
      {
        "bom-ref": "build-process",
        components: [
          {
            type: "data",
            name: "F* Source Files",
            description: "Formally verified F* source modules",
            data: [
              { type: "source-code", name: "proofs/fstar/verified-core/*.fst" }
            ]
          },
          {
            type: "data",
            name: "C Extraction Output",
            description: "C code extracted by KaRaMeL",
            data: [
              { type: "source-code", name: "generated/lowstar/verified-core/c/*.c" },
              { type: "source-code", name: "generated/lowstar/verified-core/c/*.h" }
            ]
          },
          {
            type: "data",
            name: "WASM Binary",
            description: "Final WebAssembly binary",
            data: [
              { type: "other", name: "generated/lowstar/verified-core/wasm/verified_core.wasm" }
            ]
          }
        ]
      }
    ],
    vulnerabilities: []
  };

  // Add signature info if present in manifest
  if (manifest.signature) {
    sbom.metadata.component.properties.push(
      {
        name: "cdx:verified-core:signature:algorithm",
        value: manifest.signature.algorithm
      },
      {
        name: "cdx:verified-core:signature:public_key_fingerprint",
        value: manifest.signature.public_key_fingerprint
      },
      {
        name: "cdx:verified-core:signature:signed_at",
        value: manifest.signature.signed_at
      }
    );
  }

  return sbom;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  console.log("[sbom-gen] Loading manifest...");
  const manifest = await readJson(options.manifest);

  console.log("[sbom-gen] Generating CycloneDX SBOM...");
  const sbom = await generateSbom(manifest, options.wasmPath);

  // Ensure output directory exists
  const outDir = path.dirname(options.out);
  await fs.mkdir(outDir, { recursive: true });

  // Write SBOM
  await fs.writeFile(options.out, JSON.stringify(sbom, null, 2) + "\n", "utf8");
  console.log(`[sbom-gen] SBOM written to: ${options.out}`);

  // Print summary
  console.log("[sbom-gen] Summary:");
  console.log(`  Serial: ${sbom.serialNumber}`);
  console.log(`  Components: ${sbom.components.length}`);
  console.log(`  Main component: ${sbom.metadata.component.name}`);
  console.log(`  SHA-256: ${manifest.sha256}`);
}

main().catch((error) => {
  console.error("[sbom-gen] Error:", error.message);
  process.exitCode = 1;
});
