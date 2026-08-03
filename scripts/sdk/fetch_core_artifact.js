#!/usr/bin/env node
/**
 * Fetch and verify the Verified Core WASM artefact.
 *
 * Usage example:
 *   node scripts/sdk/fetch_core_artifact.js \
 *     --manifest artifacts/verified-core/manifest.json \
 *     --wasm artifacts/verified-core/verified_core.wasm \
 *     --signature artifacts/verified-core/verified_core.wasm.sig \
 *     --public-key path/to/public.pem \
 *     --out-dir dist/verified-core
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";

/**
 * @typedef {Object} CliOptions
 * @property {string} manifest
 * @property {string} wasm
 * @property {string} outDir
 * @property {string | undefined} signature
 * @property {string | undefined} publicKey
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
    // Convert kebab-case to camelCase (e.g., --public-key → publicKey)
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    args.set(key, value);
    i += 1;
  }

  const required = [
    { key: "manifest", flag: "manifest" },
    { key: "wasm", flag: "wasm" },
    { key: "outDir", flag: "out-dir" },
  ];
  /** @type {CliOptions} */
  const options = {};
  for (const { key, flag } of required) {
    const value = args.get(key);
    if (!value) {
      throw new Error(`Missing required option --${flag}`);
    }
    options[key] = value;
  }
  options.signature = args.get("signature");
  options.publicKey = args.get("publicKey");

  if ((options.signature && !options.publicKey) || (!options.signature && options.publicKey)) {
    throw new Error("signature and publicKey must be provided together");
  }

  return options;
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
 * @param {string} dir
 */
async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

/**
 * @param {string} hashHex
 * @returns {string}
 */
function toIntegrity(hashHex) {
  const hashBuffer = Buffer.from(hashHex, "hex");
  return `sha256-${hashBuffer.toString("base64")}`;
}

/**
 * @param {Buffer} input
 * @returns {Buffer}
 */
function parseSignatureBuffer(input) {
  if (input.length === 64) {
    return input;
  }
  const asString = input.toString().trim();
  const base64Match = /^[A-Za-z0-9+/=]+$/;
  if (base64Match.test(asString)) {
    return Buffer.from(asString, "base64");
  }
  throw new Error("Unsupported signature format. Expected raw 64-byte buffer or base64 string.");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  const manifest = await readJson(options.manifest);
  if (!manifest.sha256) {
    throw new Error("Manifest is missing sha256 field.");
  }

  const wasm = await fs.readFile(options.wasm);
  const sha256 = createHash("sha256").update(wasm).digest("hex");
  if (sha256 !== manifest.sha256) {
    throw new Error(`sha256 mismatch: expected ${manifest.sha256}, actual ${sha256}`);
  }
  if (manifest.sha512) {
    const sha512 = createHash("sha512").update(wasm).digest("hex");
    if (sha512 !== manifest.sha512) {
      throw new Error(`sha512 mismatch: expected ${manifest.sha512}, actual ${sha512}`);
    }
  } else {
    console.warn("[fetch-core] manifest missing sha512, skipping verification");
  }

  const hasSignature = Boolean(options.signature && options.publicKey);
  if (hasSignature) {
    const signatureRaw = await fs.readFile(options.signature);
    const signature = parseSignatureBuffer(signatureRaw);
    const publicKeyPem = await fs.readFile(options.publicKey, "utf8");
    const publicKey = createPublicKey(publicKeyPem);

    const signatureValid = verifySignature(null, wasm, publicKey, signature);
    if (!signatureValid) {
      throw new Error("Ed25519 signature verification failed.");
    }
  } else {
    console.warn("[fetch-core] signature/public key not provided, skipping signature verification");
  }

  await ensureDir(options.outDir);
  const outputWasm = path.join(options.outDir, manifest.artifact ?? "verified_core.wasm");
  await fs.writeFile(outputWasm, wasm);
  await fs.copyFile(options.manifest, path.join(options.outDir, "manifest.json"));
  if (hasSignature) {
    await fs.copyFile(options.signature, path.join(options.outDir, "verified_core.wasm.sig"));
  }

  const integrity = toIntegrity(manifest.sha256);
  await fs.writeFile(path.join(options.outDir, "integrity.txt"), `${integrity}\n`, "utf8");

  console.log("[fetch-core] verified artefact stored in:", options.outDir);
  console.log("[fetch-core] version:", manifest.version ?? "unknown");
  if (manifest.source_commit) {
    console.log("[fetch-core] commit:", manifest.source_commit);
  }
}

main().catch((error) => {
  console.error("[fetch-core] error:", error);
  process.exitCode = 1;
});
