#!/usr/bin/env node
/**
 * Sign the Verified Core WASM artifact using Ed25519.
 *
 * This script can:
 * - Generate a new Ed25519 key pair (for development/testing)
 * - Sign a WASM binary with an existing private key
 * - Output the signature in various formats
 * - Optionally update the manifest with signature metadata
 *
 * Usage examples:
 *
 *   # Generate a new key pair (for development)
 *   node scripts/sdk/sign_core_artifact.js --generate-keys \
 *     --out-private keys/signing.pem --out-public keys/signing.pub.pem
 *
 *   # Sign an artifact with an existing key
 *   node scripts/sdk/sign_core_artifact.js \
 *     --wasm artifacts/verified-core/verified_core.wasm \
 *     --private-key keys/signing.pem \
 *     --out-signature artifacts/verified-core/verified_core.wasm.sig \
 *     --out-manifest artifacts/verified-core/manifest.json
 *
 *   # Full pipeline: sign and update manifest
 *   node scripts/sdk/sign_core_artifact.js \
 *     --wasm artifacts/verified-core/verified_core.wasm \
 *     --manifest artifacts/verified-core/manifest.json \
 *     --private-key keys/signing.pem \
 *     --out-signature artifacts/verified-core/verified_core.wasm.sig \
 *     --update-manifest
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import {
  createHash,
  generateKeyPairSync,
  sign,
  createPrivateKey,
  createPublicKey
} from "node:crypto";

/**
 * @typedef {Object} CliOptions
 * @property {boolean} generateKeys
 * @property {string | undefined} outPrivate
 * @property {string | undefined} outPublic
 * @property {string | undefined} wasm
 * @property {string | undefined} manifest
 * @property {string | undefined} privateKey
 * @property {string | undefined} outSignature
 * @property {boolean} updateManifest
 * @property {"raw" | "base64" | "hex"} signatureFormat
 */

/**
 * @param {string[]} argv
 * @returns {CliOptions}
 */
function parseArgs(argv) {
  /** @type {CliOptions} */
  const options = {
    generateKeys: false,
    updateManifest: false,
    signatureFormat: "raw"
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;

    const key = token.slice(2);

    // Boolean flags
    if (key === "generate-keys") {
      options.generateKeys = true;
      continue;
    }
    if (key === "update-manifest") {
      options.updateManifest = true;
      continue;
    }

    // Value options
    const value = argv[i + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }

    switch (key) {
      case "out-private":
        options.outPrivate = value;
        break;
      case "out-public":
        options.outPublic = value;
        break;
      case "wasm":
        options.wasm = value;
        break;
      case "manifest":
        options.manifest = value;
        break;
      case "private-key":
        options.privateKey = value;
        break;
      case "out-signature":
        options.outSignature = value;
        break;
      case "signature-format":
        if (!["raw", "base64", "hex"].includes(value)) {
          throw new Error(`Invalid signature format: ${value}. Must be raw, base64, or hex.`);
        }
        options.signatureFormat = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    i += 1;
  }

  // Validate options
  if (options.generateKeys) {
    if (!options.outPrivate || !options.outPublic) {
      throw new Error("--generate-keys requires --out-private and --out-public");
    }
  } else {
    if (!options.wasm || !options.privateKey || !options.outSignature) {
      throw new Error("Signing requires --wasm, --private-key, and --out-signature");
    }
  }

  return options;
}

/**
 * Generate a new Ed25519 key pair.
 * @returns {{ privateKey: string, publicKey: string }}
 */
function generateEd25519KeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem"
    }
  });

  return { publicKey, privateKey };
}

/**
 * Sign data with an Ed25519 private key.
 * @param {Buffer} data
 * @param {string} privateKeyPem
 * @returns {Buffer}
 */
function signData(data, privateKeyPem) {
  const privateKey = createPrivateKey(privateKeyPem);
  return sign(null, data, privateKey);
}

/**
 * Get the public key from a private key.
 * @param {string} privateKeyPem
 * @returns {string}
 */
function getPublicKeyFromPrivate(privateKeyPem) {
  const privateKey = createPrivateKey(privateKeyPem);
  const publicKey = createPublicKey(privateKey);
  return publicKey.export({ type: "spki", format: "pem" });
}

/**
 * Format a signature buffer according to the specified format.
 * @param {Buffer} signature
 * @param {"raw" | "base64" | "hex"} format
 * @returns {Buffer | string}
 */
function formatSignature(signature, format) {
  switch (format) {
    case "base64":
      return signature.toString("base64");
    case "hex":
      return signature.toString("hex");
    case "raw":
    default:
      return signature;
  }
}

/**
 * Compute the public key fingerprint (SHA-256 of the SPKI-encoded public key).
 * @param {string} publicKeyPem
 * @returns {string}
 */
function computePublicKeyFingerprint(publicKeyPem) {
  const keyObj = createPublicKey(publicKeyPem);
  const spki = keyObj.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spki).digest("hex");
}

/**
 * Ensure the parent directory exists.
 * @param {string} filePath
 */
async function ensureParentDir(filePath) {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
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
 * @param {string} filePath
 * @param {unknown} data
 */
async function writeJson(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2) + "\n", "utf8");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  // Key generation mode
  if (options.generateKeys) {
    console.log("[sign-core] Generating Ed25519 key pair...");
    const { publicKey, privateKey } = generateEd25519KeyPair();

    await ensureParentDir(options.outPrivate);
    await ensureParentDir(options.outPublic);

    await fs.writeFile(options.outPrivate, privateKey, { mode: 0o600 });
    await fs.writeFile(options.outPublic, publicKey, { mode: 0o644 });

    const fingerprint = computePublicKeyFingerprint(publicKey);

    console.log("[sign-core] Key pair generated:");
    console.log(`  Private key: ${options.outPrivate}`);
    console.log(`  Public key:  ${options.outPublic}`);
    console.log(`  Fingerprint: ${fingerprint}`);
    console.log(
      "\n[sign-core] WARNING: Keep the private key secure! Do not commit it to version control.",
    );
    return;
  }

  // Signing mode
  console.log("[sign-core] Loading WASM artifact...");
  const wasm = await fs.readFile(options.wasm);
  console.log(`[sign-core] Artifact size: ${wasm.length} bytes`);

  console.log("[sign-core] Loading private key...");
  const privateKeyPem = await fs.readFile(options.privateKey, "utf8");

  console.log("[sign-core] Signing artifact with Ed25519...");
  const signature = signData(wasm, privateKeyPem);

  if (signature.length !== 64) {
    throw new Error(`Unexpected signature length: ${signature.length} (expected 64 for Ed25519)`);
  }

  // Get public key for fingerprint
  const publicKeyPem = getPublicKeyFromPrivate(privateKeyPem);
  const fingerprint = computePublicKeyFingerprint(publicKeyPem);

  // Write signature
  await ensureParentDir(options.outSignature);
  const formattedSignature = formatSignature(signature, options.signatureFormat);
  if (typeof formattedSignature === "string") {
    await fs.writeFile(options.outSignature, formattedSignature + "\n", "utf8");
  } else {
    await fs.writeFile(options.outSignature, formattedSignature);
  }

  console.log("[sign-core] Signature generated:");
  console.log(`  Signature file: ${options.outSignature}`);
  console.log(`  Format: ${options.signatureFormat}`);
  console.log(`  Public key fingerprint: ${fingerprint}`);

  // Update manifest if requested
  if (options.updateManifest && options.manifest) {
    console.log("[sign-core] Updating manifest with signature metadata...");
    const manifest = await readJson(options.manifest);

    manifest.signature = {
      algorithm: "Ed25519",
      file: path.basename(options.outSignature),
      format: options.signatureFormat,
      public_key_fingerprint: fingerprint,
      signed_at: new Date().toISOString()
    };

    await writeJson(options.manifest, manifest);
    console.log(`[sign-core] Manifest updated: ${options.manifest}`);
  }

  // Compute artifact hash for verification
  const sha256 = createHash("sha256").update(wasm).digest("hex");
  console.log(`[sign-core] Artifact SHA-256: ${sha256}`);

  console.log("[sign-core] Done.");
}

main().catch((error) => {
  console.error("[sign-core] Error:", error.message);
  process.exitCode = 1;
});
