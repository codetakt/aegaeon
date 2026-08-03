#!/usr/bin/env node
import {
  constants,
  createHash,
  createPublicKey,
  verify as verifyBuffer,
} from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_ATTESTATION_PATH = ".artifacts/release/release-attestation.json";
const DEFAULT_DESCRIPTOR_PATH = ".artifacts/release/release-attestation.signature.json";

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types",
    "    scripts/sdk/check_sdk_release_attestation_signature.ts [options]",
    "",
    "Options:",
    "  --root <sdk-root>              Workspace root (autodetected when omitted)",
    "  --attestation <path>           Default: .artifacts/release/release-attestation.json",
    "  --descriptor <path>            Default:",
    "                                   .artifacts/release/release-attestation.signature.json",
    "  --require-signed               Fail when the attestation is unsigned",
    "",
    "Environment fallbacks:",
    "  AEGAEON_SDK_ROOT",
    "  AEGAEON_RELEASE_ATTESTATION_OUT",
    "  AEGAEON_RELEASE_ATTESTATION_SIGNATURE_DESCRIPTOR_OUT",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    attestation: process.env.AEGAEON_RELEASE_ATTESTATION_OUT ?? DEFAULT_ATTESTATION_PATH,
    descriptor:
      process.env.AEGAEON_RELEASE_ATTESTATION_SIGNATURE_DESCRIPTOR_OUT ?? DEFAULT_DESCRIPTOR_PATH,
    requireSigned: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") {
      continue;
    }
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (token === "--require-signed") {
      options.requireSigned = true;
      continue;
    }
    if (!token.startsWith("--")) {
      continue;
    }
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(key in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[key] = value;
    index += 1;
  }

  return options;
}

function findWorkspaceRoot(explicitRoot) {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR);
  while (true) {
    if (
      existsSync(path.join(current, "package.json"))
      && existsSync(path.join(current, "packages"))
    ) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function shaHex(filePath) {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

function detectVerifyAlgorithm(publicKey, keyType, label) {
  switch (keyType) {
    case "ed25519":
      if (label !== "ed25519") {
        throw new Error(`Descriptor algorithm mismatch for ${keyType}: ${label}`);
      }
      return { algorithm: null, key: publicKey };
    case "rsa":
      if (label !== "rsa-sha256") {
        throw new Error(`Descriptor algorithm mismatch for ${keyType}: ${label}`);
      }
      return { algorithm: "sha256", key: publicKey };
    case "rsa-pss":
      if (label !== "rsa-pss-sha256") {
        throw new Error(`Descriptor algorithm mismatch for ${keyType}: ${label}`);
      }
      return {
        algorithm: "sha256",
        key: {
          key: publicKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
      };
    case "ec":
      if (label !== "ecdsa-sha256") {
        throw new Error(`Descriptor algorithm mismatch for ${keyType}: ${label}`);
      }
      return { algorithm: "sha256", key: publicKey };
    default:
      throw new Error(`Unsupported key type ${keyType}`);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const attestationPath = path.resolve(rootDir, options.attestation);
  const descriptorPath = path.resolve(rootDir, options.descriptor);
  const attestation = await readJson(attestationPath);

  if (!attestation.publication?.signed_release_attestation_present) {
    if (options.requireSigned) {
      throw new Error(
        "Signed release attestation is required but the attestation is marked unsigned",
      );
    }
    if (existsSync(descriptorPath)) {
      throw new Error("Signature descriptor exists but attestation is marked unsigned");
    }
    console.log(
      `[ok] unsigned release attestation permitted for ${path.relative(rootDir, attestationPath)}`,
    );
    return;
  }

  const descriptor = await readJson(descriptorPath);
  if (descriptor.signed_release_attestation_present !== true) {
    throw new Error("Signature descriptor must indicate a signed release attestation");
  }

  const signaturePath = path.resolve(rootDir, descriptor.signature_path);
  const publicKeyPath = path.resolve(rootDir, descriptor.public_key_path);
  const attestationDigest = await shaHex(attestationPath);
  const descriptorAttestationPath = path.resolve(rootDir, descriptor.attestation_path);
  if (descriptorAttestationPath !== attestationPath) {
    throw new Error(
      "Signature descriptor attestation_path does not match the attestation under verification",
    );
  }
  if (descriptor.attestation_sha256 !== attestationDigest) {
    throw new Error("Attestation SHA-256 mismatch");
  }
  if (descriptor.signature_sha256 !== await shaHex(signaturePath)) {
    throw new Error("Signature SHA-256 mismatch");
  }
  if (descriptor.public_key_sha256 !== await shaHex(publicKeyPath)) {
    throw new Error("Public key SHA-256 mismatch");
  }

  const signatureBase64 = (await fs.readFile(signaturePath, "utf8")).trim();
  const publicKeyPem = await fs.readFile(publicKeyPath, "utf8");
  const publicKey = createPublicKey(publicKeyPem);
  const attestationBytes = await fs.readFile(attestationPath);
  const { algorithm, key } = detectVerifyAlgorithm(
    publicKey,
    descriptor.key_type,
    descriptor.signature_algorithm,
  );
  const verified = verifyBuffer(
    algorithm,
    attestationBytes,
    key,
    Buffer.from(signatureBase64, "base64"),
  );
  if (!verified) {
    throw new Error("Detached signature verification failed");
  }

  const relativeAttestationPath = path.relative(rootDir, attestationPath);
  console.log(
    "[ok] verified detached release attestation signature for",
    relativeAttestationPath,
  );
}

main().catch((error) => {
  console.error(
    "[check-release-attestation-signature] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
