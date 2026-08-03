#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { createPublicKey } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

function usage() {
  return [
    "Usage: node --experimental-strip-types scripts/sdk/materialize_verified_core_public_key.ts \\",
    "  --output <path> [--public-key <pem-or-base64-pem> | --op-reference <op://...>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_VERIFIED_CORE_PUBKEY",
    "  AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF",
    "  AEGAEON_VERIFIED_CORE_PUBKEY_OUTPUT",
    "  AEGAEON_OP_SERVICE_ACCOUNT_TOKEN",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    publicKey: process.env.AEGAEON_VERIFIED_CORE_PUBKEY ?? null,
    opReference: process.env.AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF ?? null,
    output: process.env.AEGAEON_VERIFIED_CORE_PUBKEY_OUTPUT ?? null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
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

  if (!options.output) {
    throw new Error(`Missing required option --output\n\n${usage()}`);
  }
  if (!options.publicKey && !options.opReference) {
    throw new Error(`Either --public-key or --op-reference is required.\n\n${usage()}`);
  }
  if (options.publicKey && options.opReference) {
    throw new Error("Provide only one of --public-key or --op-reference");
  }

  return options;
}

async function readPublicKeyFromOnePassword(opReference) {
  try {
    const { stdout } = await execFile("op", ["read", opReference], {
      env: process.env,
      maxBuffer: 1024 * 1024,
    });
    const value = stdout.trim();
    if (value.length === 0) {
      throw new Error("1Password returned an empty public key");
    }
    return value;
  } catch (error) {
    throw new Error(`Failed to read public key from 1Password (${opReference}): ${error}`);
  }
}

function decodePublicKey(text) {
  const trimmed = text.trim();
  if (trimmed.includes("BEGIN PUBLIC KEY")) {
    return `${trimmed}\n`;
  }

  let decoded;
  try {
    decoded = Buffer.from(trimmed, "base64").toString("utf8");
  } catch (error) {
    throw new Error(`Failed to decode base64 public key: ${error}`);
  }

  if (!decoded.includes("BEGIN PUBLIC KEY")) {
    throw new Error("public key must be PEM text or base64-encoded PEM");
  }

  return decoded.endsWith("\n") ? decoded : `${decoded}\n`;
}

function normalizePem(pem) {
  try {
    const keyObject = createPublicKey(pem);
    return keyObject.export({ type: "spki", format: "pem" }).toString("utf8");
  } catch (error) {
    throw new Error(`Invalid Ed25519 public key: ${error}`);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const outputPath = path.resolve(options.output);
  const inputText = options.publicKey ?? await readPublicKeyFromOnePassword(options.opReference);
  const pem = normalizePem(decodePublicKey(inputText));
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, pem, "utf8");
  console.log(`[materialize-verified-core-public-key] wrote ${outputPath}`);
}

main().catch((error) => {
  console.error("[materialize-verified-core-public-key] error:", error);
  process.exitCode = 1;
});
