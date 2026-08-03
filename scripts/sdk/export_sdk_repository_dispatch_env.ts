#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";

const ENV_MAPPINGS = {
  core_repo: "AEGAEON_CORE_RELEASE_REPO",
  core_release_tag: "AEGAEON_CORE_RELEASE_TAG",
  manifest_path: "AEGAEON_CORE_MANIFEST_PATH",
  wasm_path: "AEGAEON_CORE_WASM_PATH",
  signature_path: "AEGAEON_CORE_SIGNATURE_PATH",
  public_key_path: "AEGAEON_CORE_PUBLIC_KEY_PATH",
};

function usage() {
  return [
    "Usage: node --experimental-strip-types " +
      "scripts/sdk/export_sdk_repository_dispatch_env.ts --payload <path>",
    "",
    "Environment fallback:",
    "  AEGAEON_DISPATCH_PAYLOAD_PATH",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    payload: process.env.AEGAEON_DISPATCH_PAYLOAD_PATH ?? null,
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

  if (!options.payload) {
    throw new Error(`Missing required option --payload\n\n${usage()}`);
  }

  return options;
}

function sanitizeValue(name, value) {
  if (typeof value !== "string" || value.length === 0) {
    return null;
  }
  if (/[\r\n\0]/u.test(value)) {
    throw new Error(`Payload field ${name} contains an unsupported control character`);
  }
  return value;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const payloadPath = path.resolve(options.payload);
  const payload = JSON.parse(await readFile(payloadPath, "utf8"));
  const clientPayload = payload?.client_payload;

  if (!clientPayload || typeof clientPayload !== "object" || Array.isArray(clientPayload)) {
    throw new Error("client_payload must be a JSON object");
  }

  const lines = [];
  for (const [sourceKey, envKey] of Object.entries(ENV_MAPPINGS)) {
    const value = sanitizeValue(sourceKey, clientPayload[sourceKey]);
    if (value !== null) {
      lines.push(`${envKey}=${value}`);
    }
  }

  const text = lines.length > 0 ? `${lines.join("\n")}\n` : "";
  writeFileSync(process.stdout.fd, text, "utf8");
}

main().catch((error) => {
  console.error("[export-sdk-dispatch-env] error:", error);
  process.exitCode = 1;
});
