#!/usr/bin/env node
import { promises as fs } from "node:fs";
import path from "node:path";

function usage() {
  return [
    "Usage: node --experimental-strip-types " +
      "scripts/sdk/materialize_sdk_repository_dispatch_payload.ts \\",
    "  --event-type <type> --client-payload-json <json> --output <path>",
    "",
    "Environment fallbacks:",
    "  AEGAEON_DISPATCH_EVENT_TYPE",
    "  AEGAEON_DISPATCH_CLIENT_PAYLOAD",
    "  AEGAEON_DISPATCH_OUTPUT_PATH",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    eventType: process.env.AEGAEON_DISPATCH_EVENT_TYPE ?? null,
    clientPayloadJson: process.env.AEGAEON_DISPATCH_CLIENT_PAYLOAD ?? null,
    output: process.env.AEGAEON_DISPATCH_OUTPUT_PATH ?? null,
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

  for (const [field, flag] of [
    ["eventType", "event-type"],
    ["clientPayloadJson", "client-payload-json"],
    ["output", "output"],
  ]) {
    if (!options[field]) {
      throw new Error(`Missing required option --${flag}\n\n${usage()}`);
    }
  }

  return options;
}

function parseClientPayload(text) {
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid JSON for client payload: ${error}`);
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("client payload must be a JSON object");
  }
  return payload;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const payload = {
    event_type: options.eventType,
    client_payload: parseClientPayload(options.clientPayloadJson),
  };
  const outputPath = path.resolve(options.output);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  console.log(`[materialize-sdk-dispatch] wrote ${outputPath}`);
}

main().catch((error) => {
  console.error("[materialize-sdk-dispatch] error:", error);
  process.exitCode = 1;
});
