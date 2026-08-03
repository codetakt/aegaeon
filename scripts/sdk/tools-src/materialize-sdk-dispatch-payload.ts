import { promises as fs } from "node:fs";
import path from "node:path";

type DispatchClientPayload = Record<string, unknown>;

type MaterializeSdkDispatchPayload = {
  event_type: string;
  client_payload: DispatchClientPayload;
};

type MaterializeSdkDispatchPayloadOptions = {
  eventType: string | null;
  clientPayloadJson: string | null;
  output: string | null;
};

function usage(): string {
  return [
    "Usage: node dist-tools/materialize-sdk-dispatch-payload.js \\",
    "  --event-type <type> --client-payload-json <json> --output <path>",
    "",
    "Environment fallbacks:",
    "  AEGAEON_DISPATCH_EVENT_TYPE",
    "  AEGAEON_DISPATCH_CLIENT_PAYLOAD",
    "  AEGAEON_DISPATCH_OUTPUT_PATH",
  ].join("\n");
}

function parseArgs(argv: string[]): MaterializeSdkDispatchPayloadOptions {
  const options: MaterializeSdkDispatchPayloadOptions = {
    eventType: process.env.AEGAEON_DISPATCH_EVENT_TYPE ?? null,
    clientPayloadJson: process.env.AEGAEON_DISPATCH_CLIENT_PAYLOAD ?? null,
    output: process.env.AEGAEON_DISPATCH_OUTPUT_PATH ?? null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) {
      continue;
    }
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (!token.startsWith("--")) {
      continue;
    }
    const key = token!.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    switch (key) {
      case "event-type":
        options.eventType = value;
        break;
      case "client-payload-json":
        options.clientPayloadJson = value;
        break;
      case "output":
        options.output = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  if (!options.eventType) {
    throw new Error(`Missing required option --event-type\n\n${usage()}`);
  }
  if (!options.clientPayloadJson) {
    throw new Error(`Missing required option --client-payload-json\n\n${usage()}`);
  }
  if (!options.output) {
    throw new Error(`Missing required option --output\n\n${usage()}`);
  }

  return options;
}

function parseClientPayload(text: string): DispatchClientPayload {
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid JSON for client payload: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("client payload must be a JSON object");
  }
  return payload as DispatchClientPayload;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const payload: MaterializeSdkDispatchPayload = {
    event_type: options.eventType!,
    client_payload: parseClientPayload(options.clientPayloadJson!),
  };
  const outputPath = path.resolve(options.output!);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  console.log(`[materialize-sdk-dispatch] wrote ${outputPath}`);
}

main().catch((error) => {
  console.error("[materialize-sdk-dispatch] error:", error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
