#!/usr/bin/env node
import { promises as fs } from "node:fs";
import path from "node:path";

function usage() {
  return [
    "Usage: node --experimental-strip-types " +
      "scripts/sdk/build_sdk_repository_dispatch_payload.ts \\",
    "  --core-repo <owner/repo> --core-release-tag <tag> --source-commit <sha> [options]",
    "",
    "Options:",
    "  --event-type <type>          Default: verified-core-release",
    "  --source-workflow <name>     Default: Verified Core Release",
    "  --source-run-id <id>         Optional GitHub Actions run id",
    "  --release-url <url>          Optional GitHub Release URL",
    "  --generated-at <iso-8601>    Optional timestamp override",
    "  --output <path>              Write JSON payload to the given file",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    coreRepo: null,
    coreReleaseTag: null,
    sourceCommit: null,
    eventType: "verified-core-release",
    sourceWorkflow: "Verified Core Release",
    sourceRunId: null,
    releaseUrl: null,
    generatedAt: null,
    output: null,
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
    ["coreRepo", "core-repo"],
    ["coreReleaseTag", "core-release-tag"],
    ["sourceCommit", "source-commit"],
  ]) {
    if (!options[field]) {
      throw new Error(`Missing required option --${flag}\n\n${usage()}`);
    }
  }

  return options;
}

function buildPayload(options) {
  const clientPayload = {
    core_repo: options.coreRepo,
    core_release_tag: options.coreReleaseTag,
    source_commit: options.sourceCommit,
    source_workflow: options.sourceWorkflow,
    artifact_bundle: "github-release",
    generated_at: options.generatedAt ?? new Date().toISOString(),
  };

  if (options.sourceRunId) {
    clientPayload.source_run_id = options.sourceRunId;
  }
  if (options.releaseUrl) {
    clientPayload.release_url = options.releaseUrl;
  }

  return {
    event_type: options.eventType,
    client_payload: clientPayload,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const payload = buildPayload(options);
  const text = `${JSON.stringify(payload, null, 2)}\n`;

  if (options.output) {
    const outputPath = path.resolve(options.output);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, text, "utf8");
    console.log(`[sdk-dispatch-payload] wrote ${outputPath}`);
  } else {
    process.stdout.write(text);
  }
}

main().catch((error) => {
  console.error("[sdk-dispatch-payload] error:", error);
  process.exitCode = 1;
});
