#!/usr/bin/env node

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");

const TOOL_MAP = {
  "fetch-core": path.join(MODULE_DIR, "fetch-core.js"),
  "download-core:release": path.join(MODULE_DIR, "download-core-release.js"),
  "download:admin-sdk-evidence": path.join(MODULE_DIR, "download-admin-sdk-evidence.js"),
  "download:managed-provider-evidence": path.join(
    MODULE_DIR,
    "download-managed-provider-evidence.js",
  ),
  "import:managed-provider-evidence": path.join(MODULE_DIR, "import-managed-provider-evidence.js"),
  "run:admin-sdk-evidence": {
    script: path.join(MODULE_DIR, "run-hosted-evidence.js"),
    args: ["--kind", "admin-sdk"],
  },
  "run:managed-provider-evidence": {
    script: path.join(MODULE_DIR, "run-hosted-evidence.js"),
    args: ["--kind", "managed-provider"],
  },
  "run:client-evidence-gates": path.join(MODULE_DIR, "run-client-evidence-gates.js"),
  "run:real-tenant-readiness": path.join(MODULE_DIR, "run-real-tenant-readiness.js"),
  "verify-core": path.join(MODULE_DIR, "verify-core.js"),
  "materialize:sdk-dispatch": path.join(MODULE_DIR, "materialize-sdk-dispatch-payload.js"),
  "export:sdk-dispatch-env": path.join(MODULE_DIR, "export-sdk-dispatch-env.js"),
  "materialize:verified-core-public-key": path.join(
    MODULE_DIR,
    "materialize-verified-core-public-key.js",
  ),
  "audit:branch-protection": path.join(MODULE_DIR, "check-branch-protection.js"),
  "audit:external-boundary-naming": path.join(MODULE_DIR, "check-external-boundary-naming.js"),
  "audit:hosted-evidence-sources": path.join(MODULE_DIR, "check-hosted-evidence-sources.js"),
  "audit:repo-settings": path.join(MODULE_DIR, "check-repository-settings.js"),
  "audit:release-custody": path.join(MODULE_DIR, "check-release-custody.js"),
  "audit:strict-types": path.join(MODULE_DIR, "check-strict-types.js"),
  "audit:workflow-inventory": path.join(MODULE_DIR, "check-workflow-inventory.js"),
  "audit:client-claim-promotion": path.join(MODULE_DIR, "check-client-claim-promotion.js"),
  "audit:released-client-claim": path.join(MODULE_DIR, "check-released-client-claim-activation.js"),
  "audit:released-client-readiness": path.join(MODULE_DIR, "check-released-client-readiness.js"),
  "audit:managed-provider": path.join(MODULE_DIR, "check-managed-provider-readiness.js"),
  "audit:no-js-source": path.join(MODULE_DIR, "check-no-js-source.js"),
  "validate:release-attestation-signature": path.join(
    MODULE_DIR,
    "check-release-attestation-signature.js",
  ),
  "build:managed-provider-evidence": path.join(MODULE_DIR, "build-managed-provider-evidence.js"),
  "release:manifest": path.join(MODULE_DIR, "build-publish-manifest.js"),
  "release:sbom": path.join(MODULE_DIR, "build-workspace-sbom.js"),
  "release:attestation": path.join(MODULE_DIR, "build-release-attestation.js"),
  "release:client-claim-report": path.join(MODULE_DIR, "build-released-client-claim-report.js"),
  "release:publication-org-rollout-report": path.join(
    MODULE_DIR,
    "build-publication-org-rollout-report.js",
  ),
  "release:hosted-readiness-report": path.join(
    MODULE_DIR,
    "build-hosted-release-readiness-report.js",
  ),
  "release:publication-bundle": path.join(MODULE_DIR, "build-release-publication-bundle.js"),
} as const satisfies Record<string, string | { script: string; args?: string[] }>;

function usage() {
  const supportedTools = Object.keys(TOOL_MAP)
    .sort()
    .map((toolName) => `  - ${toolName}`)
    .join("\n");
  return [
    "Usage: node dist-tools/exec-tool.js <tool> [-- <args...>]",
    "",
    "Supported tools:",
    supportedTools,
  ].join("\n");
}

function parseInvocation(argv: string[]) {
  const [toolName, ...rest] = argv;
  if (!toolName || toolName === "--help" || toolName === "-h") {
    process.stdout.write(`${usage()}\n`);
    process.exit(0);
  }
  const args = rest[0] === "--" ? rest.slice(1) : rest;
  return { toolName, args };
}

async function main() {
  const { toolName, args } = parseInvocation(process.argv.slice(2));
  const toolSpec = TOOL_MAP[toolName as keyof typeof TOOL_MAP];
  if (!toolSpec) {
    throw new Error(`Unknown tool '${toolName}'.\n\n${usage()}`);
  }
  const scriptPath = typeof toolSpec === "string" ? toolSpec : toolSpec.script;
  const prefixArgs = typeof toolSpec === "string" ? [] : (toolSpec.args ?? []);

  const child = spawn(process.execPath, [scriptPath, ...prefixArgs, ...args], {
    cwd: ROOT_DIR,
    env: process.env,
    stdio: "inherit",
  });

  await new Promise<void>((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal) {
        reject(new Error(`Tool '${toolName}' terminated by signal ${signal}`));
        return;
      }
      if (code !== 0) {
        reject(new Error(`Tool '${toolName}' exited with status ${code}`));
        return;
      }
      resolve();
    });
  });
}

main().catch((error) => {
  process.stderr.write(`[exec-tool] ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
