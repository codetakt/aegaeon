#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/managed-provider/managed-provider-evidence.json";
const DEFAULT_CLAIM_BOUNDARY_PATH = "spec/client-claim-boundary.current.json";

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types " +
      "scripts/sdk/build_sdk_managed_provider_evidence.ts --config <path> [options]",
    "",
    "Options:",
    "  --root <sdk-root>                 Workspace root (autodetected when omitted)",
    "  --config <path>                  Managed-provider config JSON",
    "  --claim-boundary <path>          Default: spec/client-claim-boundary.current.json",
    "  --out <path>                     Default: " +
      ".artifacts/managed-provider/managed-provider-evidence.json",
    "  --provider-class <name>          Default: commercial",
    "  --lane-name <name>               Default: external-provider-managed",
    "  --status <passed|failed>         Default: passed",
    "  --browser <path>                 Optional browser executable path",
    "  --hosted <true|false>            Default: true",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    config: null,
    claimBoundary: process.env.AEGAEON_CLIENT_CLAIM_BOUNDARY_PATH ?? DEFAULT_CLAIM_BOUNDARY_PATH,
    out: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_OUT ?? DEFAULT_OUT_PATH,
    providerClass: process.env.AEGAEON_MANAGED_PROVIDER_CLASS ?? "commercial",
    laneName: process.env.AEGAEON_MANAGED_PROVIDER_LANE ?? "external-provider-managed",
    status: process.env.AEGAEON_MANAGED_PROVIDER_STATUS ?? "passed",
    browser: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ?? process.env.CHROME_BIN ?? null,
    hosted: process.env.AEGAEON_MANAGED_PROVIDER_HOSTED ?? "true",
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
    if (!token.startsWith("--")) {
      continue;
    }
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
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

  if (!options.config) {
    throw new Error("--config is required");
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
      existsSync(path.join(current, "package.json")) &&
      existsSync(path.join(current, "packages"))
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

function parseBool(value, label) {
  if (/^(1|true|TRUE)$/.test(String(value))) {
    return true;
  }
  if (/^(0|false|FALSE)$/.test(String(value))) {
    return false;
  }
  throw new Error(`Expected boolean string for ${label}`);
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function shaHex(filePath) {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const configPath = path.resolve(rootDir, options.config);
  const claimBoundaryPath = path.resolve(rootDir, options.claimBoundary);
  const outPath = path.resolve(rootDir, options.out);

  const config = await readJson(configPath);
  const claimBoundary = await readJson(claimBoundaryPath);
  const evidence = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    source: {
      config_path: path.relative(rootDir, configPath),
      config_sha256: await shaHex(configPath),
      claim_boundary_path: path.relative(rootDir, claimBoundaryPath),
      claim_boundary_sha256: await shaHex(claimBoundaryPath),
      github_run_id: process.env.GITHUB_RUN_ID ?? null,
      github_workflow: process.env.GITHUB_WORKFLOW ?? null,
      github_repository: process.env.GITHUB_REPOSITORY ?? null,
      github_ref: process.env.GITHUB_REF_NAME ?? process.env.GITHUB_REF ?? null,
      github_sha: process.env.GITHUB_SHA ?? null,
      github_job: process.env.GITHUB_JOB ?? null,
    },
    provider: {
      name: String(config.providerName),
      class: String(options.providerClass),
      issuer: String(config.issuer),
      client_id: String(config.clientId),
      auth_method: String(config.authMethod),
    },
    lane: {
      name: String(options.laneName),
      hosted: parseBool(options.hosted, "hosted"),
      status: String(options.status),
      browser: options.browser ? String(options.browser) : null,
    },
    runtime: {
      default_profile: claimBoundary.default_profile,
      claim_phase: claimBoundary.claim_phase,
      promoted_client_slices: claimBoundary.promoted_client_slices.map((slice) => slice.name),
      compat_only_surfaces: claimBoundary.compat_only_surfaces.map((surface) => surface.name),
    },
  };

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  console.log(`[build-managed-provider-evidence] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error(
    "[build-managed-provider-evidence] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
