import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/managed-provider/managed-provider-evidence.json";
const DEFAULT_CLAIM_BOUNDARY_PATH = "spec/client-claim-boundary.current.json";

type ManagedProviderEvidenceOptions = {
  root: string | null;
  config: string | null;
  claimBoundary: string;
  out: string;
  providerClass: string;
  laneName: string;
  status: string;
  browser: string | null;
  hosted: string;
};

type ManagedProviderConfig = {
  providerName: string;
  issuer: string;
  clientId: string;
  authMethod: string;
};

type NamedSurface = {
  name: string;
};

type ClientClaimBoundary = {
  default_profile: string;
  claim_phase: string;
  promoted_client_slices: NamedSurface[];
  compat_only_surfaces: NamedSurface[];
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/build-managed-provider-evidence.js --config <path> [options]",
    "",
    "Options:",
    "  --root <sdk-root>                 Workspace root (autodetected when omitted)",
    "  --config <path>                  Managed-provider config JSON",
    "  --claim-boundary <path>          Default: spec/client-claim-boundary.current.json",
    "  --out <path>                     Default: .artifacts/managed-provider/managed-provider-evidence.json",
    "  --provider-class <name>          Default: commercial",
    "  --lane-name <name>               Default: external-provider-managed",
    "  --status <passed|failed>         Default: passed",
    "  --browser <path>                 Optional browser executable path",
    "  --hosted <true|false>            Default: true",
  ].join("\n");
}

function parseArgs(argv: string[]): ManagedProviderEvidenceOptions {
  const options: ManagedProviderEvidenceOptions = {
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
    if (!token || token === "--") {
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
    const camelKey = rawKey.replace(/-([a-z])/g, (_, char: string) => char.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(camelKey in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[camelKey as keyof ManagedProviderEvidenceOptions] = value;
    index += 1;
  }

  if (!options.config) {
    throw new Error("--config is required");
  }

  return options;
}

function findWorkspaceRoot(explicitRoot: string | null): string {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR);
  while (true) {
    if (existsSync(path.join(current, "package.json")) && existsSync(path.join(current, "packages"))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

function parseBool(value: string, label: string): boolean {
  if (/^(1|true|TRUE)$/.test(value)) {
    return true;
  }
  if (/^(0|false|FALSE)$/.test(value)) {
    return false;
  }
  throw new Error(`Expected boolean string for ${label}`);
}

function ensureRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Expected object for ${label}`);
  }
  return value as Record<string, unknown>;
}

function ensureString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureNamedSurfaceArray(value: unknown, label: string): NamedSurface[] {
  if (!Array.isArray(value)) {
    throw new Error(`Expected array for ${label}`);
  }
  return value.map((entry, index) => {
    const record = ensureRecord(entry, `${label}[${index}]`);
    return { name: ensureString(record.name, `${label}[${index}].name`) };
  });
}

async function readJson(filePath: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as unknown;
}

function normalizeConfig(value: unknown): ManagedProviderConfig {
  const record = ensureRecord(value, "managed provider config");
  return {
    providerName: ensureString(record.providerName, "providerName"),
    issuer: ensureString(record.issuer, "issuer"),
    clientId: ensureString(record.clientId, "clientId"),
    authMethod: ensureString(record.authMethod, "authMethod"),
  };
}

function normalizeClaimBoundary(value: unknown): ClientClaimBoundary {
  const record = ensureRecord(value, "client claim boundary");
  return {
    default_profile: ensureString(record.default_profile, "default_profile"),
    claim_phase: ensureString(record.claim_phase, "claim_phase"),
    promoted_client_slices: ensureNamedSurfaceArray(
      record.promoted_client_slices,
      "promoted_client_slices",
    ),
    compat_only_surfaces: ensureNamedSurfaceArray(record.compat_only_surfaces, "compat_only_surfaces"),
  };
}

async function shaHex(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const configPath = path.resolve(rootDir, options.config as string);
  const claimBoundaryPath = path.resolve(rootDir, options.claimBoundary);
  const outPath = path.resolve(rootDir, options.out);

  const config = normalizeConfig(await readJson(configPath));
  const claimBoundary = normalizeClaimBoundary(await readJson(claimBoundaryPath));

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
      name: config.providerName,
      class: options.providerClass,
      issuer: config.issuer,
      client_id: config.clientId,
      auth_method: config.authMethod,
    },
    lane: {
      name: options.laneName,
      hosted: parseBool(options.hosted, "hosted"),
      status: options.status,
      browser: options.browser,
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
  console.error("[build-managed-provider-evidence] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
