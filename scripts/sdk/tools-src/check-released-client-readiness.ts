#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PROMOTION_REPORT_PATH = ".artifacts/release/client-claim-promotion-report.json";
const DEFAULT_RELEASED_CLIENT_CLAIM_REPORT_PATH =
  ".artifacts/release/released-client-claim-report.json";
const DEFAULT_RELEASE_PUBLICATION_BUNDLE_PATH =
  ".artifacts/release/release-publication-bundle.json";

type CliOptions = {
  root: string | null;
  managedProviderEvidence: string | null;
  adminSdkEvidence: string | null;
  lanes: string[];
  publicationOrgTasks: string[];
  promotionReport: string;
  releasedClientReport: string;
  publicationBundle: string;
  claimActive: string | null;
};

function findToolRoot(): string {
  for (const candidate of [
    path.resolve(MODULE_DIR, ".."),
    path.resolve(MODULE_DIR, "..", ".."),
    path.resolve(MODULE_DIR, "..", "..", ".."),
  ]) {
    if (existsSync(path.join(candidate, "scripts")) && existsSync(path.join(candidate, "spec"))) {
      return candidate;
    }
  }
  throw new Error("Could not locate SDK tool root");
}

const TOOL_ROOT = findToolRoot();

function resolveLocalTool(baseName: string): string {
  const candidates = [
    path.join(TOOL_ROOT, "dist-tools", `${baseName}.js`),
    path.join(TOOL_ROOT, "tools-src", `${baseName}.ts`),
    path.join(TOOL_ROOT, "scripts", "sdk", "tools-src", `${baseName}.ts`),
  ];
  const match = candidates.find((candidate) => existsSync(candidate));
  if (!match) {
    throw new Error(`Could not locate tool ${baseName}`);
  }
  return match;
}

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-released-client-readiness.js [options] " +
      "--managed-provider-evidence <path> --admin-sdk-evidence <path> " +
      "--lane <name>=<status>",
    "",
    "Options:",
    "  --root <sdk-root>                    Workspace root (autodetected when omitted)",
    "  --managed-provider-evidence <path>  Managed-provider evidence JSON",
    "  --admin-sdk-evidence <path>         Admin-console SDK evidence JSON",
    "  --lane <name>=<status>              Repeat for each hosted lane",
    "  --publication-org-task <name>=<status>  Repeat; status is pending|done",
    "  --promotion-report <path>           " +
      "Default: .artifacts/release/client-claim-promotion-report.json",
    "  --released-client-report <path>     " +
      "Default: .artifacts/release/released-client-claim-report.json",
    "  --publication-bundle <path>         " +
      "Default: .artifacts/release/release-publication-bundle.json",
    "  --claim-active <bool>               Optional override for released-client activation audit",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    managedProviderEvidence: null,
    adminSdkEvidence: null,
    lanes: [],
    publicationOrgTasks: [],
    promotionReport:
      process.env.AEGAEON_CLIENT_CLAIM_PROMOTION_REPORT_PATH ??
      DEFAULT_PROMOTION_REPORT_PATH,
    releasedClientReport:
      process.env.AEGAEON_RELEASED_CLIENT_CLAIM_REPORT_PATH ??
      DEFAULT_RELEASED_CLIENT_CLAIM_REPORT_PATH,
    publicationBundle:
      process.env.AEGAEON_RELEASE_PUBLICATION_BUNDLE_PATH ??
      DEFAULT_RELEASE_PUBLICATION_BUNDLE_PATH,
    claimActive: process.env.AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE ?? null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) {
      continue;
    }
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
    if (token === "--lane" || token === "--publication-org-task") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error(`Missing value for option ${token}`);
      }
      if (token === "--lane") {
        options.lanes.push(value);
      } else {
        options.publicationOrgTasks.push(value);
      }
      index += 1;
      continue;
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option ${token}`);
    }
    switch (token) {
      case "--root":
        options.root = value;
        break;
      case "--managed-provider-evidence":
        options.managedProviderEvidence = value;
        break;
      case "--admin-sdk-evidence":
        options.adminSdkEvidence = value;
        break;
      case "--promotion-report":
        options.promotionReport = value;
        break;
      case "--released-client-report":
        options.releasedClientReport = value;
        break;
      case "--publication-bundle":
        options.publicationBundle = value;
        break;
      case "--claim-active":
        options.claimActive = value;
        break;
      default:
        throw new Error(`Unknown option ${token}`);
    }
    index += 1;
  }

  return options;
}

function findWorkspaceRoot(explicitRoot: string | null): string {
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

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
}

async function runStep(command: string, args: string[], cwd: string): Promise<void> {
  await execFile(command, args, { cwd });
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (!options.managedProviderEvidence) {
    throw new Error("--managed-provider-evidence is required");
  }
  if (!options.adminSdkEvidence) {
    throw new Error("--admin-sdk-evidence is required");
  }

  const rootDir = findWorkspaceRoot(options.root);
  const managedProviderEvidencePath = resolveWithinRoot(
    rootDir,
    options.managedProviderEvidence,
  );
  const adminSdkEvidencePath = resolveWithinRoot(rootDir, options.adminSdkEvidence);
  const promotionReportPath = resolveWithinRoot(rootDir, options.promotionReport);
  const releasedClientReportPath = resolveWithinRoot(
    rootDir,
    options.releasedClientReport,
  );
  const publicationBundlePath = resolveWithinRoot(rootDir, options.publicationBundle);

  await runStep(
    process.execPath,
    [resolveLocalTool("check-strict-types"), "--root", rootDir],
    TOOL_ROOT,
  );
  await runStep(
    "python3",
    [
      path.join(
        TOOL_ROOT,
        "scripts",
        "validation",
        "validate_managed_provider_evidence.py",
      ),
      managedProviderEvidencePath,
    ],
    TOOL_ROOT,
  );
  await runStep(
    "python3",
    [
      path.join(
        TOOL_ROOT,
        "scripts",
        "validation",
        "validate_admin_sdk_evidence.py",
      ),
      adminSdkEvidencePath,
    ],
    TOOL_ROOT,
  );

  const promotionArgs = [
    resolveLocalTool("check-client-claim-promotion"),
    "--root",
    rootDir,
    "--managed-provider-evidence",
    managedProviderEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--report",
    promotionReportPath,
  ];
  for (const lane of options.lanes) {
    promotionArgs.push("--lane", lane);
  }
  await runStep(process.execPath, promotionArgs, TOOL_ROOT);

  const releasedClientArgs = [
    resolveLocalTool("build-released-client-claim-report"),
    "--root",
    rootDir,
    "--managed-provider-evidence",
    managedProviderEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--promotion-report",
    promotionReportPath,
    "--out",
    releasedClientReportPath,
  ];
  for (const task of options.publicationOrgTasks) {
    releasedClientArgs.push("--publication-org-task", task);
  }
  await runStep(process.execPath, releasedClientArgs, TOOL_ROOT);
  await runStep(
    "python3",
    [
      path.join(
        TOOL_ROOT,
        "scripts",
        "validation",
        "validate_released_client_claim_report.py",
      ),
      releasedClientReportPath,
    ],
    TOOL_ROOT,
  );

  const activationArgs = [
    resolveLocalTool("check-released-client-claim-activation"),
    "--root",
    rootDir,
    "--report",
    releasedClientReportPath,
  ];
  if (options.claimActive !== null && options.claimActive !== undefined) {
    activationArgs.push("--claim-active", String(options.claimActive));
  }
  await runStep(process.execPath, activationArgs, TOOL_ROOT);

  await runStep(
    process.execPath,
    [
      resolveLocalTool("build-release-publication-bundle"),
      "--root",
      rootDir,
      "--managed-provider-evidence",
      managedProviderEvidencePath,
      "--admin-sdk-evidence",
      adminSdkEvidencePath,
      "--client-claim-promotion-report",
      promotionReportPath,
      "--released-client-claim-report",
      releasedClientReportPath,
      "--out",
      publicationBundlePath,
    ],
    TOOL_ROOT,
  );
  await runStep(
    "python3",
    [
      path.join(
        TOOL_ROOT,
        "scripts",
        "validation",
        "validate_sdk_release_publication_bundle.py",
      ),
      publicationBundlePath,
    ],
    TOOL_ROOT,
  );

  console.log(
    `[released-client-readiness] promotion report: ` +
      path.relative(rootDir, promotionReportPath),
  );
  console.log(
    `[released-client-readiness] released client claim report: ` +
      path.relative(rootDir, releasedClientReportPath),
  );
  console.log(
    `[released-client-readiness] release publication bundle: ` +
      path.relative(rootDir, publicationBundlePath),
  );
}

main().catch((error) => {
  console.error(
    "[released-client-readiness] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
