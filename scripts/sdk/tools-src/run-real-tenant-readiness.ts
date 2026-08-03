#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { existsSync, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_ADMIN_SDK_EVIDENCE_PATH = ".artifacts/admin-sdk/admin-sdk-evidence.json";
const DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH =
  ".artifacts/managed-provider/managed-provider-evidence.json";
const DEFAULT_PROMOTION_REPORT_PATH = ".artifacts/release/client-claim-promotion-report.json";
const DEFAULT_RELEASED_CLIENT_REPORT_PATH = ".artifacts/release/released-client-claim-report.json";
const DEFAULT_PUBLICATION_ORG_REPORT_PATH =
  ".artifacts/release/publication-org-rollout-report.json";
const DEFAULT_PUBLICATION_BUNDLE_PATH = ".artifacts/release/release-publication-bundle.json";

type GateMode = "promotion" | "readiness";

type CliOptions = {
  root: string | null;
  mode: GateMode;
  adminSdkEvidence: string | null;
  adminSdkEvidenceJson: string | null;
  adminSdkArtifactDir: string | null;
  managedProviderConfig: string | null;
  managedProviderEvidence: string | null;
  managedProviderEvidenceJson: string | null;
  managedProviderArtifactDir: string | null;
  providerClass: string | null;
  promotionReport: string;
  releasedClientReport: string;
  publicationOrgReport: string;
  publicationBundle: string;
  claimActive: string | null;
  lanes: string[];
  publicationOrgTasks: string[];
  publicationOrgOwner: string | null;
  publicationOrgRepo: string | null;
  publicationOrgBranch: string | null;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/run-real-tenant-readiness.js [options]",
    "",
    "Options:",
    "  --root <sdk-root>                        Workspace root (autodetected when omitted)",
    "  --mode <promotion|readiness>            Default: readiness",
    "  --managed-provider-config <path>        " +
      "Managed-provider config JSON to dispatch through hosted CI",
    "  --managed-provider-evidence <path>      " +
      "Existing managed-provider-evidence JSON to promote through hosted CI",
    "  --managed-provider-evidence-json <json> " +
      "Inline managed-provider-evidence JSON to promote through hosted CI",
    "  --managed-provider-artifact-dir <dir>   Existing hosted managed-provider artifact directory",
    "  --provider-class <class>                " +
      "Managed provider class for hosted dispatch (default: commercial)",
    "  --admin-sdk-evidence <path>             Existing admin-sdk-evidence JSON",
    "  --admin-sdk-evidence-json <json>        Inline admin-sdk-evidence JSON override",
    "  --admin-sdk-artifact-dir <dir>          Existing hosted admin-sdk artifact directory",
    "  --promotion-report <path>               " +
      "Default: .artifacts/release/client-claim-promotion-report.json",
    "  --released-client-report <path>         " +
      "Default: .artifacts/release/released-client-claim-report.json",
    "  --publication-org-report <path>         " +
      "Default: .artifacts/release/publication-org-rollout-report.json",
    "  --publication-bundle <path>             " +
      "Default: .artifacts/release/release-publication-bundle.json",
    "  --claim-active <bool>                   Optional released-client activation override",
    "  --lane <name>=<status>                  Repeat; forwarded to the evidence gate runner",
    "  --publication-org-task <name>=<status>  Repeat; forwarded to the readiness gate runner",
    "  --publication-org-owner <owner>         " +
      "Optional final publication-org owner for live rollout audit",
    "  --publication-org-repo <repo>           " +
      "Optional final publication-org repo for live rollout audit",
    "  --publication-org-branch <branch>       " +
      "Optional final publication-org branch (default: main)",
    "",
    "Notes:",
    "  - Admin evidence defaults to hosted stack-e2e dispatch when no explicit input is provided.",
    "  - Managed-provider evidence defaults to hosted promotion of config/evidence inputs.",
    "  - The final promotion/readiness audit is executed through run-client-evidence-gates.",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    mode: "readiness",
    adminSdkEvidence: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_OUT ?? null,
    adminSdkEvidenceJson: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_JSON ?? null,
    adminSdkArtifactDir: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT_DIR ?? null,
    managedProviderConfig: process.env.AEGAEON_MANAGED_PROVIDER_CONFIG_PATH ?? null,
    managedProviderEvidence: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_OUT ?? null,
    managedProviderEvidenceJson: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON ?? null,
    managedProviderArtifactDir: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT_DIR ?? null,
    providerClass: process.env.AEGAEON_MANAGED_PROVIDER_CLASS ?? "commercial",
    promotionReport:
      process.env.AEGAEON_CLIENT_CLAIM_PROMOTION_REPORT_PATH ??
      DEFAULT_PROMOTION_REPORT_PATH,
    releasedClientReport:
      process.env.AEGAEON_RELEASED_CLIENT_CLAIM_REPORT_PATH ??
      DEFAULT_RELEASED_CLIENT_REPORT_PATH,
    publicationOrgReport:
      process.env.AEGAEON_PUBLICATION_ORG_ROLLOUT_REPORT_PATH ??
      DEFAULT_PUBLICATION_ORG_REPORT_PATH,
    publicationBundle:
      process.env.AEGAEON_RELEASE_PUBLICATION_BUNDLE_PATH ??
      DEFAULT_PUBLICATION_BUNDLE_PATH,
    claimActive: process.env.AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE ?? null,
    lanes: [],
    publicationOrgTasks: [],
    publicationOrgOwner: process.env.AEGAEON_PUBLICATION_ORG_OWNER ?? null,
    publicationOrgRepo: process.env.AEGAEON_PUBLICATION_ORG_REPO ?? null,
    publicationOrgBranch: process.env.AEGAEON_PUBLICATION_ORG_BRANCH ?? "main",
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
    if (!token.startsWith("--")) {
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
      case "--mode":
        if (value !== "promotion" && value !== "readiness") {
          throw new Error("--mode must be either promotion or readiness");
        }
        options.mode = value;
        break;
      case "--managed-provider-config":
        options.managedProviderConfig = value;
        break;
      case "--managed-provider-evidence":
        options.managedProviderEvidence = value;
        break;
      case "--managed-provider-evidence-json":
        options.managedProviderEvidenceJson = value;
        break;
      case "--managed-provider-artifact-dir":
        options.managedProviderArtifactDir = value;
        break;
      case "--provider-class":
        options.providerClass = value;
        break;
      case "--admin-sdk-evidence":
        options.adminSdkEvidence = value;
        break;
      case "--admin-sdk-evidence-json":
        options.adminSdkEvidenceJson = value;
        break;
      case "--admin-sdk-artifact-dir":
        options.adminSdkArtifactDir = value;
        break;
      case "--promotion-report":
        options.promotionReport = value;
        break;
      case "--released-client-report":
        options.releasedClientReport = value;
        break;
      case "--publication-org-report":
        options.publicationOrgReport = value;
        break;
      case "--publication-bundle":
        options.publicationBundle = value;
        break;
      case "--claim-active":
        options.claimActive = value;
        break;
      case "--publication-org-owner":
        options.publicationOrgOwner = value;
        break;
      case "--publication-org-repo":
        options.publicationOrgRepo = value;
        break;
      case "--publication-org-branch":
        options.publicationOrgBranch = value;
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
      throw new Error("Could not locate SDK workspace root");
    }
    current = parent;
  }
}

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
}

function resolveWorkspaceTool(rootDir: string, baseName: string): string {
  const candidates = [
    path.join(rootDir, "dist-tools", `${baseName}.js`),
    path.join(rootDir, "tools-src", `${baseName}.ts`),
    path.join(MODULE_DIR, `${baseName}.js`),
    path.join(MODULE_DIR, `${baseName}.ts`),
  ];
  const match = candidates.find((candidate) => existsSync(candidate));
  if (!match) {
    throw new Error(`Could not locate tool ${baseName}`);
  }
  return match;
}

async function ensureParentDir(filePath: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function materializeJson(outPath: string, jsonText: string): Promise<void> {
  JSON.parse(jsonText);
  await ensureParentDir(outPath);
  await fs.writeFile(outPath, jsonText.endsWith("\n") ? jsonText : `${jsonText}\n`, "utf8");
}

async function runStep(
  command: string,
  args: string[],
  cwd: string,
  env?: NodeJS.ProcessEnv,
): Promise<void> {
  await execFile(command, args, {
    cwd,
    env: env ?? process.env,
  });
}

async function resolveAdminEvidence(rootDir: string, options: CliOptions): Promise<string> {
  const outPath = resolveWithinRoot(
    rootDir,
    options.adminSdkEvidence ?? DEFAULT_ADMIN_SDK_EVIDENCE_PATH,
  );
  if (options.adminSdkEvidenceJson && options.adminSdkEvidenceJson.length > 0) {
    await materializeJson(outPath, options.adminSdkEvidenceJson);
    return outPath;
  }
  if (options.adminSdkArtifactDir) {
    const downloadTool = resolveWorkspaceTool(rootDir, "download-admin-sdk-evidence");
    await runStep(
      process.execPath,
      [
        downloadTool,
        "--root",
        rootDir,
        "--artifact-dir",
        resolveWithinRoot(rootDir, options.adminSdkArtifactDir),
        "--out",
        outPath,
      ],
      rootDir,
    );
    return outPath;
  }
  if (options.adminSdkEvidence && existsSync(outPath)) {
    return outPath;
  }
  const hostedTool = resolveWorkspaceTool(rootDir, "run-hosted-evidence");
  await runStep(
    process.execPath,
    [hostedTool, "--root", rootDir, "--kind", "admin-sdk", "--out", outPath],
    rootDir,
  );
  return outPath;
}

async function resolveManagedEvidence(rootDir: string, options: CliOptions): Promise<string> {
  const outPath = resolveWithinRoot(
    rootDir,
    options.managedProviderEvidence ?? DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH,
  );
  if (options.managedProviderArtifactDir) {
    const downloadTool = resolveWorkspaceTool(rootDir, "download-managed-provider-evidence");
    await runStep(
      process.execPath,
      [
        downloadTool,
        "--root",
        rootDir,
        "--artifact-dir",
        resolveWithinRoot(rootDir, options.managedProviderArtifactDir),
        "--out",
        outPath,
      ],
      rootDir,
    );
    return outPath;
  }

  const hostedTool = resolveWorkspaceTool(rootDir, "run-hosted-evidence");
  if (options.managedProviderConfig) {
    const args = [
      hostedTool,
      "--root",
      rootDir,
      "--kind",
      "managed-provider",
      "--config",
      resolveWithinRoot(rootDir, options.managedProviderConfig),
      "--provider-class",
      options.providerClass ?? "commercial",
      "--out",
      outPath,
    ];
    await runStep(process.execPath, args, rootDir);
    return outPath;
  }

  if (options.managedProviderEvidenceJson && options.managedProviderEvidenceJson.length > 0) {
    const tempPath = path.join(
      rootDir,
      ".cache",
      "real-tenant-readiness",
      "managed-provider-inline.json",
    );
    await materializeJson(tempPath, options.managedProviderEvidenceJson);
    await runStep(
      process.execPath,
      [
        hostedTool,
        "--root",
        rootDir,
        "--kind",
        "managed-provider",
        "--evidence",
        tempPath,
        "--out",
        outPath,
      ],
      rootDir,
    );
    return outPath;
  }

  if (options.managedProviderEvidence && existsSync(outPath)) {
    await runStep(
      process.execPath,
      [
        hostedTool,
        "--root",
        rootDir,
        "--kind",
        "managed-provider",
        "--evidence",
        outPath,
        "--out",
        outPath,
      ],
      rootDir,
    );
    return outPath;
  }

  throw new Error(
    "Managed-provider input is required; provide " +
      "--managed-provider-config, --managed-provider-evidence, " +
      "--managed-provider-evidence-json, or " +
      "--managed-provider-artifact-dir",
  );
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const adminSdkEvidencePath = await resolveAdminEvidence(rootDir, options);
  const managedProviderEvidencePath = await resolveManagedEvidence(rootDir, options);
  if (options.publicationOrgOwner && options.publicationOrgRepo) {
    const publicationOrgReportTool = resolveWorkspaceTool(
      rootDir,
      "build-publication-org-rollout-report",
    );
    await runStep(
      process.execPath,
      [
        publicationOrgReportTool,
        "--root",
        rootDir,
        "--owner",
        options.publicationOrgOwner,
        "--repo",
        options.publicationOrgRepo,
        "--branch",
        options.publicationOrgBranch ?? "main",
        "--out",
        resolveWithinRoot(rootDir, options.publicationOrgReport),
      ],
      rootDir,
    );
  }
  const gateTool = resolveWorkspaceTool(rootDir, "run-client-evidence-gates");
  const gateArgs = [
    gateTool,
    "--root",
    rootDir,
    "--mode",
    options.mode,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--managed-provider-evidence",
    managedProviderEvidencePath,
    "--promotion-report",
    resolveWithinRoot(rootDir, options.promotionReport),
    "--released-client-report",
    resolveWithinRoot(rootDir, options.releasedClientReport),
    "--publication-org-report",
    resolveWithinRoot(rootDir, options.publicationOrgReport),
    "--publication-bundle",
    resolveWithinRoot(rootDir, options.publicationBundle),
  ];
  if (options.claimActive !== null && options.claimActive !== undefined) {
    gateArgs.push("--claim-active", String(options.claimActive));
  }
  for (const lane of options.lanes) {
    gateArgs.push("--lane", lane);
  }
  for (const task of options.publicationOrgTasks) {
    gateArgs.push("--publication-org-task", task);
  }
  await runStep(process.execPath, gateArgs, rootDir);
  console.log(
    `[real-tenant-readiness] admin evidence: ` +
      path.relative(rootDir, adminSdkEvidencePath),
  );
  console.log(
    `[real-tenant-readiness] managed evidence: ` +
      path.relative(rootDir, managedProviderEvidencePath),
  );
  console.log(`[real-tenant-readiness] mode: ${options.mode}`);
}

main().catch((error) => {
  console.error("[real-tenant-readiness] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
