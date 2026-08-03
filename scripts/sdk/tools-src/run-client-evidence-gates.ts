#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { existsSync, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import type {
  ClientClaimPromotionPolicyFile,
  ReleasedClientClaimPolicyFile,
} from "./released-client-types.js";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_ADMIN_SDK_EVIDENCE_PATH = ".artifacts/admin-sdk/admin-sdk-evidence.json";
const DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH =
  ".artifacts/managed-provider/managed-provider-evidence.json";
const DEFAULT_PROMOTION_POLICY_PATH = "spec/client-claim-promotion.current.json";
const DEFAULT_RELEASED_CLIENT_CLAIM_POLICY_PATH = "spec/released-client-claim.current.json";
const DEFAULT_PROMOTION_REPORT_PATH = ".artifacts/release/client-claim-promotion-report.json";
const DEFAULT_RELEASED_CLIENT_CLAIM_REPORT_PATH =
  ".artifacts/release/released-client-claim-report.json";
const DEFAULT_RELEASE_PUBLICATION_BUNDLE_PATH =
  ".artifacts/release/release-publication-bundle.json";

type GateMode = "promotion" | "readiness";

type CliOptions = {
  root: string | null;
  mode: GateMode;
  adminSdkEvidence: string | null;
  managedProviderEvidence: string | null;
  adminSdkEvidenceJson: string | null;
  managedProviderEvidenceJson: string | null;
  adminSdkArtifactDir: string | null;
  managedProviderArtifactDir: string | null;
  dispatchHosted: boolean;
  lanes: string[];
  publicationOrgTasks: string[];
  promotionReport: string;
  releasedClientReport: string;
  publicationBundle: string;
  claimActive: string | null;
};

type EvidenceKind = "admin-sdk" | "managed-provider";

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/run-client-evidence-gates.js [options]",
    "",
    "Options:",
    "  --root <sdk-root>                     Workspace root (autodetected when omitted)",
    "  --mode <promotion|readiness>         Default: readiness",
    "  --admin-sdk-evidence <path>          Existing admin-sdk-evidence JSON or output path",
    "  --managed-provider-evidence <path>   Existing managed-provider-evidence JSON or output path",
    "  --admin-sdk-evidence-json <json>     Inline admin-sdk-evidence JSON override",
    "  --managed-provider-evidence-json <json>  Inline managed-provider-evidence JSON override",
    "  --admin-sdk-artifact-dir <dir>       Artifact directory containing admin-sdk-evidence.json",
    "  --managed-provider-artifact-dir <dir> " +
      "Artifact directory containing managed-provider-evidence.json",
    "  --dispatch-hosted                    " +
      "Dispatch hosted evidence workflows instead of downloading latest artifacts",
    "  --lane <name>=<status>               Repeat; defaults to all required lanes as passed",
    "  --publication-org-task <name>=<status> Repeat; readiness only, defaults from policy/env",
    "  --promotion-report <path>            " +
      "Default: .artifacts/release/client-claim-promotion-report.json",
    "  --released-client-report <path>      " +
      "Default: .artifacts/release/released-client-claim-report.json",
    "  --publication-bundle <path>          " +
      "Default: .artifacts/release/release-publication-bundle.json",
    "  --claim-active <bool>                Optional released-client activation override",
    "",
    "Environment fallbacks:",
    "  AEGAEON_ADMIN_SDK_EVIDENCE_JSON",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON",
    "  AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT_DIR",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT_DIR",
    "  AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN",
    "  AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS",
    "  AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    mode: "readiness",
    adminSdkEvidence: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_OUT ?? null,
    managedProviderEvidence: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_OUT ?? null,
    adminSdkEvidenceJson: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_JSON ?? null,
    managedProviderEvidenceJson: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON ?? null,
    adminSdkArtifactDir: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT_DIR ?? null,
    managedProviderArtifactDir: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT_DIR ?? null,
    dispatchHosted: /^(1|true|TRUE)$/.test(
      process.env.AEGAEON_CLIENT_EVIDENCE_DISPATCH_HOSTED ?? "",
    ),
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
    if (token === "--dispatch-hosted") {
      options.dispatchHosted = true;
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
      case "--admin-sdk-evidence":
        options.adminSdkEvidence = value;
        break;
      case "--managed-provider-evidence":
        options.managedProviderEvidence = value;
        break;
      case "--admin-sdk-evidence-json":
        options.adminSdkEvidenceJson = value;
        break;
      case "--managed-provider-evidence-json":
        options.managedProviderEvidenceJson = value;
        break;
      case "--admin-sdk-artifact-dir":
        options.adminSdkArtifactDir = value;
        break;
      case "--managed-provider-artifact-dir":
        options.managedProviderArtifactDir = value;
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
      throw new Error("Could not locate SDK workspace root");
    }
    current = parent;
  }
}

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
}

function resolveLocalTool(baseName: string): string {
  const candidates = [
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

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as T;
}

function githubTokenForKind(kind: EvidenceKind): string | undefined {
  if (kind === "admin-sdk") {
    return process.env.AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN ?? process.env.GH_TOKEN;
  }
  return process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN ?? process.env.GH_TOKEN;
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

function envWithToken(kind: EvidenceKind): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GH_TOKEN: githubTokenForKind(kind),
  };
}

async function materializeJsonOverride(
  outPath: string,
  jsonText: string,
  label: string,
): Promise<void> {
  JSON.parse(jsonText);
  await ensureParentDir(outPath);
  const normalized = jsonText.endsWith("\n") ? jsonText : `${jsonText}\n`;
  await fs.writeFile(outPath, normalized, "utf8");
  console.log(`[client-evidence-gates] materialized ${label}: ${outPath}`);
}

function resolveValidationScript(cwd: string, scriptName: string): string {
  const candidates = [
    path.join(cwd, "scripts", "validation", scriptName),
    path.resolve(MODULE_DIR, "..", "scripts", "validation", scriptName),
    path.resolve(MODULE_DIR, "..", "..", "validation", scriptName),
  ];
  const match = candidates.find((candidate) => existsSync(candidate));
  if (!match) {
    throw new Error(`Could not locate validation script ${scriptName}`);
  }
  return match;
}

async function validateEvidence(
  kind: EvidenceKind,
  evidencePath: string,
  cwd: string,
): Promise<void> {
  const validator = resolveValidationScript(
    cwd,
    kind === "admin-sdk"
      ? "validate_admin_sdk_evidence.py"
      : "validate_managed_provider_evidence.py",
  );
  const validatorRoot = path.resolve(path.dirname(validator), "..", "..");
  await runStep("python3", [validator, evidencePath], validatorRoot);
}

async function resolveEvidencePath(
  kind: EvidenceKind,
  rootDir: string,
  options: CliOptions,
): Promise<string> {
  const explicitPath =
    kind === "admin-sdk"
      ? options.adminSdkEvidence
      : options.managedProviderEvidence;
  const jsonOverride =
    kind === "admin-sdk"
      ? options.adminSdkEvidenceJson
      : options.managedProviderEvidenceJson;
  const artifactDir =
    kind === "admin-sdk"
      ? options.adminSdkArtifactDir
      : options.managedProviderArtifactDir;
  const defaultOutPath =
    kind === "admin-sdk"
      ? DEFAULT_ADMIN_SDK_EVIDENCE_PATH
      : DEFAULT_MANAGED_PROVIDER_EVIDENCE_PATH;
  const outPath = resolveWithinRoot(rootDir, explicitPath ?? defaultOutPath);

  if (kind === "managed-provider" && options.dispatchHosted) {
    let importPath: string | null = null;
    if (jsonOverride && jsonOverride.length > 0) {
      const tempOverridePath = path.join(
        rootDir,
        ".cache",
        "client-evidence-gates",
        "managed-provider-inline.json",
      );
      await materializeJsonOverride(tempOverridePath, jsonOverride, "managed-provider");
      await validateEvidence(kind, tempOverridePath, rootDir);
      importPath = tempOverridePath;
    } else if (explicitPath && existsSync(outPath)) {
      await validateEvidence(kind, outPath, rootDir);
      importPath = outPath;
    }
    if (importPath) {
      const hostedRunner = resolveLocalTool("run-hosted-evidence");
      await runStep(
        process.execPath,
        [
          hostedRunner,
          "--root",
          rootDir,
          "--kind",
          kind,
          "--evidence",
          importPath,
          "--out",
          outPath,
        ],
        rootDir,
        envWithToken(kind),
      );
      await validateEvidence(kind, outPath, rootDir);
      return outPath;
    }
  }

  if (jsonOverride && jsonOverride.length > 0) {
    await materializeJsonOverride(outPath, jsonOverride, kind);
    await validateEvidence(kind, outPath, rootDir);
    return outPath;
  }

  if (explicitPath && existsSync(outPath)) {
    await validateEvidence(kind, outPath, rootDir);
    return outPath;
  }

  if (artifactDir) {
    const downloadTool =
      kind === "admin-sdk"
        ? resolveLocalTool("download-admin-sdk-evidence")
        : resolveLocalTool("download-managed-provider-evidence");
    await runStep(
      process.execPath,
      [
        downloadTool,
        "--root",
        rootDir,
        "--artifact-dir",
        resolveWithinRoot(rootDir, artifactDir),
        "--out",
        outPath,
      ],
      rootDir,
      envWithToken(kind),
    );
    await validateEvidence(kind, outPath, rootDir);
    return outPath;
  }

  if (options.dispatchHosted) {
    const hostedRunner = resolveLocalTool("run-hosted-evidence");
    await runStep(
      process.execPath,
      [hostedRunner, "--root", rootDir, "--kind", kind, "--out", outPath],
      rootDir,
      envWithToken(kind),
    );
    await validateEvidence(kind, outPath, rootDir);
    return outPath;
  }

  const downloadTool =
    kind === "admin-sdk"
      ? resolveLocalTool("download-admin-sdk-evidence")
      : resolveLocalTool("download-managed-provider-evidence");
  await runStep(
    process.execPath,
    [downloadTool, "--root", rootDir, "--out", outPath],
    rootDir,
    envWithToken(kind),
  );
  await validateEvidence(kind, outPath, rootDir);
  return outPath;
}

async function resolveLanes(rootDir: string, explicitLanes: string[]): Promise<string[]> {
  if (explicitLanes.length > 0) {
    return explicitLanes;
  }
  const policyPath = path.join(rootDir, DEFAULT_PROMOTION_POLICY_PATH);
  const policy = await readJson<ClientClaimPromotionPolicyFile>(policyPath);
  return policy.required_lanes.map((laneName) => `${laneName}=passed`);
}

function publicationTaskEnvName(taskName: string): string {
  return `AEGAEON_${taskName.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase()}_STATUS`;
}

async function resolvePublicationTasks(
  rootDir: string,
  explicitTasks: string[],
): Promise<string[]> {
  if (explicitTasks.length > 0) {
    return explicitTasks;
  }
  const policyPath = path.join(rootDir, DEFAULT_RELEASED_CLIENT_CLAIM_POLICY_PATH);
  const policy = await readJson<ReleasedClientClaimPolicyFile>(policyPath);
  return policy.required_publication_org_tasks.map((taskName) => {
    const status = process.env[publicationTaskEnvName(taskName)] ?? "pending";
    return `${taskName}=${status}`;
  });
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const adminSdkEvidencePath = await resolveEvidencePath("admin-sdk", rootDir, options);
  const managedProviderEvidencePath = await resolveEvidencePath(
    "managed-provider",
    rootDir,
    options,
  );
  const lanes = await resolveLanes(rootDir, options.lanes);
  const promotionReportPath = resolveWithinRoot(rootDir, options.promotionReport);

  if (options.mode === "promotion") {
    const promotionTool = resolveLocalTool("check-client-claim-promotion");
    const promotionArgs = [
      promotionTool,
      "--root",
      rootDir,
      "--managed-provider-evidence",
      managedProviderEvidencePath,
      "--admin-sdk-evidence",
      adminSdkEvidencePath,
      "--report",
      promotionReportPath,
    ];
    for (const lane of lanes) {
      promotionArgs.push("--lane", lane);
    }
    await runStep(process.execPath, promotionArgs, rootDir);
    console.log(
      `[client-evidence-gates] promotion report: ` +
        path.relative(rootDir, promotionReportPath),
    );
    return;
  }

  const publicationTasks = await resolvePublicationTasks(rootDir, options.publicationOrgTasks);
  const readinessTool = resolveLocalTool("check-released-client-readiness");
  const readinessArgs = [
    readinessTool,
    "--root",
    rootDir,
    "--managed-provider-evidence",
    managedProviderEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--promotion-report",
    promotionReportPath,
    "--released-client-report",
    resolveWithinRoot(rootDir, options.releasedClientReport),
    "--publication-bundle",
    resolveWithinRoot(rootDir, options.publicationBundle),
  ];
  for (const lane of lanes) {
    readinessArgs.push("--lane", lane);
  }
  for (const task of publicationTasks) {
    readinessArgs.push("--publication-org-task", task);
  }
  if (options.claimActive !== null && options.claimActive !== undefined) {
    readinessArgs.push("--claim-active", String(options.claimActive));
  }
  await runStep(process.execPath, readinessArgs, rootDir);
  console.log(
    `[client-evidence-gates] promotion report: ` +
      path.relative(rootDir, promotionReportPath),
  );
  console.log(
    `[client-evidence-gates] released client claim report: ` +
      path.relative(rootDir, resolveWithinRoot(rootDir, options.releasedClientReport)),
  );
  console.log(
    `[client-evidence-gates] release publication bundle: ` +
      path.relative(rootDir, resolveWithinRoot(rootDir, options.publicationBundle)),
  );
}

main().catch((error) => {
  console.error("[client-evidence-gates] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
