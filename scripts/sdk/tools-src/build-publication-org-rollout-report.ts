#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { existsSync, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_BRANCH_PROTECTION_POLICY = "spec/branch-protection.main.json";
const DEFAULT_RELEASE_CUSTODY_POLICY = "spec/release-custody.current.json";
const DEFAULT_OUT_PATH = ".artifacts/release/publication-org-rollout-report.json";

type TaskStatus = "pending" | "done";

type CliOptions = {
  root: string | null;
  owner: string | null;
  repo: string | null;
  branch: string | null;
  branchProtectionPolicy: string;
  releaseCustodyPolicy: string;
  branchProtectionActual: string | null;
  releaseCustodyActual: string | null;
  out: string;
};

type PublicationOrgRolloutReport = {
  schema_version: number;
  generated_at: string;
  rollout_target: "released-client-claim";
  target_repository: {
    owner: string | null;
    repo: string | null;
    branch: string;
  };
  tasks: Array<{
    name: string;
    status: TaskStatus;
    detail: string | null;
  }>;
  ready: boolean;
  blockers: string[];
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/build-publication-org-rollout-report.js [options]",
    "",
    "Options:",
    "  --root <sdk-root>                     Workspace root (autodetected when omitted)",
    "  --owner <owner>                       GitHub repository owner",
    "  --repo <repo>                         GitHub repository name",
    "  --branch <name>                       Branch to audit (default: main)",
    "  --branch-protection-policy <path>     Default: spec/branch-protection.main.json",
    "  --release-custody-policy <path>       Default: spec/release-custody.current.json",
    "  --branch-protection-actual <path>     Saved branch-protection payload for offline audit",
    "  --release-custody-actual <path>       Saved release-custody payload for offline audit",
    "  --out <path>                          " +
      "Default: .artifacts/release/publication-org-rollout-report.json",
  ].join("\n");
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    owner: process.env.AEGAEON_GITHUB_OWNER ?? null,
    repo: process.env.AEGAEON_GITHUB_REPO ?? null,
    branch: process.env.AEGAEON_GITHUB_BRANCH ?? "main",
    branchProtectionPolicy:
      process.env.AEGAEON_BRANCH_PROTECTION_POLICY_PATH ??
      DEFAULT_BRANCH_PROTECTION_POLICY,
    releaseCustodyPolicy:
      process.env.AEGAEON_RELEASE_CUSTODY_POLICY_PATH ??
      DEFAULT_RELEASE_CUSTODY_POLICY,
    branchProtectionActual: process.env.AEGAEON_BRANCH_PROTECTION_ACTUAL_PATH ?? null,
    releaseCustodyActual: process.env.AEGAEON_RELEASE_CUSTODY_ACTUAL_PATH ?? null,
    out: process.env.AEGAEON_PUBLICATION_ORG_ROLLOUT_REPORT_OUT ?? DEFAULT_OUT_PATH,
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
    const key = rawKey.replace(
      /-([a-z])/g,
      (_, character: string) => character.toUpperCase(),
    ) as keyof CliOptions;
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(key in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[key] = value as never;
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

function compressFailure(stderr: string): string {
  const trimmed = stderr.trim();
  if (trimmed.length === 0) {
    return "audit failed";
  }
  return trimmed.split("\n").slice(-1)[0] ?? "audit failed";
}

async function runAudit(
  command: string,
  args: string[],
  cwd: string,
): Promise<{ status: TaskStatus; detail: string | null }> {
  try {
    await execFile(command, args, { cwd, env: process.env });
    return { status: "done", detail: null };
  } catch (error) {
    const stderr =
      error && typeof error === "object" && "stderr" in error
        ? String(error.stderr ?? "")
        : "";
    return { status: "pending", detail: compressFailure(stderr) };
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const branch = options.branch ?? "main";

  if (!options.branchProtectionActual && (!options.owner || !options.repo)) {
    throw new Error(
      "Branch-protection audit requires either " +
        "--branch-protection-actual or both --owner and --repo",
    );
  }
  if (!options.releaseCustodyActual && (!options.owner || !options.repo)) {
    throw new Error(
      "Release-custody audit requires either " +
        "--release-custody-actual or both --owner and --repo",
    );
  }

  const branchTool = resolveWorkspaceTool(rootDir, "check-branch-protection");
  const releaseTool = resolveWorkspaceTool(rootDir, "check-release-custody");
  const outPath = resolveWithinRoot(rootDir, options.out);

  const branchArgs = [
    branchTool,
    "--policy",
    resolveWithinRoot(rootDir, options.branchProtectionPolicy),
  ];
  if (options.branchProtectionActual) {
    branchArgs.push("--actual", resolveWithinRoot(rootDir, options.branchProtectionActual));
  } else {
    branchArgs.push(
      "--owner",
      options.owner ?? "",
      "--repo",
      options.repo ?? "",
      "--branch",
      branch,
    );
  }

  const releaseArgs = [
    releaseTool,
    "--policy",
    resolveWithinRoot(rootDir, options.releaseCustodyPolicy),
  ];
  if (options.releaseCustodyActual) {
    releaseArgs.push("--actual", resolveWithinRoot(rootDir, options.releaseCustodyActual));
  } else {
    releaseArgs.push("--owner", options.owner ?? "", "--repo", options.repo ?? "");
  }

  const branchProtection = await runAudit(process.execPath, branchArgs, rootDir);
  const releaseCustody = await runAudit(process.execPath, releaseArgs, rootDir);

  const tasks = [
    { name: "publication_org_branch_protection", ...branchProtection },
    { name: "publication_org_secret_rollout", ...releaseCustody },
  ];
  const blockers = tasks
    .filter((task) => task.status !== "done")
    .map((task) => task.detail ? `${task.name}: ${task.detail}` : `${task.name}: audit failed`);

  const report: PublicationOrgRolloutReport = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    rollout_target: "released-client-claim",
    target_repository: {
      owner: options.owner,
      repo: options.repo,
      branch,
    },
    tasks,
    ready: blockers.length === 0,
    blockers,
  };

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(`[build-publication-org-rollout-report] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error(
    "[build-publication-org-rollout-report] error:",
    error instanceof Error ? error.message : String(error),
  );
  process.exitCode = 1;
});
