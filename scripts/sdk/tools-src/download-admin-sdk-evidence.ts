import { execFile as execFileCallback } from "node:child_process";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/admin-sdk/admin-sdk-evidence.json";
const DEFAULT_WORKFLOW = "stack-e2e.yml";
const DEFAULT_BRANCH = "main";
const DEFAULT_ARTIFACT = "admin-sdk-evidence";
const EVIDENCE_FILE_NAME = "admin-sdk-evidence.json";

type DownloadAdminSdkEvidenceOptions = {
  root: string | null;
  repo: string | null;
  workflow: string;
  branch: string;
  artifact: string;
  artifactDir: string | null;
  out: string;
};

type GitHubRunSummary = {
  databaseId?: number;
  workflowName?: string;
  headBranch?: string;
  headSha?: string;
  url?: string;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/download-admin-sdk-evidence.js --repo <owner/repo> [--workflow <workflow>] [--branch <branch>] [--artifact <name>] [--out <path>]",
    "  node dist-tools/download-admin-sdk-evidence.js --artifact-dir <dir> [--out <path>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_ADMIN_CONSOLE_REPOSITORY",
    "  AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW",
    "  AEGAEON_ADMIN_CONSOLE_REF",
    "  AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT",
    "  AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT_DIR",
    "  AEGAEON_ADMIN_SDK_EVIDENCE_OUT",
    "",
    "Authentication:",
    "  Set GH_TOKEN when downloading from a hosted GitHub Actions artifact.",
  ].join("\n");
}

function writeMaybeOutput(output: string | Buffer | undefined): void {
  if (!output) {
    return;
  }
  process.stdout.write(output);
}

function writeMaybeError(output: string | Buffer | undefined): void {
  if (!output) {
    return;
  }
  process.stderr.write(output);
}

function parseArgs(argv: string[]): DownloadAdminSdkEvidenceOptions {
  const options: DownloadAdminSdkEvidenceOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    repo: process.env.AEGAEON_ADMIN_CONSOLE_REPOSITORY ?? null,
    workflow: process.env.AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW ?? DEFAULT_WORKFLOW,
    branch: process.env.AEGAEON_ADMIN_CONSOLE_REF ?? DEFAULT_BRANCH,
    artifact: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT ?? DEFAULT_ARTIFACT,
    artifactDir: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT_DIR ?? null,
    out: process.env.AEGAEON_ADMIN_SDK_EVIDENCE_OUT ?? DEFAULT_OUT_PATH,
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
    const key = token!.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    switch (key) {
      case "root":
        options.root = value;
        break;
      case "repo":
        options.repo = value;
        break;
      case "workflow":
        options.workflow = value;
        break;
      case "branch":
        options.branch = value;
        break;
      case "artifact":
        options.artifact = value;
        break;
      case "artifact-dir":
        options.artifactDir = value;
        break;
      case "out":
        options.out = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  if (!options.artifactDir && !options.repo) {
    throw new Error(`Either --artifact-dir or --repo is required.\n\n${usage()}`);
  }

  return options;
}

function findWorkspaceRoot(explicitRoot: string | null): string {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR);
  while (true) {
    if (existsSync(path.join(current, "package.json")) && existsSync(path.join(current, "spec", EVIDENCE_FILE_NAME.replace(".json", ".schema.json")))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate SDK workspace root");
    }
    current = parent;
  }
}

async function ensureDir(dirPath: string): Promise<void> {
  await fs.mkdir(dirPath, { recursive: true });
}

async function removeDir(dirPath: string): Promise<void> {
  await fs.rm(dirPath, { recursive: true, force: true });
}

async function findFilesNamed(rootDir: string, targetName: string): Promise<string[]> {
  const matches: string[] = [];
  async function walk(currentDir: string): Promise<void> {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const entryPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        await walk(entryPath);
        continue;
      }
      if (entry.isFile() && entry.name === targetName) {
        matches.push(entryPath);
      }
    }
  }
  await walk(rootDir);
  return matches;
}

async function copyEvidenceFile(sourcePath: string, outPath: string): Promise<void> {
  await ensureDir(path.dirname(outPath));
  await fs.copyFile(sourcePath, outPath);
}

async function materializeFromArtifactDir(artifactDir: string, outPath: string): Promise<void> {
  const matches = await findFilesNamed(artifactDir, EVIDENCE_FILE_NAME);
  if (matches.length === 0) {
    throw new Error(`Could not find ${EVIDENCE_FILE_NAME} under ${artifactDir}`);
  }
  await copyEvidenceFile(matches[0]!, outPath);
}

async function downloadFromGitHub(
  rootDir: string,
  options: DownloadAdminSdkEvidenceOptions,
  outPath: string,
): Promise<void> {
  const repo = options.repo;
  if (!repo) {
    throw new Error("A repository is required to download admin SDK evidence from GitHub");
  }
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "aegaeon-admin-sdk-evidence-"));
  try {
    const { stdout: listStdout, stderr: listStderr } = await execFile(
      "gh",
      [
        "run",
        "list",
        "--repo",
        repo,
        "--workflow",
        options.workflow,
        "--branch",
        options.branch,
        "--status",
        "success",
        "--limit",
        "1",
        "--json",
        "databaseId,workflowName,headBranch,headSha,url",
      ],
      { cwd: rootDir },
    );
    writeMaybeError(listStderr);
    const runs = JSON.parse(String(listStdout)) as GitHubRunSummary[];
    if (!Array.isArray(runs) || runs.length === 0) {
      throw new Error(
        `No successful ${options.workflow} runs found for ${options.repo} on branch ${options.branch}`,
      );
    }
    const run = runs[0]!;
    const runId = run.databaseId;
    if (!runId) {
      throw new Error(`Latest workflow run for ${options.repo} did not include a databaseId`);
    }

    const { stdout: downloadStdout, stderr: downloadStderr } = await execFile(
      "gh",
      [
        "run",
        "download",
        String(runId),
        "--repo",
        repo,
        "--name",
        options.artifact,
        "--dir",
        tempDir,
      ],
      { cwd: rootDir },
    );
    writeMaybeOutput(downloadStdout);
    writeMaybeError(downloadStderr);

    await materializeFromArtifactDir(tempDir, outPath);
    console.log(
      `[download-admin-sdk-evidence] downloaded ${options.artifact} from ${options.repo}#${runId}`,
    );
    if (run.url) {
      console.log(`[download-admin-sdk-evidence] workflow run: ${run.url}`);
    }
  } finally {
    await removeDir(tempDir);
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const outPath = path.resolve(rootDir, options.out);

  if (options.artifactDir) {
    await materializeFromArtifactDir(path.resolve(options.artifactDir), outPath);
  } else {
    await downloadFromGitHub(rootDir, options, outPath);
  }

  await fs.access(outPath);
  console.log(`[download-admin-sdk-evidence] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error("[download-admin-sdk-evidence] error:", error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
