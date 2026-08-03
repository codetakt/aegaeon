#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/managed-provider/managed-provider-evidence.json";
const DEFAULT_WORKFLOW = "managed-provider-evidence.yml";
const DEFAULT_BRANCH = "main";
const DEFAULT_ARTIFACT = "managed-provider-evidence";
const EVIDENCE_FILE_NAME = "managed-provider-evidence.json";

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types scripts/sdk/download_managed_provider_evidence.ts",
    "    --repo <owner/repo> [--workflow <workflow>] [--branch <branch>]",
    "    [--artifact <name>] [--out <path>]",
    "  node --experimental-strip-types scripts/sdk/download_managed_provider_evidence.ts",
    "    --artifact-dir <dir> [--out <path>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT_DIR",
    "  AEGAEON_MANAGED_PROVIDER_EVIDENCE_OUT",
    "  GITHUB_REPOSITORY",
    "",
    "Authentication:",
    "  Set GH_TOKEN when downloading from a hosted GitHub Actions artifact.",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    repo:
      process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY
      ?? process.env.GITHUB_REPOSITORY
      ?? null,
    workflow: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW ?? DEFAULT_WORKFLOW,
    branch: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF ?? DEFAULT_BRANCH,
    artifact: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT ?? DEFAULT_ARTIFACT,
    artifactDir: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT_DIR ?? null,
    out: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_OUT ?? DEFAULT_OUT_PATH,
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
    const key = rawKey.replace(/-([a-z])/g, (_, character) => character.toUpperCase());
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

  if (!options.artifactDir && !options.repo) {
    throw new Error(`Either --artifact-dir or --repo is required.\n\n${usage()}`);
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
      existsSync(path.join(current, "package.json"))
      && existsSync(path.join(current, "spec", "managed-provider-evidence.schema.json"))
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

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

async function removeDir(dirPath) {
  await fs.rm(dirPath, { recursive: true, force: true });
}

async function findFilesNamed(rootDir, targetName) {
  const matches = [];
  async function walk(currentDir) {
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

async function copyEvidenceFile(sourcePath, outPath) {
  await ensureDir(path.dirname(outPath));
  await fs.copyFile(sourcePath, outPath);
}

async function materializeFromArtifactDir(artifactDir, outPath) {
  const matches = await findFilesNamed(artifactDir, EVIDENCE_FILE_NAME);
  if (matches.length === 0) {
    throw new Error(`Could not find ${EVIDENCE_FILE_NAME} under ${artifactDir}`);
  }
  await copyEvidenceFile(matches[0], outPath);
}

async function downloadFromGitHub(rootDir, options, outPath) {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "aegaeon-managed-provider-evidence-"));
  try {
    const { stdout: listStdout, stderr: listStderr } = await execFile(
      "gh",
      [
        "run",
        "list",
        "--repo",
        options.repo,
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
    if (listStderr) {
      process.stderr.write(listStderr);
    }
    const runs = JSON.parse(listStdout);
    if (!Array.isArray(runs) || runs.length === 0) {
      throw new Error(
        `No successful ${options.workflow} runs found for ${options.repo} on branch ${
          options.branch
        }`,
      );
    }
    const run = runs[0];
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
        options.repo,
        "--name",
        options.artifact,
        "--dir",
        tempDir,
      ],
      { cwd: rootDir },
    );
    if (downloadStdout) {
      process.stdout.write(downloadStdout);
    }
    if (downloadStderr) {
      process.stderr.write(downloadStderr);
    }

    await materializeFromArtifactDir(tempDir, outPath);
    console.log(
      `[download-managed-provider-evidence] downloaded ${options.artifact} from ${
        options.repo
      }#${runId}`,
    );
    if (run.url) {
      console.log(`[download-managed-provider-evidence] workflow run: ${run.url}`);
    }
  } finally {
    await removeDir(tempDir);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const outPath = path.resolve(rootDir, options.out);

  if (options.artifactDir) {
    await materializeFromArtifactDir(path.resolve(options.artifactDir), outPath);
  } else {
    await downloadFromGitHub(rootDir, options, outPath);
  }

  await fs.access(outPath);
  console.log(`[download-managed-provider-evidence] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error(
    "[download-managed-provider-evidence] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
