import { execFile as execFileCallback } from "node:child_process";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));

const EVIDENCE_KINDS = {
  "admin-sdk": {
    envRepo: "AEGAEON_ADMIN_CONSOLE_REPOSITORY",
    envWorkflow: "AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW",
    envRef: "AEGAEON_ADMIN_CONSOLE_REF",
    envArtifact: "AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT",
    defaultWorkflow: "stack-e2e.yml",
    defaultBranch: "main",
    defaultArtifact: "admin-sdk-evidence",
    defaultOut: ".artifacts/admin-sdk/admin-sdk-evidence.json",
    evidenceFileName: "admin-sdk-evidence.json",
  },
  "managed-provider": {
    envRepo: "AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY",
    envWorkflow: "AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW",
    envRef: "AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF",
    envArtifact: "AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT",
    defaultWorkflow: "managed-provider-evidence.yml",
    defaultBranch: "main",
    defaultArtifact: "managed-provider-evidence",
    defaultOut: ".artifacts/managed-provider/managed-provider-evidence.json",
    evidenceFileName: "managed-provider-evidence.json",
  },
} as const;

type EvidenceKind = keyof typeof EVIDENCE_KINDS;

type HostedEvidenceOptions = {
  root: string | null;
  kind: EvidenceKind | null;
  repo: string | null;
  workflow: string | null;
  ref: string | null;
  artifact: string | null;
  out: string | null;
  timeoutSeconds: number;
  pollSeconds: number;
  wait: boolean;
  inputs: string[];
  configPath: string | null;
  evidencePath: string | null;
  providerClass: string | null;
};

type WorkflowConfig = {
  repo: string | null;
  workflow: string;
  ref: string;
  artifact: string;
  out: string;
  evidenceFileName: string;
};

type WorkflowRunApiRecord = {
  databaseId?: unknown;
  status?: unknown;
  conclusion?: unknown;
  createdAt?: unknown;
  url?: unknown;
};

type HostedWorkflowRun = {
  databaseId: number;
  status: string;
  conclusion: string | null;
  createdAt: string;
  url: string | null;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/run-hosted-evidence.js --kind <admin-sdk|managed-provider> [options]",
    "",
    "Options:",
    "  --kind <kind>                 Which evidence workflow to run (required)",
    "  --repo <owner/repo>          Override repository",
    "  --workflow <file>            Override workflow file name",
    "  --ref <ref>                  Override branch/ref (default: main)",
    "  --artifact <name>            Override artifact name",
    "  --out <path>                 Output evidence path",
    "  --timeout-seconds <n>        Wait timeout in seconds (default: 900)",
    "  --poll-seconds <n>           Poll interval in seconds (default: 15)",
    "  --input <key=value>          workflow_dispatch input (repeatable)",
    "  --config <path>              managed-provider only: load managed_provider_config_json from file",
    "  --evidence <path>            managed-provider only: import existing managed-provider-evidence JSON",
    "  --provider-class <name>      managed-provider only: set provider_class input",
    "  --no-wait                    Dispatch only; do not wait/download artifact",
    "",
    "Authentication:",
    "  Set GH_TOKEN for GitHub CLI access.",
  ].join("\n");
}

function isEvidenceKind(value: string): value is EvidenceKind {
  return value in EVIDENCE_KINDS;
}

function parseArgs(argv: string[]): HostedEvidenceOptions {
  const options: HostedEvidenceOptions = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    kind: null,
    repo: null,
    workflow: null,
    ref: null,
    artifact: null,
    out: null,
    timeoutSeconds: 900,
    pollSeconds: 15,
    wait: true,
    inputs: [],
    configPath: null,
    evidencePath: null,
    providerClass: null,
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
    if (token === "--no-wait") {
      options.wait = false;
      continue;
    }
    if (!token.startsWith("--")) {
      continue;
    }
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    switch (key) {
      case "root":
        options.root = value;
        break;
      case "kind":
        if (!isEvidenceKind(value)) {
          throw new Error(`--kind must be one of: ${Object.keys(EVIDENCE_KINDS).join(", ")}`);
        }
        options.kind = value;
        break;
      case "repo":
        options.repo = value;
        break;
      case "workflow":
        options.workflow = value;
        break;
      case "ref":
        options.ref = value;
        break;
      case "artifact":
        options.artifact = value;
        break;
      case "out":
        options.out = value;
        break;
      case "timeout-seconds":
        options.timeoutSeconds = Number.parseInt(value, 10);
        break;
      case "poll-seconds":
        options.pollSeconds = Number.parseInt(value, 10);
        break;
      case "input":
        options.inputs.push(value);
        break;
      case "config":
        options.configPath = value;
        break;
      case "evidence":
        options.evidencePath = value;
        break;
      case "provider-class":
        options.providerClass = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  if (options.kind === null) {
    throw new Error(`--kind must be one of: ${Object.keys(EVIDENCE_KINDS).join(", ")}`);
  }
  if (!Number.isFinite(options.timeoutSeconds) || options.timeoutSeconds <= 0) {
    throw new Error("--timeout-seconds must be a positive integer");
  }
  if (!Number.isFinite(options.pollSeconds) || options.pollSeconds <= 0) {
    throw new Error("--poll-seconds must be a positive integer");
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
      existsSync(path.join(current, "spec", "workflow-inventory.current.json"))
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

function buildKindConfig(kind: EvidenceKind, options: HostedEvidenceOptions): WorkflowConfig {
  const config = EVIDENCE_KINDS[kind];
  return {
    repo: options.repo ?? process.env[config.envRepo] ?? process.env.GITHUB_REPOSITORY ?? null,
    workflow: options.workflow ?? process.env[config.envWorkflow] ?? config.defaultWorkflow,
    ref: options.ref ?? process.env[config.envRef] ?? config.defaultBranch,
    artifact: options.artifact ?? process.env[config.envArtifact] ?? config.defaultArtifact,
    out: options.out ?? config.defaultOut,
    evidenceFileName: config.evidenceFileName,
  };
}

async function ensureDir(dirPath: string): Promise<void> {
  await fs.mkdir(dirPath, { recursive: true });
}

async function removeDir(dirPath: string): Promise<void> {
  await fs.rm(dirPath, { recursive: true, force: true });
}

async function readConfigJson(configPath: string): Promise<string> {
  const text = await fs.readFile(configPath, "utf8");
  return JSON.stringify(JSON.parse(text) as unknown);
}

function normalizeInputs(kind: EvidenceKind, options: HostedEvidenceOptions): Map<string, string> {
  const inputs = new Map<string, string>();
  for (const entry of options.inputs) {
    const separator = entry.indexOf("=");
    if (separator <= 0) {
      throw new Error(`Invalid --input value ${JSON.stringify(entry)}; expected key=value`);
    }
    inputs.set(entry.slice(0, separator), entry.slice(separator + 1));
  }
  if (kind === "managed-provider" && options.configPath) {
    inputs.set("__managed_config_path__", path.resolve(options.configPath));
  }
  if (kind === "managed-provider" && options.evidencePath) {
    inputs.set("__managed_evidence_path__", path.resolve(options.evidencePath));
  }
  if (kind === "managed-provider" && options.configPath && options.evidencePath) {
    throw new Error("--config and --evidence are mutually exclusive");
  }
  if (kind === "managed-provider" && options.providerClass) {
    inputs.set("provider_class", options.providerClass);
  }
  return inputs;
}

async function dispatchWorkflow(
  rootDir: string,
  workflowConfig: WorkflowConfig,
  inputs: Map<string, string>,
): Promise<void> {
  const ghArgs = [
    "workflow",
    "run",
    workflowConfig.workflow,
    "--repo",
    workflowConfig.repo ?? "",
    "--ref",
    workflowConfig.ref,
  ];
  for (const [key, value] of inputs.entries()) {
    if (key === "__managed_config_path__" || key === "__managed_evidence_path__") {
      continue;
    }
    ghArgs.push("-f", `${key}=${value}`);
  }
  const managedConfigPath = inputs.get("__managed_config_path__");
  if (managedConfigPath) {
    ghArgs.push("-f", `managed_provider_config_json=${await readConfigJson(managedConfigPath)}`);
  }
  const managedEvidencePath = inputs.get("__managed_evidence_path__");
  if (managedEvidencePath) {
    ghArgs.push("-f", `managed_provider_evidence_json=${await readConfigJson(managedEvidencePath)}`);
  }
  await execFile("gh", ghArgs, { cwd: rootDir });
}

function normalizeRunRecord(value: unknown): HostedWorkflowRun | null {
  if (!value || typeof value !== "object") {
    return null;
  }
  const record = value as WorkflowRunApiRecord;
  if (
    typeof record.databaseId !== "number" ||
    typeof record.status !== "string" ||
    typeof record.createdAt !== "string"
  ) {
    return null;
  }
  return {
    databaseId: record.databaseId,
    status: record.status,
    conclusion: typeof record.conclusion === "string" ? record.conclusion : null,
    createdAt: record.createdAt,
    url: typeof record.url === "string" ? record.url : null,
  };
}

async function listWorkflowRuns(rootDir: string, workflowConfig: WorkflowConfig): Promise<HostedWorkflowRun[]> {
  const { stdout } = await execFile(
    "gh",
    [
      "run",
      "list",
      "--repo",
      workflowConfig.repo ?? "",
      "--workflow",
      workflowConfig.workflow,
      "--branch",
      workflowConfig.ref,
      "--limit",
      "10",
      "--json",
      "databaseId,status,conclusion,createdAt,url",
    ],
    { cwd: rootDir },
  );
  const runs = JSON.parse(String(stdout)) as unknown;
  if (!Array.isArray(runs)) {
    throw new Error("gh run list returned a non-array payload");
  }
  return runs
    .map((entry) => normalizeRunRecord(entry))
    .filter((entry): entry is HostedWorkflowRun => entry !== null);
}

function findTriggeredRun(runs: HostedWorkflowRun[], startedAt: Date): HostedWorkflowRun | null {
  const threshold = startedAt.getTime() - 60_000;
  const candidates = runs
    .filter((run) => Date.parse(run.createdAt) >= threshold)
    .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt));
  return candidates[0] ?? null;
}

async function sleep(milliseconds: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForSuccessfulRun(
  rootDir: string,
  workflowConfig: WorkflowConfig,
  startedAt: Date,
  timeoutSeconds: number,
  pollSeconds: number,
): Promise<HostedWorkflowRun> {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const runs = await listWorkflowRuns(rootDir, workflowConfig);
    const run = findTriggeredRun(runs, startedAt);
    if (run) {
      if (run.status === "completed") {
        if (run.conclusion !== "success") {
          throw new Error(
            `Hosted workflow ${workflowConfig.workflow} completed with conclusion ${run.conclusion ?? "unknown"} (${run.url ?? "no-url"})`,
          );
        }
        return run;
      }
    }
    await sleep(pollSeconds * 1000);
  }
  throw new Error(`Timed out waiting for ${workflowConfig.workflow} on ${workflowConfig.repo}`);
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

async function downloadArtifact(
  rootDir: string,
  workflowConfig: WorkflowConfig,
  run: HostedWorkflowRun,
  evidenceFileName: string,
  outPath: string,
): Promise<void> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "aegaeon-hosted-evidence-"));
  try {
    await execFile(
      "gh",
      [
        "run",
        "download",
        String(run.databaseId),
        "--repo",
        workflowConfig.repo ?? "",
        "--name",
        workflowConfig.artifact,
        "--dir",
        tempDir,
      ],
      { cwd: rootDir },
    );
    const matches = await findFilesNamed(tempDir, evidenceFileName);
    const firstMatch = matches[0];
    if (!firstMatch) {
      throw new Error(`Could not find ${evidenceFileName} inside downloaded artifact ${workflowConfig.artifact}`);
    }
    await ensureDir(path.dirname(outPath));
    await fs.copyFile(firstMatch, outPath);
  } finally {
    await removeDir(tempDir);
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const kind = options.kind;
  if (kind === null) {
    throw new Error(`--kind must be one of: ${Object.keys(EVIDENCE_KINDS).join(", ")}`);
  }

  const rootDir = findWorkspaceRoot(options.root);
  const workflowConfig = buildKindConfig(kind, options);
  if (!workflowConfig.repo) {
    throw new Error(`No repository configured for ${kind} hosted evidence`);
  }
  const inputs = normalizeInputs(kind, options);
  const outPath = path.resolve(rootDir, workflowConfig.out);
  const startedAt = new Date();

  await dispatchWorkflow(rootDir, workflowConfig, inputs);
  console.log(`[run-hosted-evidence] dispatched ${workflowConfig.workflow} on ${workflowConfig.repo}@${workflowConfig.ref}`);

  if (!options.wait) {
    return;
  }

  const run = await waitForSuccessfulRun(
    rootDir,
    workflowConfig,
    startedAt,
    options.timeoutSeconds,
    options.pollSeconds,
  );
  await downloadArtifact(rootDir, workflowConfig, run, workflowConfig.evidenceFileName, outPath);
  console.log(`[run-hosted-evidence] downloaded ${workflowConfig.artifact} from ${workflowConfig.repo}#${run.databaseId}`);
  if (run.url) {
    console.log(`[run-hosted-evidence] workflow run: ${run.url}`);
  }
  console.log(`[run-hosted-evidence] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error("[run-hosted-evidence] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
