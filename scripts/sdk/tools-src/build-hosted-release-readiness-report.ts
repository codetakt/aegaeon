#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));

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
const DEFAULT_RELEASED_CLAIM_POLICY = path.join(
  TOOL_ROOT,
  "spec",
  "released-client-claim.current.json",
);
const DEFAULT_WORKFLOW_POLICY = path.join(TOOL_ROOT, "spec", "workflow-inventory.current.json");
const DEFAULT_OUTPUT_PATH = path.join(
  TOOL_ROOT,
  ".artifacts",
  "release",
  "hosted-release-readiness-report.json",
);

type WorkflowRunRecord = {
  workflowName: string | null;
  status: string | null;
  conclusion: string | null;
  createdAt: string | null;
  headBranch: string | null;
  headSha: string | null;
  event: string | null;
  jobName: string | null;
};

type RemoteRepositoryState = {
  repository: string;
  defaultBranch: string;
  remoteHead: string | null;
  remoteHeadMessage: string | null;
  workflowFiles: string[];
  variables: Record<string, string | null>;
  secrets: string[];
  runs: WorkflowRunRecord[];
};

type HostedEvidenceState = {
  latestSuccessfulRun: WorkflowRunRecord | null;
  ageHours: number | null;
  freshEnough: boolean;
};

type HostedReleaseReadinessReport = {
  schema_version: 1;
  generated_at: string;
  sdk_repository: string;
  admin_repository: string;
  local_sdk_head: string | null;
  remote_sdk_head: string | null;
  remote_sdk_head_message: string | null;
  remote_sdk_snapshot_source_head: string | null;
  remote_sdk_default_branch: string | null;
  sdk_remote_contains_local_head: boolean;
  sdk_remote_matches_local_snapshot: boolean;
  sdk_repository_settings_mismatches: string[];
  sdk_hosted_evidence_source_mismatches: string[];
  sdk_missing_workflow_files: string[];
  admin_missing_workflow_files: string[];
  managed_provider_evidence: HostedEvidenceState;
  admin_sdk_evidence: HostedEvidenceState;
  ready: boolean;
  blockers: string[];
};

type ReleasedClientClaimPolicy = {
  activation_requirements: {
    managed_provider_evidence_max_age_hours: number;
    managed_provider_expected_workflow: string;
    admin_sdk_evidence_max_age_hours: number;
    admin_sdk_expected_workflow: string;
  };
};

type WorkflowInventoryPolicy = {
  required_workflows: { path: string; name: string }[];
};

type BuildReportInput = {
  sdkRepository: string;
  adminRepository: string;
  localSdkHead: string | null;
  sdkState: RemoteRepositoryState;
  adminState: RemoteRepositoryState;
  sdkRepositorySettingsMismatches: string[];
  sdkHostedEvidenceSourceMismatches: string[];
  releasedClientClaimPolicy: ReleasedClientClaimPolicy;
  workflowInventoryPolicy: WorkflowInventoryPolicy;
};

function usage() {
  return [
    "Usage:",
    "  node dist-tools/build-hosted-release-readiness-report.js [options]",
    "",
    "Options:",
    "  --released-claim-policy <path>   Override released-client policy path",
    "  --workflow-policy <path>         Override workflow inventory policy path",
    "  --out <path>                    Output report path",
    "  --sdk-owner <owner>             SDK repository owner",
    "  --sdk-repo <repo>               SDK repository name",
    "  --admin-owner <owner>           Admin-console repository owner",
    "  --admin-repo <repo>             Admin-console repository name",
    "  --sdk-state <path>              Use saved SDK remote state JSON instead of GitHub",
    "  --admin-state <path>            Use saved admin remote state JSON instead of GitHub",
    "  --local-sdk-head <sha>          Override local SDK HEAD for comparison",
  ].join("\n");
}

type CliOptions = {
  releasedClaimPolicy: string;
  workflowPolicy: string;
  out: string;
  sdkOwner: string | null;
  sdkRepo: string | null;
  adminOwner: string | null;
  adminRepo: string | null;
  sdkState: string | null;
  adminState: string | null;
  localSdkHead: string | null;
};

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    releasedClaimPolicy: DEFAULT_RELEASED_CLAIM_POLICY,
    workflowPolicy: DEFAULT_WORKFLOW_POLICY,
    out: DEFAULT_OUTPUT_PATH,
    sdkOwner: null,
    sdkRepo: null,
    adminOwner: null,
    adminRepo: null,
    sdkState: null,
    adminState: null,
    localSdkHead: null,
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
    const rawKey = token.slice(2);
    const key = rawKey.replace(
      /-([a-z])/g,
      (_, char: string) => char.toUpperCase(),
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

function ensureString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function splitRepositorySlug(slug: string): { owner: string; repo: string } {
  const parts = slug.split("/");
  if (parts.length !== 2 || parts[0]?.length === 0 || parts[1]?.length === 0) {
    throw new Error(`Expected repository slug owner/repo, got ${JSON.stringify(slug)}`);
  }
  const [owner, repo] = parts;
  return {
    owner: ensureString(owner, "repository owner"),
    repo: ensureString(repo, "repository name"),
  };
}

function getErrorText(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await readFile(filePath, "utf8")) as T;
}

async function inferRepositorySlug(repoRoot: string): Promise<string | null> {
  try {
    const { stdout } = await execFile("git", ["remote", "get-url", "origin"], { cwd: repoRoot });
    const remote = stdout.trim();
    const match = remote.match(/github\.com[:/](.+?)\/(.+?)(?:\.git)?$/);
    if (!match) {
      return null;
    }
    return `${match[1]}/${match[2]}`;
  } catch {
    return null;
  }
}

async function inferLocalHead(repoRoot: string): Promise<string | null> {
  try {
    const { stdout } = await execFile("git", ["rev-parse", "HEAD"], { cwd: repoRoot });
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

async function fetchDefaultBranch(owner: string, repo: string): Promise<string> {
  const { stdout } = await execFile(
    "gh",
    ["api", `repos/${owner}/${repo}`, "--jq", ".default_branch"],
    {
      cwd: TOOL_ROOT,
    },
  );
  return stdout.trim();
}

async function fetchRemoteHead(
  owner: string,
  repo: string,
  branch: string,
): Promise<{ sha: string | null; message: string | null }> {
  const { stdout } = await execFile(
    "gh",
    ["api", `repos/${owner}/${repo}/commits/${branch}`],
    { cwd: TOOL_ROOT },
  );
  const payload = JSON.parse(stdout) as { sha?: unknown; commit?: { message?: unknown } };
  return {
    sha: typeof payload.sha === "string" && payload.sha.length > 0 ? payload.sha : null,
    message:
      payload.commit &&
      typeof payload.commit.message === "string" &&
      payload.commit.message.length > 0
        ? payload.commit.message
        : null,
  };
}

async function fetchWorkflowFiles(owner: string, repo: string, branch: string): Promise<string[]> {
  try {
    const { stdout } = await execFile(
      "gh",
      [
        "api",
        `repos/${owner}/${repo}/contents/.github/workflows?ref=${encodeURIComponent(branch)}`,
        "--jq",
        ".[].name",
      ],
      { cwd: TOOL_ROOT },
    );
    return stdout
      .split(/\r?\n/u)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  } catch (error) {
    const text = getErrorText(error);
    if (text.includes("404")) {
      return [];
    }
    throw error;
  }
}

async function fetchRemoteSecrets(owner: string, repo: string): Promise<string[]> {
  const { stdout } = await execFile(
    "gh",
    ["api", `repos/${owner}/${repo}/actions/secrets`, "--jq", ".secrets[].name"],
    { cwd: TOOL_ROOT },
  );
  return stdout
    .split(/\r?\n/u)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

async function fetchRemoteVariables(
  owner: string,
  repo: string,
): Promise<Record<string, string | null>> {
  const { stdout } = await execFile("gh", ["api", `repos/${owner}/${repo}/actions/variables`], {
    cwd: TOOL_ROOT,
  });
  const payload = JSON.parse(stdout) as {
    variables?: Array<{ name?: string; value?: string | null }>;
  };
  const variables: Record<string, string | null> = {};
  for (const entry of payload.variables ?? []) {
    if (typeof entry?.name === "string" && entry.name.length > 0) {
      variables[entry.name] = entry.value == null ? null : String(entry.value);
    }
  }
  return variables;
}

async function fetchWorkflowRuns(
  owner: string,
  repo: string,
  workflowName: string,
): Promise<WorkflowRunRecord[]> {
  try {
    const { stdout } = await execFile(
      "gh",
      [
        "run",
        "list",
        "-R",
        `${owner}/${repo}`,
        "--workflow",
        workflowName,
        "--limit",
        "20",
        "--json",
        "workflowName,status,conclusion,createdAt,headBranch,headSha,event",
      ],
      { cwd: TOOL_ROOT },
    );
    return JSON.parse(stdout) as WorkflowRunRecord[];
  } catch (error) {
    const text = getErrorText(error);
    if (text.includes("could not find any workflows")) {
      return [];
    }
    throw error;
  }
}

function normalizeRemoteState(value: unknown, label: string): RemoteRepositoryState {
  if (!value || typeof value !== "object") {
    throw new Error(`Expected object for ${label}`);
  }
  const record = value as Record<string, unknown>;
  const workflowFiles = Array.isArray(record.workflowFiles)
    ? record.workflowFiles.map((entry, index) =>
        ensureString(entry, `${label}.workflowFiles[${index}]`),
      )
    : [];
  const rawVariables = record.variables;
  if (!rawVariables || typeof rawVariables !== "object" || Array.isArray(rawVariables)) {
    throw new Error(`Expected object for ${label}.variables`);
  }
  const variables = Object.fromEntries(
    Object.entries(rawVariables).map(([name, value]) => [
      ensureString(name, `${label}.variables key`),
      value == null ? null : String(value),
    ]),
  );
  const secrets = Array.isArray(record.secrets)
    ? record.secrets.map((entry, index) => ensureString(entry, `${label}.secrets[${index}]`))
    : [];
  const runs = Array.isArray(record.runs)
    ? record.runs.map((entry) => {
        const run = (entry ?? {}) as Record<string, unknown>;
        return {
          workflowName: typeof run.workflowName === "string" ? run.workflowName : null,
          status: typeof run.status === "string" ? run.status : null,
          conclusion: typeof run.conclusion === "string" ? run.conclusion : null,
          createdAt: typeof run.createdAt === "string" ? run.createdAt : null,
          headBranch: typeof run.headBranch === "string" ? run.headBranch : null,
          headSha: typeof run.headSha === "string" ? run.headSha : null,
          event: typeof run.event === "string" ? run.event : null,
          jobName: typeof run.jobName === "string" ? run.jobName : null,
        } satisfies WorkflowRunRecord;
      })
    : [];

  return {
    repository: ensureString(record.repository, `${label}.repository`),
    defaultBranch: ensureString(record.defaultBranch, `${label}.defaultBranch`),
    remoteHead:
      typeof record.remoteHead === "string" && record.remoteHead.length > 0
        ? record.remoteHead
        : null,
    remoteHeadMessage:
      typeof record.remoteHeadMessage === "string" && record.remoteHeadMessage.length > 0
        ? record.remoteHeadMessage
        : null,
    workflowFiles,
    variables,
    secrets,
    runs,
  };
}

async function resolveRemoteState(
  statePath: string | null,
  owner: string,
  repo: string,
): Promise<RemoteRepositoryState> {
  if (statePath) {
    return normalizeRemoteState(await readJson(statePath), "remote state");
  }
  const defaultBranch = await fetchDefaultBranch(owner, repo);
  const remoteHead = await fetchRemoteHead(owner, repo, defaultBranch);
  const workflowFiles = await fetchWorkflowFiles(owner, repo, defaultBranch);
  const variables = await fetchRemoteVariables(owner, repo);
  const secrets = await fetchRemoteSecrets(owner, repo);
  return {
    repository: `${owner}/${repo}`,
    defaultBranch,
    remoteHead: remoteHead.sha,
    remoteHeadMessage: remoteHead.message,
    workflowFiles,
    variables,
    secrets,
    runs: [],
  };
}

async function loadWorkflowRuns(
  state: RemoteRepositoryState,
  workflowName: string,
): Promise<WorkflowRunRecord[]> {
  if (state.runs.length > 0) {
    return state.runs.filter((entry) => entry.workflowName === workflowName);
  }
  const { owner, repo } = splitRepositorySlug(state.repository);
  return fetchWorkflowRuns(owner, repo, workflowName);
}

async function runAuditScript(
  scriptName: string,
  args: string[],
): Promise<{ ok: true; lines: string[] } | { ok: false; lines: string[] }> {
  const candidatePaths = [
    path.join(TOOL_ROOT, "dist-tools", `${scriptName}.js`),
    path.join(TOOL_ROOT, "tools-src", `${scriptName}.ts`),
  ];
  const scriptPath = candidatePaths[0] ?? path.join(TOOL_ROOT, "dist-tools", `${scriptName}.js`);
  for (const candidate of candidatePaths) {
    try {
      await readFile(candidate, "utf8");
      return await execAuditScript(candidate, args);
    } catch (error) {
      const text = getErrorText(error);
      if (text.includes("ENOENT")) {
        continue;
      }
      throw error;
    }
  }
  return execAuditScript(scriptPath, args);
}

async function execAuditScript(
  scriptPath: string,
  args: string[],
): Promise<{ ok: true; lines: string[] } | { ok: false; lines: string[] }> {
  try {
    const { stdout, stderr } = await execFile(
      process.execPath,
      [scriptPath, ...args],
      { cwd: TOOL_ROOT },
    );
    return { ok: true, lines: [stdout, stderr].join("\n").split(/\r?\n/u).filter(Boolean) };
  } catch (error) {
    const stderr =
      typeof error === "object" && error && "stderr" in error
        ? String((error as { stderr: string }).stderr)
        : "";
    const stdout =
      typeof error === "object" && error && "stdout" in error
        ? String((error as { stdout: string }).stdout)
        : "";
    const lines = [stdout, stderr]
      .join("\n")
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("Usage:"));
    return { ok: false, lines };
  }
}

function extractMismatchLines(lines: string[]): string[] {
  return lines
    .flatMap((line) => line.split(/\n/u))
    .map((line) => line.trim())
    .filter((line) => line.startsWith("- "))
    .map((line) => line.slice(2));
}

async function collectRemoteAuditMismatches(
  scriptName: string,
  actualPayload: Record<string, unknown>,
): Promise<string[]> {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-hosted-readiness-"));
  const actualPath = path.join(tempDir, "actual.json");
  try {
    await writeFile(actualPath, `${JSON.stringify(actualPayload, null, 2)}\n`, "utf8");
    const result = await runAuditScript(scriptName, ["--actual", actualPath]);
    return result.ok ? [] : extractMismatchLines(result.lines);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

function hoursSince(isoTimestamp: string | null): number | null {
  if (!isoTimestamp) {
    return null;
  }
  const timestamp = Date.parse(isoTimestamp);
  if (Number.isNaN(timestamp)) {
    return null;
  }
  return (Date.now() - timestamp) / (1000 * 60 * 60);
}

function pickLatestSuccessfulRun(runs: WorkflowRunRecord[]): WorkflowRunRecord | null {
  const successfulRuns = runs.filter(
    (entry) =>
      entry.conclusion === "success" && typeof entry.createdAt === "string",
  );
  if (successfulRuns.length === 0) {
    return null;
  }
  successfulRuns.sort(
    (left, right) =>
      (Date.parse(right.createdAt ?? "") || 0) -
      (Date.parse(left.createdAt ?? "") || 0),
  );
  return successfulRuns[0] ?? null;
}

function extractSnapshotSourceHead(message: string | null): string | null {
  if (typeof message !== "string" || message.length === 0) {
    return null;
  }
  const explicitMatch = message.match(/source-head:\s*([0-9a-f]{7,40})/iu);
  if (explicitMatch?.[1]) {
    return explicitMatch[1].toLowerCase();
  }
  const legacyMatch = message.match(/CI snapshot \(([0-9a-f]{7,40})\)/iu);
  if (legacyMatch?.[1]) {
    return legacyMatch[1].toLowerCase();
  }
  return null;
}

export function buildHostedReleaseReadinessReport(
  input: BuildReportInput,
): HostedReleaseReadinessReport {
  const managedLatest = pickLatestSuccessfulRun(input.sdkState.runs);
  const adminLatest = pickLatestSuccessfulRun(input.adminState.runs);
  const managedAgeHours = hoursSince(managedLatest?.createdAt ?? null);
  const adminAgeHours = hoursSince(adminLatest?.createdAt ?? null);
  const requirements = input.releasedClientClaimPolicy.activation_requirements;
  const snapshotSourceHead = extractSnapshotSourceHead(input.sdkState.remoteHeadMessage);
  const directHeadMatch =
    input.localSdkHead !== null &&
    input.localSdkHead === input.sdkState.remoteHead;
  const snapshotHeadMatch =
    input.localSdkHead !== null &&
    snapshotSourceHead !== null &&
    input.localSdkHead.toLowerCase().startsWith(snapshotSourceHead);
  const sdkMissingWorkflowFiles = input.workflowInventoryPolicy.required_workflows
    .map((entry) => path.basename(entry.path))
    .filter((fileName) => !input.sdkState.workflowFiles.includes(fileName));
  const adminMissingWorkflowFiles = ["stack-e2e.yml"].filter(
    (fileName) => !input.adminState.workflowFiles.includes(fileName),
  );

  const blockers: string[] = [];
  if (!input.localSdkHead) {
    blockers.push("local_sdk_head_missing");
  } else if (!directHeadMatch && !snapshotHeadMatch) {
    blockers.push("sdk_remote_does_not_contain_local_head");
  }
  if (input.sdkRepositorySettingsMismatches.length > 0) {
    blockers.push("sdk_repository_settings_mismatch");
  }
  if (input.sdkHostedEvidenceSourceMismatches.length > 0) {
    blockers.push("sdk_hosted_evidence_source_mismatch");
  }
  if (sdkMissingWorkflowFiles.length > 0) {
    blockers.push("sdk_remote_missing_workflow_files");
  }
  if (adminMissingWorkflowFiles.length > 0) {
    blockers.push("admin_remote_missing_workflow_files");
  }
  if (!managedLatest) {
    blockers.push("managed_provider_successful_hosted_run_missing");
  } else if (
    managedAgeHours == null ||
    managedAgeHours > requirements.managed_provider_evidence_max_age_hours
  ) {
    blockers.push("managed_provider_hosted_run_stale");
  }
  if (!adminLatest) {
    blockers.push("admin_sdk_successful_hosted_run_missing");
  } else if (
    adminAgeHours == null ||
    adminAgeHours > requirements.admin_sdk_evidence_max_age_hours
  ) {
    blockers.push("admin_sdk_hosted_run_stale");
  }

  return {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    sdk_repository: input.sdkRepository,
    admin_repository: input.adminRepository,
    local_sdk_head: input.localSdkHead,
    remote_sdk_head: input.sdkState.remoteHead,
    remote_sdk_head_message: input.sdkState.remoteHeadMessage,
    remote_sdk_snapshot_source_head: snapshotSourceHead,
    remote_sdk_default_branch: input.sdkState.defaultBranch,
    sdk_remote_contains_local_head: directHeadMatch,
    sdk_remote_matches_local_snapshot: snapshotHeadMatch,
    sdk_repository_settings_mismatches: input.sdkRepositorySettingsMismatches,
    sdk_hosted_evidence_source_mismatches: input.sdkHostedEvidenceSourceMismatches,
    sdk_missing_workflow_files: sdkMissingWorkflowFiles,
    admin_missing_workflow_files: adminMissingWorkflowFiles,
    managed_provider_evidence: {
      latestSuccessfulRun: managedLatest,
      ageHours: managedAgeHours,
      freshEnough:
        managedLatest !== null &&
        managedAgeHours !== null &&
        managedAgeHours <= requirements.managed_provider_evidence_max_age_hours,
    },
    admin_sdk_evidence: {
      latestSuccessfulRun: adminLatest,
      ageHours: adminAgeHours,
      freshEnough:
        adminLatest !== null &&
        adminAgeHours !== null &&
        adminAgeHours <= requirements.admin_sdk_evidence_max_age_hours,
    },
    ready: blockers.length === 0,
    blockers,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const sdkSlug =
    options.sdkOwner && options.sdkRepo
      ? `${options.sdkOwner}/${options.sdkRepo}`
      : (await inferRepositorySlug(path.resolve(TOOL_ROOT, ".."))) ??
        process.env.GITHUB_REPOSITORY ??
        null;
  if (!sdkSlug) {
    throw new Error("Unable to infer SDK repository slug; pass --sdk-owner and --sdk-repo");
  }
  const sdkRepository = splitRepositorySlug(sdkSlug);
  const adminOwner = options.adminOwner ?? sdkRepository.owner;
  const adminRepo = options.adminRepo ?? "aegaeon-admin-console";

  const releasedClientClaimPolicy = await readJson<ReleasedClientClaimPolicy>(
    options.releasedClaimPolicy,
  );
  const workflowInventoryPolicy = await readJson<WorkflowInventoryPolicy>(options.workflowPolicy);
  const sdkState = await resolveRemoteState(
    options.sdkState,
    sdkRepository.owner,
    sdkRepository.repo,
  );
  const adminState = await resolveRemoteState(options.adminState, adminOwner, adminRepo);
  sdkState.runs = await loadWorkflowRuns(
    sdkState,
    releasedClientClaimPolicy.activation_requirements.managed_provider_expected_workflow,
  );
  adminState.runs = await loadWorkflowRuns(
    adminState,
    releasedClientClaimPolicy.activation_requirements.admin_sdk_expected_workflow,
  );

  const sdkRepositorySettingsMismatches =
    await collectRemoteAuditMismatches("check-repository-settings", {
      secrets: sdkState.secrets,
      variables: sdkState.variables,
    });
  const sdkHostedEvidenceSourceMismatches =
    await collectRemoteAuditMismatches("check-hosted-evidence-sources", {
      repository: sdkState.repository,
      secrets: sdkState.secrets,
      variables: sdkState.variables,
    });
  const localSdkHead =
    options.localSdkHead ??
    (await inferLocalHead(path.resolve(TOOL_ROOT, "..")));
  const report = buildHostedReleaseReadinessReport({
    sdkRepository: sdkState.repository,
    adminRepository: adminState.repository,
    localSdkHead,
    sdkState,
    adminState,
    sdkRepositorySettingsMismatches,
    sdkHostedEvidenceSourceMismatches,
    releasedClientClaimPolicy,
    workflowInventoryPolicy,
  });
  await mkdir(path.dirname(options.out), { recursive: true });
  await writeFile(options.out, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  console.log(`Wrote hosted release readiness report to ${options.out}`);
  if (report.ready) {
    console.log("Hosted release readiness is satisfied");
  } else {
    console.log(`Hosted release readiness blockers: ${report.blockers.join(", ")}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
