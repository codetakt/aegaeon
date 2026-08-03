import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const TOOL_ROOT = path.resolve(MODULE_DIR, "..");
const DEFAULT_POLICY_PATH = path.join(TOOL_ROOT, "spec", "hosted-evidence-sources.current.json");

type HostedEvidenceSourceOptions = {
  policy: string;
  actual: string | null;
  owner: string | null;
  repo: string | null;
  currentRepo: string | null;
};

type HostedEvidenceSource = {
  name: string;
  repositoryVariable: string;
  repositoryRequired: boolean;
  expectedRepositorySuffixes: string[];
  missingRepositoryUsesCurrentRepo: boolean;
  refVariable: string;
  defaultRef: string;
  workflowVariable: string;
  expectedWorkflow: string;
  artifactVariable: string;
  expectedArtifact: string;
  crossRepoTokenSecret: string;
};

type HostedEvidenceSourcePolicy = {
  currentRepositorySuffixes: string[];
  sources: HostedEvidenceSource[];
};

type HostedEvidenceActual = {
  repository: string | null;
  secrets: Set<string>;
  variables: Map<string, string | null>;
};

type ErrnoLike = {
  stderr?: string;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-hosted-evidence-sources.js --owner <owner> --repo <repo> [--policy <path>]",
    "  node dist-tools/check-hosted-evidence-sources.js --actual <repo-settings.json> [--policy <path>] [--current-repo <owner/repo>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_GITHUB_OWNER",
    "  AEGAEON_GITHUB_REPO",
    "  GITHUB_REPOSITORY",
  ].join("\n");
}

function parseArgs(argv: string[]): HostedEvidenceSourceOptions {
  const options: HostedEvidenceSourceOptions = {
    policy: DEFAULT_POLICY_PATH,
    actual: null,
    owner: process.env.AEGAEON_GITHUB_OWNER ?? null,
    repo: process.env.AEGAEON_GITHUB_REPO ?? null,
    currentRepo: process.env.GITHUB_REPOSITORY ?? null,
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
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    switch (key) {
      case "policy":
        options.policy = value;
        break;
      case "actual":
        options.actual = value;
        break;
      case "owner":
        options.owner = value;
        break;
      case "repo":
        options.repo = value;
        break;
      case "current-repo":
        options.currentRepo = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
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

function ensureBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function ensureNonEmptyStringArray(value: unknown, label: string): string[] {
  if (typeof value === "string" && value.length > 0) {
    return [value];
  }
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`Expected non-empty string array for ${label}`);
  }
  return value.map((entry, index) => ensureString(entry, `${label}[${index}]`));
}

function normalizeSource(entry: unknown, label: string): HostedEvidenceSource {
  if (!entry || typeof entry !== "object") {
    throw new Error(`Expected object for ${label}`);
  }
  const source = entry as Record<string, unknown>;
  return {
    name: ensureString(source.name, `${label}.name`),
    repositoryVariable: ensureString(source.repository_variable, `${label}.repository_variable`),
    repositoryRequired: ensureBoolean(source.repository_required, `${label}.repository_required`),
    expectedRepositorySuffixes: ensureNonEmptyStringArray(
      source.expected_repository_suffixes ?? source.expected_repository_suffix,
      `${label}.expected_repository_suffixes`,
    ),
    missingRepositoryUsesCurrentRepo: ensureBoolean(
      source.missing_repository_uses_current_repo,
      `${label}.missing_repository_uses_current_repo`,
    ),
    refVariable: ensureString(source.ref_variable, `${label}.ref_variable`),
    defaultRef: ensureString(source.default_ref, `${label}.default_ref`),
    workflowVariable: ensureString(source.workflow_variable, `${label}.workflow_variable`),
    expectedWorkflow: ensureString(source.expected_workflow, `${label}.expected_workflow`),
    artifactVariable: ensureString(source.artifact_variable, `${label}.artifact_variable`),
    expectedArtifact: ensureString(source.expected_artifact, `${label}.expected_artifact`),
    crossRepoTokenSecret: ensureString(source.cross_repo_token_secret, `${label}.cross_repo_token_secret`),
  };
}

function validatePolicy(policy: unknown): HostedEvidenceSourcePolicy {
  if (!policy || typeof policy !== "object") {
    throw new Error("Hosted evidence source policy must be an object");
  }
  const policyRecord = policy as Record<string, unknown>;
  if (!Array.isArray(policyRecord.sources) || policyRecord.sources.length === 0) {
    throw new Error("Hosted evidence source policy requires a non-empty `sources` array");
  }
  return {
    currentRepositorySuffixes: ensureNonEmptyStringArray(
      policyRecord.current_repository_suffixes ?? policyRecord.current_repository_suffix,
      "current_repository_suffixes",
    ),
    sources: policyRecord.sources.map((entry, index) => normalizeSource(entry, `sources[${index}]`)),
  };
}

function normalizeActual(actual: unknown, currentRepoFallback: string | null): HostedEvidenceActual {
  if (!actual || typeof actual !== "object") {
    throw new Error("Hosted evidence source payload must be an object");
  }

  const actualRecord = actual as Record<string, unknown>;
  const secrets = new Set<string>();
  if (Array.isArray(actualRecord.secrets)) {
    for (const entry of actualRecord.secrets) {
      if (typeof entry === "string") {
        secrets.add(entry);
        continue;
      }
      const secretRecord = entry as { name?: unknown } | null;
      if (secretRecord && typeof secretRecord === "object" && typeof secretRecord.name === "string") {
        secrets.add(secretRecord.name);
        continue;
      }
      throw new Error("Invalid secrets payload entry");
    }
  } else {
    throw new Error("Hosted evidence source payload requires a `secrets` array");
  }

  const variables = new Map<string, string | null>();
  const rawVariables = actualRecord.variables;
  if (rawVariables && typeof rawVariables === "object" && !Array.isArray(rawVariables)) {
    for (const [name, value] of Object.entries(rawVariables)) {
      variables.set(name, value == null ? null : String(value));
    }
  } else if (Array.isArray(rawVariables)) {
    for (const entry of rawVariables) {
      if (typeof entry === "string") {
        variables.set(entry, null);
        continue;
      }
      const variableRecord = entry as { name?: unknown; value?: unknown } | null;
      if (variableRecord && typeof variableRecord === "object" && typeof variableRecord.name === "string") {
        variables.set(variableRecord.name, variableRecord.value == null ? null : String(variableRecord.value));
        continue;
      }
      throw new Error("Invalid variables payload entry");
    }
  } else {
    throw new Error("Hosted evidence source payload requires a `variables` object or array");
  }

  return {
    repository:
      typeof actualRecord.repository === "string" && actualRecord.repository.length > 0
        ? actualRecord.repository
        : currentRepoFallback,
    secrets,
    variables,
  };
}

async function loadJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function fetchRemoteSecretNames(owner: string, repo: string): Promise<Set<string>> {
  const { stdout } = await execFile(
    "gh",
    [
      "api",
      "-H",
      "Accept: application/vnd.github+json",
      `repos/${owner}/${repo}/actions/secrets`,
    ],
    { cwd: TOOL_ROOT },
  );
  const payload = JSON.parse(String(stdout)) as { secrets?: { name?: unknown }[] };
  return new Set((payload.secrets ?? []).map((entry) => entry.name).filter((entry): entry is string => typeof entry === "string"));
}

async function fetchRemoteVariable(owner: string, repo: string, name: string): Promise<string | null | undefined> {
  try {
    const { stdout } = await execFile(
      "gh",
      [
        "api",
        "-H",
        "Accept: application/vnd.github+json",
        `repos/${owner}/${repo}/actions/variables/${name}`,
      ],
      { cwd: TOOL_ROOT },
    );
    const payload = JSON.parse(String(stdout)) as { value?: unknown };
    return payload.value == null ? null : String(payload.value);
  } catch (error) {
    if ((error as ErrnoLike | undefined)?.stderr && /404/.test((error as ErrnoLike).stderr ?? "")) {
      return undefined;
    }
    throw error;
  }
}

async function fetchRemoteActual(owner: string, repo: string, policy: HostedEvidenceSourcePolicy): Promise<HostedEvidenceActual> {
  const secrets = await fetchRemoteSecretNames(owner, repo);
  const variables = new Map<string, string | null>();
  const variableNames = new Set(
    policy.sources.flatMap((source) => [
      source.repositoryVariable,
      source.refVariable,
      source.workflowVariable,
      source.artifactVariable,
    ]),
  );

  for (const name of variableNames) {
    const value = await fetchRemoteVariable(owner, repo, name);
    if (value !== undefined) {
      variables.set(name, value);
    }
  }

  return {
    repository: `${owner}/${repo}`,
    secrets,
    variables,
  };
}

function repositoryMatches(expectedSuffixes: string[], repository: string | null): boolean {
  if (typeof repository !== "string" || repository.length === 0) {
    return false;
  }
  const parts = repository.split("/");
  return parts.length === 2 && expectedSuffixes.includes(parts[1] ?? "");
}

function compareAgainstPolicy(policy: HostedEvidenceSourcePolicy, actual: HostedEvidenceActual): string[] {
  const mismatches: string[] = [];

  if (!actual.repository) {
    mismatches.push("current repository slug is missing");
  } else if (!repositoryMatches(policy.currentRepositorySuffixes, actual.repository)) {
    mismatches.push(
      `current repository must end with one of ${JSON.stringify(policy.currentRepositorySuffixes)}; got ${JSON.stringify(actual.repository)}`,
    );
  }

  for (const source of policy.sources) {
    let repository = actual.variables.get(source.repositoryVariable) ?? null;
    if ((!repository || repository.length === 0) && source.missingRepositoryUsesCurrentRepo) {
      repository = actual.repository;
    }

    if ((!repository || repository.length === 0) && source.repositoryRequired) {
      mismatches.push(`${source.name}: missing repository variable ${source.repositoryVariable}`);
      continue;
    }

    if (repository && !repositoryMatches(source.expectedRepositorySuffixes, repository)) {
      mismatches.push(
        `${source.name}: expected repository suffix in ${JSON.stringify(source.expectedRepositorySuffixes)}, got ${JSON.stringify(repository)}`,
      );
    }

    const ref = actual.variables.get(source.refVariable) ?? source.defaultRef;
    if (typeof ref !== "string" || ref.length === 0) {
      mismatches.push(`${source.name}: missing ref (${source.refVariable})`);
    }

    const workflow = actual.variables.get(source.workflowVariable) ?? source.expectedWorkflow;
    if (workflow !== source.expectedWorkflow) {
      mismatches.push(
        `${source.name}: expected workflow ${JSON.stringify(source.expectedWorkflow)}, got ${JSON.stringify(workflow)}`,
      );
    }

    const artifact = actual.variables.get(source.artifactVariable) ?? source.expectedArtifact;
    if (artifact !== source.expectedArtifact) {
      mismatches.push(
        `${source.name}: expected artifact ${JSON.stringify(source.expectedArtifact)}, got ${JSON.stringify(artifact)}`,
      );
    }

    if (
      repository &&
      actual.repository &&
      repository !== actual.repository &&
      !actual.secrets.has(source.crossRepoTokenSecret)
    ) {
      mismatches.push(
        `${source.name}: cross-repository source ${JSON.stringify(repository)} requires secret ${source.crossRepoTokenSecret}`,
      );
    }
  }

  return mismatches;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const policy = validatePolicy(await loadJson<unknown>(options.policy));

  let actual: HostedEvidenceActual;
  if (options.actual) {
    actual = normalizeActual(await loadJson<unknown>(options.actual), options.currentRepo);
  } else if (options.owner && options.repo) {
    actual = await fetchRemoteActual(options.owner, options.repo, policy);
  } else {
    throw new Error(`Either --actual or both --owner and --repo are required.\n\n${usage()}`);
  }

  const mismatches = compareAgainstPolicy(policy, actual);
  if (mismatches.length > 0) {
    throw new Error(`Hosted evidence source mismatches:\n- ${mismatches.join("\n- ")}`);
  }

  console.log(`Hosted evidence sources match ${options.policy}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
