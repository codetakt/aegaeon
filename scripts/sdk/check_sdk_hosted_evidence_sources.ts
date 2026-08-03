#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..", "..");
const DEFAULT_POLICY_PATH = path.join(MODULE_DIR, "sdk_hosted_evidence_sources.current.json");

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types " +
      "scripts/sdk/check_sdk_hosted_evidence_sources.ts " +
      "--owner <owner> --repo <repo> [--policy <path>]",
    "  node --experimental-strip-types " +
      "scripts/sdk/check_sdk_hosted_evidence_sources.ts " +
      "--actual <repo-settings.json> [--policy <path>] " +
      "[--current-repo <owner/repo>]",
    "",
    "Environment fallbacks:",
    "  AEGAEON_GITHUB_OWNER",
    "  AEGAEON_GITHUB_REPO",
    "  GITHUB_REPOSITORY",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    policy: DEFAULT_POLICY_PATH,
    actual: null,
    owner: process.env.AEGAEON_GITHUB_OWNER ?? null,
    repo: process.env.AEGAEON_GITHUB_REPO ?? null,
    currentRepo: process.env.GITHUB_REPOSITORY ?? null,
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

  return options;
}

function ensureString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureBoolean(value, label) {
  if (typeof value !== "boolean") {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function ensureNonEmptyStringArray(value, label) {
  if (typeof value === "string" && value.length > 0) {
    return [value];
  }
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`Expected non-empty string array for ${label}`);
  }
  return value.map((entry, index) => ensureString(entry, `${label}[${index}]`));
}

function normalizeSource(entry, label) {
  if (!entry || typeof entry !== "object") {
    throw new Error(`Expected object for ${label}`);
  }
  return {
    name: ensureString(entry.name, `${label}.name`),
    repositoryVariable: ensureString(entry.repository_variable, `${label}.repository_variable`),
    repositoryRequired: ensureBoolean(entry.repository_required, `${label}.repository_required`),
    expectedRepositorySuffixes: ensureNonEmptyStringArray(
      entry.expected_repository_suffixes ?? entry.expected_repository_suffix,
      `${label}.expected_repository_suffixes`,
    ),
    missingRepositoryUsesCurrentRepo: ensureBoolean(
      entry.missing_repository_uses_current_repo,
      `${label}.missing_repository_uses_current_repo`,
    ),
    refVariable: ensureString(entry.ref_variable, `${label}.ref_variable`),
    defaultRef: ensureString(entry.default_ref, `${label}.default_ref`),
    workflowVariable: ensureString(entry.workflow_variable, `${label}.workflow_variable`),
    expectedWorkflow: ensureString(entry.expected_workflow, `${label}.expected_workflow`),
    artifactVariable: ensureString(entry.artifact_variable, `${label}.artifact_variable`),
    expectedArtifact: ensureString(entry.expected_artifact, `${label}.expected_artifact`),
    crossRepoTokenSecret: ensureString(
      entry.cross_repo_token_secret,
      `${label}.cross_repo_token_secret`,
    ),
  };
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new Error("Hosted evidence source policy must be an object");
  }
  if (!Array.isArray(policy.sources) || policy.sources.length === 0) {
    throw new Error("Hosted evidence source policy requires a non-empty `sources` array");
  }
  return {
    currentRepositorySuffixes: ensureNonEmptyStringArray(
      policy.current_repository_suffixes ?? policy.current_repository_suffix,
      "current_repository_suffixes",
    ),
    sources: policy.sources.map((entry, index) => normalizeSource(entry, `sources[${index}]`)),
  };
}

function normalizeActual(actual, currentRepoFallback) {
  if (!actual || typeof actual !== "object") {
    throw new Error("Hosted evidence source payload must be an object");
  }

  const secrets = new Set();
  if (Array.isArray(actual.secrets)) {
    for (const entry of actual.secrets) {
      if (typeof entry === "string") {
        secrets.add(entry);
        continue;
      }
      if (entry && typeof entry === "object" && typeof entry.name === "string") {
        secrets.add(entry.name);
        continue;
      }
      throw new Error("Invalid secrets payload entry");
    }
  } else {
    throw new Error("Hosted evidence source payload requires a `secrets` array");
  }

  const variables = new Map();
  const rawVariables = actual.variables;
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
      if (entry && typeof entry === "object" && typeof entry.name === "string") {
        variables.set(entry.name, entry.value == null ? null : String(entry.value));
        continue;
      }
      throw new Error("Invalid variables payload entry");
    }
  } else {
    throw new Error("Hosted evidence source payload requires a `variables` object or array");
  }

  return {
    repository: typeof actual.repository === "string" && actual.repository.length > 0
      ? actual.repository
      : currentRepoFallback,
    secrets,
    variables,
  };
}

async function loadJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function fetchRemoteSecretNames(owner, repo) {
  const { stdout } = await execFile(
    "gh",
    [
      "api",
      "-H",
      "Accept: application/vnd.github+json",
      `repos/${owner}/${repo}/actions/secrets`,
    ],
    { cwd: ROOT_DIR },
  );
  const payload = JSON.parse(stdout);
  return new Set(
    (payload.secrets ?? [])
      .map((entry) => entry.name)
      .filter((entry) => typeof entry === "string"),
  );
}

async function fetchRemoteVariable(owner, repo, name) {
  try {
    const { stdout } = await execFile(
      "gh",
      [
        "api",
        "-H",
        "Accept: application/vnd.github+json",
        `repos/${owner}/${repo}/actions/variables/${name}`,
      ],
      { cwd: ROOT_DIR },
    );
    const payload = JSON.parse(stdout);
    return payload.value == null ? null : String(payload.value);
  } catch (error) {
    if (error?.stderr && /404/.test(error.stderr)) {
      return undefined;
    }
    throw error;
  }
}

async function fetchRemoteActual(owner, repo, policy) {
  const secrets = await fetchRemoteSecretNames(owner, repo);
  const variables = new Map();
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

function repositoryMatches(expectedSuffixes, repository) {
  if (typeof repository !== "string" || repository.length === 0) {
    return false;
  }
  const parts = repository.split("/");
  return parts.length === 2 && expectedSuffixes.includes(parts[1] ?? "");
}

function compareAgainstPolicy(policy, actual) {
  const mismatches = [];

  if (!actual.repository) {
    mismatches.push("current repository slug is missing");
  } else if (!repositoryMatches(policy.currentRepositorySuffixes, actual.repository)) {
    mismatches.push(
      "current repository must end with one of " +
        `${JSON.stringify(policy.currentRepositorySuffixes)}; got ` +
        JSON.stringify(actual.repository),
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
        `${source.name}: expected repository suffixes ` +
          `${JSON.stringify(source.expectedRepositorySuffixes)}, got ` +
          JSON.stringify(repository),
      );
    }

    const ref = actual.variables.get(source.refVariable) ?? source.defaultRef;
    if (typeof ref !== "string" || ref.length === 0) {
      mismatches.push(`${source.name}: missing ref (${source.refVariable})`);
    }

    const workflow = actual.variables.get(source.workflowVariable) ?? source.expectedWorkflow;
    if (workflow !== source.expectedWorkflow) {
      mismatches.push(
        `${source.name}: expected workflow ` +
          `${JSON.stringify(source.expectedWorkflow)}, got ` +
          JSON.stringify(workflow),
      );
    }

    const artifact = actual.variables.get(source.artifactVariable) ?? source.expectedArtifact;
    if (artifact !== source.expectedArtifact) {
      mismatches.push(
        `${source.name}: expected artifact ` +
          `${JSON.stringify(source.expectedArtifact)}, got ` +
          JSON.stringify(artifact),
      );
    }

    if (
      repository &&
      actual.repository &&
      repository !== actual.repository &&
      !actual.secrets.has(source.crossRepoTokenSecret)
    ) {
      mismatches.push(
        `${source.name}: cross-repository source ` +
          `${JSON.stringify(repository)} requires secret ` +
          source.crossRepoTokenSecret,
      );
    }
  }

  return mismatches;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const policy = validatePolicy(await loadJson(options.policy));

  let actual;
  if (options.actual) {
    actual = normalizeActual(await loadJson(options.actual), options.currentRepo);
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
