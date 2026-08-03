#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");
const DEFAULT_POLICY_PATH = path.join(MODULE_DIR, "sdk_repository_settings.current.json");

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types " +
      "scripts/sdk/check_sdk_repository_settings.ts " +
      "--owner <owner> --repo <repo> [--policy <path>]",
    "  node --experimental-strip-types " +
      "scripts/sdk/check_sdk_repository_settings.ts " +
      "--actual <repo-settings.json> [--policy <path>]",
    "",
    "Options:",
    "  --policy <path>   Policy file to compare against",
    "  --actual <path>   Compare against a saved JSON payload instead of querying GitHub",
    "  --owner <owner>   GitHub repository owner",
    "  --repo <repo>     GitHub repository name",
    "",
    "Environment fallbacks:",
    "  AEGAEON_GITHUB_OWNER",
    "  AEGAEON_GITHUB_REPO",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    policy: DEFAULT_POLICY_PATH,
    actual: null,
    owner: process.env.AEGAEON_GITHUB_OWNER ?? null,
    repo: process.env.AEGAEON_GITHUB_REPO ?? null,
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
    const key = rawKey.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
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

function ensureStringArray(value, label) {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string" || entry.length === 0)
  ) {
    throw new Error(`Expected array of strings for ${label}`);
  }
  return value;
}

function normalizeVariableRules(value, label) {
  if (!Array.isArray(value)) {
    throw new Error(`Expected array for ${label}`);
  }
  return value.map((entry, index) => {
    if (!entry || typeof entry !== "object") {
      throw new Error(`Expected object at ${label}[${index}]`);
    }
    return {
      name: ensureString(entry.name, `${label}[${index}].name`),
      pattern: entry.pattern ? ensureString(entry.pattern, `${label}[${index}].pattern`) : null,
    };
  });
}

function normalizeConditionalRule(entry, label) {
  if (!entry || typeof entry !== "object") {
    throw new Error(`Expected object for ${label}`);
  }
  if (!entry.when_variable || typeof entry.when_variable !== "object") {
    throw new Error(`Expected object for ${label}.when_variable`);
  }
  return {
    name: ensureString(entry.name, `${label}.name`),
    whenVariable: {
      name: ensureString(entry.when_variable.name, `${label}.when_variable.name`),
      pattern: ensureString(entry.when_variable.pattern, `${label}.when_variable.pattern`),
    },
    requiredVariables: normalizeVariableRules(
      entry.required_variables ?? [],
      `${label}.required_variables`,
    ),
    requiredSecretSets: Array.isArray(entry.required_secret_sets)
      ? entry.required_secret_sets.map((secretSet, index) =>
          normalizeSecretSet(secretSet, `${label}.required_secret_sets[${index}]`),
        )
      : [],
  };
}

function normalizeSecretSet(entry, label) {
  if (!entry || typeof entry !== "object") {
    throw new Error(`Expected object for ${label}`);
  }
  const normalized = {
    name: ensureString(entry.name, `${label}.name`),
    allOf: null,
    oneOf: null,
  };
  if (entry.all_of !== undefined) {
    normalized.allOf = ensureStringArray(entry.all_of, `${label}.all_of`);
  }
  if (entry.one_of !== undefined) {
    if (!Array.isArray(entry.one_of) || entry.one_of.length === 0) {
      throw new Error(`Expected non-empty array for ${label}.one_of`);
    }
    normalized.oneOf = entry.one_of.map((group, index) =>
      ensureStringArray(group, `${label}.one_of[${index}]`),
    );
  }
  if (
    (normalized.allOf === null && normalized.oneOf === null) ||
    (normalized.allOf !== null && normalized.oneOf !== null)
  ) {
    throw new Error(`${label} must define exactly one of all_of or one_of`);
  }
  return normalized;
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new Error("Repository settings policy must be an object");
  }
  return {
    profile: ensureString(policy.profile, "profile"),
    requiredSecretSets: Array.isArray(policy.required_secret_sets)
      ? policy.required_secret_sets.map((entry, index) =>
          normalizeSecretSet(entry, `required_secret_sets[${index}]`),
        )
      : [],
    requiredVariables: normalizeVariableRules(
      policy.required_variables ?? [],
      "required_variables",
    ),
    optionalVariables: normalizeVariableRules(
      policy.optional_variables ?? [],
      "optional_variables",
    ),
    optionalSecretSets: Array.isArray(policy.optional_secret_sets)
      ? policy.optional_secret_sets.map((entry, index) =>
          normalizeSecretSet(entry, `optional_secret_sets[${index}]`),
        )
      : [],
    conditionalRequirements: Array.isArray(policy.conditional_requirements)
      ? policy.conditional_requirements.map((entry, index) =>
          normalizeConditionalRule(entry, `conditional_requirements[${index}]`),
        )
      : [],
    deferredSecrets: ensureStringArray(policy.deferred_secrets ?? [], "deferred_secrets"),
  };
}

function normalizeActual(actual) {
  if (!actual || typeof actual !== "object") {
    throw new Error("Repository settings payload must be an object");
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
    throw new Error("Repository settings payload requires a `secrets` array");
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
    throw new Error("Repository settings payload requires a `variables` object or array");
  }

  return { secrets, variables };
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
  const names = new Set([
    ...policy.requiredVariables.map((entry) => entry.name),
    ...policy.optionalVariables.map((entry) => entry.name),
    ...policy.conditionalRequirements.map((entry) => entry.whenVariable.name),
    ...policy.conditionalRequirements.flatMap((entry) =>
      entry.requiredVariables.map((rule) => rule.name),
    ),
  ]);
  for (const name of names) {
    const value = await fetchRemoteVariable(owner, repo, name);
    if (value !== undefined) {
      variables.set(name, value);
    }
  }
  return { secrets, variables };
}

function compareAgainstPolicy(policy, actual) {
  const mismatches = [];
  const addSecretSetMismatch = (secretSet, kind) => {
    if (secretSet.allOf) {
      const missing = secretSet.allOf.filter((entry) => !actual.secrets.has(entry));
      if (missing.length > 0) {
        mismatches.push(
          `${kind} ${secretSet.name} missing ${JSON.stringify(missing)}`,
        );
      }
      return;
    }

    const satisfied = secretSet.oneOf.some((group) =>
      group.every((entry) => actual.secrets.has(entry)),
    );
    if (!satisfied) {
      mismatches.push(
        `${kind} ${secretSet.name} not satisfied; expected one of ` +
          JSON.stringify(secretSet.oneOf),
      );
    }
  };

  for (const secretSet of policy.requiredSecretSets) {
    addSecretSetMismatch(secretSet, "required secret set");
  }

  for (const secretSet of policy.optionalSecretSets) {
    if (secretSet.allOf) {
      const present = secretSet.allOf.filter((entry) => actual.secrets.has(entry));
      if (present.length > 0 && present.length !== secretSet.allOf.length) {
        mismatches.push(
          `optional secret set ${secretSet.name} is partially configured; ` +
            `expected ${JSON.stringify(secretSet.allOf)}`,
        );
      }
      continue;
    }

    const presentGroups = secretSet.oneOf.filter((group) =>
      group.some((entry) => actual.secrets.has(entry)),
    );
    if (presentGroups.length === 0) {
      continue;
    }
    const satisfied = secretSet.oneOf.some((group) =>
      group.every((entry) => actual.secrets.has(entry)),
    );
    if (!satisfied) {
      mismatches.push(
        `optional secret set ${secretSet.name} is partially configured; ` +
          `expected one of ${JSON.stringify(secretSet.oneOf)}`,
      );
    }
  }

  for (const variable of policy.requiredVariables) {
    if (!actual.variables.has(variable.name)) {
      mismatches.push(`required variable ${variable.name} is missing`);
      continue;
    }
    const value = actual.variables.get(variable.name);
    if (
      variable.pattern &&
      (value === null || !(new RegExp(variable.pattern).test(value)))
    ) {
      mismatches.push(
        `required variable ${variable.name} does not match ` +
          `${JSON.stringify(variable.pattern)}; got ` +
          JSON.stringify(value),
      );
    }
  }

  for (const variable of policy.optionalVariables) {
    if (!actual.variables.has(variable.name)) {
      continue;
    }
    const value = actual.variables.get(variable.name);
    if (
      variable.pattern &&
      value !== null &&
      !(new RegExp(variable.pattern).test(value))
    ) {
      mismatches.push(
        `optional variable ${variable.name} does not match ` +
          `${JSON.stringify(variable.pattern)}; got ` +
          JSON.stringify(value),
      );
    }
  }

  for (const conditionalRequirement of policy.conditionalRequirements) {
    const whenValue = actual.variables.get(conditionalRequirement.whenVariable.name);
    if (
      whenValue == null ||
      !(new RegExp(conditionalRequirement.whenVariable.pattern).test(whenValue))
    ) {
      continue;
    }

    for (const variable of conditionalRequirement.requiredVariables) {
      if (!actual.variables.has(variable.name)) {
        mismatches.push(
          `conditional requirement ${conditionalRequirement.name} ` +
            `missing variable ${variable.name}`,
        );
        continue;
      }
      const value = actual.variables.get(variable.name);
      if (
        variable.pattern &&
        (value === null || !(new RegExp(variable.pattern).test(value)))
      ) {
        mismatches.push(
          `conditional requirement ${conditionalRequirement.name} ` +
            `variable ${variable.name} does not match ` +
            `${JSON.stringify(variable.pattern)}; got ` +
            JSON.stringify(value),
        );
      }
    }

    for (const secretSet of conditionalRequirement.requiredSecretSets) {
      addSecretSetMismatch(
        secretSet,
        `conditional requirement ${conditionalRequirement.name} secret set`,
      );
    }
  }

  return mismatches;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const policyPath = path.resolve(options.policy);
  const policy = validatePolicy(await loadJson(policyPath));

  let actual;
  let actualLabel;
  if (options.actual) {
    actual = normalizeActual(await loadJson(path.resolve(options.actual)));
    actualLabel = path.resolve(options.actual);
  } else {
    if (!options.owner || !options.repo) {
      throw new Error(`Either --actual or both --owner and --repo are required.\n\n${usage()}`);
    }
    actual = await fetchRemoteActual(options.owner, options.repo, policy);
    actualLabel = `${options.owner}/${options.repo}`;
  }

  const mismatches = compareAgainstPolicy(policy, actual);
  if (mismatches.length > 0) {
    console.error(
      `[repository-settings] ${actualLabel} does not match ` +
        path.relative(process.cwd(), policyPath),
    );
    for (const mismatch of mismatches) {
      console.error(`- ${mismatch}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(
    `[repository-settings] ${actualLabel} matches ` +
      path.relative(process.cwd(), policyPath),
  );
}

main().catch((error) => {
  console.error("[repository-settings] error:", error.message ?? error);
  process.exitCode = 1;
});
