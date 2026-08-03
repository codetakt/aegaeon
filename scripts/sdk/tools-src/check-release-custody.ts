import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");
const DEFAULT_POLICY_PATH = path.join(ROOT_DIR, "spec", "release-custody.current.json");

type ReleaseCustodyOptions = {
  policy: string;
  actual: string | null;
  owner: string | null;
  repo: string | null;
};

type VariableRule = {
  name: string;
  pattern: string | null;
};

type SecretSet = {
  name: string;
  allOf: string[] | null;
  oneOf: string[][] | null;
};

type ConditionalRequirement = {
  name: string;
  whenVariable: {
    name: string;
    pattern: string;
  };
  requiredVariables: VariableRule[];
  requiredSecretSets: SecretSet[];
};

type ReleaseCustodyPolicy = {
  profile: string;
  requiredSecretSets: SecretSet[];
  requiredVariables: VariableRule[];
  optionalVariables: VariableRule[];
  optionalSecretSets: SecretSet[];
  conditionalRequirements: ConditionalRequirement[];
  deferredSecrets: string[];
};

type ReleaseCustodyActual = {
  secrets: Set<string>;
  variables: Map<string, string | null>;
};

type GhSecretEntry = {
  name?: unknown;
};

type GhSecretsResponse = {
  secrets?: GhSecretEntry[];
};

type GhVariableResponse = {
  value?: unknown;
};

type StderrLikeError = {
  stderr?: string | Buffer;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-release-custody.js --owner <owner> --repo <repo> [--policy <path>]",
    "  node dist-tools/check-release-custody.js --actual <repo-settings.json> [--policy <path>]",
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

function parseArgs(argv: string[]): ReleaseCustodyOptions {
  const options: ReleaseCustodyOptions = {
    policy: DEFAULT_POLICY_PATH,
    actual: null,
    owner: process.env.AEGAEON_GITHUB_OWNER ?? null,
    repo: process.env.AEGAEON_GITHUB_REPO ?? null,
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
    const camelKey = rawKey.replace(/-([a-z])/g, (_, char: string) => char.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(camelKey in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[camelKey as keyof ReleaseCustodyOptions] = value;
    index += 1;
  }

  return options;
}

function ensureRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Expected object for ${label}`);
  }
  return value as Record<string, unknown>;
}

function ensureString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    throw new Error(`Expected array of strings for ${label}`);
  }
  return value as string[];
}

function normalizeVariableRules(value: unknown, label: string): VariableRule[] {
  if (!Array.isArray(value)) {
    throw new Error(`Expected array for ${label}`);
  }
  return value.map((entry, index) => {
    const record = ensureRecord(entry, `${label}[${index}]`);
    return {
      name: ensureString(record.name, `${label}[${index}].name`),
      pattern:
        record.pattern === undefined || record.pattern === null
          ? null
          : ensureString(record.pattern, `${label}[${index}].pattern`),
    };
  });
}

function normalizeSecretSet(value: unknown, label: string): SecretSet {
  const record = ensureRecord(value, label);
  const allOf =
    record.all_of === undefined || record.all_of === null
      ? null
      : ensureStringArray(record.all_of, `${label}.all_of`);
  const oneOf =
    record.one_of === undefined || record.one_of === null
      ? null
      : (() => {
          if (!Array.isArray(record.one_of) || record.one_of.length === 0) {
            throw new Error(`Expected non-empty array for ${label}.one_of`);
          }
          return record.one_of.map((group, index) =>
            ensureStringArray(group, `${label}.one_of[${index}]`),
          );
        })();

  if ((allOf === null && oneOf === null) || (allOf !== null && oneOf !== null)) {
    throw new Error(`${label} must define exactly one of all_of or one_of`);
  }

  return {
    name: ensureString(record.name, `${label}.name`),
    allOf,
    oneOf,
  };
}

function normalizeConditionalRequirement(value: unknown, label: string): ConditionalRequirement {
  const record = ensureRecord(value, label);
  const whenVariable = ensureRecord(record.when_variable, `${label}.when_variable`);

  return {
    name: ensureString(record.name, `${label}.name`),
    whenVariable: {
      name: ensureString(whenVariable.name, `${label}.when_variable.name`),
      pattern: ensureString(whenVariable.pattern, `${label}.when_variable.pattern`),
    },
    requiredVariables: normalizeVariableRules(record.required_variables ?? [], `${label}.required_variables`),
    requiredSecretSets: Array.isArray(record.required_secret_sets)
      ? record.required_secret_sets.map((entry, index) =>
          normalizeSecretSet(entry, `${label}.required_secret_sets[${index}]`),
        )
      : [],
  };
}

function validatePolicy(policy: unknown): ReleaseCustodyPolicy {
  const record = ensureRecord(policy, "release custody policy");

  return {
    profile: ensureString(record.profile, "profile"),
    requiredSecretSets: Array.isArray(record.required_secret_sets)
      ? record.required_secret_sets.map((entry, index) =>
          normalizeSecretSet(entry, `required_secret_sets[${index}]`),
        )
      : [],
    requiredVariables: normalizeVariableRules(record.required_variables ?? [], "required_variables"),
    optionalVariables: normalizeVariableRules(record.optional_variables ?? [], "optional_variables"),
    optionalSecretSets: Array.isArray(record.optional_secret_sets)
      ? record.optional_secret_sets.map((entry, index) =>
          normalizeSecretSet(entry, `optional_secret_sets[${index}]`),
        )
      : [],
    conditionalRequirements: Array.isArray(record.conditional_requirements)
      ? record.conditional_requirements.map((entry, index) =>
          normalizeConditionalRequirement(entry, `conditional_requirements[${index}]`),
        )
      : [],
    deferredSecrets: ensureStringArray(record.deferred_secrets ?? [], "deferred_secrets"),
  };
}

function normalizeActual(actual: unknown): ReleaseCustodyActual {
  const record = ensureRecord(actual, "release custody payload");
  const secrets = new Set<string>();
  if (!Array.isArray(record.secrets)) {
    throw new Error("Release custody payload requires a `secrets` array");
  }
  for (const entry of record.secrets) {
    if (typeof entry === "string") {
      secrets.add(entry);
      continue;
    }
    const secretRecord = ensureRecord(entry, "secrets[]");
    secrets.add(ensureString(secretRecord.name, "secrets[].name"));
  }

  const variables = new Map<string, string | null>();
  const rawVariables = record.variables;
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
      const variableRecord = ensureRecord(entry, "variables[]");
      variables.set(
        ensureString(variableRecord.name, "variables[].name"),
        variableRecord.value == null ? null : String(variableRecord.value),
      );
    }
  } else {
    throw new Error("Release custody payload requires a `variables` object or array");
  }

  return { secrets, variables };
}

async function loadJson(filePath: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as unknown;
}

function getErrorStderr(error: unknown): string {
  const stderr = (error as StderrLikeError | undefined)?.stderr;
  if (typeof stderr === "string") {
    return stderr;
  }
  if (Buffer.isBuffer(stderr)) {
    return stderr.toString("utf8");
  }
  return "";
}

async function fetchRemoteSecretNames(owner: string, repo: string): Promise<Set<string>> {
  const { stdout } = await execFile(
    "gh",
    ["api", "-H", "Accept: application/vnd.github+json", `repos/${owner}/${repo}/actions/secrets`],
    { cwd: ROOT_DIR },
  );
  const payload = JSON.parse(String(stdout)) as GhSecretsResponse;
  return new Set(
    (payload.secrets ?? [])
      .map((entry) => entry.name)
      .filter((entry): entry is string => typeof entry === "string"),
  );
}

async function fetchRemoteVariable(
  owner: string,
  repo: string,
  name: string,
): Promise<string | null | undefined> {
  try {
    const { stdout } = await execFile(
      "gh",
      ["api", "-H", "Accept: application/vnd.github+json", `repos/${owner}/${repo}/actions/variables/${name}`],
      { cwd: ROOT_DIR },
    );
    const payload = JSON.parse(String(stdout)) as GhVariableResponse;
    return payload.value == null ? null : String(payload.value);
  } catch (error) {
    if (/404/.test(getErrorStderr(error))) {
      return undefined;
    }
    throw error;
  }
}

async function fetchRemoteActual(
  owner: string,
  repo: string,
  policy: ReleaseCustodyPolicy,
): Promise<ReleaseCustodyActual> {
  const secrets = await fetchRemoteSecretNames(owner, repo);
  const variables = new Map<string, string | null>();
  const names = new Set<string>([
    ...policy.requiredVariables.map((entry) => entry.name),
    ...policy.optionalVariables.map((entry) => entry.name),
    ...policy.conditionalRequirements.map((entry) => entry.whenVariable.name),
    ...policy.conditionalRequirements.flatMap((entry) =>
      entry.requiredVariables.map((variable) => variable.name),
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

function matchesPattern(pattern: string | null, value: string | null | undefined): boolean {
  if (pattern === null) {
    return true;
  }
  return value !== null && value !== undefined && new RegExp(pattern).test(value);
}

function compareAgainstPolicy(policy: ReleaseCustodyPolicy, actual: ReleaseCustodyActual): string[] {
  const mismatches: string[] = [];

  const addSecretSetMismatch = (secretSet: SecretSet, kind: string): void => {
    if (secretSet.allOf !== null) {
      const missing = secretSet.allOf.filter((entry) => !actual.secrets.has(entry));
      if (missing.length > 0) {
        mismatches.push(`${kind} ${secretSet.name} missing ${JSON.stringify(missing)}`);
      }
      return;
    }

    const oneOf = secretSet.oneOf ?? [];
    const satisfied = oneOf.some((group) => group.every((entry) => actual.secrets.has(entry)));
    if (!satisfied) {
      mismatches.push(`${kind} ${secretSet.name} not satisfied; expected one of ${JSON.stringify(oneOf)}`);
    }
  };

  for (const secretSet of policy.requiredSecretSets) {
    addSecretSetMismatch(secretSet, "required secret set");
  }

  for (const secretSet of policy.optionalSecretSets) {
    if (secretSet.allOf !== null) {
      const present = secretSet.allOf.filter((entry) => actual.secrets.has(entry));
      if (present.length > 0 && present.length !== secretSet.allOf.length) {
        mismatches.push(
          `optional secret set ${secretSet.name} is partially configured; expected ${JSON.stringify(secretSet.allOf)}`,
        );
      }
      continue;
    }

    const oneOf = secretSet.oneOf ?? [];
    const presentGroups = oneOf.filter((group) => group.some((entry) => actual.secrets.has(entry)));
    if (presentGroups.length === 0) {
      continue;
    }
    const satisfied = oneOf.some((group) => group.every((entry) => actual.secrets.has(entry)));
    if (!satisfied) {
      mismatches.push(
        `optional secret set ${secretSet.name} is partially configured; expected one of ${JSON.stringify(oneOf)}`,
      );
    }
  }

  for (const variable of policy.requiredVariables) {
    if (!actual.variables.has(variable.name)) {
      mismatches.push(`required variable ${variable.name} is missing`);
      continue;
    }
    const value = actual.variables.get(variable.name);
    if (!matchesPattern(variable.pattern, value)) {
      mismatches.push(
        `required variable ${variable.name} does not match ${JSON.stringify(variable.pattern)}; got ${JSON.stringify(value)}`,
      );
    }
  }

  for (const variable of policy.optionalVariables) {
    if (!actual.variables.has(variable.name)) {
      continue;
    }
    const value = actual.variables.get(variable.name);
    if (variable.pattern !== null && value != null && !new RegExp(variable.pattern).test(value)) {
      mismatches.push(
        `optional variable ${variable.name} does not match ${JSON.stringify(variable.pattern)}; got ${JSON.stringify(value)}`,
      );
    }
  }

  for (const requirement of policy.conditionalRequirements) {
    const whenValue = actual.variables.get(requirement.whenVariable.name);
    if (whenValue == null || !new RegExp(requirement.whenVariable.pattern).test(whenValue)) {
      continue;
    }

    for (const variable of requirement.requiredVariables) {
      if (!actual.variables.has(variable.name)) {
        mismatches.push(`conditional requirement ${requirement.name} missing variable ${variable.name}`);
        continue;
      }
      const value = actual.variables.get(variable.name);
      if (!matchesPattern(variable.pattern, value)) {
        mismatches.push(
          `conditional requirement ${requirement.name} variable ${variable.name} does not match ${JSON.stringify(variable.pattern)}; got ${JSON.stringify(value)}`,
        );
      }
    }

    for (const secretSet of requirement.requiredSecretSets) {
      addSecretSetMismatch(secretSet, `conditional requirement ${requirement.name} secret set`);
    }
  }

  return mismatches;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const policyPath = path.resolve(options.policy);
  const policy = validatePolicy(await loadJson(policyPath));

  let actual: ReleaseCustodyActual;
  let actualLabel: string;
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
    console.error(`[release-custody] ${actualLabel} does not match ${path.relative(process.cwd(), policyPath)}`);
    for (const mismatch of mismatches) {
      console.error(`- ${mismatch}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(`[release-custody] ${actualLabel} matches ${path.relative(process.cwd(), policyPath)}`);
}

main().catch((error) => {
  console.error("[release-custody] error:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
