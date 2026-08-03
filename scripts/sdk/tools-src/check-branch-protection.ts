import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");
const DEFAULT_POLICY_PATH = path.join(ROOT_DIR, "spec", "branch-protection.main.json");

type BranchProtectionOptions = {
  policy: string;
  actual: string | null;
  owner: string | null;
  repo: string | null;
  branch: string | null;
};

type BranchProtectionPolicy = {
  branch: string;
  strictStatusChecks: boolean;
  requiredChecks: string[];
  enforceAdmins: boolean;
  requiredApprovals: number;
  dismissStaleReviews: boolean;
  requireCodeOwnerReviews: boolean;
  requireLastPushApproval: boolean;
  requiredLinearHistory: boolean;
  allowForcePushes: boolean;
  allowDeletions: boolean;
  requiredConversationResolution: boolean;
};

type BranchProtectionCheckEntry = {
  context?: unknown;
};

type BranchProtectionApiResponse = {
  required_checks?: unknown;
  strict_status_checks?: unknown;
  enforce_admins?: unknown;
  required_approvals?: unknown;
  dismiss_stale_reviews?: unknown;
  require_code_owner_reviews?: unknown;
  require_last_push_approval?: unknown;
  required_linear_history?: unknown;
  allow_force_pushes?: unknown;
  allow_deletions?: unknown;
  required_conversation_resolution?: unknown;
  required_status_checks?: {
    strict?: unknown;
    checks?: BranchProtectionCheckEntry[] | null;
    contexts?: string[] | null;
  } | null;
  required_pull_request_reviews?: {
    required_approving_review_count?: unknown;
    dismiss_stale_reviews?: unknown;
    require_code_owner_reviews?: unknown;
    require_last_push_approval?: unknown;
  } | null;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-branch-protection.js --owner <owner> --repo <repo> [--branch <name>] [--policy <path>]",
    "  node dist-tools/check-branch-protection.js --actual <github-branch-protection.json> [--policy <path>]",
    "",
    "Options:",
    "  --policy <path>   Policy file to compare against",
    "  --actual <path>   Compare against a saved GitHub API response instead of querying GitHub",
    "  --owner <owner>   GitHub repository owner",
    "  --repo <repo>     GitHub repository name",
    "  --branch <name>   Branch to audit (defaults to policy.branch)",
    "",
    "Environment fallbacks:",
    "  AEGAEON_GITHUB_OWNER",
    "  AEGAEON_GITHUB_REPO",
    "  AEGAEON_GITHUB_BRANCH",
  ].join("\n");
}

function parseArgs(argv: string[]): BranchProtectionOptions {
  const options: BranchProtectionOptions = {
    policy: DEFAULT_POLICY_PATH,
    actual: null,
    owner: process.env.AEGAEON_GITHUB_OWNER ?? null,
    repo: process.env.AEGAEON_GITHUB_REPO ?? null,
    branch: process.env.AEGAEON_GITHUB_BRANCH ?? null,
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
      case "branch":
        options.branch = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  return options;
}

function asBoolean(value: unknown): boolean {
  if (typeof value === "boolean") {
    return value;
  }
  const record = value as { enabled?: unknown } | null;
  if (record && typeof record === "object" && typeof record.enabled === "boolean") {
    return record.enabled;
  }
  return false;
}

function ensureBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function ensureStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`Expected array of strings for ${label}`);
  }
  return value as string[];
}

function validatePolicy(policy: unknown): BranchProtectionPolicy {
  if (!policy || typeof policy !== "object") {
    throw new Error("Branch protection policy must be an object");
  }
  const policyRecord = policy as Record<string, unknown>;
  if (typeof policyRecord.branch !== "string" || policyRecord.branch.length === 0) {
    throw new Error("Branch protection policy requires a non-empty `branch`");
  }
  return {
    branch: policyRecord.branch,
    strictStatusChecks: ensureBoolean(policyRecord.strict_status_checks, "strict_status_checks"),
    requiredChecks: ensureStringArray(policyRecord.required_checks, "required_checks"),
    enforceAdmins: ensureBoolean(policyRecord.enforce_admins, "enforce_admins"),
    requiredApprovals: Number.parseInt(String(policyRecord.required_approvals), 10),
    dismissStaleReviews: ensureBoolean(policyRecord.dismiss_stale_reviews, "dismiss_stale_reviews"),
    requireCodeOwnerReviews: ensureBoolean(policyRecord.require_code_owner_reviews, "require_code_owner_reviews"),
    requireLastPushApproval: ensureBoolean(policyRecord.require_last_push_approval, "require_last_push_approval"),
    requiredLinearHistory: ensureBoolean(policyRecord.required_linear_history, "required_linear_history"),
    allowForcePushes: ensureBoolean(policyRecord.allow_force_pushes, "allow_force_pushes"),
    allowDeletions: ensureBoolean(policyRecord.allow_deletions, "allow_deletions"),
    requiredConversationResolution: ensureBoolean(
      policyRecord.required_conversation_resolution,
      "required_conversation_resolution",
    ),
  };
}

function normalizeActual(actual: unknown, branch: string): BranchProtectionPolicy {
  if (!actual || typeof actual !== "object") {
    throw new Error("Branch protection response must be an object");
  }

  const actualRecord = actual as BranchProtectionApiResponse;
  if (Array.isArray(actualRecord.required_checks) && typeof actualRecord.strict_status_checks === "boolean") {
    return validatePolicy({
      branch,
      strict_status_checks: actualRecord.strict_status_checks,
      required_checks: actualRecord.required_checks,
      enforce_admins: actualRecord.enforce_admins,
      required_approvals: actualRecord.required_approvals,
      dismiss_stale_reviews: actualRecord.dismiss_stale_reviews,
      require_code_owner_reviews: actualRecord.require_code_owner_reviews,
      require_last_push_approval: actualRecord.require_last_push_approval,
      required_linear_history: actualRecord.required_linear_history,
      allow_force_pushes: actualRecord.allow_force_pushes,
      allow_deletions: actualRecord.allow_deletions,
      required_conversation_resolution: actualRecord.required_conversation_resolution,
    });
  }

  const requiredStatusChecks = actualRecord.required_status_checks ?? {};
  const checks = Array.isArray(requiredStatusChecks.checks)
    ? requiredStatusChecks.checks
        .map((entry) => entry?.context)
        .filter((entry): entry is string => typeof entry === "string")
    : [];
  const contexts = Array.isArray(requiredStatusChecks.contexts) ? requiredStatusChecks.contexts : checks;
  const reviews = actualRecord.required_pull_request_reviews ?? {};

  return {
    branch,
    strictStatusChecks: asBoolean(requiredStatusChecks.strict),
    requiredChecks: [...contexts].sort(),
    enforceAdmins: asBoolean(actualRecord.enforce_admins),
    requiredApprovals: Number.parseInt(String(reviews.required_approving_review_count ?? 0), 10),
    dismissStaleReviews: asBoolean(reviews.dismiss_stale_reviews),
    requireCodeOwnerReviews: asBoolean(reviews.require_code_owner_reviews),
    requireLastPushApproval: asBoolean(reviews.require_last_push_approval),
    requiredLinearHistory: asBoolean(actualRecord.required_linear_history),
    allowForcePushes: asBoolean(actualRecord.allow_force_pushes),
    allowDeletions: asBoolean(actualRecord.allow_deletions),
    requiredConversationResolution: asBoolean(actualRecord.required_conversation_resolution),
  };
}

function comparePolicies(expected: BranchProtectionPolicy, actual: BranchProtectionPolicy): string[] {
  const mismatches: string[] = [];
  const scalarChecks: [string, boolean | number, boolean | number][] = [
    ["strict_status_checks", expected.strictStatusChecks, actual.strictStatusChecks],
    ["enforce_admins", expected.enforceAdmins, actual.enforceAdmins],
    ["required_approvals", expected.requiredApprovals, actual.requiredApprovals],
    ["dismiss_stale_reviews", expected.dismissStaleReviews, actual.dismissStaleReviews],
    ["require_code_owner_reviews", expected.requireCodeOwnerReviews, actual.requireCodeOwnerReviews],
    ["require_last_push_approval", expected.requireLastPushApproval, actual.requireLastPushApproval],
    ["required_linear_history", expected.requiredLinearHistory, actual.requiredLinearHistory],
    ["allow_force_pushes", expected.allowForcePushes, actual.allowForcePushes],
    ["allow_deletions", expected.allowDeletions, actual.allowDeletions],
    [
      "required_conversation_resolution",
      expected.requiredConversationResolution,
      actual.requiredConversationResolution,
    ],
  ];

  for (const [label, expectedValue, actualValue] of scalarChecks) {
    if (expectedValue !== actualValue) {
      mismatches.push(`${label}: expected ${JSON.stringify(expectedValue)}, got ${JSON.stringify(actualValue)}`);
    }
  }

  const expectedChecks = [...expected.requiredChecks].sort();
  const actualChecks = [...actual.requiredChecks].sort();
  if (
    expectedChecks.length !== actualChecks.length ||
    expectedChecks.some((entry, index) => entry !== actualChecks[index])
  ) {
    const missing = expectedChecks.filter((entry) => !actualChecks.includes(entry));
    const extra = actualChecks.filter((entry) => !expectedChecks.includes(entry));
    mismatches.push(
      `required_checks mismatch: missing=${JSON.stringify(missing)}, extra=${JSON.stringify(extra)}, actual=${JSON.stringify(actualChecks)}`,
    );
  }

  return mismatches;
}

async function loadJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function fetchRemoteBranchProtection(owner: string, repo: string, branch: string): Promise<unknown> {
  const { stdout } = await execFile(
    "gh",
    [
      "api",
      "-H",
      "Accept: application/vnd.github+json",
      `repos/${owner}/${repo}/branches/${branch}/protection`,
    ],
    { cwd: ROOT_DIR },
  );
  return JSON.parse(String(stdout));
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const policyPath = path.resolve(options.policy);
  const expected = validatePolicy(await loadJson<unknown>(policyPath));
  const branch = options.branch ?? expected.branch;

  let actual: BranchProtectionPolicy;
  let actualLabel: string;
  if (options.actual) {
    actual = normalizeActual(await loadJson<unknown>(path.resolve(options.actual)), branch);
    actualLabel = path.resolve(options.actual);
  } else {
    if (!options.owner || !options.repo) {
      throw new Error(`Either --actual or both --owner and --repo are required.\n\n${usage()}`);
    }
    actual = normalizeActual(await fetchRemoteBranchProtection(options.owner, options.repo, branch), branch);
    actualLabel = `${options.owner}/${options.repo}@${branch}`;
  }

  const mismatches = comparePolicies(expected, actual);
  if (mismatches.length > 0) {
    console.error(`[branch-protection] ${actualLabel} does not match ${path.relative(process.cwd(), policyPath)}`);
    for (const mismatch of mismatches) {
      console.error(`- ${mismatch}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(`[branch-protection] ${actualLabel} matches ${path.relative(process.cwd(), policyPath)}`);
}

main().catch((error) => {
  console.error("[branch-protection] error:", error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
