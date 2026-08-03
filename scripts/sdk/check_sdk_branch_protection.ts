#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");
const DEFAULT_POLICY_PATH = path.join(ROOT_DIR, "spec", "branch-protection.main.json");

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types " +
      "scripts/sdk/check_sdk_branch_protection.ts " +
      "--owner <owner> --repo <repo> [--branch <name>] [--policy <path>]",
    "  node --experimental-strip-types " +
      "scripts/sdk/check_sdk_branch_protection.ts " +
      "--actual <github-branch-protection.json> [--policy <path>]",
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

function parseArgs(argv) {
  const options = {
    policy: DEFAULT_POLICY_PATH,
    actual: null,
    owner: process.env.AEGAEON_GITHUB_OWNER ?? null,
    repo: process.env.AEGAEON_GITHUB_REPO ?? null,
    branch: process.env.AEGAEON_GITHUB_BRANCH ?? null,
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

function asBoolean(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (value && typeof value === "object" && typeof value.enabled === "boolean") {
    return value.enabled;
  }
  return false;
}

function ensureBoolean(value, label) {
  if (typeof value !== "boolean") {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function ensureStringArray(value, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`Expected array of strings for ${label}`);
  }
  return value;
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new Error("Branch protection policy must be an object");
  }
  if (typeof policy.branch !== "string" || policy.branch.length === 0) {
    throw new Error("Branch protection policy requires a non-empty `branch`");
  }
  return {
    branch: policy.branch,
    strictStatusChecks: ensureBoolean(policy.strict_status_checks, "strict_status_checks"),
    requiredChecks: ensureStringArray(policy.required_checks, "required_checks"),
    enforceAdmins: ensureBoolean(policy.enforce_admins, "enforce_admins"),
    requiredApprovals: Number.parseInt(policy.required_approvals, 10),
    dismissStaleReviews: ensureBoolean(policy.dismiss_stale_reviews, "dismiss_stale_reviews"),
    requireCodeOwnerReviews: ensureBoolean(
      policy.require_code_owner_reviews,
      "require_code_owner_reviews",
    ),
    requireLastPushApproval: ensureBoolean(
      policy.require_last_push_approval,
      "require_last_push_approval",
    ),
    requiredLinearHistory: ensureBoolean(policy.required_linear_history, "required_linear_history"),
    allowForcePushes: ensureBoolean(policy.allow_force_pushes, "allow_force_pushes"),
    allowDeletions: ensureBoolean(policy.allow_deletions, "allow_deletions"),
    requiredConversationResolution: ensureBoolean(
      policy.required_conversation_resolution,
      "required_conversation_resolution",
    ),
  };
}

function normalizeActual(actual, branch) {
  if (!actual || typeof actual !== "object") {
    throw new Error("Branch protection response must be an object");
  }

  if (Array.isArray(actual.required_checks) && typeof actual.strict_status_checks === "boolean") {
    return validatePolicy({
      branch,
      strict_status_checks: actual.strict_status_checks,
      required_checks: actual.required_checks,
      enforce_admins: actual.enforce_admins,
      required_approvals: actual.required_approvals,
      dismiss_stale_reviews: actual.dismiss_stale_reviews,
      require_code_owner_reviews: actual.require_code_owner_reviews,
      require_last_push_approval: actual.require_last_push_approval,
      required_linear_history: actual.required_linear_history,
      allow_force_pushes: actual.allow_force_pushes,
      allow_deletions: actual.allow_deletions,
      required_conversation_resolution: actual.required_conversation_resolution,
    });
  }

  const requiredStatusChecks = actual.required_status_checks ?? {};
  const checks =
    Array.isArray(requiredStatusChecks.checks)
      ? requiredStatusChecks.checks
          .map((entry) => entry?.context)
          .filter((entry) => typeof entry === "string")
      : [];
  const contexts = Array.isArray(requiredStatusChecks.contexts)
    ? requiredStatusChecks.contexts
    : checks;
  const reviews = actual.required_pull_request_reviews ?? {};

  return {
    branch,
    strictStatusChecks: asBoolean(requiredStatusChecks.strict),
    requiredChecks: [...contexts].sort(),
    enforceAdmins: asBoolean(actual.enforce_admins),
    requiredApprovals: Number.parseInt(reviews.required_approving_review_count ?? 0, 10),
    dismissStaleReviews: asBoolean(reviews.dismiss_stale_reviews),
    requireCodeOwnerReviews: asBoolean(reviews.require_code_owner_reviews),
    requireLastPushApproval: asBoolean(reviews.require_last_push_approval),
    requiredLinearHistory: asBoolean(actual.required_linear_history),
    allowForcePushes: asBoolean(actual.allow_force_pushes),
    allowDeletions: asBoolean(actual.allow_deletions),
    requiredConversationResolution: asBoolean(actual.required_conversation_resolution),
  };
}

function comparePolicies(expected, actual) {
  const mismatches = [];
  const scalarChecks = [
    ["strict_status_checks", expected.strictStatusChecks, actual.strictStatusChecks],
    ["enforce_admins", expected.enforceAdmins, actual.enforceAdmins],
    ["required_approvals", expected.requiredApprovals, actual.requiredApprovals],
    ["dismiss_stale_reviews", expected.dismissStaleReviews, actual.dismissStaleReviews],
    [
      "require_code_owner_reviews",
      expected.requireCodeOwnerReviews,
      actual.requireCodeOwnerReviews,
    ],
    [
      "require_last_push_approval",
      expected.requireLastPushApproval,
      actual.requireLastPushApproval,
    ],
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
      mismatches.push(
        `${label}: expected ${JSON.stringify(expectedValue)}, got ` +
          JSON.stringify(actualValue),
      );
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
      "required_checks mismatch: " +
        `missing=${JSON.stringify(missing)}, ` +
        `extra=${JSON.stringify(extra)}, ` +
        `actual=${JSON.stringify(actualChecks)}`,
    );
  }

  return mismatches;
}

async function loadJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function fetchRemoteBranchProtection(owner, repo, branch) {
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
  return JSON.parse(stdout);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const policyPath = path.resolve(options.policy);
  const expected = validatePolicy(await loadJson(policyPath));
  const branch = options.branch ?? expected.branch;

  let actual;
  let actualLabel;
  if (options.actual) {
    actual = normalizeActual(await loadJson(path.resolve(options.actual)), branch);
    actualLabel = path.resolve(options.actual);
  } else {
    if (!options.owner || !options.repo) {
      throw new Error(`Either --actual or both --owner and --repo are required.\n\n${usage()}`);
    }
    actual = normalizeActual(
      await fetchRemoteBranchProtection(options.owner, options.repo, branch),
      branch,
    );
    actualLabel = `${options.owner}/${options.repo}@${branch}`;
  }

  const mismatches = comparePolicies(expected, actual);
  if (mismatches.length > 0) {
    console.error(
      `[branch-protection] ${actualLabel} does not match ` +
        path.relative(process.cwd(), policyPath),
    );
    for (const mismatch of mismatches) {
      console.error(`- ${mismatch}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(
    `[branch-protection] ${actualLabel} matches ` +
      path.relative(process.cwd(), policyPath),
  );
}

main().catch((error) => {
  console.error("[branch-protection] error:", error.message ?? error);
  process.exitCode = 1;
});
