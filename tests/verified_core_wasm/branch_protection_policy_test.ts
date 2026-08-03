#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { access } from "node:fs/promises";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);

async function firstExistingPath(...candidates) {
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {}
  }
  throw new Error(`None of the candidate paths exist: ${candidates.join(", ")}`);
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  console.log("=== branch protection policy test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-branch-protection-"));
  const scriptPath = await firstExistingPath(
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_branch_protection.ts"),
    path.join(ROOT_DIR, "dist-tools", "check-branch-protection.js"),
    path.join(ROOT_DIR, "scripts", "check-branch-protection.ts"),
  );
  const policyPath = await firstExistingPath(
    path.join(ROOT_DIR, "scripts", "sdk", "sdk_branch_protection.main.json"),
    path.join(ROOT_DIR, "spec", "branch-protection.main.json"),
  );
  const expected = JSON.parse(await readFile(policyPath, "utf8"));

  const goodActualPath = path.join(tempRoot, "good.json");
  await writeJson(goodActualPath, {
    required_status_checks: {
      strict: expected.strict_status_checks,
      contexts: expected.required_checks,
    },
    enforce_admins: { enabled: expected.enforce_admins },
    required_pull_request_reviews: {
      required_approving_review_count: expected.required_approvals,
      dismiss_stale_reviews: expected.dismiss_stale_reviews,
      require_code_owner_reviews: expected.require_code_owner_reviews,
      require_last_push_approval: expected.require_last_push_approval,
    },
    required_linear_history: { enabled: expected.required_linear_history },
    allow_force_pushes: { enabled: expected.allow_force_pushes },
    allow_deletions: { enabled: expected.allow_deletions },
    required_conversation_resolution: { enabled: expected.required_conversation_resolution },
  });

  const goodResult = await execFile(process.execPath, [
    scriptPath,
    "--policy",
    policyPath,
    "--actual",
    goodActualPath,
  ], { cwd: ROOT_DIR });
  assert.match(goodResult.stdout, /matches/);

  const badActualPath = path.join(tempRoot, "bad.json");
  await writeJson(badActualPath, {
    required_status_checks: {
      strict: false,
      contexts: expected.required_checks.filter(
        (entry) => entry !== "SDK Browser E2E / External Provider (Dex)",
      ),
    },
    enforce_admins: { enabled: expected.enforce_admins },
    required_pull_request_reviews: {
      required_approving_review_count: expected.required_approvals,
      dismiss_stale_reviews: expected.dismiss_stale_reviews,
      require_code_owner_reviews: expected.require_code_owner_reviews,
      require_last_push_approval: expected.require_last_push_approval,
    },
    required_linear_history: { enabled: expected.required_linear_history },
    allow_force_pushes: { enabled: expected.allow_force_pushes },
    allow_deletions: { enabled: expected.allow_deletions },
    required_conversation_resolution: { enabled: expected.required_conversation_resolution },
  });

  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--policy",
      policyPath,
      "--actual",
      badActualPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(execError.stderr, /strict_status_checks/);
      assert.match(execError.stderr, /External Provider \(Dex\)/);
      return true;
    },
  );

  console.log("branch protection policy tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
