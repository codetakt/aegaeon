#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../..", import.meta.url).pathname);

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    try {
      await stat(candidate);
      return candidate;
    } catch (error) {
      if (!error || error.code !== "ENOENT") {
        throw error;
      }
    }
  }
  throw new Error(`No candidate path exists: ${candidates.join(", ")}`);
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  console.log("=== repository settings policy test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-repo-settings-"));
  const SCRIPT_PATH = await firstExistingPath([
    path.join(ROOT_DIR, "dist-tools", "check-repository-settings.js"),
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_repository_settings.ts"),
  ]);
  const POLICY_PATH = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "repository-settings.current.json"),
    path.join(ROOT_DIR, "scripts", "sdk", "sdk_repository_settings.current.json"),
  ]);
  const expected = JSON.parse(await readFile(POLICY_PATH, "utf8"));

  const goodActualPath = path.join(tempRoot, "good.json");
  await writeJson(goodActualPath, {
    secrets: [
      "AEGAEON_VERIFIED_CORE_PUBKEY",
      "AEGAEON_NPM_TOKEN",
      "AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME",
      "AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD",
    ],
    variables: {
      AEGAEON_CORE_RELEASE_REPO: "openai/aegaeon",
      AEGAEON_NPM_DIST_TAG: "next",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED: "1",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON: "{\"providerName\":\"managed\"}",
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: "openai/aegaeon-admin-console",
      AEGAEON_ADMIN_CONSOLE_REF: "main",
      AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW: "stack-e2e.yml",
    },
  });

  const goodResult = await execFile(process.execPath, [
    SCRIPT_PATH,
    "--policy",
    POLICY_PATH,
    "--actual",
    goodActualPath,
  ], { cwd: ROOT_DIR });
  assert.match(goodResult.stdout, /matches/);

  const goodOpRefActualPath = path.join(tempRoot, "good-op-ref.json");
  await writeJson(goodOpRefActualPath, {
    secrets: [
      "AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF",
      "AEGAEON_OP_SERVICE_ACCOUNT_TOKEN",
      "AEGAEON_NPM_TOKEN",
    ],
    variables: {
      AEGAEON_CORE_RELEASE_REPO: "openai/aegaeon",
    },
  });

  const goodOpRefResult = await execFile(process.execPath, [
    SCRIPT_PATH,
    "--policy",
    POLICY_PATH,
    "--actual",
    goodOpRefActualPath,
  ], { cwd: ROOT_DIR });
  assert.match(goodOpRefResult.stdout, /matches/);

  const disabledManagedLanePath = path.join(tempRoot, "managed-disabled.json");
  await writeJson(disabledManagedLanePath, {
    secrets: [
      "AEGAEON_VERIFIED_CORE_PUBKEY",
      "AEGAEON_NPM_TOKEN",
    ],
    variables: {
      AEGAEON_CORE_RELEASE_REPO: "openai/aegaeon",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED: "false",
    },
  });

  const disabledManagedLaneResult = await execFile(process.execPath, [
    SCRIPT_PATH,
    "--policy",
    POLICY_PATH,
    "--actual",
    disabledManagedLanePath,
  ], { cwd: ROOT_DIR });
  assert.match(disabledManagedLaneResult.stdout, /matches/);

  const managedEvidenceOverridePath = path.join(tempRoot, "managed-evidence-override.json");
  await writeJson(managedEvidenceOverridePath, {
    secrets: [
      "AEGAEON_VERIFIED_CORE_PUBKEY",
      "AEGAEON_NPM_TOKEN",
    ],
    variables: {
      AEGAEON_CORE_RELEASE_REPO: "openai/aegaeon",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED: "false",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON: "{\"lane\":\"external-provider-managed\"}",
    },
  });

  const managedEvidenceOverrideResult = await execFile(process.execPath, [
    SCRIPT_PATH,
    "--policy",
    POLICY_PATH,
    "--actual",
    managedEvidenceOverridePath,
  ], { cwd: ROOT_DIR });
  assert.match(managedEvidenceOverrideResult.stdout, /matches/);

  const badActualPath = path.join(tempRoot, "bad.json");
  await writeJson(badActualPath, {
    secrets: [
      "AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF",
      "AEGAEON_NPM_TOKEN",
    ],
    variables: {
      AEGAEON_CORE_RELEASE_REPO: "invalid",
      AEGAEON_NPM_DIST_TAG: "bad tag",
    },
  });

  await assert.rejects(
    execFile(process.execPath, [
      SCRIPT_PATH,
      "--policy",
      POLICY_PATH,
      "--actual",
      badActualPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(execError.stderr, /verified_core_public_key/);
      assert.match(execError.stderr, /AEGAEON_CORE_RELEASE_REPO/);
      assert.match(execError.stderr, /AEGAEON_NPM_DIST_TAG/);
      return true;
    },
  );

  const missingManagedRequirementsPath = path.join(tempRoot, "missing-managed-requirements.json");
  await writeJson(missingManagedRequirementsPath, {
    secrets: [
      "AEGAEON_VERIFIED_CORE_PUBKEY",
      "AEGAEON_NPM_TOKEN",
      "AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME",
    ],
    variables: {
      AEGAEON_CORE_RELEASE_REPO: "openai/aegaeon",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED: "true",
    },
  });

  await assert.rejects(
    execFile(process.execPath, [
      SCRIPT_PATH,
      "--policy",
      POLICY_PATH,
      "--actual",
      missingManagedRequirementsPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(
        execError.stderr,
        /missing variable AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON/,
      );
      assert.match(execError.stderr, /managed_external_provider_login/);
      return true;
    },
  );

  console.log("repository settings policy tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
