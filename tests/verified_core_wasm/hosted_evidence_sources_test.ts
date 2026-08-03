#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, stat, writeFile } from "node:fs/promises";
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
  console.log("=== hosted evidence source policy test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-hosted-evidence-sources-"));
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "dist-tools", "check-hosted-evidence-sources.js"),
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_hosted_evidence_sources.ts"),
  ]);
  const policyPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "hosted-evidence-sources.current.json"),
    path.join(ROOT_DIR, "scripts", "sdk", "sdk_hosted_evidence_sources.current.json"),
  ]);

  const goodActualPath = path.join(tempRoot, "good.json");
  await writeJson(goodActualPath, {
    repository: "openai/aegaeon-sdk",
    secrets: [
      "AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN",
    ],
    variables: {
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: "openai/aegaeon-admin-console",
      AEGAEON_ADMIN_CONSOLE_REF: "main",
      AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW: "stack-e2e.yml",
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: "admin-sdk-evidence",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: "managed-provider-evidence.yml",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT: "managed-provider-evidence",
    },
  });

  const goodResult = await execFile(process.execPath, [
    scriptPath,
    "--policy",
    policyPath,
    "--actual",
    goodActualPath,
  ], { cwd: ROOT_DIR });
  assert.match(goodResult.stdout, /Hosted evidence sources match/);

  const ciActualPath = path.join(tempRoot, "ci-good.json");
  await writeJson(ciActualPath, {
    repository: "codetakt/aegaeon-sdk-ci",
    secrets: [
      "AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN",
      "AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN",
    ],
    variables: {
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: "codetakt/aegaeon-admin-console-ci",
      AEGAEON_ADMIN_CONSOLE_REF: "main",
      AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW: "stack-e2e.yml",
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: "admin-sdk-evidence",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY: "codetakt/aegaeon-sdk-ci",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF: "main",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: "managed-provider-evidence.yml",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT: "managed-provider-evidence",
    },
  });

  const ciResult = await execFile(process.execPath, [
    scriptPath,
    "--policy",
    policyPath,
    "--actual",
    ciActualPath,
  ], { cwd: ROOT_DIR });
  assert.match(ciResult.stdout, /Hosted evidence sources match/);

  const missingAdminTokenPath = path.join(tempRoot, "missing-admin-token.json");
  await writeJson(missingAdminTokenPath, {
    repository: "openai/aegaeon-sdk",
    secrets: [],
    variables: {
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: "openai/aegaeon-admin-console",
      AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW: "stack-e2e.yml",
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: "admin-sdk-evidence",
    },
  });

  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--policy",
      policyPath,
      "--actual",
      missingAdminTokenPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN/);
      return true;
    },
  );

  const missingManagedTokenPath = path.join(tempRoot, "missing-managed-token.json");
  await writeJson(missingManagedTokenPath, {
    repository: "openai/aegaeon-sdk",
    secrets: [
      "AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN",
    ],
    variables: {
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: "openai/aegaeon-admin-console",
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: "admin-sdk-evidence",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY: "openai/managed-provider-evidence",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: "managed-provider-evidence.yml",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT: "managed-provider-evidence",
    },
  });

  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--policy",
      policyPath,
      "--actual",
      missingManagedTokenPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN/);
      return true;
    },
  );

  const wrongArtifactPath = path.join(tempRoot, "wrong-artifact.json");
  await writeJson(wrongArtifactPath, {
    repository: "openai/aegaeon-sdk",
    secrets: [
      "AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN",
    ],
    variables: {
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: "openai/aegaeon-admin-console",
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: "stack-e2e",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: "playwright.yml",
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT: "managed-provider-evidence",
    },
  });

  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--policy",
      policyPath,
      "--actual",
      wrongArtifactPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /admin-sdk-evidence/);
      assert.match(error.stderr, /managed-provider-evidence\.yml/);
      return true;
    },
  );

  console.log("hosted evidence source policy tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
