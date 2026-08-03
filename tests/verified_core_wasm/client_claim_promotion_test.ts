#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);

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

async function main() {
  console.log("=== client claim promotion test ===");
  const promotionValidator = path.join(
    ROOT_DIR,
    "scripts",
    "validation",
    "validate_client_claim_promotion.py",
  );
  const adminEvidenceValidator = path.join(
    ROOT_DIR,
    "scripts",
    "validation",
    "validate_admin_sdk_evidence.py",
  );
  const promotionPolicy = path.join(ROOT_DIR, "spec", "client-claim-promotion.current.json");
  const claimBoundaryPath = path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json");
  const releaseAttestationBuilder = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_release_attestation.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-release-attestation.js"),
    path.join(ROOT_DIR, "scripts", "build-release-attestation.ts"),
  ]);
  const managedEvidenceBuilder = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_managed_provider_evidence.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-managed-provider-evidence.js"),
    path.join(ROOT_DIR, "scripts", "build-managed-provider-evidence.ts"),
  ]);
  const promotionChecker = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_client_claim_promotion.ts"),
    path.join(ROOT_DIR, "dist-tools", "check-client-claim-promotion.js"),
    path.join(ROOT_DIR, "scripts", "check-client-claim-promotion.ts"),
  ]);
  const configPath = await firstExistingPath([
    path.join(
      ROOT_DIR,
      "tests",
      "verified_core_wasm",
      "providers",
      "managed",
      "managed-provider.example.json",
    ),
    path.join(ROOT_DIR, "tests", "providers", "managed", "managed-provider.example.json"),
  ]);

  await execFile("python3", [promotionValidator, promotionPolicy], { cwd: ROOT_DIR });

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-client-claim-promotion-"));
  const publishManifestPath = path.join(tempRoot, "publish-manifest.json");
  const releaseAttestationPath = path.join(tempRoot, "release-attestation.json");
  const managedEvidencePath = path.join(tempRoot, "managed-provider-evidence.json");
  const adminSdkEvidencePath = path.join(tempRoot, "admin-sdk-evidence.json");
  const reportPath = path.join(tempRoot, "client-claim-promotion-report.json");

  await writeFile(
    publishManifestPath,
    `${JSON.stringify({
      schemaVersion: 1,
      generatedAt: "2026-03-12T00:00:00Z",
      source: {
        githubRef: "refs/heads/main",
        githubSha: "deadbeefcafebabe",
        githubRunId: "12345",
        githubWorkflow: "publish",
        npmDistTag: "latest",
      },
      tarballs: [
        {
          packageName: "@aegaeon/runtime-web",
          version: "1.0.0",
          tarball: "aegaeon-runtime-web-1.0.0.tgz",
          sha256: "0".repeat(64),
          sha512: "1".repeat(128),
          dependencyBlocks: {},
        },
      ],
      verifiedCore: {
        manifestPath: "packages/verified-core/dist/manifest.json",
        manifestSha256: "2".repeat(64),
        handoffManifestPath: "packages/verified-core/dist/verified-core-handoff-manifest.json",
        handoffManifestSha256: "3".repeat(64),
      },
    }, null, 2)}\n`,
    "utf8",
  );

  await execFile(process.execPath, [
    releaseAttestationBuilder,
    "--root",
    tempRoot,
    "--publish-manifest",
    publishManifestPath,
    "--claim-boundary",
    claimBoundaryPath,
    "--out",
    releaseAttestationPath,
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      NPM_CONFIG_PROVENANCE: "true",
    },
  });

  await execFile(process.execPath, [
    managedEvidenceBuilder,
    "--root",
    ROOT_DIR,
    "--config",
    configPath,
    "--claim-boundary",
    claimBoundaryPath,
    "--provider-class",
    "commercial",
    "--lane-name",
    "external-provider-managed",
    "--status",
    "passed",
    "--hosted",
    "true",
    "--browser",
    "/usr/bin/chromium",
    "--out",
    managedEvidencePath,
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      GITHUB_RUN_ID: "54321",
      GITHUB_WORKFLOW: "SDK Managed Provider Evidence",
      GITHUB_REPOSITORY: "openai/aegaeon-sdk",
      GITHUB_REF: "refs/heads/main",
      GITHUB_SHA: "abc123managed",
      GITHUB_JOB: "external-provider-managed",
    },
  });

  await writeFile(
    adminSdkEvidencePath,
    `${JSON.stringify({
      schema_version: 1,
      generated_at: "2026-03-15T00:00:00Z",
      source: {
        admin_sdk_boundary_path: "spec/admin-sdk-boundary.current.json",
        admin_sdk_boundary_sha256: "4".repeat(64),
        github_run_id: "67890",
        github_workflow: "Admin Console Stack E2E",
        github_repository: "openai/aegaeon-admin-console",
        github_ref: "refs/heads/main",
        github_sha: "def456admin",
        github_job: "stack-e2e",
      },
      lane: {
        name: "admin-console-stack-e2e",
        status: "passed",
        stack_mode: "compose-sibling-aegaeon",
      },
      sdk_boundary: {
        management_sdk_package: "@aegaeon/management-client",
        forbidden_oidc_packages: ["@aegaeon/issuer-spa", "@aegaeon/rp-core"],
      },
      capabilities: [
        "bootstrap-login-logout",
        "team-tenant-environment-management",
        "oauth-profile-management",
        "connection-management",
        "environment-policy-update",
        "configuration-version-management",
        "signing-key-management",
        "key-store-management",
        "user-management",
        "client-management",
        "client-secret-management",
        "audit-read-export",
      ],
    }, null, 2)}\n`,
    "utf8",
  );
  await execFile("python3", [adminEvidenceValidator, adminSdkEvidencePath], { cwd: ROOT_DIR });

  await execFile(process.execPath, [
    promotionChecker,
    "--policy",
    promotionPolicy,
    "--claim-boundary",
    claimBoundaryPath,
    "--release-attestation",
    releaseAttestationPath,
    "--managed-provider-evidence",
    managedEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--lane",
    "browser-smoke=passed",
    "--lane",
    "playwright=passed",
    "--lane",
    "external-provider-dex=passed",
    "--lane",
    "external-provider-keycloak=passed",
    "--lane",
    "external-provider-managed=passed",
    "--report",
    reportPath,
  ], { cwd: ROOT_DIR });

  const report = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(report.ready, true);
  assert.deepEqual(report.failures, []);

  const badAdminEvidence = JSON.parse(await readFile(adminSdkEvidencePath, "utf8"));
  badAdminEvidence.source.github_job = "not-stack-e2e";
  await writeFile(adminSdkEvidencePath, `${JSON.stringify(badAdminEvidence, null, 2)}\n`, "utf8");

  await assert.rejects(
    execFile(process.execPath, [
      promotionChecker,
      "--policy",
      promotionPolicy,
      "--claim-boundary",
      claimBoundaryPath,
      "--release-attestation",
      releaseAttestationPath,
      "--managed-provider-evidence",
      managedEvidencePath,
      "--admin-sdk-evidence",
      adminSdkEvidencePath,
      "--lane",
      "browser-smoke=passed",
      "--lane",
      "playwright=passed",
      "--lane",
      "external-provider-dex=passed",
      "--lane",
      "external-provider-keycloak=passed",
      "--lane",
      "external-provider-managed=passed",
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(execError.stderr, /admin-console job mismatch: expected stack-e2e/);
      return true;
    },
  );

  badAdminEvidence.source.github_job = "stack-e2e";
  await writeFile(adminSdkEvidencePath, `${JSON.stringify(badAdminEvidence, null, 2)}\n`, "utf8");

  await assert.rejects(
    execFile(process.execPath, [
      promotionChecker,
      "--policy",
      promotionPolicy,
      "--claim-boundary",
      claimBoundaryPath,
      "--release-attestation",
      releaseAttestationPath,
      "--managed-provider-evidence",
      managedEvidencePath,
      "--admin-sdk-evidence",
      adminSdkEvidencePath,
      "--lane",
      "browser-smoke=passed",
      "--lane",
      "playwright=passed",
      "--lane",
      "external-provider-dex=passed",
      "--lane",
      "external-provider-keycloak=passed",
      "--lane",
      "external-provider-managed=failed",
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(
        execError.stderr,
        /required lane external-provider-managed is not marked passed/,
      );
      return true;
    },
  );

  console.log("client claim promotion tests passed");
}

main().catch((error) => {
  console.error("[fail] client_claim_promotion_test:", error);
  process.exitCode = 1;
});
