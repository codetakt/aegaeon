#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
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

async function main() {
  console.log("=== released client claim report test ===");
  const releasedClaimValidator = path.join(
    ROOT_DIR,
    "scripts",
    "validation",
    "validate_released_client_claim.py",
  );
  const releasedClaimReportValidator = path.join(
    ROOT_DIR,
    "scripts",
    "validation",
    "validate_released_client_claim_report.py",
  );
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
  const releasedClaimPolicy = path.join(ROOT_DIR, "spec", "released-client-claim.current.json");
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
  const releasedClaimReportBuilder = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_released_client_claim_report.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-released-client-claim-report.js"),
    path.join(ROOT_DIR, "scripts", "build-released-client-claim-report.ts"),
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

  await execFile("python3", [releasedClaimValidator, releasedClaimPolicy], { cwd: ROOT_DIR });
  await execFile("python3", [promotionValidator, promotionPolicy], { cwd: ROOT_DIR });

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-released-client-claim-"));
  const freshTimestamp = new Date().toISOString();
  const staleTimestamp = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
  const publishManifestPath = path.join(tempRoot, "publish-manifest.json");
  const releaseAttestationPath = path.join(tempRoot, "release-attestation.json");
  const managedEvidencePath = path.join(tempRoot, "managed-provider-evidence.json");
  const adminSdkEvidencePath = path.join(tempRoot, "admin-sdk-evidence.json");
  const promotionReportPath = path.join(tempRoot, "client-claim-promotion-report.json");
  const reportPath = path.join(tempRoot, "released-client-claim-report.json");
  const signaturePath = path.join(tempRoot, "release-attestation.sig");
  const publicKeyPath = path.join(tempRoot, "release-attestation.public.pem");
  const descriptorPath = path.join(tempRoot, "release-attestation.signature.json");

  await writeFile(
    publishManifestPath,
    `${JSON.stringify({
      schemaVersion: 1,
      generatedAt: "2026-03-16T00:00:00Z",
      source: {
        githubRef: "main",
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

  const { privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  await execFile(
    process.execPath,
    [
      releaseAttestationBuilder,
      "--root",
      tempRoot,
      "--publish-manifest",
      publishManifestPath,
      "--claim-boundary",
      claimBoundaryPath,
      "--out",
      releaseAttestationPath,
      "--signature",
      signaturePath,
      "--public-key",
      publicKeyPath,
      "--signature-descriptor",
      descriptorPath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        NPM_CONFIG_PROVENANCE: "true",
        AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION: "true",
        AEGAEON_SDK_SBOM_PUBLICATION: "true",
        AEGAEON_COSIGN_KEY: privateKey,
      },
    },
  );

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
      GITHUB_REF_NAME: "main",
      GITHUB_SHA: "abc123managed",
      GITHUB_JOB: "external-provider-managed",
    },
  });

  await writeFile(
    adminSdkEvidencePath,
    `${JSON.stringify({
      schema_version: 1,
      generated_at: freshTimestamp,
      source: {
        admin_sdk_boundary_path: "spec/admin-sdk-boundary.current.json",
        admin_sdk_boundary_sha256: "4".repeat(64),
        github_run_id: "67890",
        github_workflow: "Admin Console Stack E2E",
        github_repository: "openai/aegaeon-admin-console",
        github_ref: "main",
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
    promotionReportPath,
  ], { cwd: ROOT_DIR });

  await execFile(process.execPath, [
    releasedClaimReportBuilder,
    "--root",
    tempRoot,
    "--policy",
    releasedClaimPolicy,
    "--claim-boundary",
    claimBoundaryPath,
    "--release-attestation",
    releaseAttestationPath,
    "--managed-provider-evidence",
    managedEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--promotion-report",
    promotionReportPath,
    "--out",
    reportPath,
  ], { cwd: ROOT_DIR });

  await execFile("python3", [releasedClaimReportValidator, reportPath], { cwd: ROOT_DIR });
  const pendingReport = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(pendingReport.ready, false);
  assert.match(
    pendingReport.blockers.join("\n"),
    /publication-org task still pending: publication_org_branch_protection/,
  );

  const staleManagedEvidence = JSON.parse(await readFile(managedEvidencePath, "utf8"));
  staleManagedEvidence.generated_at = staleTimestamp;
  await writeFile(
    managedEvidencePath,
    `${JSON.stringify(staleManagedEvidence, null, 2)}\n`,
    "utf8",
  );

  await execFile(process.execPath, [
    releasedClaimReportBuilder,
    "--root",
    tempRoot,
    "--policy",
    releasedClaimPolicy,
    "--claim-boundary",
    claimBoundaryPath,
    "--release-attestation",
    releaseAttestationPath,
    "--managed-provider-evidence",
    managedEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--promotion-report",
    promotionReportPath,
    "--publication-org-task",
    "publication_org_branch_protection=done",
    "--publication-org-task",
    "publication_org_secret_rollout=done",
    "--out",
    reportPath,
  ], { cwd: ROOT_DIR });

  const staleReport = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(staleReport.ready, false);
  assert.match(
    staleReport.blockers.join("\n"),
    /managed-provider evidence is older than 168 hours/,
  );

  const freshManagedEvidence = JSON.parse(await readFile(managedEvidencePath, "utf8"));
  freshManagedEvidence.generated_at = freshTimestamp;
  await writeFile(
    managedEvidencePath,
    `${JSON.stringify(freshManagedEvidence, null, 2)}\n`,
    "utf8",
  );

  const badAdminEvidence = JSON.parse(await readFile(adminSdkEvidencePath, "utf8"));
  badAdminEvidence.source.github_workflow = "Some Other Workflow";
  await writeFile(adminSdkEvidencePath, `${JSON.stringify(badAdminEvidence, null, 2)}\n`, "utf8");

  await execFile(process.execPath, [
    releasedClaimReportBuilder,
    "--root",
    tempRoot,
    "--policy",
    releasedClaimPolicy,
    "--claim-boundary",
    claimBoundaryPath,
    "--release-attestation",
    releaseAttestationPath,
    "--managed-provider-evidence",
    managedEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--promotion-report",
    promotionReportPath,
    "--publication-org-task",
    "publication_org_branch_protection=done",
    "--publication-org-task",
    "publication_org_secret_rollout=done",
    "--out",
    reportPath,
  ], { cwd: ROOT_DIR });

  const wrongWorkflowReport = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(wrongWorkflowReport.ready, false);
  assert.match(
    wrongWorkflowReport.blockers.join("\n"),
    /admin-console SDK evidence workflow mismatch: expected Admin Console Stack E2E/,
  );

  const fixedAdminEvidence = JSON.parse(await readFile(adminSdkEvidencePath, "utf8"));
  fixedAdminEvidence.source.github_workflow = "Admin Console Stack E2E";
  await writeFile(adminSdkEvidencePath, `${JSON.stringify(fixedAdminEvidence, null, 2)}\n`, "utf8");

  const wrongRepositoryEvidence = JSON.parse(await readFile(adminSdkEvidencePath, "utf8"));
  wrongRepositoryEvidence.source.github_repository = "openai/not-admin-console";
  await writeFile(
    adminSdkEvidencePath,
    `${JSON.stringify(wrongRepositoryEvidence, null, 2)}\n`,
    "utf8",
  );

  await execFile(process.execPath, [
    releasedClaimReportBuilder,
    "--root",
    tempRoot,
    "--policy",
    releasedClaimPolicy,
    "--claim-boundary",
    claimBoundaryPath,
    "--release-attestation",
    releaseAttestationPath,
    "--managed-provider-evidence",
    managedEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--promotion-report",
    promotionReportPath,
    "--publication-org-task",
    "publication_org_branch_protection=done",
    "--publication-org-task",
    "publication_org_secret_rollout=done",
    "--out",
    reportPath,
  ], { cwd: ROOT_DIR });

  const wrongRepositoryReport = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(wrongRepositoryReport.ready, false);
  assert.match(
    wrongRepositoryReport.blockers.join("\n"),
    /admin-console SDK evidence repository mismatch: expected suffix aegaeon-admin-console/,
  );

  wrongRepositoryEvidence.source.github_repository = "openai/aegaeon-admin-console";
  await writeFile(
    adminSdkEvidencePath,
    `${JSON.stringify(wrongRepositoryEvidence, null, 2)}\n`,
    "utf8",
  );

  await execFile(process.execPath, [
    releasedClaimReportBuilder,
    "--root",
    tempRoot,
    "--policy",
    releasedClaimPolicy,
    "--claim-boundary",
    claimBoundaryPath,
    "--release-attestation",
    releaseAttestationPath,
    "--managed-provider-evidence",
    managedEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--promotion-report",
    promotionReportPath,
    "--publication-org-task",
    "publication_org_branch_protection=done",
    "--publication-org-task",
    "publication_org_secret_rollout=done",
    "--out",
    reportPath,
  ], { cwd: ROOT_DIR });

  const readyReport = JSON.parse(await readFile(reportPath, "utf8"));
  assert.equal(readyReport.ready, true);
  assert.equal(
    readyReport.target_state.canonical_statement,
    "Aegaeon SDK provides an assumption-qualified security-tested TypeScript client SDK"
      + " and RP runtime for Aegaeon-issued OIDC flows, with a verified client core and a"
      + " promoted RS256 required client slice.",
  );
  assert.equal(readyReport.evidence.managed_provider_lane_name, "external-provider-managed");
  assert.equal(
    readyReport.evidence.managed_provider_source_workflow,
    "SDK Managed Provider Evidence",
  );
  assert.equal(readyReport.evidence.managed_provider_source_repository, "openai/aegaeon-sdk");
  assert.equal(readyReport.evidence.managed_provider_source_ref, "main");
  assert.equal(readyReport.evidence.managed_provider_source_job, "external-provider-managed");
  assert.equal(readyReport.evidence.managed_provider_github_run_id_present, true);
  assert.equal(readyReport.evidence.managed_provider_github_sha_present, true);
  assert.equal(readyReport.evidence.admin_sdk_lane_name, "admin-console-stack-e2e");
  assert.equal(readyReport.evidence.admin_sdk_source_workflow, "Admin Console Stack E2E");
  assert.equal(readyReport.evidence.admin_sdk_source_repository, "openai/aegaeon-admin-console");
  assert.equal(readyReport.evidence.admin_sdk_source_ref, "main");
  assert.equal(readyReport.evidence.admin_sdk_source_job, "stack-e2e");
  assert.equal(readyReport.evidence.admin_sdk_github_run_id_present, true);
  assert.equal(readyReport.evidence.admin_sdk_github_sha_present, true);

  console.log("released client claim report tests passed");
}

main().catch((error) => {
  console.error("[fail] released_client_claim_report_test:", error);
  process.exitCode = 1;
});
