#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
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
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function copyJson(sourcePath, targetPath) {
  await mkdir(path.dirname(targetPath), { recursive: true });
  await writeFile(targetPath, await readFile(sourcePath, "utf8"), "utf8");
}

async function writeStrictTypesFixtures(rootDir, policyPath) {
  const policy = JSON.parse(await readFile(policyPath, "utf8"));
  await writeJson(path.join(rootDir, "tsconfig.base.json"), {
    compilerOptions: policy.required_base_flags,
  });
  for (const relativePath of policy.package_tsconfig_paths) {
    await writeJson(path.join(rootDir, relativePath), {
      extends: "../../tsconfig.base.json",
      compilerOptions: { rootDir: "src", outDir: "dist" },
    });
  }
  for (const requirement of policy.additional_tsconfig_requirements ?? []) {
    await writeJson(path.join(rootDir, requirement.path), {
      extends: "./tsconfig.base.json",
      compilerOptions: requirement.required_flags,
    });
  }
  for (const relativePath of policy.required_no_tsnocheck_paths) {
    const fullPath = path.join(rootDir, relativePath);
    await mkdir(path.dirname(fullPath), { recursive: true });
    await writeFile(fullPath, "export {};\n", "utf8");
  }
}

async function main() {
  console.log("=== released client readiness test ===");
  const readinessScript = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_released_client_readiness.ts"),
    path.join(ROOT_DIR, "dist-tools", "check-released-client-readiness.js"),
    path.join(ROOT_DIR, "scripts", "check-released-client-readiness.ts"),
  ]);
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
  const configPath = await firstExistingPath([
    path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "managed", "managed-provider.example.json"),
    path.join(ROOT_DIR, "tests", "providers", "managed", "managed-provider.example.json"),
  ]);
  const claimBoundaryPath = path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json");
  const promotionPolicyPath = path.join(ROOT_DIR, "spec", "client-claim-promotion.current.json");
  const releasedClientClaimPath = path.join(ROOT_DIR, "spec", "released-client-claim.current.json");
  const strictTypesPolicyPath = path.join(ROOT_DIR, "spec", "strict-types.current.json");

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-released-client-readiness-"));
  const freshTimestamp = new Date().toISOString();
  await writeJson(path.join(tempRoot, "package.json"), { name: "aegaeon-sdk", version: "1.0.0" });
  await mkdir(path.join(tempRoot, "packages"), { recursive: true });
  await copyJson(claimBoundaryPath, path.join(tempRoot, "spec", "client-claim-boundary.current.json"));
  await copyJson(promotionPolicyPath, path.join(tempRoot, "spec", "client-claim-promotion.current.json"));
  await copyJson(releasedClientClaimPath, path.join(tempRoot, "spec", "released-client-claim.current.json"));
  await copyJson(strictTypesPolicyPath, path.join(tempRoot, "spec", "strict-types.current.json"));
  await writeStrictTypesFixtures(tempRoot, strictTypesPolicyPath);

  const publishManifestPath = path.join(tempRoot, ".artifacts", "release", "publish-manifest.json");
  const releaseAttestationPath = path.join(tempRoot, ".artifacts", "release", "release-attestation.json");
  const signaturePath = path.join(tempRoot, ".artifacts", "release", "release-attestation.sig");
  const publicKeyPath = path.join(tempRoot, ".artifacts", "release", "release-attestation.public.pem");
  const signatureDescriptorPath = path.join(tempRoot, ".artifacts", "release", "release-attestation.signature.json");
  const workspaceSbomPath = path.join(tempRoot, ".artifacts", "release", "sdk-workspace-sbom.cdx.json");
  const managedEvidencePath = path.join(tempRoot, ".artifacts", "managed-provider", "managed-provider-evidence.json");
  const adminEvidencePath = path.join(tempRoot, ".artifacts", "admin-sdk", "admin-sdk-evidence.json");
  const promotionReportPath = path.join(tempRoot, ".artifacts", "release", "client-claim-promotion-report.json");
  const releasedClientReportPath = path.join(tempRoot, ".artifacts", "release", "released-client-claim-report.json");
  const publicationBundlePath = path.join(tempRoot, ".artifacts", "release", "release-publication-bundle.json");

  await writeJson(publishManifestPath, {
    schemaVersion: 1,
    generatedAt: "2026-03-16T00:00:00Z",
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
  });

  await writeJson(workspaceSbomPath, {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:11111111-1111-4111-8111-111111111111",
    components: [
      { name: "@aegaeon/runtime-web" },
      { name: "@aegaeon/management-client" },
    ],
  });

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
      signatureDescriptorPath,
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

  await execFile(
    process.execPath,
    [
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
    ],
    {
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
    },
  );

  await writeJson(adminEvidencePath, {
    schema_version: 1,
    generated_at: freshTimestamp,
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
  });

  await execFile(
    process.execPath,
    [
      readinessScript,
      "--root",
      tempRoot,
      "--managed-provider-evidence",
      managedEvidencePath,
      "--admin-sdk-evidence",
      adminEvidencePath,
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
      "--publication-org-task",
      "publication_org_branch_protection=done",
      "--publication-org-task",
      "publication_org_secret_rollout=done",
      "--promotion-report",
      promotionReportPath,
      "--released-client-report",
      releasedClientReportPath,
      "--publication-bundle",
      publicationBundlePath,
    ],
    { cwd: ROOT_DIR },
  );

  const promotionReport = JSON.parse(await readFile(promotionReportPath, "utf8"));
  const releasedClientReport = JSON.parse(await readFile(releasedClientReportPath, "utf8"));
  const publicationBundle = JSON.parse(await readFile(publicationBundlePath, "utf8"));

  assert.equal(promotionReport.ready, true);
  assert.equal(releasedClientReport.ready, true);
  assert.equal(publicationBundle.client_claim_promotion.ready, true);
  assert.equal(publicationBundle.released_client_claim_report.ready, true);
  assert.equal(publicationBundle.admin_sdk_evidence.lane_name, "admin-console-stack-e2e");
  assert.equal(publicationBundle.managed_provider_evidence.lane_name, "external-provider-managed");

  console.log("released client readiness tests passed");
}

main().catch((error) => {
  console.error("[fail] released_client_readiness_test:", error);
  process.exitCode = 1;
});
