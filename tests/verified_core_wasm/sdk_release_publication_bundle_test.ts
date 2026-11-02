#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile, mkdir } from "node:fs/promises";
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

async function main() {
  console.log("=== sdk release publication bundle test ===");
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_release_publication_bundle.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-release-publication-bundle.js"),
    path.join(ROOT_DIR, "scripts", "build-release-publication-bundle.ts"),
  ]);
  const validatorPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "validation", "validate_sdk_release_publication_bundle.py"),
  ]);

  const testEnv = { ...process.env };
  delete testEnv.AEGAEON_PUBLICATION_ORG_ROLLOUT_REPORT_PATH;
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-release-bundle-"));
  const publishManifestPath = path.join(tempRoot, ".artifacts", "release", "publish-manifest.json");
  const releaseAttestationPath = path.join(
    tempRoot,
    ".artifacts",
    "release",
    "release-attestation.json",
  );
  const releaseAttestationSignaturePath = path.join(
    tempRoot,
    ".artifacts",
    "release",
    "release-attestation.signature.json",
  );
  const workspaceSbomPath = path.join(
    tempRoot,
    ".artifacts",
    "release",
    "sdk-workspace-sbom.cdx.json",
  );
  const managedEvidencePath = path.join(
    tempRoot,
    ".artifacts",
    "managed-provider",
    "managed-provider-evidence.json",
  );
  const adminSdkEvidencePath = path.join(
    tempRoot,
    ".artifacts",
    "admin-sdk",
    "admin-sdk-evidence.json",
  );
  const clientClaimPromotionReportPath = path.join(
    tempRoot,
    ".artifacts",
    "release",
    "client-claim-promotion-report.json",
  );
  const outPath = path.join(tempRoot, ".artifacts", "release", "release-publication-bundle.json");

  await writeJson(path.join(tempRoot, "package.json"), {
    name: "aegaeon-sdk",
    version: "1.0.0",
  });
  await mkdir(path.join(tempRoot, "packages"), { recursive: true });

  await writeJson(publishManifestPath, {
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
        packageName: "@aegaeon/runtime-node",
        version: "1.0.0",
        tarball: "aegaeon-runtime-node-1.0.0.tgz",
        sha256: "0".repeat(64),
        sha512: "1".repeat(128),
        dependencyBlocks: {},
      },
    ],
    verifiedCore: {
      manifestPath: "packages/verified-core/dist/manifest.json",
      manifestSha256: "4".repeat(64),
      handoffManifestPath: "packages/verified-core/dist/verified-core-handoff-manifest.json",
      handoffManifestSha256: "5".repeat(64),
    },
  });

  await writeJson(releaseAttestationPath, {
    schema_version: 1,
    generated_at: "2026-03-12T00:00:00Z",
    release_phase: "pre-release-client-baseline",
    source: {
      github_ref: "refs/heads/main",
      github_sha: "deadbeefcafebabe",
      github_run_id: "12345",
      github_workflow: "publish",
      npm_dist_tag: "latest",
    },
    publication: {
      npm_provenance_enabled: true,
      signed_release_attestation_present: true,
      sbom_publication_present: true,
    },
    publish_manifest: {
      path: ".artifacts/release/publish-manifest.json",
      sha256: "2".repeat(64),
      tarball_count: 1,
    },
    client_claim_boundary: {
      path: "spec/client-claim-boundary.current.json",
      sha256: "3".repeat(64),
      claim_phase: "pre-release-client-baseline",
      released_client_claim_active: false,
      default_profile: "aegaeon-rs256",
      promoted_client_slices: ["rs256-required-client-slice"],
      compat_only_surfaces: ["es256-interop-surface"],
    },
    verified_core: {
      manifest_path: "packages/verified-core/dist/manifest.json",
      manifest_sha256: "4".repeat(64),
      handoff_manifest_path: "packages/verified-core/dist/verified-core-handoff-manifest.json",
      handoff_manifest_sha256: "5".repeat(64),
    },
    deferred_requirements: [
      "released_client_claim_promotion",
    ],
  });

  await writeJson(releaseAttestationSignaturePath, {
    schema_version: 1,
    generated_at: "2026-03-12T00:00:00Z",
    attestation_path: ".artifacts/release/release-attestation.json",
    attestation_sha256: "6".repeat(64),
    signature_path: ".artifacts/release/release-attestation.sig",
    signature_sha256: "7".repeat(64),
    public_key_path: ".artifacts/release/release-attestation.public.pem",
    public_key_sha256: "8".repeat(64),
    signature_algorithm: "ecdsa-sha256",
    key_type: "ec",
    signature_encoding: "base64",
    signer_source: "cosign_key_env",
    signed_release_attestation_present: true,
  });

  await writeJson(workspaceSbomPath, {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: "urn:uuid:11111111-1111-4111-8111-111111111111",
    components: [
      { name: "@aegaeon/runtime-node" },
      { name: "@aegaeon/verified-core" },
    ],
  });

  await writeJson(managedEvidencePath, {
    schema_version: 1,
    generated_at: "2026-03-12T00:00:00Z",
    source: {
      config_path: "tests/providers/managed/managed-provider.example.json",
      config_sha256: "a".repeat(64),
      claim_boundary_path: "spec/client-claim-boundary.current.json",
      claim_boundary_sha256: "b".repeat(64),
      github_run_id: "5150",
      github_workflow: "SDK Managed Provider Evidence",
      github_repository: "openai/aegaeon-sdk",
      github_ref: "refs/heads/main",
      github_sha: "abc123managed",
      github_job: "external-provider-managed",
    },
    provider: {
      name: "commercial-staging",
      class: "commercial",
      issuer: "https://issuer.example.test",
      client_id: "client-123",
      auth_method: "client_secret_post",
    },
    lane: {
      name: "external-provider-managed",
      hosted: true,
      status: "passed",
      browser: "/usr/bin/chromium",
    },
    runtime: {
      default_profile: "aegaeon-rs256",
      claim_phase: "pre-release-client-baseline",
      promoted_client_slices: ["rs256-required-client-slice"],
      compat_only_surfaces: ["es256-interop-surface"],
    },
  });

  await writeJson(adminSdkEvidencePath, {
    schema_version: 1,
    generated_at: "2026-03-12T00:00:00Z",
    source: {
      admin_sdk_boundary_path: "spec/admin-sdk-boundary.current.json",
      admin_sdk_boundary_sha256: "9".repeat(64),
      github_run_id: "98765",
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

  await writeJson(clientClaimPromotionReportPath, {
    schema_version: 1,
    generated_at: "2026-03-12T00:00:00Z",
    policy_path: "spec/client-claim-promotion.current.json",
    claim_boundary_path: "spec/client-claim-boundary.current.json",
    release_attestation_path: ".artifacts/release/release-attestation.json",
    managed_provider_evidence_path: ".artifacts/managed-provider/managed-provider-evidence.json",
    lanes: {
      "browser-smoke": "passed",
      playwright: "passed",
      "external-provider-dex": "passed",
      "external-provider-keycloak": "passed",
      "external-provider-managed": "passed",
    },
    ready: true,
    failures: [],
  });

  await execFile(process.execPath, [
    scriptPath,
    "--root",
    tempRoot,
    "--publish-manifest",
    publishManifestPath,
    "--release-attestation",
    releaseAttestationPath,
    "--release-attestation-signature",
    releaseAttestationSignaturePath,
    "--workspace-sbom",
    workspaceSbomPath,
    "--managed-provider-evidence",
    managedEvidencePath,
    "--admin-sdk-evidence",
    adminSdkEvidencePath,
    "--client-claim-promotion-report",
    clientClaimPromotionReportPath,
    "--out",
    outPath,
  ], { cwd: ROOT_DIR, env: testEnv });

  await execFile("python3", [validatorPath, outPath], { cwd: ROOT_DIR });
  const bundle = JSON.parse(await readFile(outPath, "utf8"));
  assert.equal(bundle.schema_version, 1);
  assert.equal(bundle.publication_org_rollout_report, null);
  assert.equal(bundle.release_phase, "pre-release-client-baseline");
  assert.equal(bundle.release_attestation.npm_provenance_enabled, true);
  assert.equal(bundle.release_attestation.signed_release_attestation_present, true);
  assert.equal(bundle.release_attestation_signature.signature_algorithm, "ecdsa-sha256");
  assert.equal(bundle.release_attestation_signature.key_type, "ec");
  assert.equal(bundle.workspace_sbom.bom_format, "CycloneDX");
  assert.equal(bundle.workspace_sbom.component_count, 2);
  assert.equal(bundle.managed_provider_evidence.lane_name, "external-provider-managed");
  assert.equal(bundle.managed_provider_evidence.provider_class, "commercial");
  assert.equal(bundle.managed_provider_evidence.hosted, true);
  assert.equal(bundle.admin_sdk_evidence.lane_name, "admin-console-stack-e2e");
  assert.equal(bundle.admin_sdk_evidence.stack_mode, "compose-sibling-aegaeon");
  assert.equal(bundle.admin_sdk_evidence.management_sdk_package, "@aegaeon/management-client");
  assert.equal(bundle.admin_sdk_evidence.capability_count, 12);
  assert.equal(bundle.client_claim_promotion.ready, true);
  assert.equal(bundle.client_claim_promotion.failure_count, 0);
  assert.deepEqual(bundle.client_claim_promotion.failures, []);
  assert.deepEqual(bundle.deferred_publication_requirements, [
    "released_client_claim_promotion",
  ]);

  // Only the org report differs in these enterprise-readiness fixtures.
  async function checkEnterprise(orgReport, expectedError = null) {
    const enterprise = structuredClone(bundle);
    enterprise.release_phase = "released-client-claim";
    enterprise.source = {
      github_ref: "refs/tags/v1.0.0",
      github_sha: "a".repeat(40),
      github_run_id: "12345",
      github_workflow: "SDK Publish",
      npm_dist_tag: "latest",
    };
    enterprise.release_attestation.deferred_requirements = [];
    enterprise.deferred_publication_requirements = [];
    enterprise.released_client_claim_report = {
      path: ".artifacts/release/released-client-claim-report.json",
      sha256: "b".repeat(64),
      ready: true,
      blocker_count: 0,
      current_claim_active: true,
      target_statement: "Released client claim fixture",
    };
    enterprise.publication_org_rollout_report = orgReport;
    const enterprisePath = path.join(tempRoot, "enterprise-bundle.json");
    await writeJson(enterprisePath, enterprise);
    const check = execFile("python3", [
      validatorPath, "--require-enterprise-ready", enterprisePath,
    ], { cwd: ROOT_DIR });
    if (expectedError) {
      await assert.rejects(check, (error) => {
        assert.match(error.stderr, expectedError);
        return true;
      });
    } else {
      await check;
    }
  }

  async function rebuild(extraArgs = [], env = testEnv) {
    await execFile(process.execPath, [
      scriptPath, "--root", tempRoot, ...extraArgs,
    ], { cwd: ROOT_DIR, env });
    await execFile("python3", [validatorPath, outPath], { cwd: ROOT_DIR });
    return JSON.parse(await readFile(outPath, "utf8"));
  }

  await checkEnterprise(null, /publication-org/);
  const orgReportPath = path.join(
    tempRoot, ".artifacts", "release", "publication-org-rollout-report.json",
  );
  const pendingReport = {
    ready: false,
    blockers: ["publication-org task still pending: publication_org_secret_rollout"],
    target_repository: { owner: "example", repo: "sdk", branch: "main" },
  };
  await writeJson(orgReportPath, pendingReport);
  const pending = (await rebuild()).publication_org_rollout_report;
  assert.deepEqual(pending, {
    path: ".artifacts/release/publication-org-rollout-report.json",
    sha256: createHash("sha256").update(await readFile(orgReportPath)).digest("hex"),
    ready: false,
    blocker_count: 1,
    target_repository: "example/sdk",
  });
  await checkEnterprise(pending, /publication-org/);

  const customPath = path.join(tempRoot, "custom", "org-report.json");
  await writeJson(customPath, { ...pendingReport, ready: true, blockers: [] });
  const ready = (await rebuild([
    "--publication-org-rollout-report", "custom/org-report.json",
  ])).publication_org_rollout_report;
  assert.deepEqual(ready, {
    path: "custom/org-report.json",
    sha256: createHash("sha256").update(await readFile(customPath)).digest("hex"),
    ready: true,
    blocker_count: 0,
    target_repository: "example/sdk",
  });
  await checkEnterprise(ready);
  await checkEnterprise({ ...ready, blocker_count: 1 }, /publication-org/);
  const reportEnv = {
    ...testEnv, AEGAEON_PUBLICATION_ORG_ROLLOUT_REPORT_PATH: customPath,
  };
  assert.deepEqual((await rebuild([], reportEnv)).publication_org_rollout_report, ready);
  assert.deepEqual((await rebuild([
    "--publication-org-rollout-report", orgReportPath,
  ], reportEnv)).publication_org_rollout_report, pending);

  for (const invalid of [
    { ...pendingReport, ready: "true" },
    { ...pendingReport, blockers: null },
    { ...pendingReport, blockers: [42] },
    { ...pendingReport, target_repository: [] },
    { ...pendingReport, target_repository: { owner: 42, repo: "sdk" } },
  ]) {
    await writeJson(customPath, invalid);
    await assert.rejects(rebuild([], reportEnv), /invalid summary fields/);
  }
  await writeFile(customPath, "{invalid json", "utf8");
  await assert.rejects(rebuild([], reportEnv));

  console.log("sdk release publication bundle tests passed");
}

main().catch((error) => {
  console.error("[fail] sdk_release_publication_bundle_test:", error);
  process.exitCode = 1;
});
