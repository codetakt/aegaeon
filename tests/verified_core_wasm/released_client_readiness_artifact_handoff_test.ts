#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
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
  console.log("=== released client readiness artifact handoff test ===");
  const gateRunnerScript = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "run_sdk_client_evidence_gates.ts"),
    path.join(ROOT_DIR, "dist-tools", "run-client-evidence-gates.js"),
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

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-released-client-readiness-artifact-"));
  const freshTimestamp = new Date().toISOString();
  await writeJson(path.join(tempRoot, "package.json"), { name: "aegaeon-sdk", version: "1.0.0" });
  await mkdir(path.join(tempRoot, "packages"), { recursive: true });
  const tempClaimBoundaryPath = path.join(tempRoot, "spec", "client-claim-boundary.current.json");
  await copyJson(claimBoundaryPath, tempClaimBoundaryPath);
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
  const hostedArtifactRoot = path.join(tempRoot, "hosted-artifacts");
  const hostedAdminArtifactDir = path.join(hostedArtifactRoot, "admin-sdk-evidence");
  const hostedManagedArtifactDir = path.join(hostedArtifactRoot, "managed-provider-evidence");
  const hostedAdminEvidencePath = path.join(hostedAdminArtifactDir, "admin-sdk-evidence.json");
  const hostedManagedEvidencePath = path.join(hostedManagedArtifactDir, "managed-provider-evidence.json");

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
      tempClaimBoundaryPath,
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
      hostedManagedEvidencePath,
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

  const adminEvidenceFixture = {
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
  };
  await writeJson(hostedAdminEvidencePath, adminEvidenceFixture);

  const hostedManagedEvidence = JSON.parse(await readFile(hostedManagedEvidencePath, "utf8"));

  await execFile(
    process.execPath,
    [
      gateRunnerScript,
      "--root",
      tempRoot,
      "--mode",
      "promotion",
      "--admin-sdk-artifact-dir",
      hostedAdminArtifactDir,
      "--managed-provider-artifact-dir",
      hostedManagedArtifactDir,
      "--promotion-report",
      promotionReportPath,
    ],
    { cwd: ROOT_DIR },
  );
  await execFile(
    process.execPath,
    [
      gateRunnerScript,
      "--root",
      tempRoot,
      "--mode",
      "readiness",
      "--admin-sdk-artifact-dir",
      hostedAdminArtifactDir,
      "--managed-provider-artifact-dir",
      hostedManagedArtifactDir,
      "--promotion-report",
      promotionReportPath,
      "--released-client-report",
      releasedClientReportPath,
      "--publication-bundle",
      publicationBundlePath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS: "done",
        AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS: "done",
      },
    },
  );

  assert.deepEqual(JSON.parse(await readFile(managedEvidencePath, "utf8")), hostedManagedEvidence);
  assert.deepEqual(JSON.parse(await readFile(adminEvidencePath, "utf8")), adminEvidenceFixture);

  const promotionReport = JSON.parse(await readFile(promotionReportPath, "utf8"));
  const releasedClientReport = JSON.parse(await readFile(releasedClientReportPath, "utf8"));
  const publicationBundle = JSON.parse(await readFile(publicationBundlePath, "utf8"));

  assert.equal(promotionReport.ready, true);
  assert.equal(releasedClientReport.ready, true);
  assert.equal(publicationBundle.client_claim_promotion.ready, true);
  assert.equal(publicationBundle.released_client_claim_report.ready, true);
  assert.equal(publicationBundle.admin_sdk_evidence.path, ".artifacts/admin-sdk/admin-sdk-evidence.json");
  assert.equal(publicationBundle.managed_provider_evidence.path, ".artifacts/managed-provider/managed-provider-evidence.json");
  assert.equal(publicationBundle.admin_sdk_evidence.lane_name, "admin-console-stack-e2e");
  assert.equal(publicationBundle.managed_provider_evidence.lane_name, "external-provider-managed");

  const inlineManagedInput = {
    ...hostedManagedEvidence,
    source: {
      config_path: "tests/providers/managed/managed-provider.example.json",
      config_sha256: "c".repeat(64),
      claim_boundary_path: "spec/client-claim-boundary.current.json",
      claim_boundary_sha256: "d".repeat(64),
      github_run_id: null,
      github_workflow: null,
      github_repository: null,
      github_ref: null,
      github_sha: null,
      github_job: null,
    },
    lane: {
      ...hostedManagedEvidence.lane,
      hosted: false,
    },
  };
  const inlineManagedInputJson = JSON.stringify(inlineManagedInput);
  const fakeBinDir = path.join(tempRoot, "inline-bin");
  const fakeStateDir = path.join(tempRoot, "inline-state");
  const fakeGhLogPath = path.join(tempRoot, "inline-gh.log");
  await mkdir(fakeBinDir, { recursive: true });
  await mkdir(fakeStateDir, { recursive: true });
  const fakeGhPath = path.join(fakeBinDir, "gh");
  await writeFile(
    fakeGhPath,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$GH_LOG_PATH"
if [ "$1" = "workflow" ] && [ "$2" = "run" ]; then
  exit 0
fi
if [ "$1" = "run" ] && [ "$2" = "list" ]; then
  workflow=
  for ((i=1; i<=$#; i++)); do
    if [ "\${!i}" = "--workflow" ]; then
      next=$((i+1))
      workflow="\${!next}"
      break
    fi
  done
  count_file="$GH_STATE_DIR/$workflow.count"
  count=0
  if [ -f "$count_file" ]; then
    count=$(cat "$count_file")
  fi
  count=$((count+1))
  printf '%s' "$count" > "$count_file"
  if [ "$workflow" = "managed-provider-evidence.yml" ]; then
    if [ "$count" -eq 1 ]; then
      printf '%s\\n' '[{"databaseId":5150,"status":"in_progress","conclusion":"","createdAt":"${freshTimestamp}","url":"https://example.test/managed/5150"}]'
    else
      printf '%s\\n' '[{"databaseId":5150,"status":"completed","conclusion":"success","createdAt":"${freshTimestamp}","url":"https://example.test/managed/5150"}]'
    fi
    exit 0
  fi
  printf '%s\\n' '[]'
  exit 0
fi
if [ "$1" = "run" ] && [ "$2" = "download" ]; then
  out_dir=
  artifact=
  for ((i=1; i<=$#; i++)); do
    if [ "\${!i}" = "--dir" ]; then
      next=$((i+1))
      out_dir="\${!next}"
    fi
    if [ "\${!i}" = "--name" ]; then
      next=$((i+1))
      artifact="\${!next}"
    fi
  done
  mkdir -p "$out_dir"
  if [ "$artifact" = "managed-provider-evidence" ]; then
    cp "$MANAGED_FIXTURE_PATH" "$out_dir/managed-provider-evidence.json"
    exit 0
  fi
  echo "unexpected artifact $artifact" >&2
  exit 1
fi
echo "unexpected gh invocation: $*" >&2
exit 1
`,
    "utf8",
  );
  await chmod(fakeGhPath, 0o755);

  const inlineAdminEvidencePath = path.join(tempRoot, ".artifacts", "admin-sdk", "admin-sdk-inline.json");
  const inlineManagedEvidencePath = path.join(tempRoot, ".artifacts", "managed-provider", "managed-provider-imported.json");
  const inlinePromotionReportPath = path.join(tempRoot, ".artifacts", "release", "client-claim-promotion-inline-report.json");
  const inlineReleasedClientReportPath = path.join(tempRoot, ".artifacts", "release", "released-client-claim-inline-report.json");
  const inlinePublicationBundlePath = path.join(tempRoot, ".artifacts", "release", "release-publication-inline-bundle.json");

  await execFile(
    process.execPath,
    [
      gateRunnerScript,
      "--root",
      tempRoot,
      "--mode",
      "readiness",
      "--dispatch-hosted",
      "--admin-sdk-evidence",
      inlineAdminEvidencePath,
      "--admin-sdk-evidence-json",
      JSON.stringify(adminEvidenceFixture),
      "--managed-provider-evidence",
      inlineManagedEvidencePath,
      "--managed-provider-evidence-json",
      inlineManagedInputJson,
      "--promotion-report",
      inlinePromotionReportPath,
      "--released-client-report",
      inlineReleasedClientReportPath,
      "--publication-bundle",
      inlinePublicationBundlePath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH}`,
        GH_LOG_PATH: fakeGhLogPath,
        GH_STATE_DIR: fakeStateDir,
        MANAGED_FIXTURE_PATH: hostedManagedEvidencePath,
        AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY: "openai/aegaeon-sdk",
        AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: "managed-provider-evidence.yml",
        AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF: "main",
        AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS: "done",
        AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS: "done",
      },
    },
  );

  assert.deepEqual(JSON.parse(await readFile(inlineManagedEvidencePath, "utf8")), hostedManagedEvidence);
  assert.deepEqual(JSON.parse(await readFile(inlineAdminEvidencePath, "utf8")), adminEvidenceFixture);
  const inlineReleasedClientReport = JSON.parse(await readFile(inlineReleasedClientReportPath, "utf8"));
  const inlinePublicationBundle = JSON.parse(await readFile(inlinePublicationBundlePath, "utf8"));
  const inlineGhLog = await readFile(fakeGhLogPath, "utf8");

  assert.equal(inlineReleasedClientReport.ready, true);
  assert.equal(inlinePublicationBundle.released_client_claim_report.ready, true);
  assert.equal(
    inlinePublicationBundle.managed_provider_evidence.path,
    ".artifacts/managed-provider/managed-provider-imported.json",
  );
  assert.match(inlineGhLog, /workflow run managed-provider-evidence\.yml .*--repo openai\/aegaeon-sdk .*--ref main/);
  assert.match(inlineGhLog, /-f managed_provider_evidence_json=\{/);
  assert.doesNotMatch(inlineGhLog, /stack-e2e\.yml/);

  const fileImportGhLogPath = path.join(tempRoot, "file-gh.log");
  const fileImportStateDir = path.join(tempRoot, "file-state");
  await mkdir(fileImportStateDir, { recursive: true });
  const fileManagedEvidencePath = path.join(tempRoot, ".artifacts", "managed-provider", "managed-provider-from-file.json");
  const filePromotionReportPath = path.join(tempRoot, ".artifacts", "release", "client-claim-promotion-file-report.json");
  const fileReleasedClientReportPath = path.join(tempRoot, ".artifacts", "release", "released-client-claim-file-report.json");
  const filePublicationBundlePath = path.join(tempRoot, ".artifacts", "release", "release-publication-file-bundle.json");
  await writeJson(fileManagedEvidencePath, inlineManagedInput);

  await execFile(
    process.execPath,
    [
      gateRunnerScript,
      "--root",
      tempRoot,
      "--mode",
      "readiness",
      "--dispatch-hosted",
      "--admin-sdk-evidence-json",
      JSON.stringify(adminEvidenceFixture),
      "--managed-provider-evidence",
      fileManagedEvidencePath,
      "--promotion-report",
      filePromotionReportPath,
      "--released-client-report",
      fileReleasedClientReportPath,
      "--publication-bundle",
      filePublicationBundlePath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH}`,
        GH_LOG_PATH: fileImportGhLogPath,
        GH_STATE_DIR: fileImportStateDir,
        MANAGED_FIXTURE_PATH: hostedManagedEvidencePath,
        AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY: "openai/aegaeon-sdk",
        AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: "managed-provider-evidence.yml",
        AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF: "main",
        AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS: "done",
        AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS: "done",
      },
    },
  );

  const fileReleasedClientReport = JSON.parse(await readFile(fileReleasedClientReportPath, "utf8"));
  const filePublicationBundle = JSON.parse(await readFile(filePublicationBundlePath, "utf8"));
  const fileGhLog = await readFile(fileImportGhLogPath, "utf8");

  assert.deepEqual(JSON.parse(await readFile(fileManagedEvidencePath, "utf8")), hostedManagedEvidence);
  assert.equal(fileReleasedClientReport.ready, true);
  assert.equal(filePublicationBundle.released_client_claim_report.ready, true);
  assert.equal(filePublicationBundle.managed_provider_evidence.path, ".artifacts/managed-provider/managed-provider-from-file.json");
  assert.match(fileGhLog, /workflow run managed-provider-evidence\.yml .*--repo openai\/aegaeon-sdk .*--ref main/);
  assert.match(fileGhLog, /-f managed_provider_evidence_json=\{/);
  assert.doesNotMatch(fileGhLog, /managed_provider_config_json=/);

  console.log("released client readiness artifact handoff tests passed");
}

main().catch((error) => {
  console.error("[fail] released_client_readiness_artifact_handoff_test:", error);
  process.exitCode = 1;
});
