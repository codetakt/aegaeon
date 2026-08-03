#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const scaffoldScript = path.join(ROOT_DIR, "scripts", "sdk", "scaffold_sdk_repo_workspace.ts");

async function assertExists(filePath) {
  await stat(filePath);
}

async function ensureWorkspaceNodeModule(outDir, packageName) {
  const scopedDir = path.join(outDir, "node_modules", "@aegaeon");
  const targetDir = path.join(outDir, "packages", packageName);
  const linkPath = path.join(scopedDir, packageName);
  await mkdir(scopedDir, { recursive: true });
  await symlink(path.relative(scopedDir, targetDir), linkPath, "junction");
}

async function main() {
  console.log("=== SDK Repo Scaffold Tests ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-scaffold-"));
  const outDir = path.join(tempRoot, "aegaeon-sdk");

  await execFile(process.execPath, [scaffoldScript, "--out-dir", outDir], {
    cwd: ROOT_DIR,
  });

  for (const relativePath of [
    "package.json",
    "pnpm-workspace.yaml",
    "README.md",
    "MIGRATION.md",
    "LICENSE",
    ".npmrc",
    "tsconfig.base.json",
    ".changeset/config.json",
    ".changeset/README.md",
    "tools-src/fetch-core.ts",
    "tools-src/download-core-release.ts",
    "tools-src/download-admin-sdk-evidence.ts",
    "tools-src/download-managed-provider-evidence.ts",
    "tools-src/import-managed-provider-evidence.ts",
    "tools-src/run-client-evidence-gates.ts",
    "tools-src/run-real-tenant-readiness.ts",
    "tools-src/verify-core.ts",
    "tools-src/check-branch-protection.ts",
    "tools-src/check-external-boundary-naming.ts",
    "tools-src/check-hosted-evidence-sources.ts",
    "tools-src/check-repository-settings.ts",
    "tools-src/check-release-custody.ts",
    "tools-src/check-client-claim-promotion.ts",
    "tools-src/check-released-client-claim-activation.ts",
    "tools-src/build-released-client-claim-report.ts",
    "tools-src/check-managed-provider-readiness.ts",
    "tools-src/build-managed-provider-evidence.ts",
    "tools-src/build-publication-org-rollout-report.ts",
    "tools-src/build-workspace-sbom.ts",
    "tools-src/build-release-attestation.ts",
    "tools-src/check-release-attestation-signature.ts",
    "tools-src/build-release-publication-bundle.ts",
    "tools-src/materialize-sdk-dispatch-payload.ts",
    "tools-src/export-sdk-dispatch-env.ts",
    "tools-src/materialize-verified-core-public-key.ts",
    "scripts/validation/validate_sdk_repository_dispatch_payload.py",
    "scripts/validation/validate_verified_core_handoff_manifest.py",
    "scripts/validation/validate_managed_external_provider_config.py",
    "scripts/validation/validate_managed_provider_evidence.py",
    "scripts/validation/validate_client_claim_boundary.py",
    "scripts/validation/validate_client_claim_promotion.py",
    "scripts/validation/validate_released_client_claim.py",
    "scripts/validation/validate_released_client_claim_report.py",
    "scripts/validation/validate_sdk_release_attestation.py",
    "scripts/validation/validate_sdk_release_attestation_signature.py",
    "scripts/validation/validate_sdk_release_publication_bundle.py",
    "spec/branch-protection.main.json",
    "spec/hosted-evidence-sources.current.json",
    "spec/repository-settings.current.json",
    "spec/release-custody.current.json",
    "spec/managed-external-provider.schema.json",
    "spec/managed-provider-evidence.schema.json",
    "spec/client-claim-boundary.schema.json",
    "spec/client-claim-boundary.current.json",
    "spec/client-claim-promotion.schema.json",
    "spec/client-claim-promotion.current.json",
    "spec/released-client-claim.schema.json",
    "spec/released-client-claim.current.json",
    "spec/external-boundary-naming.current.json",
    "spec/strict-types.current.json",
    "spec/released-client-claim-report.schema.json",
    "spec/sdk-release-attestation.schema.json",
    "spec/sdk-release-attestation-signature.schema.json",
    "spec/sdk-release-publication-bundle.schema.json",
    "spec/sdk-repository-dispatch.schema.json",
    "spec/verified-core-handoff-manifest.schema.json",
    "tsconfig.base.json",
    "tsconfig.json",
    "tsconfig.tools.json",
    "tsconfig.tests.node.json",
    "tsconfig.tests.browser.json",
    "tools-src/exec-tool.ts",
    "dist-tools/exec-tool.js",
    "tests/playwright.config.ts",
    "dist-tests/playwright.config.js",
    ".github/workflows/lint.yml",
    ".github/workflows/verify-core.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/client-claim-promotion.yml",
    ".github/workflows/released-client-readiness.yml",
    ".github/workflows/publication-org-rollout.yml",
    ".github/workflows/managed-provider-evidence.yml",
    ".github/workflows/playwright.yml",
    ".github/actions/setup-nix-ci/action.yml",
    "tests/browser/runtime_web_reference.html",
    "tests/browser/runtime_web_reference_harness.ts",
    "tests/browser/globals.d.ts",
    "tests/browser/runtime_web_reference_server.ts",
    "tests/browser/runtime_web_browser_smoke_test.ts",
    "tests/node/admin_sdk_evidence_download_test.ts",
    "tests/node/aegaeon_provider_local_e2e_test.ts",
    "tests/node/managed_provider_evidence_download_test.ts",
    "tests/node/managed_provider_evidence_import_test.ts",
    "tests/node/branch_protection_policy_test.ts",
    "tests/node/external_boundary_naming_policy_test.ts",
    "tests/node/repository_settings_policy_test.ts",
    "tests/node/hosted_evidence_sources_test.ts",
    "tests/node/release_custody_policy_test.ts",
    "tests/node/managed_provider_evidence_test.ts",
    "tests/node/managed_provider_runner_test.ts",
    "tests/node/managed_provider_config_schema_test.ts",
    "tests/node/managed_provider_readiness_test.ts",
    "tests/node/client_claim_boundary_test.ts",
    "tests/node/client_claim_promotion_test.ts",
    "tests/node/released_client_claim_activation_test.ts",
    "tests/node/released_client_claim_report_test.ts",
    "tests/node/released_client_readiness_test.ts",
    "tests/node/released_client_readiness_artifact_handoff_test.ts",
    "tests/node/real_tenant_readiness_runner_test.ts",
    "tests/node/tool_exec_test.ts",
    "tests/node/workspace_sbom_test.ts",
    "tests/node/release_attestation_test.ts",
    "tests/node/release_attestation_signature_test.ts",
    "tests/node/release_publication_bundle_test.ts",
    "dist-tests/node/admin_sdk_evidence_download_test.js",
    "dist-tests/node/aegaeon_provider_local_e2e_test.js",
    "dist-tests/node/managed_provider_evidence_download_test.js",
    "dist-tests/node/managed_provider_evidence_import_test.js",
    "dist-tests/node/branch_protection_policy_test.js",
    "dist-tests/node/external_boundary_naming_policy_test.js",
    "dist-tests/node/repository_settings_policy_test.js",
    "dist-tests/node/hosted_evidence_sources_test.js",
    "dist-tests/node/release_custody_policy_test.js",
    "dist-tests/node/managed_provider_evidence_test.js",
    "dist-tests/node/managed_provider_runner_test.js",
    "dist-tests/node/managed_provider_config_schema_test.js",
    "dist-tests/node/managed_provider_readiness_test.js",
    "dist-tests/node/client_claim_boundary_test.js",
    "dist-tests/node/client_claim_promotion_test.js",
    "dist-tests/node/released_client_claim_activation_test.js",
    "dist-tests/node/released_client_claim_report_test.js",
    "dist-tests/node/released_client_readiness_test.js",
    "dist-tests/node/released_client_readiness_artifact_handoff_test.js",
    "dist-tests/node/real_tenant_readiness_runner_test.js",
    "dist-tests/node/tool_exec_test.js",
    "dist-tests/node/workspace_sbom_test.js",
    "dist-tests/node/release_attestation_test.js",
    "dist-tests/node/release_attestation_signature_test.js",
    "dist-tests/node/release_publication_bundle_test.js",
    "tests/browser/runtime_web_playwright.spec.ts",
    "tests/browser/external_provider_playwright.spec.ts",
    "tests/browser/issuer_spa_upstream_e2e.html",
    "tests/browser/issuer_spa_upstream_e2e_harness.ts",
    "tests/browser/issuer_spa_external_provider_e2e.html",
    "tests/browser/issuer_spa_external_provider_e2e_harness.ts",
    "tests/providers/dex/docker-compose.yml",
    "tests/providers/dex/dex-config.yaml",
    "tests/providers/run_workspace_pnpm.ts",
    "dist-tests/providers/run_workspace_pnpm.js",
    "tests/providers/dex/run_dex_browser_e2e.ts",
    "dist-tests/providers/dex/run_dex_browser_e2e.js",
    "tests/providers/keycloak/docker-compose.yml",
    "tests/providers/keycloak/keycloak-realm.template.json",
    "tests/providers/keycloak/run_keycloak_browser_e2e.ts",
    "dist-tests/providers/keycloak/run_keycloak_browser_e2e.js",
    "tests/providers/managed/managed-provider.example.json",
    "tests/providers/managed/run_managed_browser_e2e.ts",
    "dist-tests/providers/managed/run_managed_browser_e2e.js",
    "packages/verified-core/package.json",
    "packages/verified-core/tsconfig.json",
    "packages/runtime-node/package.json",
    "packages/runtime-node/tsconfig.json",
    "packages/runtime-node/src/index.ts",
    "packages/runtime-node/src/reference.ts",
    "packages/runtime-node/dist/index.js",
    "packages/runtime-node/dist/reference.js",
    "packages/runtime-web/package.json",
    "packages/runtime-web/tsconfig.json",
    "packages/runtime-web/src/index.ts",
    "packages/runtime-web/src/reference.ts",
    "packages/runtime-web/src/browser-smoke.ts",
    "packages/runtime-web/dist/index.js",
    "packages/runtime-web/dist/reference.js",
    "packages/runtime-web/dist/browser-smoke.js",
    "packages/management-client/package.json",
    "packages/management-client/README.md",
    "packages/management-client/tsconfig.json",
    "packages/management-client/tsconfig.test.json",
    "packages/management-client/src/index.ts",
    "packages/management-client/dist/index.js",
    "packages/management-client/test/management_client_test.ts",
    "packages/management-client/dist-test/management_client_test.js",
    "packages/issuer-spa/package.json",
    "packages/issuer-spa/README.md",
    "packages/issuer-spa/tsconfig.json",
    "packages/issuer-spa/tsconfig.test.json",
    "packages/issuer-spa/src/index.ts",
    "packages/issuer-spa/dist/index.js",
    "packages/issuer-spa/test/issuer_spa_test.ts",
    "packages/issuer-spa/dist-test/issuer_spa_test.js",
    "packages/rp-core/package.json",
    "packages/rp-core/README.md",
    "packages/rp-core/tsconfig.json",
    "packages/rp-core/tsconfig.test.json",
    "packages/rp-core/src/index.ts",
    "packages/rp-core/dist/index.js",
    "packages/rp-core/test/rp_core_test.ts",
    "packages/rp-core/dist-test/rp_core_test.js",
  ]) {
    await assertExists(path.join(outDir, relativePath));
  }

  const rootPackage = JSON.parse(await readFile(path.join(outDir, "package.json"), "utf8"));
  assert.equal(rootPackage.name, "aegaeon-sdk");
  assert.equal(rootPackage.private, true);
  assert.equal(rootPackage.packageManager, "pnpm@9.15.0");
  assert.equal(rootPackage.engines.node, ">=24");
  assert.equal(rootPackage.scripts["build:tools"], "node ./node_modules/typescript/bin/tsc --build tsconfig.tools.json");
  assert.equal(rootPackage.scripts["build:tests:node"], "node ./node_modules/typescript/bin/tsc --project tsconfig.tests.node.json");
  assert.equal(rootPackage.scripts["typecheck:tests:node"], "node ./node_modules/typescript/bin/tsc --project tsconfig.tests.node.json --pretty false --noEmit");
  assert.equal(rootPackage.scripts["fetch-core"], "pnpm run build:tools && node dist-tools/exec-tool.js fetch-core");
  assert.equal(rootPackage.scripts["download-core:release"], "pnpm run build:tools && node dist-tools/exec-tool.js download-core:release");
  assert.equal(rootPackage.scripts["download:admin-sdk-evidence"], "pnpm run build:tools && node dist-tools/exec-tool.js download:admin-sdk-evidence");
  assert.equal(rootPackage.scripts["download:managed-provider-evidence"], "pnpm run build:tools && node dist-tools/exec-tool.js download:managed-provider-evidence");
  assert.equal(rootPackage.scripts["import:managed-provider-evidence"], "pnpm run build:tools && node dist-tools/exec-tool.js import:managed-provider-evidence");
  assert.equal(rootPackage.scripts["run:admin-sdk-evidence"], "pnpm run build:tools && node dist-tools/exec-tool.js run:admin-sdk-evidence");
  assert.equal(rootPackage.scripts["run:managed-provider-evidence"], "pnpm run build:tools && node dist-tools/exec-tool.js run:managed-provider-evidence");
  assert.equal(rootPackage.scripts["run:client-evidence-gates"], "pnpm run build:tools && node dist-tools/exec-tool.js run:client-evidence-gates");
  assert.equal(rootPackage.scripts["run:real-tenant-readiness"], "pnpm run build:tools && node dist-tools/exec-tool.js run:real-tenant-readiness");
  assert.equal(rootPackage.scripts["verify-core"], "pnpm run build:tools && node dist-tools/exec-tool.js verify-core");
  assert.equal(rootPackage.scripts["materialize:sdk-dispatch"], "pnpm run build:tools && node dist-tools/exec-tool.js materialize:sdk-dispatch");
  assert.equal(rootPackage.scripts["export:sdk-dispatch-env"], "pnpm run build:tools && node dist-tools/exec-tool.js export:sdk-dispatch-env");
  assert.equal(rootPackage.scripts["materialize:verified-core-public-key"], "pnpm run build:tools && node dist-tools/exec-tool.js materialize:verified-core-public-key");
  assert.equal(rootPackage.scripts["audit:branch-protection"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:branch-protection");
  assert.equal(rootPackage.scripts["audit:external-boundary-naming"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:external-boundary-naming");
  assert.equal(rootPackage.scripts["audit:hosted-evidence-sources"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:hosted-evidence-sources");
  assert.equal(rootPackage.scripts["audit:repo-settings"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:repo-settings");
  assert.equal(rootPackage.scripts["audit:release-custody"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:release-custody");
  assert.equal(rootPackage.scripts["audit:strict-types"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:strict-types");
  assert.equal(rootPackage.scripts["audit:client-claim-promotion"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:client-claim-promotion");
  assert.equal(rootPackage.scripts["audit:released-client-claim"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:released-client-claim");
  assert.equal(rootPackage.scripts["audit:released-client-readiness"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:released-client-readiness");
  assert.equal(rootPackage.scripts["audit:managed-provider"], "pnpm run build:tools && pnpm run build:tests:browser && node dist-tools/exec-tool.js audit:managed-provider");
  assert.equal(rootPackage.scripts["audit:no-js-source"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:no-js-source");
  assert.equal(rootPackage.scripts["audit:workflow-inventory"], "pnpm run build:tools && node dist-tools/exec-tool.js audit:workflow-inventory");
  assert.equal(rootPackage.scripts["validate:sdk-dispatch"], "python3 scripts/validation/validate_sdk_repository_dispatch_payload.py");
  assert.equal(rootPackage.scripts["validate:core-handoff"], "python3 scripts/validation/validate_verified_core_handoff_manifest.py");
  assert.equal(rootPackage.scripts["validate:managed-provider-config"], "python3 scripts/validation/validate_managed_external_provider_config.py");
  assert.equal(rootPackage.scripts["validate:managed-provider-evidence"], "python3 scripts/validation/validate_managed_provider_evidence.py");
  assert.equal(rootPackage.scripts["validate:client-claim-boundary"], "python3 scripts/validation/validate_client_claim_boundary.py spec/client-claim-boundary.current.json");
  assert.equal(rootPackage.scripts["validate:client-claim-promotion"], "python3 scripts/validation/validate_client_claim_promotion.py spec/client-claim-promotion.current.json");
  assert.equal(rootPackage.scripts["validate:released-client-claim"], "python3 scripts/validation/validate_released_client_claim.py spec/released-client-claim.current.json");
  assert.equal(rootPackage.scripts["validate:release-attestation"], "python3 scripts/validation/validate_sdk_release_attestation.py .artifacts/release/release-attestation.json");
  assert.equal(rootPackage.scripts["validate:release-attestation-signature"], "pnpm run build:tools && node dist-tools/exec-tool.js validate:release-attestation-signature");
  assert.equal(rootPackage.scripts["validate:released-client-claim-report"], "python3 scripts/validation/validate_released_client_claim_report.py .artifacts/release/released-client-claim-report.json");
  assert.equal(rootPackage.scripts["validate:release-publication-bundle"], "python3 scripts/validation/validate_sdk_release_publication_bundle.py .artifacts/release/release-publication-bundle.json");
  assert.equal(rootPackage.scripts["build:managed-provider-evidence"], "pnpm run build:tools && node dist-tools/exec-tool.js build:managed-provider-evidence");
  assert.equal(rootPackage.scripts["release:manifest"], "pnpm run build:tools && node dist-tools/exec-tool.js release:manifest");
  assert.equal(rootPackage.scripts["release:sbom"], "pnpm run build:tools && node dist-tools/exec-tool.js release:sbom");
  assert.equal(rootPackage.scripts["release:attestation"], "pnpm run build:tools && node dist-tools/exec-tool.js release:attestation");
  assert.equal(rootPackage.scripts["release:client-claim-report"], "pnpm run build:tools && node dist-tools/exec-tool.js release:client-claim-report");
  assert.equal(rootPackage.scripts["release:publication-org-rollout-report"], "pnpm run build:tools && node dist-tools/exec-tool.js release:publication-org-rollout-report");
  assert.equal(rootPackage.scripts["release:hosted-readiness-report"], "pnpm run build:tools && node dist-tools/exec-tool.js release:hosted-readiness-report");
  assert.equal(rootPackage.scripts["release:publication-bundle"], "pnpm run build:tools && node dist-tools/exec-tool.js release:publication-bundle");
  assert.equal(rootPackage.scripts["ci:packages"], "pnpm run lint && pnpm run typecheck && pnpm run test && pnpm run build");
  assert.equal(rootPackage.scripts["ci:browser-smoke"], "pnpm run test:browser-smoke");
  assert.equal(rootPackage.scripts["ci"], "pnpm run ci:packages && pnpm run ci:browser-smoke");
  assert.equal(rootPackage.scripts["build:packages"], "pnpm -r --filter './packages/**' --if-present run build");
  assert.equal(rootPackage.scripts.build, "pnpm run build:tools && pnpm run build:tests:node && pnpm run build:tests:browser");
  assert.equal(rootPackage.scripts.lint, "pnpm run build:tools && node ./node_modules/typescript/bin/tsc --build --pretty false tsconfig.json");
  assert.equal(rootPackage.scripts.typecheck, "pnpm run build:tools && node ./node_modules/typescript/bin/tsc --build --pretty false tsconfig.json && pnpm run typecheck:tests:node && pnpm run typecheck:tests:browser");
  assert.equal(rootPackage.scripts["test:repo"], "pnpm run audit:no-js-source && pnpm run audit:strict-types && pnpm run audit:external-boundary-naming && pnpm run audit:workflow-inventory && pnpm run build:tools && pnpm run build:tests:node && pnpm run build:tests:browser && node dist-tests/node/tool_exec_test.js && node dist-tests/node/strict_types_policy_test.js && node dist-tests/node/external_boundary_naming_policy_test.js && node dist-tests/node/branch_protection_policy_test.js && node dist-tests/node/workflow_inventory_policy_test.js && node dist-tests/node/repository_settings_policy_test.js && node dist-tests/node/hosted_evidence_sources_test.js && node dist-tests/node/hosted_evidence_runner_test.js && node dist-tests/node/release_custody_policy_test.js && node dist-tests/node/admin_sdk_evidence_download_test.js && node dist-tests/node/managed_provider_evidence_download_test.js && node dist-tests/node/managed_provider_evidence_import_test.js && node dist-tests/node/managed_provider_runner_test.js && node dist-tests/node/managed_provider_config_schema_test.js && node dist-tests/node/managed_provider_readiness_test.js && node dist-tests/node/managed_provider_evidence_test.js && node dist-tests/node/client_claim_boundary_test.js && node dist-tests/node/client_claim_promotion_test.js && node dist-tests/node/released_client_claim_activation_test.js && node dist-tests/node/released_client_claim_report_test.js && node dist-tests/node/released_client_readiness_test.js && node dist-tests/node/released_client_readiness_artifact_handoff_test.js && node dist-tests/node/real_tenant_readiness_runner_test.js && node dist-tests/node/hosted_release_readiness_report_test.js && node dist-tests/node/workspace_sbom_test.js && node dist-tests/node/release_attestation_test.js && node dist-tests/node/release_attestation_signature_test.js && node dist-tests/node/release_publication_bundle_test.js");
  assert.equal(rootPackage.scripts["test:playwright"], "pnpm run build:tests:browser && playwright test --config dist-tests/playwright.config.js");
  assert.equal(rootPackage.scripts["test:playwright:external-provider"], "pnpm run build:tests:browser && playwright test --config dist-tests/playwright.config.js dist-tests/browser/external_provider_playwright.spec.js");
  assert.equal(rootPackage.scripts["test:provider-dex-browser"], "pnpm run build:tests:browser && node dist-tests/providers/dex/run_dex_browser_e2e.js");
  assert.equal(rootPackage.scripts["test:provider-keycloak-browser"], "pnpm run build:tests:browser && node dist-tests/providers/keycloak/run_keycloak_browser_e2e.js");
  assert.equal(rootPackage.scripts["test:provider-managed-browser"], "pnpm run build:tests:browser && node dist-tests/providers/managed/run_managed_browser_e2e.js");
  assert.equal(rootPackage.scripts["release:version"], "changeset version");
  assert.equal(rootPackage.scripts["release:publish"], "changeset publish");
  assert.equal(rootPackage.scripts["test:browser-smoke"], "pnpm run build:tests:browser && node dist-tests/browser/runtime_web_browser_smoke_test.js --required");
  assert.equal(rootPackage.scripts["test:provider-local"], "pnpm run build:tests:node && node dist-tests/node/aegaeon_provider_local_e2e_test.js");
  assert.equal(rootPackage.scripts["pack:management-client"], "pnpm --dir ./packages/management-client pack --pack-destination ../../");
  assert.equal(rootPackage.scripts["pack:issuer-spa"], "pnpm --dir ./packages/issuer-spa pack --pack-destination ../../");
  assert.equal(rootPackage.scripts["pack:rp-core"], "pnpm --dir ./packages/rp-core pack --pack-destination ../../");
  assert.equal(rootPackage.scripts["pack:verified-core"], "pnpm --dir ./packages/verified-core pack --pack-destination ../../");
  assert.equal(rootPackage.scripts["pack:runtime-node"], "pnpm --dir ./packages/runtime-node pack --pack-destination ../../");
  assert.equal(rootPackage.scripts["pack:runtime-web"], "pnpm --dir ./packages/runtime-web pack --pack-destination ../../");
  assert.match(rootPackage.scripts["pack:workspace"], /pack:management-client/);
  assert.match(rootPackage.scripts["pack:workspace"], /pack:issuer-spa/);
  assert.match(rootPackage.scripts["pack:workspace"], /pack:rp-core/);
  assert.match(rootPackage.scripts.test, /test:repo/);
  assert.equal(rootPackage.devDependencies["@changesets/cli"], "^2.29.6");
  assert.equal(rootPackage.devDependencies["@playwright/test"], "^1.55.0");
  assert.equal(rootPackage.devDependencies["@types/node"], "^24.3.0");
  assert.equal(rootPackage.devDependencies.typescript, "^5.8.2");

  const workspaceYaml = await readFile(path.join(outDir, "pnpm-workspace.yaml"), "utf8");
  assert.match(workspaceYaml, /packages:\n  - packages\/\*/);

  const rootReadme = await readFile(path.join(outDir, "README.md"), "utf8");
  assert.match(rootReadme, /Client claim boundary: `spec\/client-claim-boundary\.current\.json`, validated with `scripts\/validation\/validate_client_claim_boundary\.py`/);
  assert.match(rootReadme, /Client claim promotion gate: `spec\/client-claim-promotion\.current\.json`, audited with `tools-src\/check-client-claim-promotion\.ts` \/ `dist-tools\/check-client-claim-promotion\.js`/);
  assert.match(rootReadme, /Released client claim policy: `spec\/released-client-claim\.current\.json`, validated with `scripts\/validation\/validate_released_client_claim\.py`/);
  assert.match(rootReadme, /Released client claim activation gate: `tools-src\/check-released-client-claim-activation\.ts` \/ `dist-tools\/check-released-client-claim-activation\.js`/);
  assert.match(rootReadme, /Released client readiness gate: `tools-src\/check-released-client-readiness\.ts` \/ `dist-tools\/check-released-client-readiness\.js`/);
  assert.match(rootReadme, /Strict types policy: `spec\/strict-types\.current\.json`, audited with `tools-src\/check-strict-types\.ts` \/ `dist-tools\/check-strict-types\.js`/);
  assert.match(rootReadme, /External-boundary naming policy: `spec\/external-boundary-naming\.current\.json`, audited with `tools-src\/check-external-boundary-naming\.ts` \/ `dist-tools\/check-external-boundary-naming\.js`/);
  assert.match(rootReadme, /Repository settings policy: `spec\/repository-settings\.current\.json`, audited with `tools-src\/check-repository-settings\.ts` \/ `dist-tools\/check-repository-settings\.js`/);
  assert.match(rootReadme, /Release custody policy: `spec\/release-custody\.current\.json`, audited with `tools-src\/check-release-custody\.ts` \/ `dist-tools\/check-release-custody\.js`/);
  assert.match(rootReadme, /Workflow inventory policy: `spec\/workflow-inventory\.current\.json`, audited with `tools-src\/check-workflow-inventory\.ts` \/ `dist-tools\/check-workflow-inventory\.js`/);
  assert.match(rootReadme, /Hosted evidence source policy: `spec\/hosted-evidence-sources\.current\.json`, audited with `tools-src\/check-hosted-evidence-sources\.ts` \/ `dist-tools\/check-hosted-evidence-sources\.js`/);
  assert.match(rootReadme, /Managed-provider evidence schema: `spec\/managed-provider-evidence\.schema\.json`, built with `tools-src\/build-managed-provider-evidence\.ts` \/ `dist-tools\/build-managed-provider-evidence\.js` and validated with `scripts\/validation\/validate_managed_provider_evidence\.py`/);
  assert.match(rootReadme, /Admin-console evidence ingestion helper: `tools-src\/download-admin-sdk-evidence\.ts` \/ `dist-tools\/download-admin-sdk-evidence\.js`/);
  assert.match(rootReadme, /Managed-provider evidence ingestion helpers: `tools-src\/download-managed-provider-evidence\.ts` \/ `dist-tools\/download-managed-provider-evidence\.js` and `tools-src\/import-managed-provider-evidence\.ts` \/ `dist-tools\/import-managed-provider-evidence\.js`/);
  assert.match(rootReadme, /One-shot client evidence gate runner: `tools-src\/run-client-evidence-gates\.ts` \/ `dist-tools\/run-client-evidence-gates\.js`/);
  assert.match(rootReadme, /Hosted evidence runner: `tools-src\/run-hosted-evidence\.ts` \/ `dist-tools\/run-hosted-evidence\.js`/);
  assert.match(rootReadme, /Managed-provider readiness audit: `tools-src\/check-managed-provider-readiness\.ts` \/ `dist-tools\/check-managed-provider-readiness\.js`/);
  assert.match(rootReadme, /Release attestation scaffold: `spec\/sdk-release-attestation\.schema\.json`, `spec\/sdk-release-attestation-signature\.schema\.json`, `tools-src\/build-release-attestation\.ts`, `tools-src\/check-release-attestation-signature\.ts`, `scripts\/validation\/validate_sdk_release_attestation\.py`, `scripts\/validation\/validate_sdk_release_attestation_signature\.py`/);
  assert.match(rootReadme, /Release publication bundle: `spec\/sdk-release-publication-bundle\.schema\.json`, `tools-src\/build-workspace-sbom\.ts`, `tools-src\/check-client-claim-promotion\.ts`, `tools-src\/build-released-client-claim-report\.ts`, `tools-src\/check-released-client-readiness\.ts`, `tools-src\/build-release-publication-bundle\.ts`, `scripts\/validation\/validate_released_client_claim_report\.py`, `scripts\/validation\/validate_sdk_release_publication_bundle\.py`/);
  assert.match(rootReadme, /Release scaffolding: `\.changeset\/config\.json`, `tsconfig\.base\.json`, `tsconfig\.json`, `tsconfig\.tools\.json`, `tsconfig\.tests\.node\.json`, `tsconfig\.tests\.browser\.json`, `tools-src\/\*\.ts`, preseeded `dist-tools\/\*\.js`, preseeded `dist-tests\/node\/\*\.js`, browser\/support TypeScript tests under `tests\/browser\/\*\.ts` and `tests\/providers\/\*\*\/\*\.ts`, and workflow stubs under `\.github\/workflows\/`/);
  assert.match(rootReadme, /publication-org-rollout\.yml/);
  assert.match(rootReadme, /Repository cutover checklist: `MIGRATION\.md`/);
  assert.match(rootReadme, /validate `spec\/client-claim-boundary\.current\.json` with `pnpm run validate:client-claim-boundary` and keep `spec\/released-client-claim\.current\.json` aligned with the intended released wording/);
  assert.match(rootReadme, /Read `MIGRATION\.md`, review `spec\/external-boundary-naming\.current\.json`, `spec\/repository-settings\.current\.json`, `spec\/release-custody\.current\.json`, `spec\/workflow-inventory\.current\.json`, `spec\/hosted-evidence-sources\.current\.json`, `spec\/client-claim-promotion\.current\.json`, and `spec\/released-client-claim\.current\.json`, validate managed-provider configs against `spec\/managed-external-provider\.schema\.json`, run `pnpm run audit:external-boundary-naming` before any external-boundary rename, run `pnpm run audit:managed-provider -- --config tests\/providers\/managed\/managed-provider\.example\.json` before the first tenant-backed lane, run `pnpm run audit:hosted-evidence-sources` before wiring hosted evidence sources/);
  assert.match(rootReadme, /Branch-protection policy: `spec\/branch-protection\.main\.json`, audited with `tools-src\/check-branch-protection\.ts` \/ `dist-tools\/check-branch-protection\.js`/);
  assert.match(rootReadme, /Managed-provider config contract: `spec\/managed-external-provider\.schema\.json`, validated with `scripts\/validation\/validate_managed_external_provider_config\.py`/);
  assert.match(rootReadme, /`@aegaeon\/management-client` \(alpha\)/);
  assert.match(rootReadme, /`@aegaeon\/issuer-spa` \(alpha\)/);
  assert.match(rootReadme, /`@aegaeon\/rp-core` \(alpha\)/);
  assert.match(rootReadme, /audit:managed-provider/);
  assert.match(rootReadme, /test:provider-managed-browser/);
  assert.match(rootReadme, /run `pnpm run run:client-evidence-gates -- --mode readiness --claim-active .*` before widening released client wording/);

  const migrationChecklist = await readFile(path.join(outDir, "MIGRATION.md"), "utf8");
  assert.match(migrationChecklist, /AEGAEON_VERIFIED_CORE_PUBKEY/);
  assert.match(migrationChecklist, /AEGAEON_SDK_REPOSITORY_DISPATCH_TOKEN/);
  assert.match(migrationChecklist, /AEGAEON_CORE_RELEASE_REPO/);
  assert.match(migrationChecklist, /optional `AEGAEON_NPM_DIST_TAG`/);
  assert.match(migrationChecklist, /AEGAEON_ADMIN_CONSOLE_REPOSITORY/);
  assert.match(migrationChecklist, /AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW/);
  assert.match(migrationChecklist, /AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT/);
  assert.match(migrationChecklist, /AEGAEON_PUBLICATION_ORG_OWNER/);
  assert.match(migrationChecklist, /AEGAEON_PUBLICATION_ORG_REPO/);
  assert.match(migrationChecklist, /AEGAEON_PUBLICATION_ORG_BRANCH/);
  assert.match(migrationChecklist, /AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED/);
  assert.match(migrationChecklist, /AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON/);
  assert.match(migrationChecklist, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY/);
  assert.match(migrationChecklist, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW/);
  assert.match(migrationChecklist, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON/);
  assert.match(migrationChecklist, /import:managed-provider-evidence/);
  assert.match(migrationChecklist, /spec\/managed-external-provider\.schema\.json/);
  assert.match(migrationChecklist, /spec\/release-custody\.current\.json/);
  assert.match(migrationChecklist, /spec\/hosted-evidence-sources\.current\.json/);
  assert.match(migrationChecklist, /spec\/managed-provider-evidence\.schema\.json/);
  assert.match(migrationChecklist, /spec\/client-claim-boundary\.current\.json/);
  assert.match(migrationChecklist, /spec\/client-claim-promotion\.current\.json/);
  assert.match(migrationChecklist, /spec\/released-client-claim\.current\.json/);
  assert.match(migrationChecklist, /validate:managed-provider-config/);
  assert.match(migrationChecklist, /validate:client-claim-boundary/);
  assert.match(migrationChecklist, /validate:released-client-claim/);
  assert.match(migrationChecklist, /validate:managed-provider-evidence/);
  assert.match(migrationChecklist, /download:managed-provider-evidence -- --artifact-dir <managed-provider-evidence-dir>/);
  assert.match(migrationChecklist, /audit:managed-provider -- --config tests\/providers\/managed\/managed-provider\.example\.json/);
  assert.match(migrationChecklist, /audit:hosted-evidence-sources/);
  assert.match(migrationChecklist, /run:client-evidence-gates -- --mode readiness --claim-active/);
  assert.match(migrationChecklist, /AEGAEON_CARGO_REGISTRY_TOKEN/);
  assert.match(migrationChecklist, /AEGAEON_COSIGN_KEY/);
  assert.match(migrationChecklist, /pnpm run audit:repo-settings -- --owner <owner> --repo aegaeon-sdk/);
  assert.match(migrationChecklist, /pnpm run audit:release-custody -- --owner <owner> --repo aegaeon-sdk/);
  assert.match(migrationChecklist, /CI - Lint \/ Lint/);
  assert.match(migrationChecklist, /CI - Lint \/ TypeScript Lint/);
  assert.match(migrationChecklist, /SDK Verify Core \/ Verify Core/);
  assert.match(migrationChecklist, /CI - SDK \/ Browser Smoke/);
  assert.match(migrationChecklist, /SDK Browser E2E \/ Core Playwright/);
  assert.match(migrationChecklist, /SDK Browser E2E \/ External Provider \(Dex\)/);
  assert.match(migrationChecklist, /SDK Browser E2E \/ External Provider \(Keycloak\)/);
  assert.match(migrationChecklist, /external-provider-managed/);
  assert.match(migrationChecklist, /pnpm run audit:branch-protection -- --owner <owner> --repo aegaeon-sdk/);
  assert.match(migrationChecklist, /reports a match/);
  assert.match(migrationChecklist, /pnpm run test:playwright/);
  assert.match(migrationChecklist, /pnpm run test:provider-keycloak-browser -- --required/);
  assert.match(migrationChecklist, /pnpm run test:provider-managed-browser/);
  assert.match(migrationChecklist, /pnpm run release:sbom/);
  assert.match(migrationChecklist, /pnpm run release:attestation/);
  assert.match(migrationChecklist, /pnpm run run:client-evidence-gates -- --mode readiness --claim-active/);
  assert.match(migrationChecklist, /pnpm run validate:release-attestation/);
  assert.match(migrationChecklist, /pnpm run validate:release-attestation-signature/);
  assert.match(migrationChecklist, /the backend and SDK repositories agree on the latest `spec\/client-claim-boundary\.current\.json`/);
  assert.match(migrationChecklist, /release-attestation\.json/);
  assert.match(migrationChecklist, /release-publication-bundle\.json/);

  const npmrc = await readFile(path.join(outDir, ".npmrc"), "utf8");
  assert.match(npmrc, /engine-strict=true/);
  assert.match(npmrc, /prefer-workspace-packages=true/);

  const gitignore = await readFile(path.join(outDir, ".gitignore"), "utf8");
  assert.match(gitignore, /^\*\.tgz$/m);
  assert.match(gitignore, /^\.artifacts\/$/m);

  const changesetConfig = JSON.parse(await readFile(path.join(outDir, ".changeset", "config.json"), "utf8"));
  assert.equal(changesetConfig.access, "public");
  assert.equal(changesetConfig.baseBranch, "main");
  assert.equal(changesetConfig.changelog, "@changesets/cli/changelog");

  const runtimeNodePackage = JSON.parse(await readFile(path.join(outDir, "packages", "runtime-node", "package.json"), "utf8"));
  const runtimeWebPackage = JSON.parse(await readFile(path.join(outDir, "packages", "runtime-web", "package.json"), "utf8"));
  const verifiedCorePackage = JSON.parse(await readFile(path.join(outDir, "packages", "verified-core", "package.json"), "utf8"));
  const managementClientPackage = JSON.parse(await readFile(path.join(outDir, "packages", "management-client", "package.json"), "utf8"));
  const issuerSpaPackage = JSON.parse(await readFile(path.join(outDir, "packages", "issuer-spa", "package.json"), "utf8"));
  const rpCorePackage = JSON.parse(await readFile(path.join(outDir, "packages", "rp-core", "package.json"), "utf8"));
  assert.equal(runtimeNodePackage.name, "@aegaeon/runtime-node");
  assert.equal(runtimeWebPackage.name, "@aegaeon/runtime-web");
  assert.equal(managementClientPackage.name, "@aegaeon/management-client");
  assert.equal(issuerSpaPackage.name, "@aegaeon/issuer-spa");
  assert.equal(rpCorePackage.name, "@aegaeon/rp-core");
  assert.equal(verifiedCorePackage.scripts.typecheck, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit");
  assert.equal(runtimeNodePackage.scripts.typecheck, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit");
  assert.equal(runtimeWebPackage.scripts.typecheck, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit");
  assert.equal(managementClientPackage.scripts.typecheck, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit");
  assert.equal(issuerSpaPackage.scripts.typecheck, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit");
  assert.equal(issuerSpaPackage.scripts.build, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json");
  assert.equal(issuerSpaPackage.scripts.lint, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit");
  assert.equal(rpCorePackage.scripts.typecheck, "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit");
  assert.equal(runtimeNodePackage.scripts.test, "node --input-type=module -e \"await import('./dist/index.js'); await import('./dist/reference.js');\"");
  assert.equal(runtimeWebPackage.scripts.test, "node --input-type=module -e \"await import('./dist/index.js'); await import('./dist/reference.js'); await import('./dist/browser-smoke.js');\"");
  assert.equal(managementClientPackage.scripts["build:test"], "node ../../node_modules/typescript/bin/tsc --project tsconfig.test.json");
  assert.equal(issuerSpaPackage.scripts["build:test"], "node ../../node_modules/typescript/bin/tsc --project tsconfig.test.json");
  assert.equal(rpCorePackage.scripts["build:test"], "node ../../node_modules/typescript/bin/tsc --project tsconfig.test.json");
  assert.equal(managementClientPackage.scripts.test, "pnpm run build && pnpm run build:test && node dist-test/management_client_test.js");
  assert.equal(issuerSpaPackage.scripts.test, "pnpm run build && pnpm run build:test && node dist-test/issuer_spa_test.js");
  assert.equal(rpCorePackage.scripts.test, "pnpm run build && pnpm run build:test && node dist-test/rp_core_test.js");
  assert.equal(runtimeNodePackage.publishConfig.access, "public");
  assert.equal(runtimeWebPackage.publishConfig.access, "public");
  assert.equal(managementClientPackage.publishConfig.access, "public");
  assert.equal(issuerSpaPackage.publishConfig.access, "public");
  assert.equal(rpCorePackage.publishConfig.access, "public");
  assert.equal(runtimeNodePackage.dependencies["@aegaeon/verified-core"], "workspace:*");
  assert.equal(runtimeWebPackage.dependencies["@aegaeon/verified-core"], "workspace:*");
  assert.equal(issuerSpaPackage.dependencies["@aegaeon/runtime-web"], "workspace:*");
  assert.equal(issuerSpaPackage.dependencies["@aegaeon/rp-core"], "workspace:*");
  assert.equal(rpCorePackage.dependencies, undefined);

  const runtimeNodeIndex = await readFile(path.join(outDir, "packages", "runtime-node", "dist", "index.js"), "utf8");
  assert.match(runtimeNodeIndex, /CLIENT_CRYPTO_PROFILES/);
  assert.match(runtimeNodeIndex, /DEFAULT_CLIENT_CRYPTO_PROFILE/);
  assert.match(runtimeNodeIndex, /resolveJwtAllowedAlgorithmsBitmaskForProfile/);
  assert.match(runtimeNodeIndex, /resolveDpopAllowedAlgorithmsBitmaskForProfile/);

  const runtimeWebIndex = await readFile(path.join(outDir, "packages", "runtime-web", "dist", "index.js"), "utf8");
  assert.match(runtimeWebIndex, /CLIENT_CRYPTO_PROFILES/);
  assert.match(runtimeWebIndex, /DEFAULT_CLIENT_CRYPTO_PROFILE/);
  assert.match(runtimeWebIndex, /resolveJwtAllowedAlgorithmsBitmaskForProfile/);
  assert.match(runtimeWebIndex, /resolveDpopAllowedAlgorithmsBitmaskForProfile/);

  const runtimeWebBrowserSmoke = await readFile(path.join(outDir, "packages", "runtime-web", "dist", "browser-smoke.js"), "utf8");
  assert.match(runtimeWebBrowserSmoke, /\.\.\/\.\.\/verified-core\/dist\/web\.js/);

  const runtimeNodeReadme = await readFile(path.join(outDir, "packages", "runtime-node", "README.md"), "utf8");
  assert.match(runtimeNodeReadme, /aegaeon-rs256/);
  assert.match(runtimeNodeReadme, /compat-interop/);
  const managementClientReadme = await readFile(path.join(outDir, "packages", "management-client", "README.md"), "utf8");
  assert.match(managementClientReadme, /Alpha management-plane SDK/i);
  assert.match(managementClientReadme, /automatic `teamId` path insertion/);
  const issuerSpaReadme = await readFile(path.join(outDir, "packages", "issuer-spa", "README.md"), "utf8");
  assert.match(issuerSpaReadme, /browser-facing login orchestration helpers/i);
  assert.match(issuerSpaReadme, /persist Authorization Code \+ PKCE transactions/);
  const rpCoreReadme = await readFile(path.join(outDir, "packages", "rp-core", "README.md"), "utf8");
  assert.match(rpCoreReadme, /Authorization Code \+ PKCE/);
  assert.match(rpCoreReadme, /Use `@aegaeon\/runtime-web` or `@aegaeon\/runtime-node`/);

  const downloadCoreReleaseScript = await readFile(path.join(outDir, "tools-src", "download-core-release.ts"), "utf8");
  assert.match(downloadCoreReleaseScript, /verified-core-handoff-manifest\.json/);
  assert.match(downloadCoreReleaseScript, /\[download-core-release\] handoff manifest:/);
  assert.match(downloadCoreReleaseScript, /token === "--"/);
  const downloadAdminSdkEvidenceScript = await readFile(path.join(outDir, "tools-src", "download-admin-sdk-evidence.ts"), "utf8");
  assert.match(downloadAdminSdkEvidenceScript, /\[download-admin-sdk-evidence\] wrote/);
  assert.match(downloadAdminSdkEvidenceScript, /admin-sdk-evidence/);
  assert.match(downloadAdminSdkEvidenceScript, /"gh",\s*\[/);
  const runClientEvidenceGatesScript = await readFile(path.join(outDir, "tools-src", "run-client-evidence-gates.ts"), "utf8");
  assert.match(runClientEvidenceGatesScript, /\[client-evidence-gates\] promotion report:/);
  assert.match(runClientEvidenceGatesScript, /--dispatch-hosted/);

  const verifyCoreScript = await readFile(path.join(outDir, "tools-src", "verify-core.ts"), "utf8");
  assert.match(verifyCoreScript, /token === "--"/);

  const publishManifestScript = await readFile(path.join(outDir, "tools-src", "build-publish-manifest.ts"), "utf8");
  assert.match(publishManifestScript, /workspace:/);
  assert.match(publishManifestScript, /No tarballs found at workspace root/);
  const workspaceSbomScript = await readFile(path.join(outDir, "tools-src", "build-workspace-sbom.ts"), "utf8");
  assert.match(workspaceSbomScript, /CycloneDX/);
  assert.match(workspaceSbomScript, /sdk-workspace-sbom\.cdx\.json/);
  const releaseAttestationScript = await readFile(path.join(outDir, "tools-src", "build-release-attestation.ts"), "utf8");
  assert.match(releaseAttestationScript, /released_client_claim_active/);
  assert.match(releaseAttestationScript, /published_sdk_sboms/);
  assert.match(releaseAttestationScript, /release-attestation\.json/);
  assert.match(releaseAttestationScript, /release-attestation\.signature\.json/);
  const releaseAttestationSignatureScript = await readFile(
    path.join(outDir, "tools-src", "check-release-attestation-signature.ts"),
    "utf8",
  );
  assert.match(releaseAttestationSignatureScript, /release-attestation\.signature\.json/);
  const releasePublicationBundleScript = await readFile(path.join(outDir, "tools-src", "build-release-publication-bundle.ts"), "utf8");
  assert.match(releasePublicationBundleScript, /release-publication-bundle/);
  assert.match(releasePublicationBundleScript, /sdk-workspace-sbom\.cdx\.json/);
  assert.match(releasePublicationBundleScript, /client-claim-promotion-report\.json/);
  const branchProtectionScript = await readFile(path.join(outDir, "tools-src", "check-branch-protection.ts"), "utf8");
  assert.match(branchProtectionScript, /Accept: application\/vnd\.github\+json/);
  assert.match(branchProtectionScript, /required_checks mismatch/);
  const repositorySettingsScript = await readFile(path.join(outDir, "tools-src", "check-repository-settings.ts"), "utf8");
  assert.match(repositorySettingsScript, /actions\/secrets/);
  assert.match(repositorySettingsScript, /actions\/variables/);
  assert.match(repositorySettingsScript, /required secret set/);
  assert.match(repositorySettingsScript, /optional secret set/);
  const releaseCustodyScript = await readFile(path.join(outDir, "tools-src", "check-release-custody.ts"), "utf8");
  assert.match(releaseCustodyScript, /release-custody/);
  assert.match(releaseCustodyScript, /actions\/secrets/);
  assert.match(releaseCustodyScript, /actions\/variables/);
  const clientClaimPromotionScript = await readFile(path.join(outDir, "tools-src", "check-client-claim-promotion.ts"), "utf8");
  assert.match(clientClaimPromotionScript, /client-claim-promotion/);
  assert.match(clientClaimPromotionScript, /required lane/);
  const managedProviderEvidenceScript = await readFile(path.join(outDir, "tools-src", "build-managed-provider-evidence.ts"), "utf8");
  assert.match(managedProviderEvidenceScript, /build-managed-provider-evidence/);
  assert.match(managedProviderEvidenceScript, /managed-provider-evidence\.json/);
  const managedProviderReadinessScript = await readFile(path.join(outDir, "tools-src", "check-managed-provider-readiness.ts"), "utf8");
  assert.match(managedProviderReadinessScript, /--require-browser/);
  assert.match(managedProviderReadinessScript, /managed provider client secret/);
  assert.match(managedProviderReadinessScript, /checks passed/);

  const verifyCoreWorkflow = await readFile(path.join(outDir, ".github", "workflows", "verify-core.yml"), "utf8");
  assert.match(verifyCoreWorkflow, /name: SDK Verify Core/);
  assert.match(verifyCoreWorkflow, /repository_dispatch/);
  assert.match(verifyCoreWorkflow, /core_release_tag/);
  assert.match(verifyCoreWorkflow, /sdk-repository-dispatch\.json/);
  assert.match(verifyCoreWorkflow, /pnpm run materialize:sdk-dispatch/);
  assert.match(verifyCoreWorkflow, /pnpm run validate:sdk-dispatch -- \.cache\/sdk-repository-dispatch\.json/);
  assert.match(
    verifyCoreWorkflow,
    /pnpm run export:sdk-dispatch-env -- --payload \.cache\/sdk-repository-dispatch\.json' >> "\$GITHUB_ENV"/,
  );
  assert.match(verifyCoreWorkflow, /pnpm run materialize:verified-core-public-key/);
  assert.match(verifyCoreWorkflow, /Require public key when signature is present/);
  assert.match(verifyCoreWorkflow, /AEGAEON_VERIFIED_CORE_PUBKEY/);
  assert.match(verifyCoreWorkflow, /AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF/);
  assert.match(verifyCoreWorkflow, /AEGAEON_OP_SERVICE_ACCOUNT_TOKEN/);
  assert.match(verifyCoreWorkflow, /pnpm run download-core:release/);
  assert.match(verifyCoreWorkflow, /pnpm run verify-core/);
  assert.match(verifyCoreWorkflow, /AEGAEON_CORE_RELEASE_REPO/);
  assert.match(verifyCoreWorkflow, /AEGAEON_CORE_MANIFEST_PATH/);
  assert.match(verifyCoreWorkflow, /AEGAEON_CORE_HANDOFF_MANIFEST_PATH/);
  assert.match(verifyCoreWorkflow, /pnpm run validate:core-handoff -- "\$AEGAEON_CORE_HANDOFF_MANIFEST_PATH"/);
  assert.match(verifyCoreWorkflow, /actions\/upload-artifact@v4/);
  assert.match(verifyCoreWorkflow, /verified-core-handoff/);
  assert.match(verifyCoreWorkflow, /packages\/verified-core\/dist/);

  const rootSchema = await readFile(path.join(ROOT_DIR, "spec", "sdk-repository-dispatch.schema.json"), "utf8");
  const scaffoldSchema = await readFile(path.join(outDir, "spec", "sdk-repository-dispatch.schema.json"), "utf8");
  assert.equal(scaffoldSchema, rootSchema);
  const rootManagedSchema = await readFile(path.join(ROOT_DIR, "spec", "managed-external-provider.schema.json"), "utf8");
  const scaffoldManagedSchema = await readFile(path.join(outDir, "spec", "managed-external-provider.schema.json"), "utf8");
  assert.equal(scaffoldManagedSchema, rootManagedSchema);
  const rootClientClaimBoundarySchema = await readFile(path.join(ROOT_DIR, "spec", "client-claim-boundary.schema.json"), "utf8");
  const scaffoldClientClaimBoundarySchema = await readFile(path.join(outDir, "spec", "client-claim-boundary.schema.json"), "utf8");
  assert.equal(scaffoldClientClaimBoundarySchema, rootClientClaimBoundarySchema);
  const rootClientClaimBoundaryCurrent = await readFile(path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json"), "utf8");
  const scaffoldClientClaimBoundaryCurrent = await readFile(path.join(outDir, "spec", "client-claim-boundary.current.json"), "utf8");
  assert.equal(scaffoldClientClaimBoundaryCurrent, rootClientClaimBoundaryCurrent);
  const rootClientClaimPromotionSchema = await readFile(path.join(ROOT_DIR, "spec", "client-claim-promotion.schema.json"), "utf8");
  const scaffoldClientClaimPromotionSchema = await readFile(path.join(outDir, "spec", "client-claim-promotion.schema.json"), "utf8");
  assert.equal(scaffoldClientClaimPromotionSchema, rootClientClaimPromotionSchema);
  const rootClientClaimPromotionCurrent = await readFile(path.join(ROOT_DIR, "spec", "client-claim-promotion.current.json"), "utf8");
  const scaffoldClientClaimPromotionCurrent = await readFile(path.join(outDir, "spec", "client-claim-promotion.current.json"), "utf8");
  assert.equal(scaffoldClientClaimPromotionCurrent, rootClientClaimPromotionCurrent);
  const rootStrictTypesPolicy = await readFile(path.join(ROOT_DIR, "spec", "strict-types.current.json"), "utf8");
  const scaffoldStrictTypesPolicy = await readFile(path.join(outDir, "spec", "strict-types.current.json"), "utf8");
  assert.equal(scaffoldStrictTypesPolicy, rootStrictTypesPolicy);
  const rootManagedProviderEvidenceSchema = await readFile(path.join(ROOT_DIR, "spec", "managed-provider-evidence.schema.json"), "utf8");
  const scaffoldManagedProviderEvidenceSchema = await readFile(path.join(outDir, "spec", "managed-provider-evidence.schema.json"), "utf8");
  assert.equal(scaffoldManagedProviderEvidenceSchema, rootManagedProviderEvidenceSchema);
  const rootExternalBoundaryNamingPolicy = await readFile(path.join(ROOT_DIR, "spec", "external-boundary-naming.current.json"), "utf8");
  const scaffoldExternalBoundaryNamingPolicy = await readFile(path.join(outDir, "spec", "external-boundary-naming.current.json"), "utf8");
  assert.equal(scaffoldExternalBoundaryNamingPolicy, rootExternalBoundaryNamingPolicy);
  const rootBranchProtectionPolicy = await readFile(path.join(ROOT_DIR, "scripts", "sdk", "sdk_branch_protection.main.json"), "utf8");
  const scaffoldBranchProtectionPolicy = await readFile(path.join(outDir, "spec", "branch-protection.main.json"), "utf8");
  assert.equal(scaffoldBranchProtectionPolicy, rootBranchProtectionPolicy);
  const rootRepositorySettingsPolicy = await readFile(path.join(ROOT_DIR, "scripts", "sdk", "sdk_repository_settings.current.json"), "utf8");
  const scaffoldRepositorySettingsPolicy = await readFile(path.join(outDir, "spec", "repository-settings.current.json"), "utf8");
  assert.equal(scaffoldRepositorySettingsPolicy, rootRepositorySettingsPolicy);
  assert.match(scaffoldRepositorySettingsPolicy, /AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED/);
  assert.match(scaffoldRepositorySettingsPolicy, /managed_external_provider_login/);
  assert.match(scaffoldRepositorySettingsPolicy, /AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT/);
  assert.match(scaffoldRepositorySettingsPolicy, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY/);
  assert.match(scaffoldRepositorySettingsPolicy, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON/);
  assert.match(scaffoldRepositorySettingsPolicy, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN/);
  const rootHostedEvidenceSourcesPolicy = await readFile(path.join(ROOT_DIR, "scripts", "sdk", "sdk_hosted_evidence_sources.current.json"), "utf8");
  const scaffoldHostedEvidenceSourcesPolicy = await readFile(path.join(outDir, "spec", "hosted-evidence-sources.current.json"), "utf8");
  assert.equal(scaffoldHostedEvidenceSourcesPolicy, rootHostedEvidenceSourcesPolicy);
  assert.match(scaffoldHostedEvidenceSourcesPolicy, /AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT/);
  assert.match(scaffoldHostedEvidenceSourcesPolicy, /managed-provider-evidence\.yml/);
  const rootReleaseCustodyPolicy = await readFile(path.join(ROOT_DIR, "scripts", "sdk", "sdk_release_custody.current.json"), "utf8");
  const scaffoldReleaseCustodyPolicy = await readFile(path.join(outDir, "spec", "release-custody.current.json"), "utf8");
  assert.equal(scaffoldReleaseCustodyPolicy, rootReleaseCustodyPolicy);
  assert.match(scaffoldReleaseCustodyPolicy, /AEGAEON_REAL_PUBLISH_ENABLED/);
  assert.match(scaffoldReleaseCustodyPolicy, /AEGAEON_COSIGN_KEY/);
  const rootHandoffSchema = await readFile(path.join(ROOT_DIR, "spec", "verified-core-handoff-manifest.schema.json"), "utf8");
  const scaffoldHandoffSchema = await readFile(path.join(outDir, "spec", "verified-core-handoff-manifest.schema.json"), "utf8");
  assert.equal(scaffoldHandoffSchema, rootHandoffSchema);
  const rootReleaseAttestationSchema = await readFile(path.join(ROOT_DIR, "spec", "sdk-release-attestation.schema.json"), "utf8");
  const scaffoldReleaseAttestationSchema = await readFile(path.join(outDir, "spec", "sdk-release-attestation.schema.json"), "utf8");
  assert.equal(scaffoldReleaseAttestationSchema, rootReleaseAttestationSchema);
  const rootReleaseAttestationSignatureSchema = await readFile(
    path.join(ROOT_DIR, "spec", "sdk-release-attestation-signature.schema.json"),
    "utf8",
  );
  const scaffoldReleaseAttestationSignatureSchema = await readFile(
    path.join(outDir, "spec", "sdk-release-attestation-signature.schema.json"),
    "utf8",
  );
  assert.equal(scaffoldReleaseAttestationSignatureSchema, rootReleaseAttestationSignatureSchema);
  const rootReleasePublicationBundleSchema = await readFile(path.join(ROOT_DIR, "spec", "sdk-release-publication-bundle.schema.json"), "utf8");
  const scaffoldReleasePublicationBundleSchema = await readFile(path.join(outDir, "spec", "sdk-release-publication-bundle.schema.json"), "utf8");
  assert.equal(scaffoldReleasePublicationBundleSchema, rootReleasePublicationBundleSchema);
  const scaffoldNodeTestsTsconfig = JSON.parse(await readFile(path.join(outDir, "tsconfig.tests.node.json"), "utf8"));
  assert.equal(scaffoldNodeTestsTsconfig.compilerOptions.strict, true);
  assert.equal(scaffoldNodeTestsTsconfig.compilerOptions.strictNullChecks, true);
  assert.equal(scaffoldNodeTestsTsconfig.compilerOptions.exactOptionalPropertyTypes, true);
  assert.equal(scaffoldNodeTestsTsconfig.compilerOptions.noUncheckedIndexedAccess, true);
  assert.equal(scaffoldNodeTestsTsconfig.compilerOptions.noImplicitAny, true);
  assert.equal(scaffoldNodeTestsTsconfig.compilerOptions.useUnknownInCatchVariables, true);
  const scaffoldBrowserTestsTsconfig = JSON.parse(await readFile(path.join(outDir, "tsconfig.tests.browser.json"), "utf8"));
  assert.equal(scaffoldBrowserTestsTsconfig.compilerOptions.strict, true);
  assert.equal(scaffoldBrowserTestsTsconfig.compilerOptions.strictNullChecks, true);
  assert.equal(scaffoldBrowserTestsTsconfig.compilerOptions.exactOptionalPropertyTypes, true);
  assert.equal(scaffoldBrowserTestsTsconfig.compilerOptions.noUncheckedIndexedAccess, true);
  assert.equal(scaffoldBrowserTestsTsconfig.compilerOptions.noImplicitAny, true);
  assert.equal(scaffoldBrowserTestsTsconfig.compilerOptions.useUnknownInCatchVariables, true);
  const scaffoldRuntimeNodeTsconfig = JSON.parse(
    await readFile(path.join(outDir, "packages", "runtime-node", "tsconfig.json"), "utf8"),
  );
  assert.equal(scaffoldRuntimeNodeTsconfig.compilerOptions.noImplicitAny, true);
  assert.equal(scaffoldRuntimeNodeTsconfig.compilerOptions.useUnknownInCatchVariables, true);

  const ciWorkflow = await readFile(path.join(outDir, ".github", "workflows", "ci.yml"), "utf8");
  assert.match(ciWorkflow, /name: CI - SDK/);
  assert.match(ciWorkflow, /workflow_call/);
  assert.match(ciWorkflow, /browser-smoke:/);
  assert.match(ciWorkflow, /pnpm run ci:packages/);
  assert.match(ciWorkflow, /pnpm run test:browser-smoke -- --artifact-dir \.artifacts\/browser-smoke/);
  assert.match(ciWorkflow, /pnpm run pack:workspace/);
  assert.match(ciWorkflow, /actions\/upload-artifact@v4/);
  assert.match(ciWorkflow, /workspace-packages/);
  assert.match(ciWorkflow, /browser-smoke-diagnostics/);
  assert.match(ciWorkflow, /sdk\/\*\.tgz/);
  assert.match(ciWorkflow, /\.artifacts\/browser-smoke/);

  const lintWorkflow = await readFile(path.join(outDir, ".github", "workflows", "lint.yml"), "utf8");
  assert.match(lintWorkflow, /name: CI - Lint/);
  assert.match(lintWorkflow, /name: Lint/);
  assert.match(lintWorkflow, /name: TypeScript Lint/);
  assert.match(lintWorkflow, /pnpm run audit:workflow-inventory/);
  assert.match(lintWorkflow, /pnpm run audit:strict-types/);

  const publishWorkflow = await readFile(path.join(outDir, ".github", "workflows", "publish.yml"), "utf8");
  assert.match(publishWorkflow, /uses: \.\/\.github\/workflows\/verify-core\.yml/);
  assert.match(publishWorkflow, /uses: \.\/\.github\/workflows\/ci\.yml/);
  assert.match(publishWorkflow, /uses: \.\/\.github\/workflows\/playwright\.yml/);
  assert.match(publishWorkflow, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW \|\| 'managed-provider-evidence\.yml'/);
  assert.match(publishWorkflow, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON/);
  assert.match(publishWorkflow, /managed_provider_evidence_json/);
  assert.match(publishWorkflow, /dispatch_hosted:/);
  assert.match(publishWorkflow, /AEGAEON_CLIENT_EVIDENCE_DISPATCH_HOSTED:/);
  assert.match(publishWorkflow, /pnpm run validate:client-claim-boundary/);
  assert.match(publishWorkflow, /pnpm run validate:released-client-claim/);
  assert.match(publishWorkflow, /pnpm run validate:client-claim-promotion/);
  assert.match(publishWorkflow, /actions: read/);
  assert.match(publishWorkflow, /AEGAEON_ADMIN_CONSOLE_REPOSITORY/);
  assert.match(publishWorkflow, /AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN/);
  assert.match(publishWorkflow, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY/);
  assert.match(publishWorkflow, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN/);
  assert.match(publishWorkflow, /Run client evidence gates \(readiness\)/);
  assert.match(publishWorkflow, /pnpm run run:client-evidence-gates -- --mode readiness --claim-active/);
  assert.match(publishWorkflow, /pnpm run release:manifest/);
  assert.match(publishWorkflow, /pnpm run release:sbom/);
  assert.match(publishWorkflow, /pnpm run release:attestation/);
  assert.match(publishWorkflow, /pnpm run validate:release-attestation/);
  assert.match(publishWorkflow, /pnpm run validate:release-attestation-signature/);
  assert.match(publishWorkflow, /AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE:/);
  assert.match(publishWorkflow, /AEGAEON_REAL_PUBLISH_ENABLED:/);
  assert.match(publishWorkflow, /AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION:/);
  assert.match(publishWorkflow, /AEGAEON_SDK_SBOM_PUBLICATION:/);
  assert.match(publishWorkflow, /AEGAEON_SDK_CARGO_PUBLISH_ENABLED:/);
  assert.match(publishWorkflow, /AEGAEON_COSIGN_KEY:/);
  assert.match(publishWorkflow, /refs\/heads\/main/);
  assert.match(publishWorkflow, /NPM_CONFIG_PROVENANCE: "true"/);
  assert.match(publishWorkflow, /publish-workspace-release/);
  assert.match(publishWorkflow, /sdk\/\.artifacts\/release/);
  assert.match(publishWorkflow, /pnpm run release:publish/);

  const releasedClientReadinessWorkflow = await readFile(
    path.join(outDir, ".github", "workflows", "released-client-readiness.yml"),
    "utf8",
  );
  const clientClaimPromotionWorkflow = await readFile(
    path.join(outDir, ".github", "workflows", "client-claim-promotion.yml"),
    "utf8",
  );
  assert.match(clientClaimPromotionWorkflow, /name: SDK Client Claim Promotion/);
  assert.match(clientClaimPromotionWorkflow, /workflow_call/);
  assert.match(clientClaimPromotionWorkflow, /uses: \.\/\.github\/workflows\/verify-core\.yml/);
  assert.match(clientClaimPromotionWorkflow, /uses: \.\/\.github\/workflows\/ci\.yml/);
  assert.match(clientClaimPromotionWorkflow, /uses: \.\/\.github\/workflows\/playwright\.yml/);
  assert.match(clientClaimPromotionWorkflow, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW \|\| 'managed-provider-evidence\.yml'/);
  assert.match(clientClaimPromotionWorkflow, /dispatch_hosted:/);
  assert.match(clientClaimPromotionWorkflow, /AEGAEON_CLIENT_EVIDENCE_DISPATCH_HOSTED:/);
  assert.match(clientClaimPromotionWorkflow, /Run client evidence gates \(promotion\)/);
  assert.match(clientClaimPromotionWorkflow, /pnpm run run:client-evidence-gates -- --mode promotion/);
  assert.match(clientClaimPromotionWorkflow, /name: client-claim-promotion/);
  assert.match(clientClaimPromotionWorkflow, /sdk\/\.artifacts\/release\/client-claim-promotion-report\.json/);
  assert.match(releasedClientReadinessWorkflow, /name: SDK Released Client Readiness/);
  assert.match(releasedClientReadinessWorkflow, /workflow_call/);
  assert.match(releasedClientReadinessWorkflow, /uses: \.\/\.github\/workflows\/verify-core\.yml/);
  assert.match(releasedClientReadinessWorkflow, /uses: \.\/\.github\/workflows\/ci\.yml/);
  assert.match(releasedClientReadinessWorkflow, /uses: \.\/\.github\/workflows\/playwright\.yml/);
  assert.match(releasedClientReadinessWorkflow, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW \|\| 'managed-provider-evidence\.yml'/);
  assert.match(releasedClientReadinessWorkflow, /AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON/);
  assert.match(releasedClientReadinessWorkflow, /managed_provider_evidence_json/);
  assert.match(releasedClientReadinessWorkflow, /dispatch_hosted:/);
  assert.match(releasedClientReadinessWorkflow, /AEGAEON_CLIENT_EVIDENCE_DISPATCH_HOSTED:/);
  const managedProviderEvidenceWorkflow = await readFile(path.join(outDir, ".github", "workflows", "managed-provider-evidence.yml"), "utf8");
  assert.match(managedProviderEvidenceWorkflow, /name: SDK Managed Provider Evidence/);
  assert.match(managedProviderEvidenceWorkflow, /managed_provider_evidence_json/);
  assert.match(managedProviderEvidenceWorkflow, /pnpm run import:managed-provider-evidence/);
  assert.match(managedProviderEvidenceWorkflow, /name: External Provider \(Managed\)/);
  assert.match(managedProviderEvidenceWorkflow, /name: managed-provider-evidence/);
  assert.match(releasedClientReadinessWorkflow, /name: Released Client Readiness/);
  assert.match(releasedClientReadinessWorkflow, /pnpm run validate:released-client-claim/);
  assert.match(releasedClientReadinessWorkflow, /pnpm run validate:client-claim-boundary/);
  assert.match(releasedClientReadinessWorkflow, /pnpm run validate:client-claim-promotion/);
  assert.match(releasedClientReadinessWorkflow, /Run client evidence gates \(readiness\)/);
  assert.match(releasedClientReadinessWorkflow, /pnpm run run:client-evidence-gates -- --mode readiness --claim-active/);
  assert.match(releasedClientReadinessWorkflow, /name: released-client-readiness/);
  assert.match(releasedClientReadinessWorkflow, /sdk\/\.artifacts\/release/);
  assert.match(releasedClientReadinessWorkflow, /sdk\/\.artifacts\/admin-sdk\/admin-sdk-evidence\.json/);
  assert.match(releasedClientReadinessWorkflow, /sdk\/\.artifacts\/managed-provider\/managed-provider-evidence\.json/);

  const publicationOrgRolloutWorkflow = await readFile(path.join(outDir, ".github", "workflows", "publication-org-rollout.yml"), "utf8");
  assert.match(publicationOrgRolloutWorkflow, /name: SDK Publication-Org Rollout/);
  assert.match(publicationOrgRolloutWorkflow, /name: Publication-Org Rollout/);
  assert.match(publicationOrgRolloutWorkflow, /AEGAEON_PUBLICATION_ORG_OWNER/);
  assert.match(publicationOrgRolloutWorkflow, /AEGAEON_PUBLICATION_ORG_REPO/);
  assert.match(publicationOrgRolloutWorkflow, /AEGAEON_PUBLICATION_ORG_BRANCH/);
  assert.match(publicationOrgRolloutWorkflow, /pnpm run release:publication-org-rollout-report/);
  assert.match(publicationOrgRolloutWorkflow, /publication-org-rollout-report/);

  const setupNixCiAction = await readFile(path.join(outDir, ".github", "actions", "setup-nix-ci", "action.yml"), "utf8");
  assert.match(setupNixCiAction, /^name: Setup Nix CI/m);
  assert.match(setupNixCiAction, /DeterminateSystems\/nix-installer-action@v21/);
  assert.match(setupNixCiAction, /enable-flakehub-cache/);
  assert.match(setupNixCiAction, /DeterminateSystems\/flakehub-cache-action@v1/);

  const playwrightWorkflow = await readFile(path.join(outDir, ".github", "workflows", "playwright.yml"), "utf8");
  assert.match(playwrightWorkflow, /name: playwright/);
  assert.match(playwrightWorkflow, /workflow_call/);
  assert.match(playwrightWorkflow, /uses: \.\/\.github\/actions\/setup-nix-ci/);
  assert.match(playwrightWorkflow, /pnpm install --frozen-lockfile/);
  assert.match(playwrightWorkflow, /pnpm run test:playwright/);
  assert.match(playwrightWorkflow, /external-provider-dex:/);
  assert.match(playwrightWorkflow, /docker version/);
  assert.match(playwrightWorkflow, /pnpm run test:provider-dex-browser -- --required/);
  assert.match(playwrightWorkflow, /external-provider-keycloak:/);
  assert.match(playwrightWorkflow, /pnpm run test:provider-keycloak-browser -- --required/);
  assert.match(playwrightWorkflow, /external-provider-managed:/);
  assert.match(playwrightWorkflow, /AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON/);
  assert.match(playwrightWorkflow, /validate:managed-provider-config -- \.cache\/managed-external-provider\.json/);
  assert.match(playwrightWorkflow, /Audit managed provider readiness/);
  assert.match(playwrightWorkflow, /pnpm run audit:managed-provider -- --config \.cache\/managed-external-provider\.json --require-browser/);
  assert.match(playwrightWorkflow, /pnpm run test:provider-managed-browser -- --required --config \.cache\/managed-external-provider\.json/);
  assert.match(playwrightWorkflow, /pnpm run build:managed-provider-evidence -- --config \.cache\/managed-external-provider\.json --provider-class commercial --lane-name external-provider-managed --status passed --hosted true/);
  assert.match(playwrightWorkflow, /actions\/upload-artifact@v4/);
  assert.match(playwrightWorkflow, /playwright-diagnostics/);
  assert.match(playwrightWorkflow, /playwright-dex-diagnostics/);
  assert.match(playwrightWorkflow, /playwright-keycloak-diagnostics/);
  assert.match(playwrightWorkflow, /Upload managed provider evidence/);
  assert.match(playwrightWorkflow, /name: managed-provider-evidence/);
  assert.match(playwrightWorkflow, /playwright-managed-provider-diagnostics/);
  assert.doesNotMatch(playwrightWorkflow, /name: playwright-managed-provider-diagnostics[\s\S]*managed-provider-evidence\.json/);
  assert.match(playwrightWorkflow, /playwright-report/);
  assert.match(playwrightWorkflow, /test-results/);

  const playwrightConfig = await readFile(path.join(outDir, "tests", "playwright.config.ts"), "utf8");
  assert.match(playwrightConfig, /outputDir: "\.\.\/test-results\/playwright"/);
  assert.match(playwrightConfig, /outputFolder: "\.\.\/playwright-report"/);
  assert.match(playwrightConfig, /outputFile: "\.\.\/test-results\/playwright-report\.json"/);
  assert.match(playwrightConfig, /trace: "retain-on-failure"/);
  assert.match(playwrightConfig, /screenshot: "only-on-failure"/);
  assert.match(playwrightConfig, /video: "retain-on-failure"/);
  assert.match(playwrightConfig, /PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH/);

  for (const packageName of ["verified-core", "runtime-node", "runtime-web", "management-client", "issuer-spa", "rp-core"]) {
    await ensureWorkspaceNodeModule(outDir, packageName);
  }

  await execFile(process.execPath, ["--check", "dist-tools/exec-tool.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/check-branch-protection.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/check-workflow-inventory.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/check-hosted-evidence-sources.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/check-repository-settings.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/check-managed-provider-readiness.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/download-admin-sdk-evidence.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/download-managed-provider-evidence.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/import-managed-provider-evidence.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/run-client-evidence-gates.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/build-managed-provider-evidence.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/build-publish-manifest.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/build-workspace-sbom.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/build-release-attestation.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/check-release-attestation-signature.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/build-release-publication-bundle.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["--check", "dist-tools/check-client-claim-promotion.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tools/check-no-js-source.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["packages/management-client/dist-test/management_client_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/branch_protection_policy_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/workflow_inventory_policy_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/repository_settings_policy_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/admin_sdk_evidence_download_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/managed_provider_evidence_download_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/managed_provider_evidence_import_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/managed_provider_runner_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/managed_provider_config_schema_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/managed_provider_readiness_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/managed_provider_evidence_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/client_claim_boundary_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/client_claim_promotion_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/released_client_readiness_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/released_client_readiness_artifact_handoff_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/workspace_sbom_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/release_attestation_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/release_attestation_signature_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["dist-tests/node/release_publication_bundle_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["packages/issuer-spa/dist-test/issuer_spa_test.js"], {
    cwd: outDir,
  });
  await execFile(process.execPath, ["packages/rp-core/dist-test/rp_core_test.js"], {
    cwd: outDir,
  });
  const browserHarness = await readFile(path.join(outDir, "tests", "browser", "runtime_web_reference_harness.ts"), "utf8");
  assert.match(browserHarness, /\.\.\/\.\.\/packages\/runtime-web\/dist\/browser-smoke\.js/);
  const browserPlaywrightSpec = await readFile(path.join(outDir, "tests", "browser", "runtime_web_playwright.spec.ts"), "utf8");
  assert.match(browserPlaywrightSpec, /sdk browser test server listening/);
  assert.match(browserPlaywrightSpec, /issuer-spa completes a local upstream authorization code flow/);
  const externalProviderPlaywrightSpec = await readFile(path.join(outDir, "tests", "browser", "external_provider_playwright.spec.ts"), "utf8");
  assert.match(externalProviderPlaywrightSpec, /AEGAEON_EXTERNAL_PROVIDER_ISSUER/);
  assert.match(externalProviderPlaywrightSpec, /configured external-provider authorization code flow/);
  assert.match(externalProviderPlaywrightSpec, /AEGAEON_EXTERNAL_PROVIDER_LOGIN_SCRIPT_JSON/);
  const issuerSpaE2eHtml = await readFile(path.join(outDir, "tests", "browser", "issuer_spa_upstream_e2e.html"), "utf8");
  assert.match(issuerSpaE2eHtml, /@aegaeon\/issuer-spa/);
  const issuerSpaE2eHarness = await readFile(path.join(outDir, "tests", "browser", "issuer_spa_upstream_e2e_harness.ts"), "utf8");
  assert.match(issuerSpaE2eHarness, /fetchIssuerMetadata/);
  assert.match(issuerSpaE2eHarness, /\/tests\/browser\/issuer_spa_upstream_e2e\.html/);
  const externalIssuerSpaE2eHtml = await readFile(path.join(outDir, "tests", "browser", "issuer_spa_external_provider_e2e.html"), "utf8");
  assert.match(externalIssuerSpaE2eHtml, /external provider e2e/);
  const externalIssuerSpaE2eHarness = await readFile(path.join(outDir, "tests", "browser", "issuer_spa_external_provider_e2e_harness.ts"), "utf8");
  assert.match(externalIssuerSpaE2eHarness, /test-config\/external-provider/);
  assert.match(externalIssuerSpaE2eHarness, /runtime-web verified the external-provider RS256 ID Token/);
  const dexCompose = await readFile(path.join(outDir, "tests", "providers", "dex", "docker-compose.yml"), "utf8");
  assert.match(dexCompose, /ghcr\.io\/dexidp\/dex:v2\.41\.1/);
  const dexConfig = await readFile(path.join(outDir, "tests", "providers", "dex", "dex-config.yaml"), "utf8");
  assert.match(dexConfig, /issuer_spa_external_provider_e2e\.html/);
  const keycloakCompose = await readFile(path.join(outDir, "tests", "providers", "keycloak", "docker-compose.yml"), "utf8");
  assert.match(keycloakCompose, /quay\.io\/keycloak\/keycloak:26\.1\.3/);
  const keycloakRealm = await readFile(path.join(outDir, "tests", "providers", "keycloak", "keycloak-realm.template.json"), "utf8");
  assert.match(keycloakRealm, /__KEYCLOAK_REDIRECT_URI__/);
  const managedProviderExample = await readFile(path.join(outDir, "tests", "providers", "managed", "managed-provider.example.json"), "utf8");
  assert.match(managedProviderExample, /providerName/);
  const managedProviderRunner = await readFile(path.join(outDir, "tests", "providers", "managed", "run_managed_browser_e2e.ts"), "utf8");
  assert.match(managedProviderRunner, /AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG/);

  const sourceArtifactDir = path.join(outDir, ".cache", "source-artifacts");
  await mkdir(sourceArtifactDir, { recursive: true });
  for (const name of [
    "manifest.json",
    "verified_core.wasm",
    "verified_core.abi.json",
    "verified_core.wasm.sha256",
    "verified_core.wasm.sha512",
    "verified_core.wasm.sri",
    "verified-core-sbom.json",
    "types.d.ts",
    "integrity.txt",
  ]) {
    await cp(path.join(ROOT_DIR, "artifacts", "verified-core", name), path.join(sourceArtifactDir, name));
  }
  await writeFile(
    path.join(sourceArtifactDir, "verified-core-handoff-manifest.json"),
    JSON.stringify({
      schema_version: 1,
      bundle_format: "github-release",
      handoff_manifest_file: "verified-core-handoff-manifest.json",
      core_repo: "example/aegaeon",
      core_release_tag: "v0.9.0-core.1",
      source_commit: "deadbeefcafebabe",
      source_workflow: "Verified Core Release",
      generated_at: "2026-03-10T00:00:00Z",
      release_artifact_name: "verified-core-v0.9.0-core.1",
      dispatch_artifact_name: "verified-core-sdk-dispatch-v0.9.0-core.1",
      required_files: [
        "manifest.json",
        "verified_core.wasm",
        "verified_core.abi.json",
        "verified_core.wasm.sha256",
        "verified_core.wasm.sha512",
        "verified_core.wasm.sri",
        "verified-core-sbom.json",
        "types.d.ts",
        "integrity.txt",
      ],
      optional_files: [
        "verified_core.wasm.sig",
        "verified_core.wasm.cosign.sig",
      ],
    }, null, 2) + "\n",
  );

  const releaseCacheDir = path.join(outDir, ".cache", "release-download");
  await execFile(process.execPath, [
    "dist-tools/download-core-release.js",
    "--",
    "--artifact-dir", sourceArtifactDir,
    "--out-dir", releaseCacheDir,
  ], {
    cwd: outDir,
  });
  await assertExists(path.join(releaseCacheDir, "manifest.json"));
  await assertExists(path.join(releaseCacheDir, "verified_core.wasm"));
  await assertExists(path.join(releaseCacheDir, "verified-core-handoff-manifest.json"));
  await execFile("python3", [
    "scripts/validation/validate_verified_core_handoff_manifest.py",
    path.join(releaseCacheDir, "verified-core-handoff-manifest.json"),
  ], {
    cwd: outDir,
  });

  await execFile(process.execPath, [
    "dist-tools/verify-core.js",
    "--",
    "--manifest", path.join(releaseCacheDir, "manifest.json"),
    "--wasm", path.join(releaseCacheDir, "verified_core.wasm"),
  ], {
    cwd: outDir,
  });
  await assertExists(path.join(outDir, "packages", "verified-core", "dist", "manifest.json"));
  await assertExists(path.join(outDir, "packages", "verified-core", "dist", "verified_core.wasm"));

  const dispatchPayloadPath = path.join(outDir, ".cache", "sdk-repository-dispatch.json");
  const dispatchPayload = {
    event_type: "verified-core-release",
    client_payload: {
      artifact_bundle: "github-release",
      core_repo: "example/aegaeon",
      core_release_tag: "v0.9.0-core.1",
      source_commit: "deadbeefcafebabe",
      source_workflow: "Verified Core Release",
      generated_at: "2026-03-10T00:00:00Z",
    },
  };
  await execFile(process.execPath, [
    "dist-tools/materialize-sdk-dispatch-payload.js",
    "--event-type", dispatchPayload.event_type,
    "--client-payload-json", JSON.stringify(dispatchPayload.client_payload),
    "--output", dispatchPayloadPath,
  ], {
    cwd: outDir,
  });
  await execFile("python3", [
    "scripts/validation/validate_sdk_repository_dispatch_payload.py",
    dispatchPayloadPath,
  ], {
    cwd: outDir,
  });
  const { stdout: dispatchEnv } = await execFile(process.execPath, [
    "dist-tools/export-sdk-dispatch-env.js",
    "--payload", dispatchPayloadPath,
  ], {
    cwd: outDir,
  });
  assert.match(dispatchEnv, /AEGAEON_CORE_RELEASE_REPO=example\/aegaeon/);
  assert.match(dispatchEnv, /AEGAEON_CORE_RELEASE_TAG=v0\.9\.0-core\.1/);

  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString("utf8");
  const publicKeyOutputPath = path.join(outDir, ".cache", "verified-core.pub.pem");
  await execFile(process.execPath, [
    "dist-tools/materialize-verified-core-public-key.js",
    "--public-key", Buffer.from(publicKeyPem, "utf8").toString("base64"),
    "--output", publicKeyOutputPath,
  ], {
    cwd: outDir,
  });
  assert.equal(await readFile(publicKeyOutputPath, "utf8"), publicKeyPem);


  console.log("=== sdk repo scaffold checks passed ===");
}

main().catch((error) => {
  console.error("[fail] scaffold_sdk_repo_test:", error);
  process.exitCode = 1;
});
