#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { promises as fs } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..", "..");
const TOOL_SOURCE_DIR = path.join(MODULE_DIR, "tools-src");
const TOOL_SOURCE_FILES = [
  "build-managed-provider-evidence.ts",
  "build-publication-org-rollout-report.ts",
  "build-publish-manifest.ts",
  "build-release-attestation.ts",
  "build-hosted-release-readiness-report.ts",
  "build-release-publication-bundle.ts",
  "build-released-client-claim-report.ts",
  "build-workspace-sbom.ts",
  "check-branch-protection.ts",
  "check-client-claim-promotion.ts",
  "check-external-boundary-naming.ts",
  "check-strict-types.ts",
  "check-hosted-evidence-sources.ts",
  "check-managed-provider-readiness.ts",
  "check-no-js-source.ts",
  "check-release-attestation-signature.ts",
  "check-release-custody.ts",
  "check-released-client-claim-activation.ts",
  "check-released-client-readiness.ts",
  "check-repository-settings.ts",
  "check-workflow-inventory.ts",
  "download-admin-sdk-evidence.ts",
  "download-core-release.ts",
  "download-managed-provider-evidence.ts",
  "import-managed-provider-evidence.ts",
  "run-client-evidence-gates.ts",
  "run-real-tenant-readiness.ts",
  "run-hosted-evidence.ts",
  "released-client-types.ts",
  "exec-tool.ts",
  "export-sdk-dispatch-env.ts",
  "fetch-core.ts",
  "materialize-sdk-dispatch-payload.ts",
  "materialize-verified-core-public-key.ts",
  "verify-core.ts",
];
const LICENSE_PATH = path.join(ROOT_DIR, "LICENSE");
const BRANCH_PROTECTION_POLICY_SOURCE = path.join(MODULE_DIR, "sdk_branch_protection.main.json");
const REPOSITORY_SETTINGS_POLICY_SOURCE = path.join(MODULE_DIR, "sdk_repository_settings.current.json");
const RELEASE_CUSTODY_POLICY_SOURCE = path.join(MODULE_DIR, "sdk_release_custody.current.json");
const HOSTED_EVIDENCE_SOURCES_POLICY_SOURCE = path.join(MODULE_DIR, "sdk_hosted_evidence_sources.current.json");
const WORKFLOW_INVENTORY_POLICY_SOURCE = path.join(MODULE_DIR, "sdk_workflow_inventory.current.json");
const EXTERNAL_BOUNDARY_NAMING_POLICY_SOURCE = path.join(ROOT_DIR, "spec", "external-boundary-naming.current.json");

function adaptToolRootForScaffold(source: string): string {
  return source.replace(
    /const TOOL_ROOT = path\.resolve\(path\.dirname\(fileURLToPath\(import\.meta\.url\)\), "\.\.", "\.\.", "\.\."\);/,
    "const TOOL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), \"..\");",
  );
}
const MANAGED_PROVIDER_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "managed-external-provider.schema.json");
const MANAGED_PROVIDER_EVIDENCE_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "managed-provider-evidence.schema.json");
const ADMIN_SDK_EVIDENCE_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "admin-sdk-evidence.schema.json");
const CLIENT_CLAIM_BOUNDARY_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "client-claim-boundary.schema.json");
const CLIENT_CLAIM_BOUNDARY_CURRENT_SOURCE = path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json");
const CLIENT_CLAIM_PROMOTION_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "client-claim-promotion.schema.json");
const CLIENT_CLAIM_PROMOTION_CURRENT_SOURCE = path.join(ROOT_DIR, "spec", "client-claim-promotion.current.json");
const RELEASED_CLIENT_CLAIM_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "released-client-claim.schema.json");
const RELEASED_CLIENT_CLAIM_CURRENT_SOURCE = path.join(ROOT_DIR, "spec", "released-client-claim.current.json");
const STRICT_TYPES_POLICY_SOURCE = path.join(ROOT_DIR, "spec", "strict-types.current.json");
const RELEASED_CLIENT_CLAIM_REPORT_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "released-client-claim-report.schema.json");
const RELEASE_ATTESTATION_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "sdk-release-attestation.schema.json");
const RELEASE_ATTESTATION_SIGNATURE_SCHEMA_SOURCE = path.join(
  ROOT_DIR,
  "spec",
  "sdk-release-attestation-signature.schema.json",
);
const RELEASE_PUBLICATION_BUNDLE_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "sdk-release-publication-bundle.schema.json");
const MANAGED_PROVIDER_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_managed_external_provider_config.py");
const MANAGED_PROVIDER_EVIDENCE_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_managed_provider_evidence.py");
const ADMIN_SDK_EVIDENCE_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_admin_sdk_evidence.py");
const CLIENT_CLAIM_BOUNDARY_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_client_claim_boundary.py");
const CLIENT_CLAIM_PROMOTION_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_client_claim_promotion.py");
const RELEASED_CLIENT_CLAIM_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_released_client_claim.py");
const RELEASED_CLIENT_CLAIM_REPORT_VALIDATOR_SOURCE = path.join(
  ROOT_DIR,
  "scripts",
  "validation",
  "validate_released_client_claim_report.py",
);
const RELEASE_ATTESTATION_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_sdk_release_attestation.py");
const RELEASE_ATTESTATION_SIGNATURE_VALIDATOR_SOURCE = path.join(
  ROOT_DIR,
  "scripts",
  "validation",
  "validate_sdk_release_attestation_signature.py",
);
const RELEASE_PUBLICATION_BUNDLE_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_sdk_release_publication_bundle.py");
const SETUP_NIX_CI_ACTION_SOURCE = path.join(ROOT_DIR, ".github", "actions", "setup-nix-ci", "action.yml");
const FETCH_CORE_SCRIPT = path.join(MODULE_DIR, "fetch_core_artifact.js");
const DISPATCH_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "sdk-repository-dispatch.schema.json");
const DISPATCH_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_sdk_repository_dispatch_payload.py");
const HANDOFF_SCHEMA_SOURCE = path.join(ROOT_DIR, "spec", "verified-core-handoff-manifest.schema.json");
const HANDOFF_VALIDATOR_SOURCE = path.join(ROOT_DIR, "scripts", "validation", "validate_verified_core_handoff_manifest.py");
const STAGE_SCRIPT = path.join(MODULE_DIR, "stage_reference_sdk_workspace.ts");
const PLAYWRIGHT_CONFIG_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "playwright.config.ts");
const BROWSER_GLOBALS_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "browser-globals.d.ts");
const BROWSER_HARNESS_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "runtime_web_reference_harness.ts");
const BROWSER_HTML_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "runtime_web_reference.html");
const BROWSER_SERVER_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "runtime_web_reference_server.ts");
const BROWSER_RUNNER_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "runtime_web_browser_smoke_test.ts");
const BRANCH_PROTECTION_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "branch_protection_policy_test.ts");
const STRICT_TYPES_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "strict_types_policy_test.ts");
const EXTERNAL_BOUNDARY_NAMING_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "external_boundary_naming_policy_test.ts",
);
const WORKFLOW_INVENTORY_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "workflow_inventory_policy_test.ts");
const REPOSITORY_SETTINGS_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "repository_settings_policy_test.ts");
const HOSTED_EVIDENCE_SOURCES_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "hosted_evidence_sources_test.ts",
);
const HOSTED_EVIDENCE_RUNNER_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "hosted_evidence_runner_test.ts",
);
const RELEASE_CUSTODY_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "release_custody_policy_test.ts");
const MANAGED_PROVIDER_EVIDENCE_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "managed_provider_evidence_test.ts");
const MANAGED_PROVIDER_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "managed_provider_runner_test.ts");
const MANAGED_PROVIDER_SCHEMA_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "managed_provider_config_schema_test.ts");
const MANAGED_PROVIDER_READINESS_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "managed_provider_readiness_test.ts");
const CLIENT_CLAIM_BOUNDARY_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "client_claim_boundary_test.ts");
const CLIENT_CLAIM_PROMOTION_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "client_claim_promotion_test.ts");
const ADMIN_SDK_EVIDENCE_DOWNLOAD_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "admin_sdk_evidence_download_test.ts",
);
const AEGAEON_PROVIDER_LOCAL_E2E_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "aegaeon_provider_local_e2e_test.ts",
);
const MANAGED_PROVIDER_EVIDENCE_DOWNLOAD_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "managed_provider_evidence_download_test.ts",
);
const MANAGED_PROVIDER_EVIDENCE_IMPORT_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "managed_provider_evidence_import_test.ts",
);
const TOOL_EXEC_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "sdk_tool_exec_test.ts");
const REAL_TENANT_READINESS_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "real_tenant_readiness_runner_test.ts",
);
const HOSTED_RELEASE_READINESS_REPORT_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "hosted_release_readiness_report_test.ts",
);
const RELEASED_CLIENT_CLAIM_ACTIVATION_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "released_client_claim_activation_test.ts",
);
const RELEASE_ATTESTATION_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "sdk_release_attestation_test.ts");
const RELEASE_ATTESTATION_SIGNATURE_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "sdk_release_attestation_signature_test.ts",
);
const WORKSPACE_SBOM_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "sdk_workspace_sbom_test.ts");
const RELEASE_PUBLICATION_BUNDLE_TEST_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "sdk_release_publication_bundle_test.ts");
const RELEASED_CLIENT_CLAIM_REPORT_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "released_client_claim_report_test.ts",
);
const RELEASED_CLIENT_READINESS_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "released_client_readiness_test.ts",
);
const RELEASED_CLIENT_READINESS_ARTIFACT_HANDOFF_TEST_SOURCE = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "released_client_readiness_artifact_handoff_test.ts",
);
const BROWSER_PLAYWRIGHT_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "runtime_web_playwright.spec.ts");
const BROWSER_ISSUER_HTML_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "issuer_spa_upstream_e2e.html");
const BROWSER_ISSUER_HARNESS_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "issuer_spa_upstream_e2e_harness.ts");
const BROWSER_EXTERNAL_PLAYWRIGHT_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "external_provider_playwright.spec.ts");
const BROWSER_EXTERNAL_ISSUER_HTML_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "issuer_spa_external_provider_e2e.html");
const BROWSER_EXTERNAL_ISSUER_HARNESS_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "issuer_spa_external_provider_e2e_harness.ts");
const PROVIDER_DEX_COMPOSE_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "dex", "docker-compose.yml");
const PROVIDER_DEX_CONFIG_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "dex", "dex-config.yaml");
const PROVIDER_RUN_WORKSPACE_PNPM_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "run_workspace_pnpm.ts");
const PROVIDER_DEX_RUNNER_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "dex", "run_dex_browser_e2e.ts");
const PROVIDER_KEYCLOAK_COMPOSE_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "keycloak", "docker-compose.yml");
const PROVIDER_KEYCLOAK_REALM_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "keycloak", "keycloak-realm.template.json");
const PROVIDER_KEYCLOAK_RUNNER_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "keycloak", "run_keycloak_browser_e2e.ts");
const PROVIDER_MANAGED_EXAMPLE_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "managed", "managed-provider.example.json");
const PROVIDER_MANAGED_RUNNER_SOURCE = path.join(ROOT_DIR, "tests", "verified_core_wasm", "providers", "managed", "run_managed_browser_e2e.ts");
const DEFAULT_DIST_DIR = path.join(ROOT_DIR, "artifacts", "verified-core");
const DEFAULT_OUT_DIR = path.join(ROOT_DIR, "artifacts", "sdk-repo-scaffold");

function parseArgs(argv) {
  const options = {
    distDir: DEFAULT_DIST_DIR,
    outDir: DEFAULT_OUT_DIR,
    version: null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      continue;
    }
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    switch (key) {
      case "dist-dir":
        options.distDir = path.resolve(value);
        break;
      case "out-dir":
        options.outDir = path.resolve(value);
        break;
      case "version":
        options.version = value;
        break;
      default:
        throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  return options;
}

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

async function removeDir(dirPath) {
  await fs.rm(dirPath, { recursive: true, force: true });
}

async function writeJson(filePath, value) {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeText(filePath, text) {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, text, "utf8");
}

async function readText(filePath) {
  return fs.readFile(filePath, "utf8");
}

async function stageWorkspace(tempDir, options) {
  const args = [STAGE_SCRIPT, "--dist-dir", options.distDir, "--out-dir", tempDir];
  if (options.version) {
    args.push("--version", options.version);
  }
  await execFile(process.execPath, args, { cwd: ROOT_DIR });
}

function rootPackageJson(version) {
  return {
    name: "aegaeon-sdk",
    private: true,
    version,
    packageManager: "pnpm@9.15.0",
    type: "module",
    description: "Separate SDK workspace scaffold generated from the Aegaeon backend repository.",
    engines: {
      node: ">=24",
    },
    devDependencies: {
      "@changesets/cli": "^2.29.6",
      "@playwright/test": "^1.55.0",
      "@types/node": "^24.3.0",
      typescript: "^5.8.2",
    },
    scripts: {
      "build:tools": "node ./node_modules/typescript/bin/tsc --build tsconfig.tools.json",
      "build:tests:node": "node ./node_modules/typescript/bin/tsc --project tsconfig.tests.node.json",
      "build:tests:browser": "pnpm run build:packages && node ./node_modules/typescript/bin/tsc --project tsconfig.tests.browser.json",
      "typecheck:tests:node": "node ./node_modules/typescript/bin/tsc --project tsconfig.tests.node.json --pretty false --noEmit",
      "typecheck:tests:browser": "node ./node_modules/typescript/bin/tsc --project tsconfig.tests.browser.json --pretty false --noEmit",
      "fetch-core": "pnpm run build:tools && node dist-tools/exec-tool.js fetch-core",
      "download-core:release": "pnpm run build:tools && node dist-tools/exec-tool.js download-core:release",
      "download:admin-sdk-evidence": "pnpm run build:tools && node dist-tools/exec-tool.js download:admin-sdk-evidence",
      "download:managed-provider-evidence": "pnpm run build:tools && node dist-tools/exec-tool.js download:managed-provider-evidence",
      "import:managed-provider-evidence": "pnpm run build:tools && node dist-tools/exec-tool.js import:managed-provider-evidence",
      "run:admin-sdk-evidence": "pnpm run build:tools && node dist-tools/exec-tool.js run:admin-sdk-evidence",
      "run:managed-provider-evidence": "pnpm run build:tools && node dist-tools/exec-tool.js run:managed-provider-evidence",
      "run:client-evidence-gates": "pnpm run build:tools && node dist-tools/exec-tool.js run:client-evidence-gates",
      "run:real-tenant-readiness": "pnpm run build:tools && node dist-tools/exec-tool.js run:real-tenant-readiness",
      "verify-core": "pnpm run build:tools && node dist-tools/exec-tool.js verify-core",
      "materialize:sdk-dispatch": "pnpm run build:tools && node dist-tools/exec-tool.js materialize:sdk-dispatch",
      "export:sdk-dispatch-env": "pnpm run build:tools && node dist-tools/exec-tool.js export:sdk-dispatch-env",
      "materialize:verified-core-public-key": "pnpm run build:tools && node dist-tools/exec-tool.js materialize:verified-core-public-key",
      "audit:branch-protection": "pnpm run build:tools && node dist-tools/exec-tool.js audit:branch-protection",
      "audit:external-boundary-naming": "pnpm run build:tools && node dist-tools/exec-tool.js audit:external-boundary-naming",
      "audit:hosted-evidence-sources": "pnpm run build:tools && node dist-tools/exec-tool.js audit:hosted-evidence-sources",
      "audit:repo-settings": "pnpm run build:tools && node dist-tools/exec-tool.js audit:repo-settings",
      "audit:release-custody": "pnpm run build:tools && node dist-tools/exec-tool.js audit:release-custody",
      "audit:strict-types": "pnpm run build:tools && node dist-tools/exec-tool.js audit:strict-types",
      "audit:workflow-inventory": "pnpm run build:tools && node dist-tools/exec-tool.js audit:workflow-inventory",
      "audit:client-claim-promotion": "pnpm run build:tools && node dist-tools/exec-tool.js audit:client-claim-promotion",
      "audit:released-client-claim": "pnpm run build:tools && node dist-tools/exec-tool.js audit:released-client-claim",
      "audit:released-client-readiness": "pnpm run build:tools && node dist-tools/exec-tool.js audit:released-client-readiness",
      "audit:managed-provider": "pnpm run build:tools && pnpm run build:tests:browser && node dist-tools/exec-tool.js audit:managed-provider",
      "audit:no-js-source": "pnpm run build:tools && node dist-tools/exec-tool.js audit:no-js-source",
      "validate:sdk-dispatch": "python3 scripts/validation/validate_sdk_repository_dispatch_payload.py",
      "validate:core-handoff": "python3 scripts/validation/validate_verified_core_handoff_manifest.py",
      "validate:managed-provider-config": "python3 scripts/validation/validate_managed_external_provider_config.py",
      "validate:managed-provider-evidence": "python3 scripts/validation/validate_managed_provider_evidence.py",
      "validate:admin-sdk-evidence": "python3 scripts/validation/validate_admin_sdk_evidence.py",
      "validate:client-claim-boundary": "python3 scripts/validation/validate_client_claim_boundary.py spec/client-claim-boundary.current.json",
      "validate:client-claim-promotion": "python3 scripts/validation/validate_client_claim_promotion.py spec/client-claim-promotion.current.json",
      "validate:released-client-claim": "python3 scripts/validation/validate_released_client_claim.py spec/released-client-claim.current.json",
      "validate:release-attestation": "python3 scripts/validation/validate_sdk_release_attestation.py .artifacts/release/release-attestation.json",
      "validate:release-attestation-signature": "pnpm run build:tools && node dist-tools/exec-tool.js validate:release-attestation-signature",
      "validate:released-client-claim-report": "python3 scripts/validation/validate_released_client_claim_report.py .artifacts/release/released-client-claim-report.json",
      "validate:release-publication-bundle": "python3 scripts/validation/validate_sdk_release_publication_bundle.py .artifacts/release/release-publication-bundle.json",
      "build:managed-provider-evidence": "pnpm run build:tools && node dist-tools/exec-tool.js build:managed-provider-evidence",
      "release:manifest": "pnpm run build:tools && node dist-tools/exec-tool.js release:manifest",
      "release:sbom": "pnpm run build:tools && node dist-tools/exec-tool.js release:sbom",
      "release:attestation": "pnpm run build:tools && node dist-tools/exec-tool.js release:attestation",
      "release:client-claim-report": "pnpm run build:tools && node dist-tools/exec-tool.js release:client-claim-report",
      "release:publication-org-rollout-report": "pnpm run build:tools && node dist-tools/exec-tool.js release:publication-org-rollout-report",
      "release:hosted-readiness-report": "pnpm run build:tools && node dist-tools/exec-tool.js release:hosted-readiness-report",
      "release:publication-bundle": "pnpm run build:tools && node dist-tools/exec-tool.js release:publication-bundle",
      "ci:packages": "pnpm run lint && pnpm run typecheck && pnpm run test && pnpm run build",
      "ci:browser-smoke": "pnpm run test:browser-smoke",
      "build:packages": "pnpm -r --filter './packages/**' --if-present run build",
      build: "pnpm run build:tools && pnpm run build:tests:node && pnpm run build:tests:browser",
      lint: "pnpm run build:tools && node ./node_modules/typescript/bin/tsc --build --pretty false tsconfig.json",
      typecheck: "pnpm run build:tools && node ./node_modules/typescript/bin/tsc --build --pretty false tsconfig.json && pnpm run typecheck:tests:node && pnpm run typecheck:tests:browser",
      "test:packages": "pnpm -r --if-present run test",
      "test:repo": "pnpm run audit:no-js-source && pnpm run audit:strict-types && pnpm run audit:external-boundary-naming && pnpm run audit:workflow-inventory && pnpm run build:tools && pnpm run build:tests:node && pnpm run build:tests:browser && node dist-tests/node/tool_exec_test.js && node dist-tests/node/strict_types_policy_test.js && node dist-tests/node/external_boundary_naming_policy_test.js && node dist-tests/node/branch_protection_policy_test.js && node dist-tests/node/workflow_inventory_policy_test.js && node dist-tests/node/repository_settings_policy_test.js && node dist-tests/node/hosted_evidence_sources_test.js && node dist-tests/node/hosted_evidence_runner_test.js && node dist-tests/node/release_custody_policy_test.js && node dist-tests/node/admin_sdk_evidence_download_test.js && node dist-tests/node/managed_provider_evidence_download_test.js && node dist-tests/node/managed_provider_evidence_import_test.js && node dist-tests/node/managed_provider_runner_test.js && node dist-tests/node/managed_provider_config_schema_test.js && node dist-tests/node/managed_provider_readiness_test.js && node dist-tests/node/managed_provider_evidence_test.js && node dist-tests/node/client_claim_boundary_test.js && node dist-tests/node/client_claim_promotion_test.js && node dist-tests/node/released_client_claim_activation_test.js && node dist-tests/node/released_client_claim_report_test.js && node dist-tests/node/released_client_readiness_test.js && node dist-tests/node/released_client_readiness_artifact_handoff_test.js && node dist-tests/node/real_tenant_readiness_runner_test.js && node dist-tests/node/hosted_release_readiness_report_test.js && node dist-tests/node/workspace_sbom_test.js && node dist-tests/node/release_attestation_test.js && node dist-tests/node/release_attestation_signature_test.js && node dist-tests/node/release_publication_bundle_test.js",
      test: "pnpm run test:packages && pnpm run test:repo",
      "test:browser-smoke": "pnpm run build:tests:browser && node dist-tests/browser/runtime_web_browser_smoke_test.js --required",
      "test:provider-local": "pnpm run build:tests:node && node dist-tests/node/aegaeon_provider_local_e2e_test.js",
      "test:playwright:external-provider": "pnpm run build:tests:browser && playwright test --config dist-tests/playwright.config.js dist-tests/browser/external_provider_playwright.spec.js",
      "test:provider-dex-browser": "pnpm run build:tests:browser && node dist-tests/providers/dex/run_dex_browser_e2e.js",
      "test:provider-keycloak-browser": "pnpm run build:tests:browser && node dist-tests/providers/keycloak/run_keycloak_browser_e2e.js",
      "test:provider-managed-browser": "pnpm run build:tests:browser && node dist-tests/providers/managed/run_managed_browser_e2e.js",
      "test:playwright": "pnpm run build:tests:browser && playwright test --config dist-tests/playwright.config.js",
      ci: "pnpm run ci:packages && pnpm run ci:browser-smoke",
      changeset: "changeset",
      "release:version": "changeset version",
      "release:publish": "changeset publish",
      "pack:verified-core": "pnpm --dir ./packages/verified-core pack --pack-destination ../../",
      "pack:runtime-node": "pnpm --dir ./packages/runtime-node pack --pack-destination ../../",
      "pack:runtime-web": "pnpm --dir ./packages/runtime-web pack --pack-destination ../../",
      "pack:management-client": "pnpm --dir ./packages/management-client pack --pack-destination ../../",
      "pack:issuer-spa": "pnpm --dir ./packages/issuer-spa pack --pack-destination ../../",
      "pack:rp-core": "pnpm --dir ./packages/rp-core pack --pack-destination ../../",
      "pack:workspace": "pnpm run pack:verified-core && pnpm run pack:runtime-node && pnpm run pack:runtime-web && pnpm run pack:management-client && pnpm run pack:issuer-spa && pnpm run pack:rp-core",
    },
  };
}

function pnpmWorkspaceYaml() {
  return `packages:\n  - packages/*\n`;
}

function gitignoreText() {
  return `node_modules/\n.pnpm-store/\n*.tgz\n.artifacts/\n.cache/\ndist-tools/\ndist-tests/\npackages/*/dist-test/\npackages/*/*.tgz\ncoverage/\nplaywright-report/\ntest-results/\n`;
}

function npmrcText() {
  return `engine-strict=true\nprefer-workspace-packages=true\nsave-workspace-protocol=true\n`;
}

function changesetReadme() {
  return `This directory is pre-seeded for the eventual dedicated \`aegaeon-sdk\` repository.\n\nAdd one markdown file per package change and run \`pnpm run release:version\` before publishing.\n`;
}

function changesetConfig() {
  return {
    $schema: "https://unpkg.com/@changesets/config@3.0.0/schema.json",
    changelog: "@changesets/cli/changelog",
    commit: false,
    fixed: [],
    linked: [],
    access: "public",
    baseBranch: "main",
    updateInternalDependencies: "patch",
    ignore: [],
  };
}

function tsconfigBaseJson() {
  return {
    compilerOptions: {
      target: "ES2022",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      moduleDetection: "force",
      allowJs: false,
      checkJs: false,
      noEmit: true,
      strict: true,
      exactOptionalPropertyTypes: true,
      noUncheckedIndexedAccess: true,
      verbatimModuleSyntax: true,
      resolveJsonModule: true,
      skipLibCheck: true,
      lib: ["ES2022", "DOM", "DOM.Iterable"],
      types: ["node"],
    },
  };
}

function tsconfigJson() {
  return {
    files: [],
    references: [
      { path: "./tsconfig.tools.json" },
      { path: "./packages/verified-core/tsconfig.json" },
      { path: "./packages/runtime-node/tsconfig.json" },
      { path: "./packages/runtime-web/tsconfig.json" },
      { path: "./packages/management-client/tsconfig.json" },
      { path: "./packages/issuer-spa/tsconfig.json" },
      { path: "./packages/rp-core/tsconfig.json" },
    ],
  };
}

function tsconfigTestsNodeJson() {
  return {
    extends: "./tsconfig.base.json",
    compilerOptions: {
      allowJs: false,
      checkJs: false,
      noEmit: false,
      strict: true,
      strictNullChecks: true,
      exactOptionalPropertyTypes: true,
      noUncheckedIndexedAccess: true,
      noImplicitAny: true,
      useUnknownInCatchVariables: true,
      rootDir: "./tests/node",
      outDir: "./dist-tests/node",
      lib: ["ES2022"],
    },
    include: ["tests/node/**/*.ts"],
  };
}

function tsconfigToolsJson() {
  return {
    extends: "./tsconfig.base.json",
    compilerOptions: {
      allowJs: false,
      checkJs: false,
      noEmit: false,
      rootDir: "./tools-src",
      outDir: "./dist-tools",
      lib: ["ES2022"],
      composite: true,
      tsBuildInfoFile: "./.cache/tsbuildinfo/tools.tsbuildinfo",
    },
    include: ["tools-src/**/*.ts"],
  };
}

function toolExecDistText() {
  return `#!/usr/bin/env node
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..");

const TOOL_MAP = {
  "fetch-core": path.join(MODULE_DIR, "fetch-core.js"),
  "download-core:release": path.join(MODULE_DIR, "download-core-release.js"),
  "download:admin-sdk-evidence": path.join(MODULE_DIR, "download-admin-sdk-evidence.js"),
  "download:managed-provider-evidence": path.join(MODULE_DIR, "download-managed-provider-evidence.js"),
  "run:admin-sdk-evidence": {
    script: path.join(MODULE_DIR, "run-hosted-evidence.js"),
    args: ["--kind", "admin-sdk"],
  },
  "run:managed-provider-evidence": {
    script: path.join(MODULE_DIR, "run-hosted-evidence.js"),
    args: ["--kind", "managed-provider"],
  },
  "run:client-evidence-gates": path.join(MODULE_DIR, "run-client-evidence-gates.js"),
  "run:real-tenant-readiness": path.join(MODULE_DIR, "run-real-tenant-readiness.js"),
  "verify-core": path.join(MODULE_DIR, "verify-core.js"),
  "materialize:sdk-dispatch": path.join(MODULE_DIR, "materialize-sdk-dispatch-payload.js"),
  "export:sdk-dispatch-env": path.join(MODULE_DIR, "export-sdk-dispatch-env.js"),
  "materialize:verified-core-public-key": path.join(MODULE_DIR, "materialize-verified-core-public-key.js"),
  "audit:branch-protection": path.join(MODULE_DIR, "check-branch-protection.js"),
  "audit:strict-types": path.join(MODULE_DIR, "check-strict-types.js"),
  "audit:repo-settings": path.join(MODULE_DIR, "check-repository-settings.js"),
  "audit:release-custody": path.join(MODULE_DIR, "check-release-custody.js"),
  "audit:client-claim-promotion": path.join(MODULE_DIR, "check-client-claim-promotion.js"),
  "audit:released-client-claim": path.join(MODULE_DIR, "check-released-client-claim-activation.js"),
  "audit:released-client-readiness": path.join(MODULE_DIR, "check-released-client-readiness.js"),
  "audit:managed-provider": path.join(MODULE_DIR, "check-managed-provider-readiness.js"),
  "audit:no-js-source": path.join(MODULE_DIR, "check-no-js-source.js"),
  "validate:release-attestation-signature": path.join(MODULE_DIR, "check-release-attestation-signature.js"),
  "build:managed-provider-evidence": path.join(MODULE_DIR, "build-managed-provider-evidence.js"),
  "release:manifest": path.join(MODULE_DIR, "build-publish-manifest.js"),
  "release:sbom": path.join(MODULE_DIR, "build-workspace-sbom.js"),
  "release:attestation": path.join(MODULE_DIR, "build-release-attestation.js"),
  "release:client-claim-report": path.join(MODULE_DIR, "build-released-client-claim-report.js"),
  "release:publication-org-rollout-report": path.join(MODULE_DIR, "build-publication-org-rollout-report.js"),
  "release:hosted-readiness-report": path.join(MODULE_DIR, "build-hosted-release-readiness-report.js"),
  "release:publication-bundle": path.join(MODULE_DIR, "build-release-publication-bundle.js"),
};

function usage() {
  const supportedTools = Object.keys(TOOL_MAP)
    .sort()
    .map((toolName) => \`  - \${toolName}\`)
    .join("\\n");
  return [
    "Usage: node dist-tools/exec-tool.js <tool> [-- <args...>]",
    "",
    "Supported tools:",
    supportedTools,
  ].join("\\n");
}

function parseInvocation(argv) {
  const [toolName, ...rest] = argv;
  if (!toolName || toolName === "--help" || toolName === "-h") {
    process.stdout.write(\`\${usage()}\\n\`);
    process.exit(0);
  }
  const args = rest[0] === "--" ? rest.slice(1) : rest;
  return { toolName, args };
}

async function main() {
  const { toolName, args } = parseInvocation(process.argv.slice(2));
  const scriptPath = TOOL_MAP[toolName];
  if (!scriptPath) {
    throw new Error(\`Unknown tool '\${toolName}'.\\n\\n\${usage()}\`);
  }

  const child = spawn(process.execPath, [scriptPath, ...args], {
    cwd: ROOT_DIR,
    env: process.env,
    stdio: "inherit",
  });

  await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal) {
        reject(new Error(\`Tool '\${toolName}' terminated by signal \${signal}\`));
        return;
      }
      if (code !== 0) {
        reject(new Error(\`Tool '\${toolName}' exited with status \${code}\`));
        return;
      }
      resolve();
    });
  });
}

main().catch((error) => {
  process.stderr.write(\`[exec-tool] \${error instanceof Error ? error.message : String(error)}\\n\`);
  process.exitCode = 1;
});
`;
}

function rootReadme(version) {
  return [
    "# aegaeon-sdk",
    "",
    "Scaffolded SDK workspace generated from the Aegaeon backend repository.",
    "",
    `- Version: \`${version}\``,
    "- Generated by: `scripts/sdk/scaffold_sdk_repo_workspace.ts`",
    "- Verified Core and evidence ingestion helpers: `tools-src/fetch-core.ts`, `tools-src/download-core-release.ts`, `tools-src/download-admin-sdk-evidence.ts`, `tools-src/download-managed-provider-evidence.ts`, `tools-src/verify-core.ts` (runtime JS emitted under `dist-tools/`)",
    "- Dispatch payload contract: `spec/sdk-repository-dispatch.schema.json`, `scripts/validation/validate_sdk_repository_dispatch_payload.py`",
    "- Release handoff contract: `spec/verified-core-handoff-manifest.schema.json`, `verified-core-handoff-manifest.json` (downloaded when present)",
    "- Client claim boundary: `spec/client-claim-boundary.current.json`, validated with `scripts/validation/validate_client_claim_boundary.py`",
    "- Client claim promotion gate: `spec/client-claim-promotion.current.json`, audited with `tools-src/check-client-claim-promotion.ts` / `dist-tools/check-client-claim-promotion.js`",
    "- Released client claim policy: `spec/released-client-claim.current.json`, validated with `scripts/validation/validate_released_client_claim.py`",
    "- Released client claim activation gate: `tools-src/check-released-client-claim-activation.ts` / `dist-tools/check-released-client-claim-activation.js`",
    "- Released client readiness gate: `tools-src/check-released-client-readiness.ts` / `dist-tools/check-released-client-readiness.js`",
    "- Strict types policy: `spec/strict-types.current.json`, audited with `tools-src/check-strict-types.ts` / `dist-tools/check-strict-types.js`",
    "- External-boundary naming policy: `spec/external-boundary-naming.current.json`, audited with `tools-src/check-external-boundary-naming.ts` / `dist-tools/check-external-boundary-naming.js`",
    "- Repository settings policy: `spec/repository-settings.current.json`, audited with `tools-src/check-repository-settings.ts` / `dist-tools/check-repository-settings.js`",
    "- Release custody policy: `spec/release-custody.current.json`, audited with `tools-src/check-release-custody.ts` / `dist-tools/check-release-custody.js`",
    "- Workflow inventory policy: `spec/workflow-inventory.current.json`, audited with `tools-src/check-workflow-inventory.ts` / `dist-tools/check-workflow-inventory.js`",
    "- Hosted evidence source policy: `spec/hosted-evidence-sources.current.json`, audited with `tools-src/check-hosted-evidence-sources.ts` / `dist-tools/check-hosted-evidence-sources.js`",
    "- Managed-provider config contract: `spec/managed-external-provider.schema.json`, validated with `scripts/validation/validate_managed_external_provider_config.py`",
    "- Managed-provider evidence schema: `spec/managed-provider-evidence.schema.json`, built with `tools-src/build-managed-provider-evidence.ts` / `dist-tools/build-managed-provider-evidence.js` and validated with `scripts/validation/validate_managed_provider_evidence.py`",
    "- Admin-console SDK evidence schema: `spec/admin-sdk-evidence.schema.json`, validated with `scripts/validation/validate_admin_sdk_evidence.py`",
    "- Admin-console evidence ingestion helper: `tools-src/download-admin-sdk-evidence.ts` / `dist-tools/download-admin-sdk-evidence.js`",
    "- Managed-provider evidence ingestion helpers: `tools-src/download-managed-provider-evidence.ts` / `dist-tools/download-managed-provider-evidence.js` and `tools-src/import-managed-provider-evidence.ts` / `dist-tools/import-managed-provider-evidence.js`",
    "- One-shot client evidence gate runner: `tools-src/run-client-evidence-gates.ts` / `dist-tools/run-client-evidence-gates.js`",
    "- Hosted evidence runner: `tools-src/run-hosted-evidence.ts` / `dist-tools/run-hosted-evidence.js`",
    "- Managed-provider readiness audit: `tools-src/check-managed-provider-readiness.ts` / `dist-tools/check-managed-provider-readiness.js`",
    "- Dispatch payload helpers: `tools-src/materialize-sdk-dispatch-payload.ts`, `tools-src/export-sdk-dispatch-env.ts` (runtime JS under `dist-tools/`)",
    "- Branch-protection policy: `spec/branch-protection.main.json`, audited with `tools-src/check-branch-protection.ts` / `dist-tools/check-branch-protection.js`",
    "- Public-key helper: `tools-src/materialize-verified-core-public-key.ts` / `dist-tools/materialize-verified-core-public-key.js` (`AEGAEON_VERIFIED_CORE_PUBKEY` or `AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF`)",
    "- Release attestation scaffold: `spec/sdk-release-attestation.schema.json`, `spec/sdk-release-attestation-signature.schema.json`, `tools-src/build-release-attestation.ts`, `tools-src/check-release-attestation-signature.ts`, `scripts/validation/validate_sdk_release_attestation.py`, `scripts/validation/validate_sdk_release_attestation_signature.py`",
    "- Release publication bundle: `spec/sdk-release-publication-bundle.schema.json`, `tools-src/build-workspace-sbom.ts`, `tools-src/check-client-claim-promotion.ts`, `tools-src/build-released-client-claim-report.ts`, `tools-src/check-released-client-readiness.ts`, `tools-src/build-release-publication-bundle.ts`, `scripts/validation/validate_released_client_claim_report.py`, `scripts/validation/validate_sdk_release_publication_bundle.py`",
    "- Release scaffolding: `.changeset/config.json`, `tsconfig.base.json`, `tsconfig.json`, `tsconfig.tools.json`, `tsconfig.tests.node.json`, `tsconfig.tests.browser.json`, `tools-src/*.ts`, preseeded `dist-tools/*.js`, preseeded `dist-tests/node/*.js`, browser/support TypeScript tests under `tests/browser/*.ts` and `tests/providers/**/*.ts`, and workflow stubs under `.github/workflows/` (`lint.yml`, `verify-core.yml`, `ci.yml`, `playwright.yml`, `managed-provider-evidence.yml`, `client-claim-promotion.yml`, `released-client-readiness.yml`, `publish.yml`, `publication-org-rollout.yml`)",
    "- Repository cutover checklist: `MIGRATION.md`",
    "",
    "This scaffold carries the current package-shaped surfaces for:",
    "- `@aegaeon/verified-core`",
    "- `@aegaeon/runtime-node`",
    "- `@aegaeon/runtime-web`",
    "- `@aegaeon/management-client` (alpha)",
    "- `@aegaeon/issuer-spa` (alpha)",
    "- `@aegaeon/rp-core` (alpha)",
    "",
    "Suggested first commands after moving this scaffold into `aegaeon-sdk`:",
    "1. `nix develop .`",
    "2. `cd sdk && pnpm install --frozen-lockfile`",
    "3. `pnpm run verify-core -- --manifest <path> --wasm <path>` or `pnpm run download-core:release -- --artifact-dir <path>`",
    "4. Inspect `verified-core-handoff-manifest.json` when it is present in the downloaded release bundle.",
    "5. validate `spec/client-claim-boundary.current.json` with `pnpm run validate:client-claim-boundary` and keep `spec/released-client-claim.current.json` aligned with the intended released wording.",
    "6. Read `MIGRATION.md`, review `spec/external-boundary-naming.current.json`, `spec/repository-settings.current.json`, `spec/release-custody.current.json`, `spec/workflow-inventory.current.json`, `spec/hosted-evidence-sources.current.json`, `spec/client-claim-promotion.current.json`, and `spec/released-client-claim.current.json`, validate managed-provider configs against `spec/managed-external-provider.schema.json`, run `pnpm run audit:external-boundary-naming` before any external-boundary rename, run `pnpm run audit:managed-provider -- --config tests/providers/managed/managed-provider.example.json` before the first tenant-backed lane, run `pnpm run audit:hosted-evidence-sources` before wiring hosted evidence sources, configure branch protection from `spec/branch-protection.main.json`, and apply the repository cutover checklist before enabling required CI lanes.",
    "7. `pnpm run ci`",
    "8. `pnpm run pack:workspace`",
    "9. `pnpm run release:manifest && pnpm run release:sbom && pnpm run release:attestation && pnpm run validate:release-attestation && pnpm run validate:release-attestation-signature && pnpm run run:client-evidence-gates -- --mode promotion && pnpm run run:client-evidence-gates -- --mode readiness --claim-active ${AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE:-false}`",
    "10. `pnpm run test:provider-dex-browser -- --required` and `pnpm run test:provider-keycloak-browser -- --required`",
    "11. after a real managed-provider browser pass, materialize `pnpm run build:managed-provider-evidence -- --config tests/providers/managed/managed-provider.example.json --provider-class commercial --lane-name external-provider-managed --status passed --hosted true`",
    "12. materialize `managed-provider-evidence.json` from the hosted managed-provider lane with `pnpm run download:managed-provider-evidence -- --artifact-dir <managed-provider-evidence-dir>` (or use the hosted artifact path through `AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY`, set `dispatch_hosted=true` on the hosted readiness/publish lanes to trigger fresh evidence capture first, or use the explicit `AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON` override when a hosted artifact cannot be wired directly; hosted import flows can normalize that JSON via `pnpm run import:managed-provider-evidence -- --evidence <path>`) and validate it with `pnpm run validate:managed-provider-evidence -- .artifacts/managed-provider/managed-provider-evidence.json`",
    "13. materialize `admin-sdk-evidence.json` from the sibling admin-console stack lane with `pnpm run download:admin-sdk-evidence -- --artifact-dir <admin-sdk-evidence-dir>` (or use the hosted artifact path through `AEGAEON_ADMIN_CONSOLE_REPOSITORY`, set `dispatch_hosted=true` on the hosted readiness/publish lanes to trigger fresh admin evidence capture first, or use the explicit `AEGAEON_ADMIN_SDK_EVIDENCE_JSON` override when a hosted artifact cannot be wired directly) and validate it with `pnpm run validate:admin-sdk-evidence -- .artifacts/admin-sdk/admin-sdk-evidence.json`",
    "14. run `pnpm run run:real-tenant-readiness -- --managed-provider-config tests/providers/managed/managed-provider.example.json --mode readiness --claim-active ${AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE:-false}` when a single command should dispatch hosted admin/managed evidence and execute the readiness gate",
    "15. run `pnpm run run:client-evidence-gates -- --mode readiness --claim-active ${AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE:-false}` before widening released client wording, or use the hosted `released-client-readiness.yml` lane with `dispatch_hosted=true` when fresh hosted evidence should be captured first",
    "16. optionally materialize a credential-backed commercial provider config and run `pnpm run audit:managed-provider -- --config tests/providers/managed/managed-provider.example.json`",
    "17. optionally materialize a credential-backed commercial provider config and run `pnpm run test:provider-managed-browser -- --config tests/providers/managed/managed-provider.example.json`",
    "",
    "Next steps after generation:",
    "1. Move this scaffold into the dedicated `aegaeon-sdk` repository.",
    "2. Apply `MIGRATION.md` before enabling `repository_dispatch` or npm publish.",
    "3. Replace the workflow stubs under `.github/workflows/` with repository-specific secrets, artifact download, readiness-gate wiring, publish wiring, and any managed external-provider credentials.",
    "4. Keep the pre-release client-claim boundary, client-claim promotion gate, released-client policy, managed-provider evidence contract, admin-console SDK evidence contract, release-attestation scaffold, and release-publication bundle source-managed until the final released client claim is explicitly promoted.",
  ].join("\n");
}

function migrationChecklist(version) {
  return [
    "# Migration Checklist for `aegaeon-sdk`",
    "",
    "This checklist is generated by `scripts/sdk/scaffold_sdk_repo_workspace.ts`.",
    "Use it when moving this scaffold into the real separate SDK repository.",
    "",
    `- Scaffold version: \`${version}\``,
    "- Generated from: `aegaeon/scripts/sdk/scaffold_sdk_repo_workspace.ts`",
    "",
    "## 1. Repository Bootstrap",
    "",
    "1. Create the target repository and copy this scaffold as the initial tree.",
    "2. Set the default branch to `main`.",
    "3. Run `pnpm install --frozen-lockfile`.",
    "4. Run `pnpm run ci` locally before enabling required checks.",
    "5. Keep `spec/external-boundary-naming.current.json`, `spec/repository-settings.current.json`, `spec/release-custody.current.json`, `spec/workflow-inventory.current.json`, `spec/hosted-evidence-sources.current.json`, `spec/managed-external-provider.schema.json`, `spec/managed-provider-evidence.schema.json`, `spec/admin-sdk-evidence.schema.json`, `spec/client-claim-boundary.current.json`, `spec/client-claim-promotion.current.json`, `spec/released-client-claim.current.json`, and `spec/branch-protection.main.json` as the source of truth for repository configuration and client-claim posture.",
    "",
    "## 2. Repository Secrets and Inputs",
    "",
    "Configure the following repository secrets before enabling signed Verified Core ingestion:",
    "",
    "- `AEGAEON_VERIFIED_CORE_PUBKEY` or `AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF`",
    "- `AEGAEON_OP_SERVICE_ACCOUNT_TOKEN` when `AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF` is used",
    "- `AEGAEON_NPM_TOKEN` (current real-publish baseline when `AEGAEON_REAL_PUBLISH_ENABLED=true`)",
    "",
    "Configure the following repository variables:",
    "",
    "- `AEGAEON_CORE_RELEASE_REPO`",
    "- optional `AEGAEON_NPM_DIST_TAG` (defaults to `latest` when omitted)",
    "- optional `AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED` (`1` / `true` to enable the managed commercial upstream lane)",
    "- optional `AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON` (JSON payload matching `spec/managed-external-provider.schema.json`; see `tests/providers/managed/managed-provider.example.json`)",
    "- optional `AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY` (for hosted `managed-provider-evidence` artifact download; defaults to the current SDK repo)",
    "- optional `AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF` (defaults to `main` for hosted managed-provider evidence download)",
    "- optional `AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW` (defaults to `managed-provider-evidence.yml`)",
    "- optional `AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT` (defaults to `managed-provider-evidence`)",
    "- optional `AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON` (explicit JSON override when the hosted artifact cannot be wired directly; hosted lanes normalize it through `pnpm run import:managed-provider-evidence`)",
    "- optional `AEGAEON_ADMIN_CONSOLE_REPOSITORY` (for hosted `admin-sdk-evidence` artifact download)",
    "- optional `AEGAEON_ADMIN_CONSOLE_REF` (defaults to `main` for hosted admin evidence download)",
    "- optional `AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW` (defaults to `stack-e2e.yml`)",
    "- optional `AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT` (defaults to `admin-sdk-evidence`)",
    "- optional `AEGAEON_PUBLICATION_ORG_OWNER`",
    "- optional `AEGAEON_PUBLICATION_ORG_REPO`",
    "- optional `AEGAEON_PUBLICATION_ORG_BRANCH` (defaults to `main`)",
    "",
    "Keep these deferred publication-time secrets out of the active sandbox baseline until they are actually used:",
    "",
    "- `AEGAEON_COSIGN_KEY` (required only when `AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION=true`)",
    "- `AEGAEON_CARGO_REGISTRY_TOKEN` (required only when `AEGAEON_SDK_CARGO_PUBLISH_ENABLED=true`)",
    "",
    "Use `spec/release-custody.current.json` plus `pnpm run audit:release-custody` to decide when those deferred secrets become required.",
    "If hosted admin-console evidence comes from a separate or private repository, configure `AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN` so `dist-tools/download-admin-sdk-evidence.js` can download the `admin-sdk-evidence` artifact.",
    "If hosted managed-provider evidence comes from a separate or private repository, configure `AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN` so `dist-tools/download-managed-provider-evidence.js` can download the `managed-provider-evidence` artifact.",
    "Hosted `client-claim-promotion.yml`, `released-client-readiness.yml`, and `publish.yml` also accept `dispatch_hosted=true` when a run should trigger fresh hosted evidence capture before artifact download.",
    "",
    "Configure the backend repository separately when you want automatic handoff notifications:",
    "",
    "- backend secret: `AEGAEON_SDK_REPOSITORY_DISPATCH_TOKEN`",
    "- backend `release-core` input: `sdk_repo=<owner/aegaeon-sdk>`",
    "",
    "## 3. Verify Core Handoff Wiring",
    "",
    "1. Replace every `OWNER/REPO` placeholder in `.github/workflows/verify-core.yml`.",
    "2. Decide whether the SDK repo consumes:",
    "   - release-tag downloads through `pnpm run download-core:release`, or",
    "   - direct artefact paths through `pnpm run verify-core`.",
    "3. Keep all schema checks enabled:",
    "   - `pnpm run validate:sdk-dispatch -- .cache/sdk-repository-dispatch.json`",
    "   - `pnpm run validate:core-handoff -- .cache/verified-core/verified-core-handoff-manifest.json`",
    "   - `pnpm run validate:managed-provider-config -- .cache/managed-external-provider.json`",
    "   - `pnpm run validate:client-claim-boundary`",
    "4. Keep the repository-settings audit fail-closed for the managed-provider lane: if `AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED=true`, require both `AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON` and the login secret set.",
    "5. Run the managed-provider readiness audit before the first hosted tenant-backed run:",
    "",
    "```bash",
    "pnpm run audit:managed-provider -- --config tests/providers/managed/managed-provider.example.json",
    "```",
    "",
    "6. After the first hosted tenant-backed pass, materialize managed-provider evidence and keep it with the release evidence bundle:",
    "",
    "```bash",
    "pnpm run build:managed-provider-evidence -- --config tests/providers/managed/managed-provider.example.json --provider-class commercial --lane-name external-provider-managed --status passed --hosted true",
    "pnpm run validate:managed-provider-evidence -- .artifacts/managed-provider/managed-provider-evidence.json",
    "pnpm run download:managed-provider-evidence -- --artifact-dir <managed-provider-evidence-dir>",
    "pnpm run download:admin-sdk-evidence -- --artifact-dir <admin-sdk-evidence-dir>",
    "pnpm run validate:admin-sdk-evidence -- .artifacts/admin-sdk/admin-sdk-evidence.json",
    "```",
    "",
    "7. Keep fail-closed behaviour for signed artefacts with no public key.",
    "8. Audit the repository settings contract before the first hosted run:",
    "",
    "```bash",
    "pnpm run audit:repo-settings -- --owner <owner> --repo aegaeon-sdk",
    "pnpm run audit:hosted-evidence-sources",
    "pnpm run audit:release-custody -- --owner <owner> --repo aegaeon-sdk",
    "```",
    "",
    "## 4. Required CI Lanes",
    "",
    "Promote these workflow jobs to required repository checks after the first green run:",
    "",
    "- `CI - Lint / Lint`",
    "- `CI - Lint / TypeScript Lint`",
    "- `SDK Verify Core / Verify Core`",
    "- `CI - SDK / Packages`",
    "- `CI - SDK / Browser Smoke`",
    "- `SDK Browser E2E / Core Playwright`",
    "- `SDK Browser E2E / External Provider (Dex)`",
    "",
    "After applying these settings on the hosted forge, audit them with:",
    "",
    "```bash",
    "pnpm run audit:repo-settings -- --owner <owner> --repo aegaeon-sdk",
    "pnpm run audit:release-custody -- --owner <owner> --repo aegaeon-sdk",
    "pnpm run audit:branch-protection -- --owner <owner> --repo aegaeon-sdk",
    "```",
    "",
    "## 5. Browser and Diagnostics Bring-up",
    "",
    "1. Confirm the runner allows localhost bind and headless Chrome.",
    "2. Keep browser artefact upload enabled:",
    "   - `.artifacts/browser-smoke/`",
    "   - `playwright-report/`",
    "   - `test-results/`",
    "3. Fail the migration if browser smoke stays in skip mode on the target CI runner.",
    "",
    "## 6. First Dry Run",
    "",
    "Run the following after secrets and workflow placeholders are configured:",
    "",
    "```bash",
    "pnpm run download-core:release -- --artifact-dir <verified-core-bundle>",
    "pnpm run verify-core -- --manifest .cache/verified-core/manifest.json --wasm .cache/verified-core/verified_core.wasm",
    "pnpm run validate:client-claim-boundary",
    "pnpm run validate:released-client-claim",
    "pnpm run ci",
    "pnpm run pack:workspace",
    "pnpm run release:manifest",
    "pnpm run release:sbom",
    "pnpm run release:attestation",
    "pnpm run validate:release-attestation",
    "pnpm run validate:release-attestation-signature",
    "pnpm run run:client-evidence-gates -- --mode readiness --claim-active ${AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE:-false}",
    "pnpm run build:managed-provider-evidence -- --config tests/providers/managed/managed-provider.example.json --provider-class commercial --lane-name external-provider-managed --status passed --hosted true",
    "pnpm run validate:managed-provider-evidence -- .artifacts/managed-provider/managed-provider-evidence.json",
    "pnpm run validate:client-claim-promotion",
    "pnpm run validate:admin-sdk-evidence -- .artifacts/admin-sdk/admin-sdk-evidence.json",
    "pnpm run run:client-evidence-gates -- --mode readiness --claim-active ${AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE:-false}",
    "pnpm run audit:repo-settings -- --owner <owner> --repo aegaeon-sdk",
    "pnpm run audit:release-custody -- --owner <owner> --repo aegaeon-sdk",
    "pnpm run audit:branch-protection -- --owner <owner> --repo aegaeon-sdk",
    "pnpm run test:playwright",
    "pnpm run test:provider-dex-browser -- --required",
    "pnpm run test:provider-keycloak-browser -- --required",
    "# optional credential-backed commercial lane when config + secrets are present:",
    "pnpm run audit:managed-provider -- --config tests/providers/managed/managed-provider.example.json",
    "pnpm run test:provider-managed-browser -- --config tests/providers/managed/managed-provider.example.json",
    "```",
    "",
    "## 7. Release Readiness Exit Criteria",
    "",
    "Do not treat the separate SDK repository as ready until all of the following are true:",
    "",
    "- `SDK Verify Core / Verify Core` is green from a real handoff bundle",
    "- `CI - SDK / Browser Smoke` is green on a browser-capable runner",
    "- `SDK Browser E2E / Core Playwright` is green and uploads diagnostics on failure",
    "- `SDK Browser E2E / External Provider (Dex)` is green on a browser-capable hosted runner",
    "- `SDK Browser E2E / External Provider (Keycloak)` is green on a browser-capable hosted runner",
    "- the optional `SDK Browser E2E / External Provider (Managed)` lane is green when a credential-backed provider config is enabled",
    "- `pnpm run audit:repo-settings -- --owner <owner> --repo aegaeon-sdk` reports a match",
    "- `pnpm run audit:release-custody -- --owner <owner> --repo aegaeon-sdk` reports a match",
    "- `pnpm run audit:branch-protection -- --owner <owner> --repo aegaeon-sdk` reports a match",
    "- the backend `release-core` workflow can deliver a valid `repository_dispatch` payload",
    "- the backend and SDK repositories agree on the latest `spec/sdk-repository-dispatch.schema.json`",
    "- the backend and SDK repositories agree on the latest `spec/verified-core-handoff-manifest.schema.json`",
    "- the backend and SDK repositories agree on the latest `spec/client-claim-boundary.current.json`",
    "- the backend and SDK repositories agree on the latest `spec/client-claim-promotion.current.json`",
    "- `.artifacts/managed-provider/managed-provider-evidence.json` exists and validates after the hosted commercial-provider lane passes",
    "- `.artifacts/release/release-attestation.json` exists, validates, still records any deferred publication-time obligations that remain open, and its detached signature verifies when signing is enabled",
    "- `.artifacts/release/sdk-workspace-sbom.cdx.json` and `.artifacts/release/release-publication-bundle.json` exist and validate",
  ].join("\n");
}

function workflowVerifyCore() {
  return `name: SDK Verify Core
on:
  push:
    branches:
      - main
  pull_request:
  workflow_call:
    inputs:
      core_repo:
        type: string
        required: false
      core_release_tag:
        type: string
        required: false
      manifest_path:
        type: string
        required: false
      wasm_path:
        type: string
        required: false
      signature_path:
        type: string
        required: false
      public_key_path:
        type: string
        required: false
  workflow_dispatch:
    inputs:
      core_repo:
        description: Backend repository that publishes Verified Core release assets
        required: false
      core_release_tag:
        description: Verified Core release tag
        required: false
      manifest_path:
        description: Direct manifest path fallback
        required: false
      wasm_path:
        description: Direct wasm path fallback
        required: false
      signature_path:
        description: Optional Ed25519 signature path
        required: false
      public_key_path:
        description: Optional Ed25519 public key path
        required: false
  repository_dispatch:
    types:
      - verified-core-release
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
permissions:
  contents: read
concurrency:
  group: verify-core-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  fetch-and-test:
    name: Verify Core
    runs-on: ubuntu-latest
    env:
      AEGAEON_CORE_RELEASE_REPO: \${{ vars.AEGAEON_CORE_RELEASE_REPO || '' }}
      AEGAEON_CORE_RELEASE_TAG: ""
      AEGAEON_CORE_MANIFEST_PATH: ""
      AEGAEON_CORE_WASM_PATH: ""
      AEGAEON_CORE_SIGNATURE_PATH: ""
      AEGAEON_CORE_PUBLIC_KEY_PATH: ""
      AEGAEON_CORE_HANDOFF_MANIFEST_PATH: ""
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - name: Apply workflow_dispatch inputs
        if: github.event_name == 'workflow_dispatch'
        env:
          INPUT_CORE_REPO: \${{ github.event.inputs.core_repo || '' }}
          INPUT_CORE_RELEASE_TAG: \${{ github.event.inputs.core_release_tag || '' }}
          INPUT_MANIFEST_PATH: \${{ github.event.inputs.manifest_path || '' }}
          INPUT_WASM_PATH: \${{ github.event.inputs.wasm_path || '' }}
          INPUT_SIGNATURE_PATH: \${{ github.event.inputs.signature_path || '' }}
          INPUT_PUBLIC_KEY_PATH: \${{ github.event.inputs.public_key_path || '' }}
        run: |
          {
            [ -n "$INPUT_CORE_REPO" ] && echo "AEGAEON_CORE_RELEASE_REPO=$INPUT_CORE_REPO"
            [ -n "$INPUT_CORE_RELEASE_TAG" ] && echo "AEGAEON_CORE_RELEASE_TAG=$INPUT_CORE_RELEASE_TAG"
            [ -n "$INPUT_MANIFEST_PATH" ] && echo "AEGAEON_CORE_MANIFEST_PATH=$INPUT_MANIFEST_PATH"
            [ -n "$INPUT_WASM_PATH" ] && echo "AEGAEON_CORE_WASM_PATH=$INPUT_WASM_PATH"
            [ -n "$INPUT_SIGNATURE_PATH" ] && echo "AEGAEON_CORE_SIGNATURE_PATH=$INPUT_SIGNATURE_PATH"
            [ -n "$INPUT_PUBLIC_KEY_PATH" ] && echo "AEGAEON_CORE_PUBLIC_KEY_PATH=$INPUT_PUBLIC_KEY_PATH"
          } >> "$GITHUB_ENV"
      - name: Apply workflow_call inputs
        if: github.event_name == 'workflow_call'
        env:
          INPUT_CORE_REPO: \${{ inputs.core_repo || '' }}
          INPUT_CORE_RELEASE_TAG: \${{ inputs.core_release_tag || '' }}
          INPUT_MANIFEST_PATH: \${{ inputs.manifest_path || '' }}
          INPUT_WASM_PATH: \${{ inputs.wasm_path || '' }}
          INPUT_SIGNATURE_PATH: \${{ inputs.signature_path || '' }}
          INPUT_PUBLIC_KEY_PATH: \${{ inputs.public_key_path || '' }}
        run: |
          {
            [ -n "$INPUT_CORE_REPO" ] && echo "AEGAEON_CORE_RELEASE_REPO=$INPUT_CORE_REPO"
            [ -n "$INPUT_CORE_RELEASE_TAG" ] && echo "AEGAEON_CORE_RELEASE_TAG=$INPUT_CORE_RELEASE_TAG"
            [ -n "$INPUT_MANIFEST_PATH" ] && echo "AEGAEON_CORE_MANIFEST_PATH=$INPUT_MANIFEST_PATH"
            [ -n "$INPUT_WASM_PATH" ] && echo "AEGAEON_CORE_WASM_PATH=$INPUT_WASM_PATH"
            [ -n "$INPUT_SIGNATURE_PATH" ] && echo "AEGAEON_CORE_SIGNATURE_PATH=$INPUT_SIGNATURE_PATH"
            [ -n "$INPUT_PUBLIC_KEY_PATH" ] && echo "AEGAEON_CORE_PUBLIC_KEY_PATH=$INPUT_PUBLIC_KEY_PATH"
          } >> "$GITHUB_ENV"
      - name: Materialize repository_dispatch payload
        if: github.event_name == 'repository_dispatch'
        env:
          AEGAEON_DISPATCH_EVENT_TYPE: \${{ github.event.action }}
          AEGAEON_DISPATCH_CLIENT_PAYLOAD: \${{ toJson(github.event.client_payload) }}
          AEGAEON_DISPATCH_OUTPUT_PATH: .cache/sdk-repository-dispatch.json
        run: |
          mkdir -p sdk/.cache
          nix develop . --command bash -lc 'cd sdk && pnpm run materialize:sdk-dispatch'
      - name: Validate repository_dispatch payload
        if: github.event_name == 'repository_dispatch'
        run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:sdk-dispatch -- .cache/sdk-repository-dispatch.json'
      - name: Export validated repository_dispatch inputs
        if: github.event_name == 'repository_dispatch'
        run: nix develop . --command bash -lc 'cd sdk && pnpm run export:sdk-dispatch-env -- --payload .cache/sdk-repository-dispatch.json' >> "$GITHUB_ENV"
      - name: Select repository-local Verified Core artefact
        if: env.AEGAEON_CORE_RELEASE_TAG == '' && env.AEGAEON_CORE_MANIFEST_PATH == '' && env.AEGAEON_CORE_WASM_PATH == ''
        run: |
          echo "AEGAEON_CORE_MANIFEST_PATH=\${{ github.workspace }}/sdk/packages/verified-core/dist/manifest.json" >> "$GITHUB_ENV"
          echo "AEGAEON_CORE_WASM_PATH=\${{ github.workspace }}/sdk/packages/verified-core/dist/verified_core.wasm" >> "$GITHUB_ENV"
          if [ -f "sdk/packages/verified-core/dist/verified_core.wasm.sig" ]; then
            echo "AEGAEON_CORE_SIGNATURE_PATH=\${{ github.workspace }}/sdk/packages/verified-core/dist/verified_core.wasm.sig" >> "$GITHUB_ENV"
          fi
          if [ -f "sdk/packages/verified-core/dist/verified-core-handoff-manifest.json" ]; then
            echo "AEGAEON_CORE_HANDOFF_MANIFEST_PATH=\${{ github.workspace }}/sdk/packages/verified-core/dist/verified-core-handoff-manifest.json" >> "$GITHUB_ENV"
          fi
      - name: Download release assets when a core tag is provided
        if: env.AEGAEON_CORE_RELEASE_TAG != ''
        run: nix develop . --command bash -lc "cd sdk && pnpm run download-core:release -- --repo \"$AEGAEON_CORE_RELEASE_REPO\" --tag \"$AEGAEON_CORE_RELEASE_TAG\" --out-dir .cache/verified-core"
      - name: Select downloaded release assets
        if: env.AEGAEON_CORE_RELEASE_TAG != ''
        run: |
          echo "AEGAEON_CORE_MANIFEST_PATH=\${{ github.workspace }}/sdk/.cache/verified-core/manifest.json" >> "$GITHUB_ENV"
          echo "AEGAEON_CORE_WASM_PATH=\${{ github.workspace }}/sdk/.cache/verified-core/verified_core.wasm" >> "$GITHUB_ENV"
          if [ -f "sdk/.cache/verified-core/verified_core.wasm.sig" ]; then
            echo "AEGAEON_CORE_SIGNATURE_PATH=\${{ github.workspace }}/sdk/.cache/verified-core/verified_core.wasm.sig" >> "$GITHUB_ENV"
          fi
          if [ -f "sdk/.cache/verified-core/verified-core-handoff-manifest.json" ]; then
            echo "AEGAEON_CORE_HANDOFF_MANIFEST_PATH=\${{ github.workspace }}/sdk/.cache/verified-core/verified-core-handoff-manifest.json" >> "$GITHUB_ENV"
          fi
      - name: Validate handoff manifest when present
        if: env.AEGAEON_CORE_HANDOFF_MANIFEST_PATH != ''
        run: nix develop . --command bash -lc "cd sdk && pnpm run validate:core-handoff -- \"$AEGAEON_CORE_HANDOFF_MANIFEST_PATH\""
      - name: Materialize public key from secret when needed
        if: env.AEGAEON_CORE_SIGNATURE_PATH != '' && env.AEGAEON_CORE_PUBLIC_KEY_PATH == ''
        env:
          AEGAEON_VERIFIED_CORE_PUBKEY: \${{ secrets.AEGAEON_VERIFIED_CORE_PUBKEY }}
          AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF: \${{ secrets.AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF }}
          AEGAEON_VERIFIED_CORE_PUBKEY_OUTPUT: .cache/verified-core.pub.pem
          AEGAEON_OP_SERVICE_ACCOUNT_TOKEN: \${{ secrets.AEGAEON_OP_SERVICE_ACCOUNT_TOKEN }}
        run: |
          if [ -z "$AEGAEON_VERIFIED_CORE_PUBKEY" ] && [ -z "$AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF" ]; then
            exit 0
          fi
          mkdir -p sdk/.cache
          nix develop . --command bash -lc 'cd sdk && pnpm run materialize:verified-core-public-key'
          echo "AEGAEON_CORE_PUBLIC_KEY_PATH=\${{ github.workspace }}/sdk/.cache/verified-core.pub.pem" >> "$GITHUB_ENV"
      - name: Require public key when signature is present
        if: env.AEGAEON_CORE_SIGNATURE_PATH != '' && env.AEGAEON_CORE_PUBLIC_KEY_PATH == ''
        run: |
          echo "Signed artefact present but no public key path, AEGAEON_VERIFIED_CORE_PUBKEY, or AEGAEON_VERIFIED_CORE_PUBKEY_OP_REF secret is configured." >&2
          exit 1
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run verify-core'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run lint'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run typecheck'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run test'
      - name: Upload verified-core handoff artefacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: verified-core-handoff
          path: |
            sdk/.cache/sdk-repository-dispatch.json
            sdk/.cache/verified-core
            sdk/packages/verified-core/dist
          if-no-files-found: warn
          retention-days: 14
`;
}

function workflowCi() {
  return `name: CI - SDK
on:
  push:
    branches:
      - main
  pull_request:
  workflow_call:
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
permissions:
  contents: read
concurrency:
  group: ci-\${{ github.workflow }}-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  sdk:
    name: Packages
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run ci:packages'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run pack:workspace'
      - name: Upload workspace packages
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: workspace-packages
          path: sdk/*.tgz
          if-no-files-found: warn
          retention-days: 14
  browser-smoke:
    name: Browser Smoke
    runs-on: ubuntu-latest
    needs: sdk
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && mkdir -p .artifacts/browser-smoke && pnpm run test:browser-smoke -- --artifact-dir .artifacts/browser-smoke'
      - name: Upload browser smoke diagnostics
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: browser-smoke-diagnostics
          path: sdk/.artifacts/browser-smoke
          if-no-files-found: warn
          retention-days: 14
`;
}

function workflowLint() {
  return `name: CI - Lint
on:
  push:
    branches:
      - main
  pull_request:
  workflow_dispatch:
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
permissions:
  contents: read
concurrency:
  group: lint-\${{ github.workflow }}-\${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - name: Install SDK dependencies (sdk/)
        run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - name: Run pre-commit hooks
        run: PRE_COMMIT_HOME=/tmp/pre-commit-sdk nix develop . --command pre-commit run --all-files
      - name: Run workflow inventory audit
        run: nix develop . --command bash -lc 'cd sdk && pnpm run audit:workflow-inventory'
      - name: Lint commit messages (push)
        if: github.event_name == 'push'
        run: |
          if [ "\${{ github.event.before }}" = "0000000000000000000000000000000000000000" ]; then
            if [ "\${{ github.ref_name }}" = "\${{ github.event.repository.default_branch }}" ]; then
              nix develop . --command ./scripts/commitlint-range.sh --to HEAD
            else
              git fetch origin "\${{ github.event.repository.default_branch }}" --depth=1
              base_sha="$(git merge-base HEAD "origin/\${{ github.event.repository.default_branch }}" || true)"
              nix develop . --command ./scripts/commitlint-range.sh --from "$base_sha" --to HEAD
            fi
          else
            nix develop . --command ./scripts/commitlint-range.sh --from "\${{ github.event.before }}" --to "\${{ github.sha }}"
          fi
      - name: Lint commit messages (pull_request)
        if: github.event_name == 'pull_request'
        run: |
          git fetch origin "\${{ github.base_ref }}" --depth=1
          base_sha="$(git merge-base HEAD "origin/\${{ github.base_ref }}" || true)"
          nix develop . --command ./scripts/commitlint-range.sh --from "$base_sha" --to HEAD
      - name: Lint PR title
        if: github.event_name == 'pull_request'
        env:
          PR_TITLE: \${{ github.event.pull_request.title }}
        run: |
          printf '%s\n' "$PR_TITLE" > /tmp/pr-title
          nix develop . --command commitlint --edit /tmp/pr-title
  typescript-lint:
    name: TypeScript Lint
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - name: Install SDK dependencies (sdk/)
        run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - name: Run TypeScript lint
        run: nix develop . --command bash -lc 'cd sdk && pnpm run lint'
      - name: Run TypeScript type checks
        run: nix develop . --command bash -lc 'cd sdk && pnpm run typecheck'
      - name: Run strict TypeScript policy audit
        run: nix develop . --command bash -lc 'cd sdk && pnpm run audit:strict-types'
`;
}

function workflowPublish() {
  return `name: SDK Publish
on:
  workflow_dispatch:
    inputs:
      dispatch_hosted:
        description: Dispatch hosted evidence workflows instead of downloading the latest successful artifacts
        required: false
        default: "false"
      dry_run:
        description: Run publish in dry-run mode
        required: false
        default: "true"
      dist_tag:
        description: npm dist-tag for publication
        required: false
        default: latest
      claim_active:
        description: Override released-client claim active flag for one-off publish runs
        required: false
        default: "false"
      admin_sdk_evidence_json:
        description: Inline admin-sdk-evidence JSON override
        required: false
      managed_provider_evidence_json:
        description: Inline managed-provider-evidence JSON override
        required: false
      publication_org_branch_protection_status:
        description: Publication-org branch protection rollout status
        required: false
        default: pending
      publication_org_secret_rollout_status:
        description: Publication-org secret rollout status
        required: false
        default: pending
permissions:
  contents: write
  id-token: write
  actions: read
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
concurrency:
  group: publish-\${{ github.ref }}
  cancel-in-progress: false
jobs:
  preflight-core:
    uses: ./.github/workflows/verify-core.yml
  preflight-ci:
    uses: ./.github/workflows/ci.yml
  preflight-playwright:
    uses: ./.github/workflows/playwright.yml
  release:
    name: Publish
    needs:
      - preflight-core
      - preflight-ci
      - preflight-playwright
    runs-on: ubuntu-latest
    env:
      AEGAEON_CLIENT_EVIDENCE_DISPATCH_HOSTED: \${{ github.event.inputs.dispatch_hosted || 'false' }}
      AEGAEON_NPM_DIST_TAG: \${{ github.event.inputs.dist_tag || vars.AEGAEON_NPM_DIST_TAG || 'latest' }}
      AEGAEON_REAL_PUBLISH_ENABLED: \${{ github.event.inputs.dry_run != 'true' && 'true' || 'false' }}
      AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE: \${{ github.event.inputs.claim_active || vars.AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE || 'false' }}
      AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION: \${{ vars.AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION || 'false' }}
      AEGAEON_SDK_SBOM_PUBLICATION: \${{ vars.AEGAEON_SDK_SBOM_PUBLICATION || 'false' }}
      AEGAEON_SDK_CARGO_PUBLISH_ENABLED: \${{ vars.AEGAEON_SDK_CARGO_PUBLISH_ENABLED || 'false' }}
      AEGAEON_ADMIN_SDK_EVIDENCE_JSON: \${{ github.event.inputs.admin_sdk_evidence_json || vars.AEGAEON_ADMIN_SDK_EVIDENCE_JSON || '' }}
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: \${{ vars.AEGAEON_ADMIN_CONSOLE_REPOSITORY || '' }}
      AEGAEON_ADMIN_CONSOLE_REF: \${{ vars.AEGAEON_ADMIN_CONSOLE_REF || 'main' }}
      AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW: \${{ vars.AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW || 'stack-e2e.yml' }}
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: \${{ vars.AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT || 'admin-sdk-evidence' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON: \${{ github.event.inputs.managed_provider_evidence_json || vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON || '' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY || github.repository }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF || 'main' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW || 'managed-provider-evidence.yml' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT || 'managed-provider-evidence' }}
      AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS: \${{ github.event.inputs.publication_org_branch_protection_status || vars.AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS || 'pending' }}
      AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS: \${{ github.event.inputs.publication_org_secret_rollout_status || vars.AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS || 'pending' }}
      AEGAEON_COSIGN_KEY: \${{ secrets.AEGAEON_COSIGN_KEY }}
      AEGAEON_COSIGN_PASSWORD: \${{ secrets.AEGAEON_COSIGN_PASSWORD }}
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:client-claim-boundary'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:released-client-claim'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run pack:workspace'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:manifest'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:sbom'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:attestation'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:release-attestation'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:release-attestation-signature'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:client-claim-promotion'
      - name: Run client evidence gates (readiness)
        env:
          AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN: \${{ secrets.AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN || github.token }}
          AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN: \${{ secrets.AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN || github.token }}
        run: nix develop . --command bash -lc "cd sdk && pnpm run run:client-evidence-gates -- --mode readiness --claim-active \\\"\$AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE\\\""
      - name: Require main branch and publish token
        if: github.event.inputs.dry_run != 'true'
        env:
          NODE_AUTH_TOKEN: \${{ secrets.AEGAEON_NPM_TOKEN }}
        run: |
          if [ "\$GITHUB_REF" != "refs/heads/main" ]; then
            echo "Refusing to publish from non-main ref: \$GITHUB_REF" >&2
            exit 1
          fi
          if [ -z "\$NODE_AUTH_TOKEN" ]; then
            echo "AEGAEON_NPM_TOKEN is required for a real publish." >&2
            exit 1
          fi
      - name: Dry-run changeset status
        if: github.event.inputs.dry_run == 'true'
        run: nix develop . --command bash -lc 'cd sdk && pnpm dlx changeset status'
      - name: Publish packages
        if: github.event.inputs.dry_run != 'true'
        env:
          NODE_AUTH_TOKEN: \${{ secrets.AEGAEON_NPM_TOKEN }}
          NPM_CONFIG_PROVENANCE: "true"
          NPM_CONFIG_ACCESS: public
        run: nix develop . --command bash -lc "cd sdk && pnpm run release:publish -- --tag \\\"\$AEGAEON_NPM_DIST_TAG\\\""
      - name: Upload publish artefacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: publish-workspace-release
          path: |
            sdk/*.tgz
            sdk/.artifacts/release
            sdk/.artifacts/admin-sdk/admin-sdk-evidence.json
            sdk/.artifacts/managed-provider/managed-provider-evidence.json
          if-no-files-found: warn
          retention-days: 14
`;
}

function workflowPublicationOrgRollout() {
  return `name: SDK Publication-Org Rollout
on:
  workflow_dispatch:
    inputs:
      publication_org_owner:
        description: Publication-org owner
        required: false
      publication_org_repo:
        description: Publication-org repository name
        required: false
      publication_org_branch:
        description: Publication-org branch name
        required: false
        default: main
  workflow_call:
permissions:
  contents: read
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
concurrency:
  group: publication-org-rollout-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  rollout:
    name: Publication-Org Rollout
    runs-on: ubuntu-latest
    env:
      AEGAEON_PUBLICATION_ORG_OWNER: \${{ github.event.inputs.publication_org_owner || vars.AEGAEON_PUBLICATION_ORG_OWNER || '' }}
      AEGAEON_PUBLICATION_ORG_REPO: \${{ github.event.inputs.publication_org_repo || vars.AEGAEON_PUBLICATION_ORG_REPO || '' }}
      AEGAEON_PUBLICATION_ORG_BRANCH: \${{ github.event.inputs.publication_org_branch || vars.AEGAEON_PUBLICATION_ORG_BRANCH || 'main' }}
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - name: Validate publication-org target
        run: |
          if [ -z "$AEGAEON_PUBLICATION_ORG_OWNER" ] || [ -z "$AEGAEON_PUBLICATION_ORG_REPO" ]; then
            echo "AEGAEON_PUBLICATION_ORG_OWNER and AEGAEON_PUBLICATION_ORG_REPO are required." >&2
            exit 1
          fi
      - run: nix develop . --command bash -lc "cd sdk && pnpm run release:publication-org-rollout-report -- --owner \"$AEGAEON_PUBLICATION_ORG_OWNER\" --repo \"$AEGAEON_PUBLICATION_ORG_REPO\" --branch \"$AEGAEON_PUBLICATION_ORG_BRANCH\""
        env:
          GH_TOKEN: \${{ github.token }}
      - name: Upload publication-org rollout report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: publication-org-rollout-report
          path: sdk/.artifacts/release/publication-org-rollout-report.json
          if-no-files-found: warn
          retention-days: 14
`;
}

function workflowReleasedClientReadiness() {
  return `name: SDK Released Client Readiness
on:
  workflow_dispatch:
    inputs:
      dispatch_hosted:
        description: Dispatch hosted evidence workflows instead of downloading the latest successful artifacts
        required: false
        default: "false"
      claim_active:
        description: Override released-client claim active flag for one-off readiness runs
        required: false
        default: "false"
      admin_sdk_evidence_json:
        description: Inline admin-sdk-evidence JSON override
        required: false
      managed_provider_evidence_json:
        description: Inline managed-provider-evidence JSON override
        required: false
      publication_org_branch_protection_status:
        description: Publication-org branch protection rollout status
        required: false
        default: pending
      publication_org_secret_rollout_status:
        description: Publication-org secret rollout status
        required: false
        default: pending
  workflow_call:
permissions:
  contents: read
  actions: read
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
concurrency:
  group: released-client-readiness-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  preflight-core:
    uses: ./.github/workflows/verify-core.yml
  preflight-ci:
    uses: ./.github/workflows/ci.yml
  preflight-playwright:
    uses: ./.github/workflows/playwright.yml
  readiness:
    name: Released Client Readiness
    needs:
      - preflight-core
      - preflight-ci
      - preflight-playwright
    runs-on: ubuntu-latest
    env:
      AEGAEON_CLIENT_EVIDENCE_DISPATCH_HOSTED: \${{ github.event.inputs.dispatch_hosted || 'false' }}
      AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE: \${{ github.event.inputs.claim_active || vars.AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE || 'false' }}
      AEGAEON_ADMIN_SDK_EVIDENCE_JSON: \${{ github.event.inputs.admin_sdk_evidence_json || vars.AEGAEON_ADMIN_SDK_EVIDENCE_JSON || '' }}
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: \${{ vars.AEGAEON_ADMIN_CONSOLE_REPOSITORY || '' }}
      AEGAEON_ADMIN_CONSOLE_REF: \${{ vars.AEGAEON_ADMIN_CONSOLE_REF || 'main' }}
      AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW: \${{ vars.AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW || 'stack-e2e.yml' }}
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: \${{ vars.AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT || 'admin-sdk-evidence' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON: \${{ github.event.inputs.managed_provider_evidence_json || vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON || '' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY || github.repository }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF || 'main' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW || 'managed-provider-evidence.yml' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT || 'managed-provider-evidence' }}
      AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS: \${{ github.event.inputs.publication_org_branch_protection_status || vars.AEGAEON_PUBLICATION_ORG_BRANCH_PROTECTION_STATUS || 'pending' }}
      AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS: \${{ github.event.inputs.publication_org_secret_rollout_status || vars.AEGAEON_PUBLICATION_ORG_SECRET_ROLLOUT_STATUS || 'pending' }}
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:released-client-claim'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:client-claim-boundary'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:client-claim-promotion'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run pack:workspace'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:manifest'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:sbom'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:attestation'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:release-attestation'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:release-attestation-signature'
      - name: Run client evidence gates (readiness)
        env:
          AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN: \${{ secrets.AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN || github.token }}
          AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN: \${{ secrets.AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN || github.token }}
        run: nix develop . --command bash -lc "cd sdk && pnpm run run:client-evidence-gates -- --mode readiness --claim-active \\\"\$AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE\\\""
      - name: Upload released-client readiness artefacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: released-client-readiness
          path: |
            sdk/.artifacts/release
            sdk/.artifacts/admin-sdk/admin-sdk-evidence.json
            sdk/.artifacts/managed-provider/managed-provider-evidence.json
          if-no-files-found: warn
          retention-days: 14
`;
}

function workflowClientClaimPromotion() {
  return `name: SDK Client Claim Promotion
on:
  workflow_dispatch:
    inputs:
      dispatch_hosted:
        description: Dispatch hosted evidence workflows instead of downloading the latest successful artifacts
        required: false
        default: "false"
      admin_sdk_evidence_json:
        description: Inline admin-sdk-evidence JSON override
        required: false
      managed_provider_evidence_json:
        description: Inline managed-provider-evidence JSON override
        required: false
  workflow_call:
permissions:
  contents: read
  actions: read
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
concurrency:
  group: client-claim-promotion-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  preflight-core:
    uses: ./.github/workflows/verify-core.yml
  preflight-ci:
    uses: ./.github/workflows/ci.yml
  preflight-playwright:
    uses: ./.github/workflows/playwright.yml
  promotion:
    name: Client Claim Promotion
    needs:
      - preflight-core
      - preflight-ci
      - preflight-playwright
    runs-on: ubuntu-latest
    env:
      AEGAEON_CLIENT_EVIDENCE_DISPATCH_HOSTED: \${{ github.event.inputs.dispatch_hosted || 'false' }}
      AEGAEON_ADMIN_SDK_EVIDENCE_JSON: \${{ github.event.inputs.admin_sdk_evidence_json || vars.AEGAEON_ADMIN_SDK_EVIDENCE_JSON || '' }}
      AEGAEON_ADMIN_CONSOLE_REPOSITORY: \${{ vars.AEGAEON_ADMIN_CONSOLE_REPOSITORY || '' }}
      AEGAEON_ADMIN_CONSOLE_REF: \${{ vars.AEGAEON_ADMIN_CONSOLE_REF || 'main' }}
      AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW: \${{ vars.AEGAEON_ADMIN_CONSOLE_STACK_WORKFLOW || 'stack-e2e.yml' }}
      AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT: \${{ vars.AEGAEON_ADMIN_SDK_EVIDENCE_ARTIFACT || 'admin-sdk-evidence' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON: \${{ github.event.inputs.managed_provider_evidence_json || vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON || '' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REPOSITORY || github.repository }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_REF || 'main' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_WORKFLOW || 'managed-provider-evidence.yml' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT: \${{ vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_ARTIFACT || 'managed-provider-evidence' }}
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:client-claim-boundary'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:client-claim-promotion'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run pack:workspace'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:manifest'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run release:attestation'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:release-attestation'
      - name: Run client evidence gates (promotion)
        env:
          AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN: \${{ secrets.AEGAEON_ADMIN_SDK_EVIDENCE_TOKEN || github.token }}
          AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN: \${{ secrets.AEGAEON_MANAGED_PROVIDER_EVIDENCE_TOKEN || github.token }}
        run: nix develop . --command bash -lc 'cd sdk && pnpm run run:client-evidence-gates -- --mode promotion'
      - name: Upload client-claim promotion artefacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: client-claim-promotion
          path: |
            sdk/.artifacts/release/client-claim-promotion-report.json
            sdk/.artifacts/release/release-attestation.json
            sdk/.artifacts/admin-sdk/admin-sdk-evidence.json
            sdk/.artifacts/managed-provider/managed-provider-evidence.json
          if-no-files-found: warn
          retention-days: 14
`;
}

function workflowManagedProviderEvidence() {
  return `name: SDK Managed Provider Evidence
on:
  workflow_dispatch:
    inputs:
      managed_provider_config_json:
        description: Managed external provider config JSON override for one-off runs
        required: false
      managed_provider_evidence_json:
        description: Managed-provider evidence JSON override for one-off hosted imports
        required: false
      provider_class:
        description: Provider class recorded in managed-provider-evidence.json
        required: false
        default: commercial
  workflow_call:
permissions:
  contents: read
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
concurrency:
  group: managed-provider-evidence-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  external-provider-managed:
    name: External Provider (Managed)
    if: github.event_name == 'workflow_dispatch' || vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED == '1' || vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED == 'true' || vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED == 'TRUE'
    runs-on: ubuntu-latest
    env:
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON: \${{ github.event.inputs.managed_provider_config_json || vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON || '' }}
      AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON: \${{ github.event.inputs.managed_provider_evidence_json || vars.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON || '' }}
      AEGAEON_MANAGED_PROVIDER_CLASS: \${{ github.event.inputs.provider_class || 'commercial' }}
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - name: Materialize managed provider evidence override
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON != ''
        run: |
          mkdir -p sdk/.cache sdk/.artifacts/managed-provider
          printf '%s' "$AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON" > sdk/.cache/managed-provider-evidence.import.json
      - name: Import managed provider evidence
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON != ''
        run: nix develop . --command bash -lc 'cd sdk && pnpm run import:managed-provider-evidence -- --evidence .cache/managed-provider-evidence.import.json --out .artifacts/managed-provider/managed-provider-evidence.json'
      - name: Validate imported managed provider evidence
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON != ''
        run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:managed-provider-evidence -- .artifacts/managed-provider/managed-provider-evidence.json'
      - name: Materialize managed provider config
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON == ''
        run: |
          if [ -z "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON" ]; then
            echo "managed_provider_config_json input or AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON repository variable is required." >&2
            exit 1
          fi
          mkdir -p sdk/.cache
          printf '%s' "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON" > sdk/.cache/managed-external-provider.json
      - name: Validate managed provider config
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON == ''
        run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:managed-provider-config -- .cache/managed-external-provider.json'
      - name: Audit managed provider readiness
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON == ''
        env:
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET }}
        run: nix develop . --command bash -lc 'cd sdk && pnpm run audit:managed-provider -- --config .cache/managed-external-provider.json --require-browser'
      - name: Run managed provider browser lane
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON == ''
        env:
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG: sdk/.cache/managed-external-provider.json
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET }}
        run: |
          if [ -z "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME" ] || [ -z "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD" ]; then
            echo "AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME and AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD are required when external-provider-managed is enabled." >&2
            exit 1
          fi
          nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-managed-browser -- --required --config .cache/managed-external-provider.json'
      - name: Build managed provider evidence
        if: env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_JSON == ''
        run: nix develop . --command bash -lc "cd sdk && pnpm run build:managed-provider-evidence -- --config .cache/managed-external-provider.json --provider-class \"$AEGAEON_MANAGED_PROVIDER_CLASS\" --lane-name external-provider-managed --status passed --hosted true --browser \"$PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH\""
      - name: Upload managed provider evidence
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: managed-provider-evidence
          path: sdk/.artifacts/managed-provider/managed-provider-evidence.json
          if-no-files-found: error
          retention-days: 14
      - name: Upload managed provider diagnostics
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-managed-provider-diagnostics
          path: |
            sdk/playwright-report
            sdk/test-results
          if-no-files-found: warn
          retention-days: 14
`;
}

function workflowPlaywright() {
  return `name: SDK Browser E2E
on:
  pull_request:
  workflow_call:
  workflow_dispatch:
env:
  NIX_CONFIG: experimental-features = nix-command flakes
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
permissions:
  contents: read
concurrency:
  group: playwright-\${{ github.ref }}
  cancel-in-progress: true
jobs:
  playwright:
    name: Core Playwright
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run test:playwright'
      - name: Upload Playwright diagnostics
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-diagnostics
          path: |
            sdk/playwright-report
            sdk/test-results
          if-no-files-found: warn
          retention-days: 14
  external-provider-dex:
    name: External Provider (Dex)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: docker version
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-dex-browser -- --required'
      - name: Upload Dex Playwright diagnostics
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-dex-diagnostics
          path: |
            sdk/playwright-report
            sdk/test-results
          if-no-files-found: warn
          retention-days: 14
  external-provider-keycloak:
    name: External Provider (Keycloak)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: docker version
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - run: nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-keycloak-browser -- --required'
      - name: Upload Keycloak Playwright diagnostics
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-keycloak-diagnostics
          path: |
            sdk/playwright-report
            sdk/test-results
          if-no-files-found: warn
          retention-days: 14
  external-provider-managed:
    name: External Provider (Managed)
    if: vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED == '1' || vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED == 'true' || vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED == 'TRUE'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Nix CI
        uses: ./.github/actions/setup-nix-ci
        with:
          enable-flakehub-cache: "true"
      - run: nix develop . --command bash -lc 'cd sdk && pnpm install --frozen-lockfile'
      - name: Materialize managed provider config
        env:
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON: \${{ vars.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON }}
        run: |
          if [ -z "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON" ]; then
            echo "AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON is required when external-provider-managed is enabled." >&2
            exit 1
          fi
          mkdir -p sdk/.cache
          printf '%s' "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON" > sdk/.cache/managed-external-provider.json
      - name: Validate managed provider config
        run: nix develop . --command bash -lc 'cd sdk && pnpm run validate:managed-provider-config -- .cache/managed-external-provider.json'
      - name: Audit managed provider readiness
        env:
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET }}
        run: nix develop . --command bash -lc 'cd sdk && pnpm run audit:managed-provider -- --config .cache/managed-external-provider.json --require-browser'
      - name: Run managed provider browser lane
        env:
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG: sdk/.cache/managed-external-provider.json
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD }}
          AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET: \${{ secrets.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET }}
        run: |
          if [ -z "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME" ] || [ -z "$AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD" ]; then
            echo "AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME and AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD are required when external-provider-managed is enabled." >&2
            exit 1
          fi
          nix develop . --command bash -lc 'cd sdk && pnpm run test:provider-managed-browser -- --required --config .cache/managed-external-provider.json'
      - name: Build managed provider evidence
        run: nix develop . --command bash -lc "cd sdk && pnpm run build:managed-provider-evidence -- --config .cache/managed-external-provider.json --provider-class commercial --lane-name external-provider-managed --status passed --hosted true --browser \"$PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH\""
      - name: Upload managed provider evidence
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: managed-provider-evidence
          path: sdk/.artifacts/managed-provider/managed-provider-evidence.json
          if-no-files-found: error
          retention-days: 14
      - name: Upload managed provider diagnostics
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-managed-provider-diagnostics
          path: |
            sdk/playwright-report
            sdk/test-results
          if-no-files-found: warn
          retention-days: 14
`;
}

function playwrightConfigText() {
  return `import { defineConfig } from "@playwright/test";\n\nconst executablePath =\n  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ??\n  process.env.CHROME_BIN ??\n  undefined;\n\nexport default defineConfig({\n  testDir: "./tests/browser",\n  outputDir: "./test-results/playwright",\n  timeout: 30_000,\n  retries: process.env.CI ? 1 : 0,\n  reporter: [\n    ["list"],\n    ["html", { open: "never", outputFolder: "playwright-report" }],\n    ["json", { outputFile: "test-results/playwright-report.json" }],\n  ],\n  use: {\n    browserName: "chromium",\n    headless: true,\n    trace: "retain-on-failure",\n    screenshot: "only-on-failure",\n    video: "retain-on-failure",\n    launchOptions: executablePath\n      ? {\n          executablePath,\n        }\n      : undefined,\n  },\n});\n`;
}

function packageTsconfig(packageName) {
  const include = packageName === "verified-core" || packageName === "runtime-node" || packageName === "runtime-web"
    ? ["src/**/*.ts"]
    : packageName === "management-client"
      ? ["src/**/*.ts"]
    : packageName === "issuer-spa"
        ? ["src/**/*.ts"]
    : packageName === "rp-core"
      ? ["src/**/*.ts"]
      : ["dist/index.js", "dist/reference.js"];
  const references =
    packageName === "runtime-node" || packageName === "runtime-web"
      ? [{ path: "../verified-core/tsconfig.json" }]
      : packageName === "issuer-spa"
        ? [
            { path: "../runtime-web/tsconfig.json" },
            { path: "../rp-core/tsconfig.json" },
          ]
        : [];
  return {
    extends: "../../tsconfig.base.json",
    compilerOptions: {
      rootDir: packageName === "verified-core" || packageName === "runtime-node" || packageName === "runtime-web" || packageName === "management-client" || packageName === "issuer-spa" || packageName === "rp-core" ? "src" : ".",
      ...((packageName === "verified-core" || packageName === "runtime-node" || packageName === "runtime-web" || packageName === "management-client" || packageName === "issuer-spa" || packageName === "rp-core")
        ? {
            outDir: "dist",
            noEmit: false,
            allowJs: false,
            checkJs: false,
            ...(packageName === "runtime-node"
              ? {
                  noImplicitAny: true,
                  useUnknownInCatchVariables: true,
                }
              : {}),
            ...(packageName === "verified-core" || packageName === "runtime-node" || packageName === "runtime-web" || packageName === "issuer-spa" || packageName === "rp-core"
              ? { declaration: true }
              : {}),
          }
        : {}),
      composite: true,
      tsBuildInfoFile: `../../.cache/tsbuildinfo/packages-${packageName}.tsbuildinfo`,
      ...((packageName === "verified-core" || packageName === "runtime-node" || packageName === "runtime-web" || packageName === "management-client" || packageName === "issuer-spa" || packageName === "rp-core")
        ? {}
        : { checkJs: false }),
    },
    ...(references.length > 0 ? { references } : {}),
    include,
  };
}

function runtimeWebBrowserSmokeModule() {
  return `import * as reference from "./reference.js";\nimport { loadBundledArtifact, resolveBundledArtifactUrls as resolveBundledUrls } from "../../verified-core/dist/web.js";\nimport type { WebInitOptions } from "./reference.js";\n\nexport const VC_STATUS = reference.VC_STATUS;\nexport const VC_ALG = reference.VC_ALG;\nexport const VC_DPOP_FLAGS = reference.VC_DPOP_FLAGS;\nexport const VC_JWT_FLAGS = reference.VC_JWT_FLAGS;\nexport const CLIENT_CRYPTO_PROFILES = reference.CLIENT_CRYPTO_PROFILES;\nexport const DEFAULT_CLIENT_CRYPTO_PROFILE = reference.DEFAULT_CLIENT_CRYPTO_PROFILE;\nexport const createInMemoryReplayStore = reference.createInMemoryReplayStore;\nexport const resolveJwtAllowedAlgorithmsBitmaskForProfile = reference.resolveJwtAllowedAlgorithmsBitmaskForProfile;\nexport const resolveDpopAllowedAlgorithmsBitmaskForProfile = reference.resolveDpopAllowedAlgorithmsBitmaskForProfile;\n\nexport function resolveBundledArtifactUrls() {\n  return resolveBundledUrls();\n}\n\nexport async function initCore(options: WebInitOptions = {}) {\n  const hasExplicitArtifact = Boolean(options.manifest || options.manifestUrl || options.wasmBytes || options.wasmUrl);\n  if (hasExplicitArtifact) {\n    return reference.initCore(options);\n  }\n  const { manifest, wasmBytes, signatureBytes } = await loadBundledArtifact({ fetchImpl: options.fetchImpl });\n  return reference.initCore({\n    ...options,\n    manifest,\n    wasmBytes,\n    ...(signatureBytes ? { signatureBytes } : {}),\n  });\n}\n`;
}

function runtimeDistJavaScript(source) {
  return stripTypeScriptTypes(source);
}

function packageScripts(packageName) {
  if (packageName === "verified-core") {
    return {
      build: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json",
      lint: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      typecheck: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      test: "node --input-type=module -e \"await import('./dist/index.js'); await import('./dist/node.js'); await import('./dist/web.js');\"",
      pack: "npm pack .",
    };
  }
  if (packageName === "management-client") {
    return {
      build: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json",
      "build:test": "node ../../node_modules/typescript/bin/tsc --project tsconfig.test.json",
      lint: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      typecheck: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      test: "pnpm run build && pnpm run build:test && node dist-test/management_client_test.js",
      pack: "npm pack .",
    };
  }
  if (packageName === "issuer-spa") {
    return {
      build: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json",
      "build:test": "node ../../node_modules/typescript/bin/tsc --project tsconfig.test.json",
      lint: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      typecheck: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      test: "pnpm run build && pnpm run build:test && node dist-test/issuer_spa_test.js",
      pack: "npm pack .",
    };
  }
  if (packageName === "rp-core") {
    return {
      build: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json",
      "build:test": "node ../../node_modules/typescript/bin/tsc --project tsconfig.test.json",
      lint: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      typecheck: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      test: "pnpm run build && pnpm run build:test && node dist-test/rp_core_test.js",
      pack: "npm pack .",
    };
  }
  if (packageName === "runtime-node") {
    return {
      build: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json",
      lint: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      typecheck: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      test: "node --input-type=module -e \"await import('./dist/index.js'); await import('./dist/reference.js');\"",
      pack: "npm pack .",
    };
  }
  if (packageName === "runtime-web") {
    return {
      build: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json",
      lint: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      typecheck: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json --pretty false --noEmit",
      test: "node --input-type=module -e \"await import('./dist/index.js'); await import('./dist/reference.js'); await import('./dist/browser-smoke.js');\"",
      pack: "npm pack .",
    };
  }
  return {
    build: "node --check dist/index.js && node --check dist/reference.js",
    lint: "node --check dist/index.js && node --check dist/reference.js",
    typecheck: "node ../../node_modules/typescript/bin/tsc --project tsconfig.json",
    test: "node --input-type=module -e \"await import('./dist/index.js'); await import('./dist/reference.js');\"",
    pack: "npm pack .",
  };
}

async function augmentPackage(packageDir, packageName) {
  const packageJsonPath = path.join(packageDir, "package.json");
  const packageJson = JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
  if (packageName === "runtime-node" || packageName === "runtime-web") {
    packageJson.dependencies = {
      ...(packageJson.dependencies ?? {}),
      "@aegaeon/verified-core": "workspace:*",
    };
  }
  if (packageName === "issuer-spa") {
    packageJson.dependencies = {
      ...(packageJson.dependencies ?? {}),
      "@aegaeon/runtime-web": "workspace:*",
      "@aegaeon/rp-core": "workspace:*",
    };
  }
  packageJson.scripts = {
    ...packageScripts(packageName),
    ...(packageJson.scripts ?? {}),
  };
  await writeJson(packageJsonPath, packageJson);
  await writeJson(path.join(packageDir, "tsconfig.json"), packageTsconfig(packageName));
  if (packageName === "management-client" || packageName === "issuer-spa" || packageName === "rp-core") {
    await writeJson(path.join(packageDir, "tsconfig.test.json"), {
      extends: "../../tsconfig.base.json",
      compilerOptions: {
        allowJs: false,
        checkJs: false,
        noEmit: false,
        ...(packageName === "management-client"
          ? {
              strict: false,
              exactOptionalPropertyTypes: false,
              noUncheckedIndexedAccess: false,
              noImplicitAny: false,
              useUnknownInCatchVariables: false,
            }
          : {}),
        rootDir: "test",
        outDir: "dist-test",
        lib: ["ES2022", "DOM", "DOM.Iterable"],
      },
      include: ["test/**/*.ts"],
    });
  }
}

async function copyNodeTestFixture(sourcePath, outDir, fileName) {
  const sourceText = await fs.readFile(sourcePath, "utf8");
  await writeText(path.join(outDir, "tests", "node", `${fileName}.ts`), sourceText);
  await writeText(path.join(outDir, "dist-tests", "node", `${fileName}.js`), runtimeDistJavaScript(sourceText));
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const tempStageRoot = await fs.mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-stage-"));
  const tempStageWorkspace = path.join(tempStageRoot, "workspace");

  try {
    await stageWorkspace(tempStageWorkspace, options);
    const stagedRootPackage = JSON.parse(await fs.readFile(path.join(tempStageWorkspace, "package.json"), "utf8"));
    const version = options.version ?? stagedRootPackage.version ?? "0.0.0-reference";

    await removeDir(options.outDir);
    await ensureDir(options.outDir);
    await ensureDir(path.join(options.outDir, "packages"));
    await ensureDir(path.join(options.outDir, "tools-src"));
    await ensureDir(path.join(options.outDir, "dist-tools"));
    await ensureDir(path.join(options.outDir, "scripts", "validation"));
    await ensureDir(path.join(options.outDir, "spec"));
    await ensureDir(path.join(options.outDir, "tests", "browser"));
    await ensureDir(path.join(options.outDir, "tests", "node"));
    await ensureDir(path.join(options.outDir, "dist-tests", "node"));
    await ensureDir(path.join(options.outDir, "dist-tests", "browser"));
    await ensureDir(path.join(options.outDir, "dist-tests", "providers"));
    await ensureDir(path.join(options.outDir, "dist-tests", "providers", "dex"));
    await ensureDir(path.join(options.outDir, "dist-tests", "providers", "keycloak"));
    await ensureDir(path.join(options.outDir, "dist-tests", "providers", "managed"));
    await ensureDir(path.join(options.outDir, ".github", "workflows"));
    await ensureDir(path.join(options.outDir, ".github", "actions", "setup-nix-ci"));
    await ensureDir(path.join(options.outDir, ".changeset"));

    await writeJson(path.join(options.outDir, "package.json"), rootPackageJson(version));
    await writeText(path.join(options.outDir, "pnpm-workspace.yaml"), pnpmWorkspaceYaml());
    await writeText(path.join(options.outDir, ".gitignore"), gitignoreText());
    await writeText(path.join(options.outDir, ".npmrc"), npmrcText());
    await writeText(path.join(options.outDir, "README.md"), rootReadme(version));
    await writeText(path.join(options.outDir, "MIGRATION.md"), migrationChecklist(version));
    await writeJson(path.join(options.outDir, "tsconfig.base.json"), tsconfigBaseJson());
    await writeJson(path.join(options.outDir, "tsconfig.json"), tsconfigJson());
    await writeJson(path.join(options.outDir, "tsconfig.tools.json"), tsconfigToolsJson());
    await writeJson(path.join(options.outDir, "tsconfig.tests.node.json"), tsconfigTestsNodeJson());
    await fs.copyFile(path.join(ROOT_DIR, "tests", "verified_core_wasm", "tsconfig.tests.browser.json"), path.join(options.outDir, "tsconfig.tests.browser.json"));
    await writeJson(path.join(options.outDir, ".changeset", "config.json"), changesetConfig());
    await writeText(path.join(options.outDir, ".changeset", "README.md"), changesetReadme());
    await fs.copyFile(LICENSE_PATH, path.join(options.outDir, "LICENSE"));
    for (const fileName of TOOL_SOURCE_FILES) {
      const sourcePath = path.join(TOOL_SOURCE_DIR, fileName);
      const toolSourceText = await readText(sourcePath);
      await writeText(path.join(options.outDir, "tools-src", fileName), toolSourceText);
      if (fileName === "exec-tool.ts") {
        await writeText(path.join(options.outDir, "dist-tools", "exec-tool.js"), toolExecDistText());
        continue;
      }
      await writeText(
        path.join(options.outDir, "dist-tools", fileName.replace(/\.ts$/, ".js")),
        runtimeDistJavaScript(toolSourceText),
      );
    }
    await fs.copyFile(DISPATCH_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_sdk_repository_dispatch_payload.py"));
    await fs.copyFile(HANDOFF_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_verified_core_handoff_manifest.py"));
    await fs.copyFile(MANAGED_PROVIDER_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_managed_external_provider_config.py"));
    await fs.copyFile(MANAGED_PROVIDER_EVIDENCE_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_managed_provider_evidence.py"));
    await fs.copyFile(ADMIN_SDK_EVIDENCE_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_admin_sdk_evidence.py"));
    await fs.copyFile(CLIENT_CLAIM_BOUNDARY_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_client_claim_boundary.py"));
    await fs.copyFile(CLIENT_CLAIM_PROMOTION_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_client_claim_promotion.py"));
    await fs.copyFile(RELEASED_CLIENT_CLAIM_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_released_client_claim.py"));
    await fs.copyFile(RELEASED_CLIENT_CLAIM_REPORT_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_released_client_claim_report.py"));
    await fs.copyFile(RELEASE_ATTESTATION_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_sdk_release_attestation.py"));
    await fs.copyFile(
      RELEASE_ATTESTATION_SIGNATURE_VALIDATOR_SOURCE,
      path.join(options.outDir, "scripts", "validation", "validate_sdk_release_attestation_signature.py"),
    );
    await fs.copyFile(RELEASE_PUBLICATION_BUNDLE_VALIDATOR_SOURCE, path.join(options.outDir, "scripts", "validation", "validate_sdk_release_publication_bundle.py"));
    await fs.copyFile(DISPATCH_SCHEMA_SOURCE, path.join(options.outDir, "spec", "sdk-repository-dispatch.schema.json"));
    await fs.copyFile(HANDOFF_SCHEMA_SOURCE, path.join(options.outDir, "spec", "verified-core-handoff-manifest.schema.json"));
    await fs.copyFile(MANAGED_PROVIDER_SCHEMA_SOURCE, path.join(options.outDir, "spec", "managed-external-provider.schema.json"));
    await fs.copyFile(MANAGED_PROVIDER_EVIDENCE_SCHEMA_SOURCE, path.join(options.outDir, "spec", "managed-provider-evidence.schema.json"));
    await fs.copyFile(ADMIN_SDK_EVIDENCE_SCHEMA_SOURCE, path.join(options.outDir, "spec", "admin-sdk-evidence.schema.json"));
    await fs.copyFile(CLIENT_CLAIM_BOUNDARY_SCHEMA_SOURCE, path.join(options.outDir, "spec", "client-claim-boundary.schema.json"));
    await fs.copyFile(CLIENT_CLAIM_BOUNDARY_CURRENT_SOURCE, path.join(options.outDir, "spec", "client-claim-boundary.current.json"));
    await fs.copyFile(CLIENT_CLAIM_PROMOTION_SCHEMA_SOURCE, path.join(options.outDir, "spec", "client-claim-promotion.schema.json"));
    await fs.copyFile(CLIENT_CLAIM_PROMOTION_CURRENT_SOURCE, path.join(options.outDir, "spec", "client-claim-promotion.current.json"));
    await fs.copyFile(RELEASED_CLIENT_CLAIM_SCHEMA_SOURCE, path.join(options.outDir, "spec", "released-client-claim.schema.json"));
    await fs.copyFile(RELEASED_CLIENT_CLAIM_CURRENT_SOURCE, path.join(options.outDir, "spec", "released-client-claim.current.json"));
    await fs.copyFile(STRICT_TYPES_POLICY_SOURCE, path.join(options.outDir, "spec", "strict-types.current.json"));
    await fs.copyFile(EXTERNAL_BOUNDARY_NAMING_POLICY_SOURCE, path.join(options.outDir, "spec", "external-boundary-naming.current.json"));
    await fs.copyFile(RELEASED_CLIENT_CLAIM_REPORT_SCHEMA_SOURCE, path.join(options.outDir, "spec", "released-client-claim-report.schema.json"));
    await fs.copyFile(RELEASE_ATTESTATION_SCHEMA_SOURCE, path.join(options.outDir, "spec", "sdk-release-attestation.schema.json"));
    await fs.copyFile(
      RELEASE_ATTESTATION_SIGNATURE_SCHEMA_SOURCE,
      path.join(options.outDir, "spec", "sdk-release-attestation-signature.schema.json"),
    );
    await fs.copyFile(RELEASE_PUBLICATION_BUNDLE_SCHEMA_SOURCE, path.join(options.outDir, "spec", "sdk-release-publication-bundle.schema.json"));
    await fs.copyFile(BRANCH_PROTECTION_POLICY_SOURCE, path.join(options.outDir, "spec", "branch-protection.main.json"));
    await fs.copyFile(WORKFLOW_INVENTORY_POLICY_SOURCE, path.join(options.outDir, "spec", "workflow-inventory.current.json"));
    await fs.copyFile(HOSTED_EVIDENCE_SOURCES_POLICY_SOURCE, path.join(options.outDir, "spec", "hosted-evidence-sources.current.json"));
    await fs.copyFile(REPOSITORY_SETTINGS_POLICY_SOURCE, path.join(options.outDir, "spec", "repository-settings.current.json"));
    await fs.copyFile(RELEASE_CUSTODY_POLICY_SOURCE, path.join(options.outDir, "spec", "release-custody.current.json"));
    await fs.copyFile(SETUP_NIX_CI_ACTION_SOURCE, path.join(options.outDir, ".github", "actions", "setup-nix-ci", "action.yml"));

    await writeText(path.join(options.outDir, ".github", "workflows", "lint.yml"), workflowLint());
    await writeText(path.join(options.outDir, ".github", "workflows", "verify-core.yml"), workflowVerifyCore());
    await writeText(path.join(options.outDir, ".github", "workflows", "ci.yml"), workflowCi());
    await writeText(path.join(options.outDir, ".github", "workflows", "publish.yml"), workflowPublish());
    await writeText(path.join(options.outDir, ".github", "workflows", "client-claim-promotion.yml"), workflowClientClaimPromotion());
    await writeText(path.join(options.outDir, ".github", "workflows", "released-client-readiness.yml"), workflowReleasedClientReadiness());
    await writeText(path.join(options.outDir, ".github", "workflows", "publication-org-rollout.yml"), workflowPublicationOrgRollout());
    await writeText(path.join(options.outDir, ".github", "workflows", "managed-provider-evidence.yml"), workflowManagedProviderEvidence());
    await writeText(path.join(options.outDir, ".github", "workflows", "playwright.yml"), workflowPlaywright());
    const playwrightConfigSource = await readText(PLAYWRIGHT_CONFIG_SOURCE);
    await writeText(path.join(options.outDir, "tests", "playwright.config.ts"), playwrightConfigSource);
    await writeText(path.join(options.outDir, "dist-tests", "playwright.config.js"), runtimeDistJavaScript(playwrightConfigSource));

    for (const packageName of ["verified-core", "runtime-node", "runtime-web", "management-client", "issuer-spa", "rp-core"]) {
      await fs.cp(
        path.join(tempStageWorkspace, "packages", packageName),
        path.join(options.outDir, "packages", packageName),
        { recursive: true },
      );
      await augmentPackage(path.join(options.outDir, "packages", packageName), packageName);
    }
    const runtimeWebBrowserSmokeSource = runtimeWebBrowserSmokeModule();
    await writeText(path.join(options.outDir, "packages", "runtime-web", "src", "browser-smoke.ts"), runtimeWebBrowserSmokeSource);
    await writeText(
      path.join(options.outDir, "packages", "runtime-web", "dist", "browser-smoke.js"),
      runtimeDistJavaScript(runtimeWebBrowserSmokeSource),
    );

    const browserReferenceHtml = (await readText(BROWSER_HTML_SOURCE)).replace(
      "./runtime_web_reference_harness.ts",
      "/dist-tests/browser/runtime_web_reference_harness.js",
    );
    const browserIssuerHtml = (await readText(BROWSER_ISSUER_HTML_SOURCE)).replace(
      "./issuer_spa_upstream_e2e_harness.ts",
      "/dist-tests/browser/issuer_spa_upstream_e2e_harness.js",
    );
    const browserExternalIssuerHtml = (await readText(BROWSER_EXTERNAL_ISSUER_HTML_SOURCE)).replace(
      "./issuer_spa_external_provider_e2e_harness.ts",
      "/dist-tests/browser/issuer_spa_external_provider_e2e_harness.js",
    );

    await fs.copyFile(BROWSER_GLOBALS_SOURCE, path.join(options.outDir, "tests", "browser", "globals.d.ts"));
    const browserHarnessSource = (await readText(BROWSER_HARNESS_SOURCE)).replace(
      "../../scripts/sdk/runtime_web_reference.ts",
      "../../packages/runtime-web/dist/browser-smoke.js",
    );
    await writeText(path.join(options.outDir, "tests", "browser", "runtime_web_reference_harness.ts"), browserHarnessSource);
    await writeText(path.join(options.outDir, "tests", "browser", "runtime_web_reference.html"), browserReferenceHtml);
    await fs.copyFile(BROWSER_SERVER_SOURCE, path.join(options.outDir, "tests", "browser", "runtime_web_reference_server.ts"));
    await fs.copyFile(BROWSER_RUNNER_SOURCE, path.join(options.outDir, "tests", "browser", "runtime_web_browser_smoke_test.ts"));
    await copyNodeTestFixture(BRANCH_PROTECTION_TEST_SOURCE, options.outDir, "branch_protection_policy_test");
    await copyNodeTestFixture(STRICT_TYPES_TEST_SOURCE, options.outDir, "strict_types_policy_test");
    await copyNodeTestFixture(EXTERNAL_BOUNDARY_NAMING_TEST_SOURCE, options.outDir, "external_boundary_naming_policy_test");
    await copyNodeTestFixture(WORKFLOW_INVENTORY_TEST_SOURCE, options.outDir, "workflow_inventory_policy_test");
    await copyNodeTestFixture(REPOSITORY_SETTINGS_TEST_SOURCE, options.outDir, "repository_settings_policy_test");
    await copyNodeTestFixture(HOSTED_EVIDENCE_SOURCES_TEST_SOURCE, options.outDir, "hosted_evidence_sources_test");
    await copyNodeTestFixture(HOSTED_EVIDENCE_RUNNER_TEST_SOURCE, options.outDir, "hosted_evidence_runner_test");
    await copyNodeTestFixture(RELEASE_CUSTODY_TEST_SOURCE, options.outDir, "release_custody_policy_test");
    await copyNodeTestFixture(TOOL_EXEC_TEST_SOURCE, options.outDir, "tool_exec_test");
    await copyNodeTestFixture(ADMIN_SDK_EVIDENCE_DOWNLOAD_TEST_SOURCE, options.outDir, "admin_sdk_evidence_download_test");
    await copyNodeTestFixture(AEGAEON_PROVIDER_LOCAL_E2E_TEST_SOURCE, options.outDir, "aegaeon_provider_local_e2e_test");
    await copyNodeTestFixture(
      MANAGED_PROVIDER_EVIDENCE_DOWNLOAD_TEST_SOURCE,
      options.outDir,
      "managed_provider_evidence_download_test",
    );
    await copyNodeTestFixture(
      MANAGED_PROVIDER_EVIDENCE_IMPORT_TEST_SOURCE,
      options.outDir,
      "managed_provider_evidence_import_test",
    );
    await copyNodeTestFixture(MANAGED_PROVIDER_EVIDENCE_TEST_SOURCE, options.outDir, "managed_provider_evidence_test");
    await copyNodeTestFixture(MANAGED_PROVIDER_TEST_SOURCE, options.outDir, "managed_provider_runner_test");
    await copyNodeTestFixture(
      MANAGED_PROVIDER_SCHEMA_TEST_SOURCE,
      options.outDir,
      "managed_provider_config_schema_test",
    );
    await copyNodeTestFixture(MANAGED_PROVIDER_READINESS_TEST_SOURCE, options.outDir, "managed_provider_readiness_test");
    await copyNodeTestFixture(CLIENT_CLAIM_BOUNDARY_TEST_SOURCE, options.outDir, "client_claim_boundary_test");
    await copyNodeTestFixture(CLIENT_CLAIM_PROMOTION_TEST_SOURCE, options.outDir, "client_claim_promotion_test");
    await copyNodeTestFixture(
      RELEASED_CLIENT_CLAIM_ACTIVATION_TEST_SOURCE,
      options.outDir,
      "released_client_claim_activation_test",
    );
    await copyNodeTestFixture(
      RELEASED_CLIENT_CLAIM_REPORT_TEST_SOURCE,
      options.outDir,
      "released_client_claim_report_test",
    );
    await copyNodeTestFixture(RELEASED_CLIENT_READINESS_TEST_SOURCE, options.outDir, "released_client_readiness_test");
    await copyNodeTestFixture(
      RELEASED_CLIENT_READINESS_ARTIFACT_HANDOFF_TEST_SOURCE,
      options.outDir,
      "released_client_readiness_artifact_handoff_test",
    );
    await copyNodeTestFixture(
      REAL_TENANT_READINESS_TEST_SOURCE,
      options.outDir,
      "real_tenant_readiness_runner_test",
    );
    await copyNodeTestFixture(
      HOSTED_RELEASE_READINESS_REPORT_TEST_SOURCE,
      options.outDir,
      "hosted_release_readiness_report_test",
    );
    await copyNodeTestFixture(WORKSPACE_SBOM_TEST_SOURCE, options.outDir, "workspace_sbom_test");
    await copyNodeTestFixture(RELEASE_ATTESTATION_TEST_SOURCE, options.outDir, "release_attestation_test");
    await copyNodeTestFixture(
      RELEASE_ATTESTATION_SIGNATURE_TEST_SOURCE,
      options.outDir,
      "release_attestation_signature_test",
    );
    await copyNodeTestFixture(RELEASE_PUBLICATION_BUNDLE_TEST_SOURCE, options.outDir, "release_publication_bundle_test");
    await fs.copyFile(BROWSER_PLAYWRIGHT_SOURCE, path.join(options.outDir, "tests", "browser", "runtime_web_playwright.spec.ts"));
    await writeText(path.join(options.outDir, "tests", "browser", "issuer_spa_upstream_e2e.html"), browserIssuerHtml);
    await fs.copyFile(BROWSER_ISSUER_HARNESS_SOURCE, path.join(options.outDir, "tests", "browser", "issuer_spa_upstream_e2e_harness.ts"));
    await fs.copyFile(BROWSER_EXTERNAL_PLAYWRIGHT_SOURCE, path.join(options.outDir, "tests", "browser", "external_provider_playwright.spec.ts"));
    await writeText(path.join(options.outDir, "tests", "browser", "issuer_spa_external_provider_e2e.html"), browserExternalIssuerHtml);
    await fs.copyFile(BROWSER_EXTERNAL_ISSUER_HARNESS_SOURCE, path.join(options.outDir, "tests", "browser", "issuer_spa_external_provider_e2e_harness.ts"));
    await ensureDir(path.join(options.outDir, "tests", "providers", "dex"));
    const providerWorkspacePnpmSource = await readText(PROVIDER_RUN_WORKSPACE_PNPM_SOURCE);
    await writeText(path.join(options.outDir, "tests", "providers", "run_workspace_pnpm.ts"), providerWorkspacePnpmSource);
    await writeText(path.join(options.outDir, "dist-tests", "providers", "run_workspace_pnpm.js"), runtimeDistJavaScript(providerWorkspacePnpmSource));
    await fs.copyFile(PROVIDER_DEX_COMPOSE_SOURCE, path.join(options.outDir, "tests", "providers", "dex", "docker-compose.yml"));
    await fs.copyFile(PROVIDER_DEX_CONFIG_SOURCE, path.join(options.outDir, "tests", "providers", "dex", "dex-config.yaml"));
    const providerDexRunnerSource = await readText(PROVIDER_DEX_RUNNER_SOURCE);
    await writeText(path.join(options.outDir, "tests", "providers", "dex", "run_dex_browser_e2e.ts"), providerDexRunnerSource);
    await writeText(path.join(options.outDir, "dist-tests", "providers", "dex", "run_dex_browser_e2e.js"), runtimeDistJavaScript(providerDexRunnerSource));
    await ensureDir(path.join(options.outDir, "tests", "providers", "keycloak"));
    await fs.copyFile(PROVIDER_KEYCLOAK_COMPOSE_SOURCE, path.join(options.outDir, "tests", "providers", "keycloak", "docker-compose.yml"));
    await fs.copyFile(PROVIDER_KEYCLOAK_REALM_SOURCE, path.join(options.outDir, "tests", "providers", "keycloak", "keycloak-realm.template.json"));
    const providerKeycloakRunnerSource = await readText(PROVIDER_KEYCLOAK_RUNNER_SOURCE);
    await writeText(path.join(options.outDir, "tests", "providers", "keycloak", "run_keycloak_browser_e2e.ts"), providerKeycloakRunnerSource);
    await writeText(path.join(options.outDir, "dist-tests", "providers", "keycloak", "run_keycloak_browser_e2e.js"), runtimeDistJavaScript(providerKeycloakRunnerSource));
    await ensureDir(path.join(options.outDir, "tests", "providers", "managed"));
    await fs.copyFile(PROVIDER_MANAGED_EXAMPLE_SOURCE, path.join(options.outDir, "tests", "providers", "managed", "managed-provider.example.json"));
    const providerManagedRunnerSource = await readText(PROVIDER_MANAGED_RUNNER_SOURCE);
    await writeText(path.join(options.outDir, "tests", "providers", "managed", "run_managed_browser_e2e.ts"), providerManagedRunnerSource);
    await writeText(path.join(options.outDir, "dist-tests", "providers", "managed", "run_managed_browser_e2e.js"), runtimeDistJavaScript(providerManagedRunnerSource));

    console.log("[scaffold-sdk] generated SDK repo scaffold:", options.outDir);
    console.log("[scaffold-sdk] package version:", version);
    console.log("[scaffold-sdk] workflows:");
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "lint.yml")}`);
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "verify-core.yml")}`);
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "ci.yml")}`);
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "publish.yml")}`);
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "client-claim-promotion.yml")}`);
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "released-client-readiness.yml")}`);
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "managed-provider-evidence.yml")}`);
    console.log(`  - ${path.join(options.outDir, ".github", "workflows", "playwright.yml")}`);
  } finally {
    await removeDir(tempStageRoot);
  }
}

main().catch((error) => {
  console.error("[scaffold-sdk] error:", error);
  process.exitCode = 1;
});
