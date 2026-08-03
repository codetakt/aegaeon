#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../..", import.meta.url).pathname);
const INACTIVE_POLICY_ERROR = new RegExp(
  [
    "released client claim activation was requested,",
    "but the source-managed policy still marks it inactive",
  ].join(" "),
);

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  console.log("=== released client claim activation test ===");
  const checker = path.join(ROOT_DIR, "dist-tools", "check-released-client-claim-activation.js");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-released-client-activation-"));
  const policyPath = path.join(tempRoot, "released-client-claim.current.json");
  const reportPath = path.join(tempRoot, "released-client-claim-report.json");

  const inactivePolicy = {
    schema_version: 1,
    claim_target: "released-client-claim",
    current_state: {
      claim_phase: "pre-release-client-baseline",
      released_client_claim_active: false,
      canonical_statement: "Published packages and a released client claim do not exist yet.",
    },
    target_state: {
      claim_phase: "released-client-claim",
      canonical_statement:
        "Aegaeon SDK provides an assumption-qualified security-tested TypeScript client SDK"
        + " and RP runtime for Aegaeon-issued OIDC flows, with a verified client core and a"
        + " promoted RS256 required client slice.",
      default_profile: "aegaeon-rs256",
      promoted_client_slices: ["rs256-required-client-slice"],
      compat_only_surfaces: ["es256-interop-surface"],
    },
    activation_requirements: {
      promotion_report_ready: true,
      managed_provider_evidence_required: true,
      admin_sdk_evidence_required: true,
      signed_release_attestation_required: true,
      sbom_publication_required: true,
      publication_org_tasks_must_be_done: true,
    },
    required_publication_org_tasks: [
      "publication_org_branch_protection",
      "publication_org_secret_rollout",
    ],
  };

  const blockedReport = {
    schema_version: 1,
    generated_at: "2026-03-16T00:00:00Z",
    claim_target: "released-client-claim",
    current_state: {
      claim_phase: "pre-release-client-baseline",
      released_client_claim_active: false,
      canonical_statement: inactivePolicy.current_state.canonical_statement,
    },
    target_state: {
      claim_phase: "released-client-claim",
      canonical_statement: inactivePolicy.target_state.canonical_statement,
      default_profile: "aegaeon-rs256",
      promoted_client_slices: ["rs256-required-client-slice"],
      compat_only_surfaces: ["es256-interop-surface"],
    },
    evidence: {},
    publication_org_tasks: [
      { name: "publication_org_branch_protection", status: "pending" },
      { name: "publication_org_secret_rollout", status: "pending" },
    ],
    ready: false,
    blockers: ["publication-org task still pending: publication_org_branch_protection"],
  };

  await writeJson(policyPath, inactivePolicy);
  await writeJson(reportPath, blockedReport);

  await execFile(
    process.execPath,
    [checker, "--root", tempRoot, "--policy", policyPath, "--report", reportPath],
    {
      cwd: ROOT_DIR,
    },
  );

  await assert.rejects(
    execFile(
      process.execPath,
      [
        checker,
        "--root",
        tempRoot,
        "--policy",
        policyPath,
        "--report",
        reportPath,
        "--claim-active",
        "true",
      ],
      {
        cwd: ROOT_DIR,
      },
    ),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(execError.stderr, INACTIVE_POLICY_ERROR);
      return true;
    },
  );

  const activePolicy = structuredClone(inactivePolicy);
  activePolicy.current_state.claim_phase = "released-client-claim";
  activePolicy.current_state.released_client_claim_active = true;
  activePolicy.current_state.canonical_statement = inactivePolicy.target_state.canonical_statement;
  await writeJson(policyPath, activePolicy);

  await assert.rejects(
    execFile(
      process.execPath,
      [checker, "--root", tempRoot, "--policy", policyPath, "--report", reportPath],
      {
        cwd: ROOT_DIR,
      },
    ),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(execError.stderr, /released-client report: publication-org task still pending/);
      return true;
    },
  );

  const readyReport = structuredClone(blockedReport);
  readyReport.current_state.claim_phase = "released-client-claim";
  readyReport.current_state.released_client_claim_active = true;
  readyReport.current_state.canonical_statement = activePolicy.current_state.canonical_statement;
  readyReport.ready = true;
  readyReport.blockers = [];
  readyReport.publication_org_tasks = [
    { name: "publication_org_branch_protection", status: "done" },
    { name: "publication_org_secret_rollout", status: "done" },
  ];
  await writeJson(reportPath, readyReport);

  await execFile(
    process.execPath,
    [checker, "--root", tempRoot, "--policy", policyPath, "--report", reportPath],
    {
      cwd: ROOT_DIR,
    },
  );

  console.log("released client claim activation tests passed");
}

main().catch((error) => {
  console.error("[fail] released_client_claim_activation_test:", error);
  process.exitCode = 1;
});
