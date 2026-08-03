#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat } from "node:fs/promises";
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
  console.log("=== managed provider evidence test ===");
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_managed_provider_evidence.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-managed-provider-evidence.js"),
    path.join(ROOT_DIR, "scripts", "build-managed-provider-evidence.ts"),
  ]);
  const validatorPath = path.join(
    ROOT_DIR,
    "scripts",
    "validation",
    "validate_managed_provider_evidence.py",
  );
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
  const claimBoundaryPath = path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-managed-provider-evidence-"));
  const outPath = path.join(tempRoot, "managed-provider-evidence.json");

  await execFile(process.execPath, [
    scriptPath,
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
    outPath,
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

  await execFile("python3", [validatorPath, outPath], { cwd: ROOT_DIR });
  const evidence = JSON.parse(await readFile(outPath, "utf8"));
  assert.equal(evidence.schema_version, 1);
  assert.equal(evidence.provider.name, "commercial-staging");
  assert.equal(evidence.provider.class, "commercial");
  assert.equal(evidence.provider.auth_method, "client_secret_post");
  assert.equal(evidence.lane.name, "external-provider-managed");
  assert.equal(evidence.lane.hosted, true);
  assert.equal(evidence.lane.status, "passed");
  assert.equal(evidence.lane.browser, "/usr/bin/chromium");
  assert.equal(evidence.runtime.default_profile, "aegaeon-rs256");
  assert.equal(evidence.runtime.claim_phase, "pre-release-client-baseline");
  assert.deepEqual(evidence.runtime.promoted_client_slices, ["rs256-required-client-slice"]);
  assert.deepEqual(evidence.runtime.compat_only_surfaces, ["es256-interop-surface"]);
  assert.match(evidence.source.config_sha256, /^[0-9a-f]{64}$/);
  assert.match(evidence.source.claim_boundary_sha256, /^[0-9a-f]{64}$/);
  assert.equal(evidence.source.github_run_id, "54321");
  assert.equal(evidence.source.github_workflow, "SDK Managed Provider Evidence");
  assert.equal(evidence.source.github_repository, "openai/aegaeon-sdk");
  assert.equal(evidence.source.github_ref, "main");
  assert.equal(evidence.source.github_sha, "abc123managed");
  assert.equal(evidence.source.github_job, "external-provider-managed");
  console.log("managed provider evidence tests passed");
}

main().catch((error) => {
  console.error("[fail] managed_provider_evidence_test:", error);
  process.exitCode = 1;
});
