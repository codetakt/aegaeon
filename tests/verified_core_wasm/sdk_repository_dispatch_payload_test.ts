#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const exportEnvScriptPath = path.join(
  ROOT_DIR,
  "scripts",
  "sdk",
  "export_sdk_repository_dispatch_env.ts",
);
const materializeScriptPath = path.join(
  ROOT_DIR,
  "scripts",
  "sdk",
  "materialize_sdk_repository_dispatch_payload.ts",
);
const scriptPath = path.join(
  ROOT_DIR,
  "scripts",
  "sdk",
  "build_sdk_repository_dispatch_payload.ts",
);
const validatorPath = path.join(
  ROOT_DIR,
  "scripts",
  "validation",
  "validate_sdk_repository_dispatch_payload.py",
);
const schemaPath = path.join(ROOT_DIR, "spec", "sdk-repository-dispatch.schema.json");
const workflowPath = path.join(ROOT_DIR, ".github", "workflows", "release-core.yml");

async function assertExists(filePath) {
  await stat(filePath);
}

async function main() {
  console.log("=== SDK Repository Dispatch Payload Tests ===");

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-dispatch-"));
  const outputPath = path.join(tempRoot, "dispatch.json");
  const directArtifactPath = path.join(tempRoot, "dispatch-direct.json");
  const invalidPath = path.join(tempRoot, "dispatch-invalid.json");

  await execFile(process.execPath, [
    scriptPath,
    "--core-repo", "example/aegaeon",
    "--core-release-tag", "v0.9.0-core.1",
    "--source-commit", "deadbeefcafebabe",
    "--source-run-id", "12345",
    "--source-workflow", "Verified Core Release",
    "--release-url", "https://example.invalid/releases/v0.9.0-core.1",
    "--generated-at", "2026-03-10T00:00:00Z",
    "--output", outputPath,
  ], { cwd: ROOT_DIR });

  await assertExists(outputPath);
  await assertExists(validatorPath);
  await assertExists(schemaPath);
  await assertExists(materializeScriptPath);
  await assertExists(exportEnvScriptPath);
  const payload = JSON.parse(await readFile(outputPath, "utf8"));

  assert.equal(payload.event_type, "verified-core-release");
  assert.equal(payload.client_payload.core_repo, "example/aegaeon");
  assert.equal(payload.client_payload.core_release_tag, "v0.9.0-core.1");
  assert.equal(payload.client_payload.source_commit, "deadbeefcafebabe");
  assert.equal(payload.client_payload.source_workflow, "Verified Core Release");
  assert.equal(payload.client_payload.source_run_id, "12345");
  assert.equal(
    payload.client_payload.release_url,
    "https://example.invalid/releases/v0.9.0-core.1",
  );
  assert.equal(payload.client_payload.generated_at, "2026-03-10T00:00:00Z");
  assert.equal(payload.client_payload.artifact_bundle, "github-release");

  await execFile("python3", [validatorPath, outputPath], { cwd: ROOT_DIR });

  const materializedPath = path.join(tempRoot, "dispatch-materialized.json");
  await execFile(process.execPath, [
    materializeScriptPath,
    "--event-type", payload.event_type,
    "--client-payload-json", JSON.stringify(payload.client_payload),
    "--output", materializedPath,
  ], { cwd: ROOT_DIR });
  assert.deepEqual(
    JSON.parse(await readFile(materializedPath, "utf8")),
    payload,
  );

  const { stdout: envStdout } = await execFile(process.execPath, [
    exportEnvScriptPath,
    "--payload", outputPath,
  ], { cwd: ROOT_DIR });
  assert.match(envStdout, /AEGAEON_CORE_RELEASE_REPO=example\/aegaeon/);
  assert.match(envStdout, /AEGAEON_CORE_RELEASE_TAG=v0\.9\.0-core\.1/);

  await writeFile(directArtifactPath, `${JSON.stringify({
    event_type: "verified-core-release",
    client_payload: {
      artifact_bundle: "direct-artifact",
      manifest_path: "dist/manifest.json",
      wasm_path: "dist/verified_core.wasm",
      signature_path: "dist/verified_core.wasm.sig",
      public_key_path: "keys/verified-core.pub",
      source_commit: "deadbeefcafebabe",
      source_workflow: "manual-sdk-handoff",
      generated_at: "2026-03-10T00:00:00Z",
    },
  }, null, 2)}\n`);
  await execFile("python3", [validatorPath, directArtifactPath], { cwd: ROOT_DIR });

  await writeFile(invalidPath, `${JSON.stringify({
    event_type: "verified-core-release",
    client_payload: {
      artifact_bundle: "github-release",
      core_repo: "example/aegaeon",
      source_commit: "deadbeefcafebabe",
      source_workflow: "Verified Core Release",
      generated_at: "2026-03-10T00:00:00Z",
    },
  }, null, 2)}\n`);
  await assert.rejects(
    execFile("python3", [validatorPath, invalidPath], { cwd: ROOT_DIR }),
    (error) => Number(error?.code) === 1,
  );

  const workflow = await readFile(workflowPath, "utf8");
  assert.match(workflow, /sdk_repo:/);
  assert.match(workflow, /sdk_dispatch_event_type:/);
  assert.match(workflow, /build_sdk_repository_dispatch_payload\.(mjs|ts)/);
  assert.match(
    workflow,
    /validate_sdk_repository_dispatch_payload\.py dist\/sdk-repository-dispatch\.json/,
  );
  assert.match(workflow, /sdk-repository-dispatch\.json/);
  assert.match(workflow, /repos\/\$\{\{ github\.event\.inputs\.sdk_repo \}\}\/dispatches/);

  console.log("=== sdk dispatch payload checks passed ===");
}

main().catch((error) => {
  console.error("[fail] sdk_repository_dispatch_payload_test:", error);
  process.exitCode = 1;
});
