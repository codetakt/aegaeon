#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const scriptPath = path.join(ROOT_DIR, "scripts", "sdk", "build_verified_core_handoff_manifest.ts");
const validatorPath = path.join(
  ROOT_DIR,
  "scripts",
  "validation",
  "validate_verified_core_handoff_manifest.py",
);
const schemaPath = path.join(ROOT_DIR, "spec", "verified-core-handoff-manifest.schema.json");
const workflowPath = path.join(ROOT_DIR, ".github", "workflows", "release-core.yml");

async function assertExists(filePath) {
  await stat(filePath);
}

async function main() {
  console.log("=== Verified Core Handoff Manifest Tests ===");

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-core-handoff-"));
  const outputPath = path.join(tempRoot, "verified-core-handoff-manifest.json");

  await assertExists(scriptPath);
  await assertExists(validatorPath);
  await assertExists(schemaPath);

  await execFile(process.execPath, [
    scriptPath,
    "--core-repo", "example/aegaeon",
    "--core-release-tag", "v0.9.0-core.1",
    "--source-commit", "deadbeefcafebabe",
    "--source-workflow", "Verified Core Release",
    "--source-run-id", "12345",
    "--release-url", "https://example.invalid/releases/v0.9.0-core.1",
    "--release-artifact-name", "verified-core-v0.9.0-core.1",
    "--dispatch-artifact-name", "verified-core-sdk-dispatch-v0.9.0-core.1",
    "--generated-at", "2026-03-10T00:00:00Z",
    "--output", outputPath,
  ], { cwd: ROOT_DIR });

  await execFile("python3", [validatorPath, outputPath], { cwd: ROOT_DIR });

  const manifest = JSON.parse(await readFile(outputPath, "utf8"));
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.bundle_format, "github-release");
  assert.equal(manifest.handoff_manifest_file, "verified-core-handoff-manifest.json");
  assert.equal(manifest.core_repo, "example/aegaeon");
  assert.equal(manifest.core_release_tag, "v0.9.0-core.1");
  assert.equal(manifest.source_commit, "deadbeefcafebabe");
  assert.equal(manifest.source_workflow, "Verified Core Release");
  assert.equal(manifest.source_run_id, "12345");
  assert.equal(manifest.release_url, "https://example.invalid/releases/v0.9.0-core.1");
  assert.equal(manifest.release_artifact_name, "verified-core-v0.9.0-core.1");
  assert.equal(manifest.dispatch_artifact_name, "verified-core-sdk-dispatch-v0.9.0-core.1");
  assert.deepEqual(manifest.required_files, [
    "manifest.json",
    "verified_core.wasm",
    "verified_core.abi.json",
    "verified_core.wasm.sha256",
    "verified_core.wasm.sha512",
    "verified_core.wasm.sri",
    "verified-core-sbom.json",
    "types.d.ts",
    "integrity.txt",
  ]);
  assert.deepEqual(manifest.optional_files, [
    "verified_core.wasm.sig",
    "verified_core.wasm.cosign.sig",
  ]);

  const workflow = await readFile(workflowPath, "utf8");
  assert.match(workflow, /CORE_RELEASE_ARTIFACT_NAME:/);
  assert.match(workflow, /CORE_SDK_DISPATCH_ARTIFACT_NAME:/);
  assert.match(workflow, /CORE_HANDOFF_MANIFEST_FILE:/);
  assert.match(workflow, /build_verified_core_handoff_manifest\.(mjs|ts)/);
  assert.match(workflow, /validate_verified_core_handoff_manifest\.py/);
  assert.match(workflow, /verified-core-handoff-manifest\.json/);

  console.log("=== verified core handoff manifest checks passed ===");
}

main().catch((error) => {
  console.error("[fail] verified_core_handoff_manifest_test:", error);
  process.exitCode = 1;
});
