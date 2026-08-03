#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
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
  console.log("=== sdk release attestation test ===");
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "build_sdk_release_attestation.ts"),
    path.join(ROOT_DIR, "dist-tools", "build-release-attestation.js"),
    path.join(ROOT_DIR, "scripts", "build-release-attestation.ts"),
  ]);
  const validatorPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "validation", "validate_sdk_release_attestation.py"),
  ]);
  const signatureCheckPath = await firstExistingPath([
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_release_attestation_signature.ts"),
    path.join(ROOT_DIR, "dist-tools", "check-release-attestation-signature.js"),
    path.join(ROOT_DIR, "scripts", "check-release-attestation-signature.ts"),
  ]);
  const schemaPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "sdk-release-attestation.schema.json"),
  ]);
  const boundaryPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "client-claim-boundary.current.json"),
  ]);

  await stat(scriptPath);
  await stat(validatorPath);
  await stat(schemaPath);

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-attestation-"));
  const publishManifestPath = path.join(tempRoot, "publish-manifest.json");
  const outPath = path.join(tempRoot, "release-attestation.json");

  await writeFile(
    publishManifestPath,
    `${JSON.stringify({
      schemaVersion: 1,
      generatedAt: "2026-03-12T00:00:00Z",
      source: {
        githubRef: "refs/heads/main",
        githubSha: "deadbeefcafebabe",
        githubRunId: "12345",
        githubWorkflow: "publish",
        npmDistTag: "next",
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
        manifestSha256: "2".repeat(64),
        handoffManifestPath: "packages/verified-core/dist/verified-core-handoff-manifest.json",
        handoffManifestSha256: "3".repeat(64),
      },
    }, null, 2)}\n`,
    "utf8",
  );

  await execFile(
    process.execPath,
    [
      scriptPath,
      "--root",
      tempRoot,
      "--publish-manifest",
      publishManifestPath,
      "--claim-boundary",
      boundaryPath,
      "--out",
      outPath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        NPM_CONFIG_PROVENANCE: "true",
      },
    },
  );

  await execFile("python3", [validatorPath, outPath], { cwd: ROOT_DIR });
  await execFile(
    process.execPath,
    [signatureCheckPath, "--root", tempRoot, "--attestation", outPath],
    {
      cwd: ROOT_DIR,
    },
  );
  const attestation = JSON.parse(await readFile(outPath, "utf8"));

  assert.equal(attestation.schema_version, 1);
  assert.equal(attestation.release_phase, "pre-release-client-baseline");
  assert.equal(attestation.publication.npm_provenance_enabled, true);
  assert.equal(attestation.publication.signed_release_attestation_present, false);
  assert.equal(attestation.publication.sbom_publication_present, false);
  assert.equal(attestation.client_claim_boundary.default_profile, "aegaeon-rs256");
  assert.equal(attestation.client_claim_boundary.released_client_claim_active, false);
  assert.deepEqual(attestation.client_claim_boundary.promoted_client_slices, [
    "rs256-required-client-slice",
  ]);
  assert.deepEqual(attestation.client_claim_boundary.compat_only_surfaces, [
    "es256-interop-surface",
  ]);
  assert.equal(attestation.publish_manifest.tarball_count, 1);
  assert.equal(
    attestation.verified_core.manifest_path,
    "packages/verified-core/dist/manifest.json",
  );
  assert.equal(
    attestation.verified_core.handoff_manifest_path,
    "packages/verified-core/dist/verified-core-handoff-manifest.json",
  );
  assert.match(attestation.publish_manifest.sha256, /^[0-9a-f]{64}$/);
  assert.match(attestation.client_claim_boundary.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(attestation.deferred_requirements, [
    "signed_release_attestations",
    "published_sdk_sboms",
    "released_client_claim_promotion",
  ]);

  console.log("sdk release attestation tests passed");
}

main().catch((error) => {
  console.error("[fail] sdk_release_attestation_test:", error);
  process.exitCode = 1;
});
