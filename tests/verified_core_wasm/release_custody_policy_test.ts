#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, stat, writeFile } from "node:fs/promises";
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
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  console.log("=== release custody policy test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-release-custody-"));
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "dist-tools", "check-release-custody.js"),
    path.join(ROOT_DIR, "scripts", "check-release-custody.ts"),
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_release_custody.ts"),
  ]);
  const policyPath = await firstExistingPath([
    path.join(ROOT_DIR, "spec", "release-custody.current.json"),
    path.join(ROOT_DIR, "scripts", "sdk", "sdk_release_custody.current.json"),
  ]);

  const baselineActualPath = path.join(tempRoot, "baseline.json");
  await writeJson(baselineActualPath, {
    secrets: [],
    variables: {
      AEGAEON_REAL_PUBLISH_ENABLED: "false",
      AEGAEON_NPM_DIST_TAG: "next",
    },
  });
  const baselineResult = await execFile(process.execPath, [
    scriptPath,
    "--policy",
    policyPath,
    "--actual",
    baselineActualPath,
  ], { cwd: ROOT_DIR });
  assert.match(baselineResult.stdout, /matches/);

  const productionActualPath = path.join(tempRoot, "production.json");
  await writeJson(productionActualPath, {
    secrets: [
      "AEGAEON_NPM_TOKEN",
      "AEGAEON_COSIGN_KEY",
      "AEGAEON_CARGO_REGISTRY_TOKEN",
    ],
    variables: {
      AEGAEON_REAL_PUBLISH_ENABLED: "true",
      AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION: "true",
      AEGAEON_SDK_SBOM_PUBLICATION: "true",
      AEGAEON_SDK_CARGO_PUBLISH_ENABLED: "true",
      AEGAEON_NPM_DIST_TAG: "latest",
    },
  });
  const productionResult = await execFile(process.execPath, [
    scriptPath,
    "--policy",
    policyPath,
    "--actual",
    productionActualPath,
  ], { cwd: ROOT_DIR });
  assert.match(productionResult.stdout, /matches/);

  const missingPublishTokenPath = path.join(tempRoot, "missing-publish-token.json");
  await writeJson(missingPublishTokenPath, {
    secrets: [],
    variables: {
      AEGAEON_REAL_PUBLISH_ENABLED: "true",
    },
  });
  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--policy",
      policyPath,
      "--actual",
      missingPublishTokenPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(execError.stderr, /real_publish_lane/);
      assert.match(execError.stderr, /npm_publish/);
      return true;
    },
  );

  const missingSigningKeyPath = path.join(tempRoot, "missing-signing-key.json");
  await writeJson(missingSigningKeyPath, {
    secrets: [
      "AEGAEON_NPM_TOKEN",
    ],
    variables: {
      AEGAEON_REAL_PUBLISH_ENABLED: "false",
      AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION: "true",
    },
  });
  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--policy",
      policyPath,
      "--actual",
      missingSigningKeyPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(
        execError.stderr,
        /signed_release_attestation_lane variable AEGAEON_REAL_PUBLISH_ENABLED/,
      );
      assert.match(execError.stderr, /signed_release_attestation_key/);
      return true;
    },
  );

  const missingCargoTokenPath = path.join(tempRoot, "missing-cargo-token.json");
  await writeJson(missingCargoTokenPath, {
    secrets: [
      "AEGAEON_NPM_TOKEN",
      "AEGAEON_COSIGN_KEY",
    ],
    variables: {
      AEGAEON_REAL_PUBLISH_ENABLED: "true",
      AEGAEON_SDK_CARGO_PUBLISH_ENABLED: "true",
    },
  });
  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--policy",
      policyPath,
      "--actual",
      missingCargoTokenPath,
    ], { cwd: ROOT_DIR }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(execError.code, 1);
      assert.match(execError.stderr, /cargo_publish_lane/);
      assert.match(execError.stderr, /AEGAEON_CARGO_REGISTRY_TOKEN/);
      return true;
    },
  );

  console.log("release custody policy tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
