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
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  throw new Error(`No candidate path exists: ${candidates.join(", ")}`);
}

async function resolveExamplePath() {
  return firstExistingPath([
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
}

async function main() {
  console.log("=== managed provider readiness test ===");
  const scriptPath = await firstExistingPath([
    path.join(ROOT_DIR, "dist-tools", "check-managed-provider-readiness.js"),
    path.join(ROOT_DIR, "sdk", "dist-tools", "check-managed-provider-readiness.js"),
    path.join(ROOT_DIR, "scripts", "sdk", "check_managed_provider_readiness.ts"),
    path.join(ROOT_DIR, "scripts", "check-managed-provider-readiness.ts"),
  ]);
  const examplePath = await resolveExamplePath();

  const success = await execFile(process.execPath, [
    scriptPath,
    "--config",
    examplePath,
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: "alice@example.com",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: "correct-horse-battery-staple",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET: "client-secret",
    },
  });
  assert.match(success.stdout, /checks passed/);

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-managed-readiness-"));
  const noneConfigPath = path.join(tempRoot, "managed-none.json");
  const noneConfig = /** @type {any} */ (JSON.parse(await readFile(examplePath, "utf8")));
  noneConfig.authMethod = "none";
  delete noneConfig.clientSecretEnv;
  await writeFile(noneConfigPath, `${JSON.stringify(noneConfig, null, 2)}\n`, "utf8");

  const authNone = await execFile(process.execPath, [
    scriptPath,
    "--config",
    noneConfigPath,
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: "alice@example.com",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: "correct-horse-battery-staple",
    },
  });
  assert.match(authNone.stdout, /checks passed/);

  await assert.rejects(
    execFile(process.execPath, [
      scriptPath,
      "--config",
      examplePath,
    ], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: "alice@example.com",
        AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: "correct-horse-battery-staple",
      },
    }),
    (error) => {
      const execError = /** @type {any} */ (error);
      assert.equal(Number(execError?.code), 1);
      assert.match(execError.stderr, /managed provider client secret/);
      return true;
    },
  );

  const requireBrowser = await execFile(process.execPath, [
    scriptPath,
    "--config",
    examplePath,
    "--require-browser",
  ], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: "alice@example.com",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: "correct-horse-battery-staple",
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET: "client-secret",
      PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH: process.execPath,
    },
  });
  assert.match(requireBrowser.stdout, /chromium:/);
  assert.match(requireBrowser.stdout, /checks passed/);

  console.log("managed provider readiness tests passed");
}

main().catch((error) => {
  console.error("[fail] managed_provider_readiness_test:", error);
  process.exitCode = 1;
});
