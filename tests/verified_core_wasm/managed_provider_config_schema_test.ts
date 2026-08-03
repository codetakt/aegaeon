#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const validatorPath = path.join(
  ROOT_DIR,
  "scripts",
  "validation",
  "validate_managed_external_provider_config.py",
);
const schemaPath = path.join(ROOT_DIR, "spec", "managed-external-provider.schema.json");

async function resolveExamplePath() {
  const candidates = [
    path.join(
      ROOT_DIR,
      "tests",
      "verified_core_wasm",
      "providers",
      "managed",
      "managed-provider.example.json",
    ),
    path.join(ROOT_DIR, "tests", "providers", "managed", "managed-provider.example.json"),
  ];
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
  throw new Error("Unable to locate managed-provider.example.json");
}

async function assertExists(filePath) {
  await stat(filePath);
}

async function main() {
  console.log("=== managed provider config schema test ===");
  await assertExists(validatorPath);
  await assertExists(schemaPath);
  const examplePath = await resolveExamplePath();

  await execFile("python3", [validatorPath, examplePath], { cwd: ROOT_DIR });

  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-managed-schema-"));
  const invalidConfigPath = path.join(tempRoot, "managed-invalid.json");
  const invalidConfig = /** @type {any} */ (JSON.parse(await readFile(examplePath, "utf8")));
  invalidConfig.usernameEnv = "CUSTOM_USERNAME_ENV";
  await writeFile(invalidConfigPath, `${JSON.stringify(invalidConfig, null, 2)}\n`, "utf8");

  await assert.rejects(
    execFile("python3", [validatorPath, invalidConfigPath], { cwd: ROOT_DIR }),
    (error) => Number((/** @type {any} */ (error))?.code) === 1,
  );

  console.log("managed provider config schema tests passed");
}

main().catch((error) => {
  console.error("[fail] managed_provider_config_schema_test:", error);
  process.exitCode = 1;
});
