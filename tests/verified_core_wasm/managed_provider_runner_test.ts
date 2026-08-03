#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

async function loadManagedRunnerModule() {
  const candidates = [
    pathToFileURL(
      path.join(ROOT_DIR, "dist-tests", "providers", "managed", "run_managed_browser_e2e.js"),
    ),
  ];
  for (const candidate of candidates) {
    try {
      return await import(candidate.href);
    } catch (error) {
      if (error?.code !== "ERR_MODULE_NOT_FOUND") {
        throw error;
      }
    }
  }
  throw new Error("Unable to locate dist-tests/providers/managed/run_managed_browser_e2e.js");
}

const {
  loadManagedProviderConfig,
  resolveManagedProviderExecution,
} = await loadManagedRunnerModule();

async function main() {
  console.log("=== managed provider runner test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-managed-provider-"));
  const configPath = path.join(tempRoot, "provider.json");
  await writeFile(configPath, `${JSON.stringify({
    providerName: "managed-example",
    issuer: "https://login.example.com/oidc",
    clientId: "browser-client",
    authMethod: "client_secret_post",
    usernameEnv: "AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME",
    passwordEnv: "AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD",
    clientSecretEnv: "AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET",
    loginScript: [
      { action: "waitForSelector", selector: "#username", timeoutMs: 1000 },
      { action: "fill", selector: "#username", valueFrom: "username" },
      { action: "click", selector: "button[type='submit']" },
      { action: "waitForSelector", selector: "#password", timeoutMs: 1000 },
      { action: "fill", selector: "#password", valueFrom: "password" },
      { action: "clickIfVisible", selector: "#consent", timeoutMs: 250 },
    ],
  }, null, 2)}\n`, "utf8");

  const config = await loadManagedProviderConfig(configPath);
  assert.equal(config.providerName, "managed-example");
  assert.equal(config.authMethod, "client_secret_post");
  assert.equal(config.loginScript.length, 6);

  const execution = resolveManagedProviderExecution(config, {
    AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: "alice@example.com",
    AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD: "password-123",
    AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET: "client-secret",
  });
  assert.equal(execution.AEGAEON_EXTERNAL_PROVIDER_KIND, "scripted");
  assert.equal(execution.AEGAEON_EXTERNAL_PROVIDER_ISSUER, "https://login.example.com/oidc");
  assert.equal(execution.AEGAEON_EXTERNAL_PROVIDER_CLIENT_ID, "browser-client");
  assert.equal(execution.AEGAEON_EXTERNAL_PROVIDER_CLIENT_SECRET, "client-secret");

  const resolvedScript = JSON.parse(execution.AEGAEON_EXTERNAL_PROVIDER_LOGIN_SCRIPT_JSON);
  assert.deepEqual(resolvedScript[1], {
    action: "fill",
    selector: "#username",
    value: "alice@example.com",
  });
  assert.deepEqual(resolvedScript[4], {
    action: "fill",
    selector: "#password",
    value: "password-123",
  });

  assert.throws(
    () => resolveManagedProviderExecution(config, {
      AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME: "alice@example.com",
    }),
    /managed provider password/,
  );

  console.log("managed provider runner tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
