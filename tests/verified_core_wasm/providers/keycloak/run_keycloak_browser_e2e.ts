#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = path.resolve(MODULE_DIR, "..", "..", "..");
const composeFile = path.join(MODULE_DIR, "docker-compose.yml");
const realmTemplatePath = path.join(MODULE_DIR, "keycloak-realm.template.json");
const externalClientId = process.env.AEGAEON_EXTERNAL_PROVIDER_CLIENT_ID ?? "browser-client";
const keycloakLoginScript = Object.freeze([
  {
    action: "waitForURL",
    pattern: "/realms/[^/]+/(protocol/openid-connect/auth|login-actions/authenticate)",
    timeoutMs: 20_000,
  },
  {
    action: "waitForSelector",
    selector: "#username",
    timeoutMs: 20_000,
  },
  {
    action: "fill",
    selector: "#username",
    value: process.env.AEGAEON_EXTERNAL_PROVIDER_USERNAME ?? "sdk-user",
  },
  {
    action: "fill",
    selector: "#password",
    value: process.env.AEGAEON_EXTERNAL_PROVIDER_PASSWORD ?? "password",
  },
  {
    action: "click",
    selector: "#kc-login",
  },
]);

function parseArgs(argv) {
  return {
    required: argv.includes("--required"),
  };
}

async function commandExists(command) {
  try {
    await execFile("bash", ["-lc", `command -v ${command}`], { cwd: WORKSPACE_ROOT });
    return true;
  } catch {
    return false;
  }
}

async function resolveChromiumPath() {
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH) {
    return process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  }
  if (process.env.CHROME_BIN) {
    return process.env.CHROME_BIN;
  }
  for (const candidate of [
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
  ]) {
    try {
      const { stdout } = await execFile("bash", ["-lc", `command -v ${candidate}`], {
        cwd: WORKSPACE_ROOT,
      });
      const resolved = stdout.trim();
      if (resolved.length > 0) {
        return resolved;
      }
    } catch {
      continue;
    }
  }
  return null;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForKeycloak(issuer) {
  const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(discoveryUrl, { headers: { accept: "application/json" } });
      if (response.ok) {
        return;
      }
    } catch {
      await delay(1_000);
      continue;
    }
    await delay(1_000);
  }
  throw new Error("timed out waiting for Keycloak discovery");
}

async function findAvailablePort(host = "127.0.0.1") {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        if (!port) {
          reject(new Error("failed to allocate an ephemeral port"));
          return;
        }
        resolve(port);
      });
    });
  });
}

async function createRealmImport({ browserPort, keycloakPort }) {
  const template = await readFile(realmTemplatePath, "utf8");
  const issuer = `http://127.0.0.1:${keycloakPort}/realms/aegaeon`;
  const redirectUri =
    `http://127.0.0.1:${browserPort}` +
    "/tests/browser/issuer_spa_external_provider_e2e.html";
  const webOrigin = `http://127.0.0.1:${browserPort}`;
  const postLogoutRedirectUri = `http://127.0.0.1:${browserPort}/post-logout`;
  const rendered = template
    .replaceAll("__KEYCLOAK_REDIRECT_URI__", redirectUri)
    .replaceAll("__KEYCLOAK_WEB_ORIGIN__", webOrigin)
    .replaceAll("__KEYCLOAK_POST_LOGOUT_REDIRECT_URI__", postLogoutRedirectUri);
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-keycloak-"));
  const configPath = path.join(tempDir, "keycloak-realm.json");
  await writeFile(configPath, rendered, "utf8");
  return {
    configPath,
    issuer,
    tempDir,
  };
}

async function dockerCompose(args, env = process.env) {
  return execFile("docker", ["compose", "-f", composeFile, ...args], {
    cwd: MODULE_DIR,
    env,
  });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const hasDocker = await commandExists("docker");
  const chromiumPath = await resolveChromiumPath();
  if (!hasDocker || !chromiumPath) {
    const reason = !hasDocker ? "docker is required" : "chromium executable is required";
    if (options.required) {
      throw new Error(reason);
    }
    console.log(`[skip] ${reason}`);
    return;
  }

  const browserPort = Number(process.env.AEGAEON_BROWSER_SMOKE_PORT ?? await findAvailablePort());
  const keycloakPort = Number(
    process.env.AEGAEON_EXTERNAL_PROVIDER_KEYCLOAK_PORT ?? await findAvailablePort(),
  );
  const realmImport = await createRealmImport({ browserPort, keycloakPort });
  const composeEnv = {
    ...process.env,
    AEGAEON_EXTERNAL_PROVIDER_KEYCLOAK_PORT: String(keycloakPort),
    AEGAEON_EXTERNAL_PROVIDER_KEYCLOAK_REALM_PATH: realmImport.configPath,
    COMPOSE_PROJECT_NAME: `aegaeon_sdk_keycloak_${keycloakPort}`,
  };

  await dockerCompose(["down", "-v", "--remove-orphans"], composeEnv).catch(() => {});
  await dockerCompose(["up", "-d"], composeEnv);
  try {
    await waitForKeycloak(realmImport.issuer);
    const { stdout, stderr } = await execFile("corepack", [
      "pnpm",
      "run",
      "test:playwright:external-provider",
    ], {
      cwd: WORKSPACE_ROOT,
      env: {
        ...process.env,
        PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH: chromiumPath,
        AEGAEON_BROWSER_SMOKE_PORT: String(browserPort),
        AEGAEON_EXTERNAL_PROVIDER_ISSUER: realmImport.issuer,
        AEGAEON_EXTERNAL_PROVIDER_CLIENT_ID: externalClientId,
        AEGAEON_EXTERNAL_PROVIDER_KIND: "scripted",
        AEGAEON_EXTERNAL_PROVIDER_NAME: "keycloak-local",
        AEGAEON_EXTERNAL_PROVIDER_USERNAME: "sdk-user",
        AEGAEON_EXTERNAL_PROVIDER_PASSWORD: "password",
        AEGAEON_EXTERNAL_PROVIDER_LOGIN_SCRIPT_JSON: JSON.stringify(keycloakLoginScript),
      },
    });
    if (stdout) {
      process.stdout.write(stdout);
    }
    if (stderr) {
      process.stderr.write(stderr);
    }
  } finally {
    await dockerCompose(["down", "-v"], composeEnv).catch(() => {});
    await rm(realmImport.tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

main().catch((error) => {
  console.error("[keycloak-browser-e2e] error:", error);
  process.exitCode = 1;
});
