#!/usr/bin/env node
import { execFile as execFileCallback } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = path.resolve(MODULE_DIR, "..", "..", "..");
const DEFAULT_USERNAME_ENV = "AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME";
const DEFAULT_PASSWORD_ENV = "AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD";
const DEFAULT_CLIENT_SECRET_ENV = "AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET";

function ensureHostedEnvName(value, expected, label) {
  const normalized = ensureOptionalString(value ?? null, label);
  if (normalized == null) {
    return expected;
  }
  if (normalized !== expected) {
    throw new Error(`${label} must be ${JSON.stringify(expected)} when provided`);
  }
  return normalized;
}

function parseArgs(argv) {
  const options = {
    required: false,
    config: process.env.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG ?? null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--required") {
      options.required = true;
      continue;
    }
    if (token === "--config") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("Missing value for option --config");
      }
      options.config = value;
      index += 1;
      continue;
    }
  }

  return options;
}

function ensureString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function ensureOptionalString(value, label) {
  if (value == null) {
    return null;
  }
  return ensureString(value, label);
}

function ensureNonNegativeInteger(value, label) {
  if (value == null) {
    return null;
  }
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer when provided`);
  }
  return value;
}

function normalizeStep(step, index) {
  if (!step || typeof step !== "object" || Array.isArray(step)) {
    throw new Error(`loginScript[${index}] must be an object`);
  }
  const action = ensureString(step.action, `loginScript[${index}].action`);
  switch (action) {
    case "waitForURL":
      return Object.freeze({
        action,
        pattern: ensureString(step.pattern, `loginScript[${index}].pattern`),
        timeoutMs: ensureNonNegativeInteger(
          step.timeoutMs ?? null,
          `loginScript[${index}].timeoutMs`,
        ),
      });
    case "waitForSelector":
      return Object.freeze({
        action,
        selector: ensureString(step.selector, `loginScript[${index}].selector`),
        timeoutMs: ensureNonNegativeInteger(
          step.timeoutMs ?? null,
          `loginScript[${index}].timeoutMs`,
        ),
      });
    case "fill": {
      const selector = ensureString(step.selector, `loginScript[${index}].selector`);
      const literalValue = ensureOptionalString(step.value ?? null, `loginScript[${index}].value`);
      const valueFrom = ensureOptionalString(
        step.valueFrom ?? null,
        `loginScript[${index}].valueFrom`,
      );
      if ((literalValue == null) === (valueFrom == null)) {
        throw new Error(`loginScript[${index}] fill must define exactly one of value or valueFrom`);
      }
      if (valueFrom && valueFrom !== "username" && valueFrom !== "password") {
        throw new Error(`loginScript[${index}].valueFrom must be "username" or "password"`);
      }
      return Object.freeze({
        action,
        selector,
        value: literalValue,
        valueFrom,
      });
    }
    case "click":
      return Object.freeze({
        action,
        selector: ensureString(step.selector, `loginScript[${index}].selector`),
      });
    case "clickIfVisible":
      return Object.freeze({
        action,
        selector: ensureString(step.selector, `loginScript[${index}].selector`),
        timeoutMs: ensureNonNegativeInteger(
          step.timeoutMs ?? null,
          `loginScript[${index}].timeoutMs`,
        ),
      });
    case "press":
      return Object.freeze({
        action,
        selector: ensureOptionalString(step.selector ?? null, `loginScript[${index}].selector`),
        key: ensureString(step.key, `loginScript[${index}].key`),
      });
    case "waitForTimeout":
      return Object.freeze({
        action,
        timeoutMs: ensureNonNegativeInteger(
          step.timeoutMs ?? step.ms ?? null,
          `loginScript[${index}].timeoutMs`,
        ),
      });
    default:
      throw new Error(`loginScript[${index}] uses unsupported action ${JSON.stringify(action)}`);
  }
}

export async function loadManagedProviderConfig(configPath) {
  const resolvedPath = path.resolve(configPath);
  const parsed = JSON.parse(await readFile(resolvedPath, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("managed provider config must be an object");
  }
  const authMethod = ensureOptionalString(parsed.authMethod ?? null, "authMethod") ?? "none";
  if (!["none", "client_secret_basic", "client_secret_post"].includes(authMethod)) {
    throw new Error(
      "authMethod must be one of " +
        '"none", "client_secret_basic", or "client_secret_post"; got ' +
        JSON.stringify(authMethod),
    );
  }
  if (!Array.isArray(parsed.loginScript) || parsed.loginScript.length === 0) {
    throw new Error("loginScript must be a non-empty array");
  }
  return Object.freeze({
    configPath: resolvedPath,
    providerName: ensureString(parsed.providerName ?? "managed-external-provider", "providerName"),
    issuer: ensureString(parsed.issuer, "issuer"),
    clientId: ensureString(parsed.clientId, "clientId"),
    authMethod,
    discoveryUrl: ensureOptionalString(parsed.discoveryUrl ?? null, "discoveryUrl"),
    usernameEnv: ensureHostedEnvName(
      parsed.usernameEnv ?? null,
      DEFAULT_USERNAME_ENV,
      "usernameEnv",
    ),
    passwordEnv: ensureHostedEnvName(
      parsed.passwordEnv ?? null,
      DEFAULT_PASSWORD_ENV,
      "passwordEnv",
    ),
    clientSecretEnv: ensureHostedEnvName(
      parsed.clientSecretEnv ?? null,
      DEFAULT_CLIENT_SECRET_ENV,
      "clientSecretEnv",
    ),
    loginScript: Object.freeze(parsed.loginScript.map((step, index) => normalizeStep(step, index))),
  });
}

function resolveSecret(env, envName, label, { required = true } = {}) {
  const value = env[envName] ?? null;
  if (value == null || value.length === 0) {
    if (required) {
      throw new Error(`${label} must be provided through ${envName}`);
    }
    return null;
  }
  return value;
}

export function resolveManagedProviderExecution(config, env = process.env) {
  const username = resolveSecret(env, config.usernameEnv, "managed provider username");
  const password = resolveSecret(env, config.passwordEnv, "managed provider password");
  const clientSecretRequired = config.authMethod !== "none";
  const clientSecret = resolveSecret(
    env,
    config.clientSecretEnv,
    "managed provider client secret",
    {
      required: clientSecretRequired,
    },
  );

  const loginScript = config.loginScript.map((step) => {
    if (step.action !== "fill") {
      return step;
    }
    return {
      action: step.action,
      selector: step.selector,
      value: step.valueFrom === "username"
        ? username
        : step.valueFrom === "password"
          ? password
          : step.value,
    };
  });

  return Object.freeze({
    AEGAEON_EXTERNAL_PROVIDER_ISSUER: config.issuer,
    AEGAEON_EXTERNAL_PROVIDER_CLIENT_ID: config.clientId,
    AEGAEON_EXTERNAL_PROVIDER_KIND: "scripted",
    AEGAEON_EXTERNAL_PROVIDER_NAME: config.providerName,
    AEGAEON_EXTERNAL_PROVIDER_AUTH_METHOD: config.authMethod,
    ...(config.discoveryUrl
      ? { AEGAEON_EXTERNAL_PROVIDER_DISCOVERY_URL: config.discoveryUrl }
      : {}),
    ...(clientSecret ? { AEGAEON_EXTERNAL_PROVIDER_CLIENT_SECRET: clientSecret } : {}),
    AEGAEON_EXTERNAL_PROVIDER_LOGIN_SCRIPT_JSON: JSON.stringify(loginScript),
  });
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
      const { stdout } = await execFile(
        "bash",
        ["-lc", `command -v ${candidate}`],
        { cwd: WORKSPACE_ROOT },
      );
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

export async function runManagedBrowserE2E({ required = false, configPath }) {
  const chromiumPath = await resolveChromiumPath();
  if (!chromiumPath) {
    if (required) {
      throw new Error("chromium executable is required");
    }
    console.log("[skip] chromium executable is required");
    return;
  }

  if (!configPath) {
    if (required) {
      throw new Error("managed provider config is required");
    }
    console.log("[skip] managed provider config is not configured");
    return;
  }

  const config = await loadManagedProviderConfig(configPath);
  const executionEnv = resolveManagedProviderExecution(config, process.env);
  const { stdout, stderr } = await execFile("corepack", [
    "pnpm",
    "run",
    "test:playwright:external-provider",
  ], {
    cwd: WORKSPACE_ROOT,
    env: {
      ...process.env,
      PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH: chromiumPath,
      ...executionEnv,
    },
  });
  if (stdout) {
    process.stdout.write(stdout);
  }
  if (stderr) {
    process.stderr.write(stderr);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  await runManagedBrowserE2E({
    required: options.required,
    configPath: options.config,
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error("[managed-browser-e2e] error:", error);
    process.exitCode = 1;
  });
}
