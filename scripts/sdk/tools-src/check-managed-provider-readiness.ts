import { execFile as execFileCallback } from "node:child_process";
import { access } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));

type ManagedProviderReadinessOptions = {
  config: string | null;
  requireBrowser: boolean;
};

type ManagedProviderConfig = {
  configPath: string;
  authMethod: string;
  usernameEnv: string;
  passwordEnv: string;
  clientSecretEnv: string;
};

type ManagedProviderRunnerModule = {
  loadManagedProviderConfig(configPath: string): Promise<ManagedProviderConfig>;
};

type ManagedProviderReadinessResult = {
  config: ManagedProviderConfig;
  chromiumPath: string | null;
  rootDir: string;
};

type ErrnoLike = {
  code?: string;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-managed-provider-readiness.js --config <path> [--require-browser]",
    "",
    "Environment:",
    "  AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG",
    "  AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME",
    "  AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD",
    "  AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET",
    "  PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
    "  CHROME_BIN",
  ].join("\n");
}

function parseArgs(argv: string[]): ManagedProviderReadinessOptions {
  const options: ManagedProviderReadinessOptions = {
    config: process.env.AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG ?? null,
    requireBrowser: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) {
      continue;
    }
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
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
    if (token === "--require-browser") {
      options.requireBrowser = true;
    }
  }

  if (!options.config) {
    throw new Error(`--config is required.\n\n${usage()}`);
  }

  return options;
}

async function firstExistingPath(candidates: string[]): Promise<string> {
  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch (error) {
      if ((error as ErrnoLike | undefined)?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  throw new Error(`No candidate path exists: ${candidates.join(", ")}`);
}

async function resolveWorkspaceRoot(): Promise<string> {
  return firstExistingPath([
    path.resolve(MODULE_DIR, "..", "..", "spec", "managed-external-provider.schema.json"),
    path.resolve(MODULE_DIR, "..", "spec", "managed-external-provider.schema.json"),
  ]).then((schemaPath) => path.dirname(path.dirname(schemaPath)));
}

async function resolveValidatorPath(rootDir: string): Promise<string> {
  return firstExistingPath([
    path.join(rootDir, "scripts", "validation", "validate_managed_external_provider_config.py"),
  ]);
}

async function loadManagedRunnerModule(rootDir: string): Promise<ManagedProviderRunnerModule> {
  const modulePath = await firstExistingPath([
    path.join(rootDir, "dist-tests", "providers", "managed", "run_managed_browser_e2e.js"),
    path.join(rootDir, "tests", "verified_core_wasm", "providers", "managed", "run_managed_browser_e2e.ts"),
  ]);
  return import(pathToFileURL(modulePath).href) as Promise<ManagedProviderRunnerModule>;
}

function ensureEnvValue(env: NodeJS.ProcessEnv, name: string, label: string): string {
  const value = env[name] ?? "";
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be provided through ${name}`);
  }
  return value;
}

async function resolveChromiumPath(rootDir: string, env: NodeJS.ProcessEnv): Promise<string | null> {
  const direct = env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || env.CHROME_BIN || "";
  if (direct.length > 0) {
    await access(direct);
    return direct;
  }

  for (const candidate of ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]) {
    try {
      const { stdout } = await execFile("bash", ["-lc", `command -v ${candidate}`], { cwd: rootDir });
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

export async function auditManagedProviderReadiness({
  configPath,
  requireBrowser = false,
  env = process.env,
}: {
  configPath: string;
  requireBrowser?: boolean;
  env?: NodeJS.ProcessEnv;
}): Promise<ManagedProviderReadinessResult> {
  const rootDir = await resolveWorkspaceRoot();
  const resolvedConfigPath = path.resolve(configPath);
  const validatorPath = await resolveValidatorPath(rootDir);
  await execFile("python3", [validatorPath, resolvedConfigPath], { cwd: rootDir });

  const runnerModule = await loadManagedRunnerModule(rootDir);
  const config = await runnerModule.loadManagedProviderConfig(resolvedConfigPath);

  ensureEnvValue(env, config.usernameEnv, "managed provider username");
  ensureEnvValue(env, config.passwordEnv, "managed provider password");
  if (config.authMethod !== "none") {
    ensureEnvValue(env, config.clientSecretEnv, "managed provider client secret");
  }

  let chromiumPath = null;
  if (requireBrowser) {
    chromiumPath = await resolveChromiumPath(rootDir, env);
    if (!chromiumPath) {
      throw new Error("chromium executable is required");
    }
  }

  return {
    config,
    chromiumPath,
    rootDir,
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const result = await auditManagedProviderReadiness({
    configPath: options.config!,
    requireBrowser: options.requireBrowser,
  });

  console.log(`[managed-provider-readiness] config: ${path.relative(result.rootDir, result.config.configPath)}`);
  console.log(`[managed-provider-readiness] auth method: ${result.config.authMethod}`);
  console.log(`[managed-provider-readiness] username env: ${result.config.usernameEnv}`);
  console.log(`[managed-provider-readiness] password env: ${result.config.passwordEnv}`);
  if (result.config.authMethod !== "none") {
    console.log(`[managed-provider-readiness] client secret env: ${result.config.clientSecretEnv}`);
  }
  if (result.chromiumPath) {
    console.log(`[managed-provider-readiness] chromium: ${result.chromiumPath}`);
  }
  console.log("[managed-provider-readiness] checks passed");
}

main().catch((error) => {
  console.error("[managed-provider-readiness] error:", error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
