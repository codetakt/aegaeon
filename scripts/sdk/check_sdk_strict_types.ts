#!/usr/bin/env node
import { existsSync, promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

type StrictTypesPolicy = {
  schema_version: number;
  required_base_flags: Record<string, boolean>;
  package_tsconfig_paths: string[];
  additional_tsconfig_requirements: Array<{
    path: string;
    required_flags: Record<string, boolean>;
  }>;
  forbidden_false_overrides: string[];
  required_no_tsnocheck_paths: string[];
};

type TsconfigLike = {
  compilerOptions?: Record<string, unknown>;
};

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_POLICY_PATH = "spec/strict-types.current.json";

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-strict-types.js [--root <sdk-root>] [--policy <path>]",
  ].join("\n");
}

function parseArgs(argv: string[]): { root: string | null; policy: string } {
  const options = {
    root: process.env["AEGAEON_SDK_ROOT"] ?? process.env["AEG_SDK_ROOT"] ?? null,
    policy:
      process.env["AEGAEON_STRICT_TYPES_POLICY_PATH"] ??
      process.env["AEG_STRICT_TYPES_POLICY_PATH"] ??
      DEFAULT_POLICY_PATH,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) {
      continue;
    }
    if (token === "--") {
      continue;
    }
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (!token.startsWith("--")) {
      continue;
    }
    const rawKey = token.slice(2);
    const key = rawKey.replace(/-([a-z])/g, (_match, character: string) => character.toUpperCase());
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(key in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[key as keyof typeof options] = value;
    index += 1;
  }

  return options;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as T;
}

function ensureBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function ensureStringArray(value: unknown, label: string): string[] {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string" || entry.length === 0)
  ) {
    throw new Error(`Expected array of non-empty strings for ${label}`);
  }
  return value as string[];
}

function ensureBooleanRecord(value: unknown, label: string): Record<string, boolean> {
  if (!isRecord(value)) {
    throw new Error(`Expected object for ${label}`);
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, ensureBoolean(entry, `${label}.${key}`)]),
  );
}

function ensureAdditionalTsconfigRequirements(
  value: unknown,
  label: string,
): Array<{ path: string; required_flags: Record<string, boolean> }> {
  if (!Array.isArray(value)) {
    throw new Error(`Expected array for ${label}`);
  }

  return value.map((entry, index) => {
    if (!isRecord(entry)) {
      throw new Error(`Expected object for ${label}[${String(index)}]`);
    }

    if (typeof entry["path"] !== "string" || entry["path"].length === 0) {
      throw new Error(`Expected non-empty string for ${label}[${String(index)}].path`);
    }

    return {
      path: entry["path"],
      required_flags: ensureBooleanRecord(
        entry["required_flags"],
        `${label}[${String(index)}].required_flags`,
      ),
    };
  });
}

function validatePolicy(policy: unknown): StrictTypesPolicy {
  if (!isRecord(policy)) {
    throw new Error("Strict types policy must be an object");
  }
  if (!isRecord(policy["required_base_flags"])) {
    throw new Error("Strict types policy requires required_base_flags");
  }

  const requiredBaseFlags = Object.fromEntries(
    Object.entries(policy["required_base_flags"]).map(([key, value]) => [
      key,
      ensureBoolean(value, `required_base_flags.${key}`),
    ]),
  );

  return {
    schema_version: Number(policy["schema_version"] ?? 0),
    required_base_flags: requiredBaseFlags,
    package_tsconfig_paths: ensureStringArray(
      policy["package_tsconfig_paths"],
      "package_tsconfig_paths",
    ),
    additional_tsconfig_requirements: ensureAdditionalTsconfigRequirements(
      policy["additional_tsconfig_requirements"] ?? [],
      "additional_tsconfig_requirements",
    ),
    forbidden_false_overrides: ensureStringArray(
      policy["forbidden_false_overrides"],
      "forbidden_false_overrides",
    ),
    required_no_tsnocheck_paths: ensureStringArray(
      policy["required_no_tsnocheck_paths"],
      "required_no_tsnocheck_paths",
    ),
  };
}

function findWorkspaceRoot(explicitRoot: string | null): string {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR);
  for (;;) {
    const packageJsonPath = path.join(current, "package.json");
    const packagesPath = path.join(current, "packages");
    if (existsSync(packageJsonPath) && existsSync(packagesPath)) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
}

function containsTsNoCheckDirective(sourceText: string): boolean {
  return /^\s*\/\/\s*@ts-nocheck\b/m.test(sourceText) || /\/\*\s*@ts-nocheck\b/.test(sourceText);
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const policyPath = resolveWithinRoot(rootDir, options.policy);
  const policy = validatePolicy(await readJson<unknown>(policyPath));
  const baseTsconfig = await readJson<TsconfigLike>(path.join(rootDir, "tsconfig.base.json"));
  const baseCompilerOptions = baseTsconfig.compilerOptions ?? {};
  const failures: string[] = [];

  for (const [flagName, expectedValue] of Object.entries(policy.required_base_flags)) {
    if (baseCompilerOptions[flagName] !== expectedValue) {
      failures.push(
        `tsconfig.base.json compilerOptions.${flagName} must be ` +
          `${String(expectedValue)} (got ${String(baseCompilerOptions[flagName])})`,
      );
    }
  }

  for (const relativePath of policy.package_tsconfig_paths) {
    const packageTsconfig = await readJson<TsconfigLike>(resolveWithinRoot(rootDir, relativePath));
    const compilerOptions = packageTsconfig.compilerOptions ?? {};
    for (const flagName of policy.forbidden_false_overrides) {
      if (compilerOptions[flagName] === false) {
        failures.push(`${relativePath} must not override compilerOptions.${flagName}=false`);
      }
    }
  }

  for (const requirement of policy.additional_tsconfig_requirements) {
    const tsconfig = await readJson<TsconfigLike>(resolveWithinRoot(rootDir, requirement.path));
    const compilerOptions = tsconfig.compilerOptions ?? {};
    for (const [flagName, expectedValue] of Object.entries(requirement.required_flags)) {
      if (compilerOptions[flagName] !== expectedValue) {
        failures.push(
          `${requirement.path} compilerOptions.${flagName} must be ` +
            `${String(expectedValue)} (got ${String(compilerOptions[flagName])})`,
        );
      }
    }
  }

  for (const relativePath of policy.required_no_tsnocheck_paths) {
    const sourceText = await fs.readFile(resolveWithinRoot(rootDir, relativePath), "utf8");
    if (containsTsNoCheckDirective(sourceText)) {
      failures.push(`${relativePath} still contains @ts-nocheck`);
    }
  }

  if (failures.length > 0) {
    throw new Error(`Strict types policy mismatches:\n- ${failures.join("\n- ")}`);
  }

  console.log(`Strict types policy at ${path.relative(rootDir, policyPath)} matches ${rootDir}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
