#!/usr/bin/env node

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TOOL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const DEFAULT_POLICY_PATH = path.join(TOOL_ROOT, "spec", "external-boundary-naming.current.json");
const DEFAULT_IGNORED_PATHS = new Set<string>([
  ".artifacts",
  ".git",
  "coverage",
  "dist",
  "dist-tests",
  "dist-tools",
  "node_modules",
  "result",
  "storybook-static",
  "target",
]);

interface PrefixPolicy {
  target_prefix: string;
  deprecated_prefix: string;
}

interface ArtifactNamingPolicy {
  target_prefix: string;
}

interface InternalCodePolicy {
  prefix_policy: "none";
}

interface MigrationPolicy {
  strategy: "breaking_cutover_no_aliases";
  phase_order: string[];
}

interface ScopePolicy {
  external_boundary_kinds: string[];
  excluded_kinds: string[];
}

interface ExternalBoundaryNamingPolicy {
  version: 1;
  external_boundary_env: PrefixPolicy;
  external_boundary_wire: PrefixPolicy;
  artifact_naming: ArtifactNamingPolicy;
  internal_code: InternalCodePolicy;
  migration: MigrationPolicy;
  scope: ScopePolicy;
  ignore_paths: string[];
}

interface ParsedOptions {
  root: string;
  policy: string;
}

interface PrefixInventory {
  identifiers: number;
  occurrences: number;
  top: Array<[string, number]>;
}

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-external-boundary-naming.js [--root <repo-root>] [--policy <path>]",
  ].join("\n");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function ensureString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`Expected array for ${label}`);
  }
  return value.map((entry, index) => ensureString(entry, `${label}[${index}]`));
}

function parseArgs(argv: readonly string[]): ParsedOptions {
  const options: ParsedOptions = {
    root: TOOL_ROOT,
    policy: DEFAULT_POLICY_PATH,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") {
      continue;
    }
    if (token === "--help" || token === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (token == null || !token.startsWith("--")) {
      continue;
    }

    const optionName = token.slice(2);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`Missing value for option --${optionName}`);
    }

    switch (optionName) {
      case "root":
        options.root = path.resolve(value);
        break;
      case "policy":
        options.policy = path.resolve(value);
        break;
      default:
        throw new Error(`Unknown option --${optionName}`);
    }

    index += 1;
  }

  return options;
}

function parsePolicy(value: unknown): ExternalBoundaryNamingPolicy {
  if (!isRecord(value)) {
    throw new Error("External-boundary naming policy must be an object");
  }

  const externalBoundaryEnv = value["external_boundary_env"];
  const externalBoundaryWire = value["external_boundary_wire"];
  const artifactNaming = value["artifact_naming"];
  const internalCode = value["internal_code"];
  const migration = value["migration"];
  const scope = value["scope"];

  if (
    !isRecord(externalBoundaryEnv) ||
    !isRecord(externalBoundaryWire) ||
    !isRecord(artifactNaming) ||
    !isRecord(internalCode) ||
    !isRecord(migration) ||
    !isRecord(scope)
  ) {
    throw new Error("External-boundary naming policy is missing required objects");
  }

  return {
    version: 1,
    external_boundary_env: {
      target_prefix: ensureString(
        externalBoundaryEnv["target_prefix"],
        "external_boundary_env.target_prefix",
      ),
      deprecated_prefix: ensureString(
        externalBoundaryEnv["deprecated_prefix"],
        "external_boundary_env.deprecated_prefix",
      ),
    },
    external_boundary_wire: {
      target_prefix: ensureString(
        externalBoundaryWire["target_prefix"],
        "external_boundary_wire.target_prefix",
      ),
      deprecated_prefix: ensureString(
        externalBoundaryWire["deprecated_prefix"],
        "external_boundary_wire.deprecated_prefix",
      ),
    },
    artifact_naming: {
      target_prefix: ensureString(
        artifactNaming["target_prefix"],
        "artifact_naming.target_prefix",
      ),
    },
    internal_code: {
      prefix_policy: ensureString(
        internalCode["prefix_policy"],
        "internal_code.prefix_policy",
      ) as "none",
    },
    migration: {
      strategy: ensureString(
        migration["strategy"],
        "migration.strategy",
      ) as "breaking_cutover_no_aliases",
      phase_order: ensureStringArray(migration["phase_order"], "migration.phase_order"),
    },
    scope: {
      external_boundary_kinds: ensureStringArray(
        scope["external_boundary_kinds"],
        "scope.external_boundary_kinds",
      ),
      excluded_kinds: ensureStringArray(scope["excluded_kinds"], "scope.excluded_kinds"),
    },
    ignore_paths: ensureStringArray(value["ignore_paths"], "ignore_paths"),
  };
}

function validateCanonicalPolicy(policy: ExternalBoundaryNamingPolicy): void {
  if (policy.version !== 1) {
    throw new Error(`Expected version 1, got ${String(policy.version)}`);
  }
  if (policy.external_boundary_env.target_prefix !== "AEGAEON_") {
    throw new Error('Expected external_boundary_env.target_prefix to equal "AEGAEON_"');
  }
  if (policy.external_boundary_env.deprecated_prefix !== "AEG_") {
    throw new Error('Expected external_boundary_env.deprecated_prefix to equal "AEG_"');
  }
  if (policy.external_boundary_wire.target_prefix !== "aegaeon_") {
    throw new Error('Expected external_boundary_wire.target_prefix to equal "aegaeon_"');
  }
  if (policy.external_boundary_wire.deprecated_prefix !== "aeg_") {
    throw new Error('Expected external_boundary_wire.deprecated_prefix to equal "aeg_"');
  }
  if (policy.artifact_naming.target_prefix !== "aegaeon-") {
    throw new Error('Expected artifact_naming.target_prefix to equal "aegaeon-"');
  }
  if (policy.internal_code.prefix_policy !== "none") {
    throw new Error('Expected internal_code.prefix_policy to equal "none"');
  }
  if (policy.migration.strategy !== "breaking_cutover_no_aliases") {
    throw new Error('Expected migration.strategy to equal "breaking_cutover_no_aliases"');
  }
  const expectedPhaseOrder = [
    "policy",
    "server",
    "sdk",
    "admin-console",
    "ci-mirrors",
    "verification",
  ];
  if (policy.migration.phase_order.join("|") !== expectedPhaseOrder.join("|")) {
    throw new Error(
      `Expected migration.phase_order to equal ` +
        JSON.stringify(expectedPhaseOrder),
    );
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function readJsonFile(filePath: string): Promise<unknown> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as unknown;
}

async function collectFiles(
  rootDir: string,
  ignoredPaths: Set<string>,
  currentDir = rootDir,
): Promise<string[]> {
  const entries = await fs.readdir(currentDir, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    const absolutePath = path.join(currentDir, entry.name);
    const relativePath = path.relative(rootDir, absolutePath);
    const pathParts = relativePath.split(path.sep);
    if (pathParts.some((part) => ignoredPaths.has(part))) {
      continue;
    }
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(rootDir, ignoredPaths, absolutePath)));
      continue;
    }
    if (entry.isFile()) {
      files.push(absolutePath);
    }
  }

  return files;
}

async function collectPrefixInventory(
  files: readonly string[],
  pattern: RegExp,
): Promise<Map<string, number>> {
  const counts = new Map<string, number>();

  for (const filePath of files) {
    const source = await fs.readFile(filePath, "utf8");
    for (const match of source.matchAll(pattern)) {
      const identifier = match[0];
      counts.set(identifier, (counts.get(identifier) ?? 0) + 1);
    }
  }

  return counts;
}

function summarizeInventory(counts: Map<string, number>): PrefixInventory {
  const top = [...counts.entries()].sort((left, right) => right[1] - left[1]).slice(0, 8);
  return {
    identifiers: counts.size,
    occurrences: [...counts.values()].reduce((sum, value) => sum + value, 0),
    top,
  };
}

function formatSummary(label: string, summary: PrefixInventory): string {
  const top =
    summary.top.length === 0
      ? "none"
      : summary.top.map(([identifier, count]) => `${identifier}(${count})`).join(", ");
  return (
    `${label}: ${summary.identifiers} identifiers / ` +
    `${summary.occurrences} occurrences [top: ${top}]`
  );
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const policy = parsePolicy(await readJsonFile(options.policy));
  validateCanonicalPolicy(policy);

  const ignoredPaths = new Set<string>([...DEFAULT_IGNORED_PATHS, ...policy.ignore_paths]);
  const files = await collectFiles(options.root, ignoredPaths);

  const legacyEnv = summarizeInventory(
    await collectPrefixInventory(files, /\bAEG_[A-Z0-9_]+\b/g),
  );
  const targetEnv = summarizeInventory(
    await collectPrefixInventory(files, /\bAEGAEON_[A-Z0-9_]+\b/g),
  );
  const legacyWire = summarizeInventory(
    await collectPrefixInventory(files, /\baeg_[a-z0-9_]+\b/g),
  );
  const targetWire = summarizeInventory(
    await collectPrefixInventory(files, /\baegaeon_[a-z0-9_]+\b/g),
  );

  console.log(
    [
      `External-boundary naming policy matches ${options.policy}`,
      formatSummary(
        `  deprecated env prefix (${policy.external_boundary_env.deprecated_prefix})`,
        legacyEnv,
      ),
      formatSummary(
        `  target env prefix (${policy.external_boundary_env.target_prefix})`,
        targetEnv,
      ),
      formatSummary(
        `  deprecated wire prefix (${policy.external_boundary_wire.deprecated_prefix})`,
        legacyWire,
      ),
      formatSummary(
        `  target wire prefix (${policy.external_boundary_wire.target_prefix})`,
        targetWire,
      ),
    ].join("\n"),
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
