#!/usr/bin/env node
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_POLICY_PATH = path.join(ROOT_DIR, 'spec', 'server-strict-types.current.json');
const TS_SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts']);
const IGNORED_DIRECTORY_NAMES = new Set([
  '.git',
  'artifacts',
  'generated',
  'node_modules',
  'result',
  'result-dev',
  'result-server',
  'target',
]);

interface TsconfigRequirement {
  path: string;
  requiredFlags: Record<string, boolean>;
  requiredIncludePaths: string[];
}

interface DocumentedBlocker {
  path: string;
  flag: string;
  requiredValue: boolean;
  reason: string;
  blockedBy: string[];
}

interface StrictTypesPolicy {
  schemaVersion: number;
  requiredTsconfigRequirements: TsconfigRequirement[];
  requiredNoTsNoCheckPaths: string[];
  documentedBlockers: DocumentedBlocker[];
}

interface ParsedOptions {
  root: string;
  policy: string;
}

interface TsconfigLike {
  compilerOptions?: Record<string, unknown>;
  include?: unknown;
}

type OptionArgument = 'root' | 'policy';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return typeof error === 'object' && error !== null && 'code' in error;
}

function usage(): string {
  return [
    'Usage:',
    '  node --experimental-strip-types scripts/check-strict-types.ts ' +
      '[--root <repo-root>] [--policy <path>]',
  ].join('\n');
}

function parseArgs(argv: readonly string[]): ParsedOptions {
  const options: ParsedOptions = {
    root: ROOT_DIR,
    policy: DEFAULT_POLICY_PATH,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === undefined) {
      break;
    }
    if (token === '--') {
      continue;
    }
    if (token === '--help' || token === '-h') {
      console.log(usage());
      process.exit(0);
    }
    if (!token.startsWith('--')) {
      continue;
    }

    const optionName = token.slice(2);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing value for option --${optionName}`);
    }

    switch (optionName as OptionArgument) {
      case 'root':
        options.root = path.resolve(value);
        break;
      case 'policy':
        options.policy = path.resolve(value);
        break;
      default:
        throw new Error(`Unknown option --${optionName}`);
    }

    index += 1;
  }

  return options;
}

function ensureNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function ensureStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`Expected array of non-empty strings for ${label}`);
  }

  const items: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.length === 0) {
      throw new Error(`Expected array of non-empty strings for ${label}`);
    }
    items.push(entry);
  }
  return items;
}

function ensureBooleanRecord(value: unknown, label: string): Record<string, boolean> {
  if (!isRecord(value)) {
    throw new Error(`Expected object for ${label}`);
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, ensureBoolean(entry, `${label}.${key}`)]),
  );
}

function parseTsconfigRequirement(value: unknown, label: string): TsconfigRequirement {
  if (!isRecord(value)) {
    throw new Error(`Expected object for ${label}`);
  }

  return {
    path: ensureNonEmptyString(value['path'], `${label}.path`),
    requiredFlags: ensureBooleanRecord(value['required_flags'], `${label}.required_flags`),
    requiredIncludePaths: Array.isArray(value['required_include_paths'])
      ? ensureStringArray(value['required_include_paths'], `${label}.required_include_paths`)
      : [],
  };
}

function parseDocumentedBlocker(value: unknown, label: string): DocumentedBlocker {
  if (!isRecord(value)) {
    throw new Error(`Expected object for ${label}`);
  }

  return {
    path: ensureNonEmptyString(value['path'], `${label}.path`),
    flag: ensureNonEmptyString(value['flag'], `${label}.flag`),
    requiredValue: ensureBoolean(value['required_value'], `${label}.required_value`),
    reason: ensureNonEmptyString(value['reason'], `${label}.reason`),
    blockedBy: ensureStringArray(value['blocked_by'], `${label}.blocked_by`),
  };
}

function validatePolicy(value: unknown): StrictTypesPolicy {
  if (!isRecord(value)) {
    throw new Error('Strict types policy must be an object');
  }

  const requiredTsconfigRequirementsValue = value['required_tsconfig_requirements'];
  if (!Array.isArray(requiredTsconfigRequirementsValue)) {
    throw new Error('Strict types policy requires `required_tsconfig_requirements`');
  }

  return {
    schemaVersion: Number(value['schema_version'] ?? 0),
    requiredTsconfigRequirements: requiredTsconfigRequirementsValue.map((entry, index) =>
      parseTsconfigRequirement(entry, `required_tsconfig_requirements[${String(index)}]`),
    ),
    requiredNoTsNoCheckPaths: ensureStringArray(
      value['required_no_tsnocheck_paths'],
      'required_no_tsnocheck_paths',
    ),
    documentedBlockers: Array.isArray(value['documented_blockers'])
      ? value['documented_blockers'].map((entry, index) =>
          parseDocumentedBlocker(entry, `documented_blockers[${String(index)}]`),
        )
      : [],
  };
}

function resolveWithinRoot(rootDir: string, targetPath: string): string {
  return path.isAbsolute(targetPath) ? targetPath : path.resolve(rootDir, targetPath);
}

function containsTsNoCheckDirective(sourceText: string): boolean {
  return /^\s*\/\/\s*@ts-nocheck\b/m.test(sourceText) || /\/\*\s*@ts-nocheck\b/.test(sourceText);
}

function isTypeScriptSourceFile(filePath: string): boolean {
  return TS_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function normalizeRelativePath(filePath: string): string {
  return filePath.split(path.sep).join('/');
}

function normalizePathList(paths: readonly string[]): string[] {
  return [...new Set(paths.map((entry) => normalizeRelativePath(entry)))].sort((left, right) =>
    left.localeCompare(right),
  );
}

async function readJsonFile<T>(filePath: string): Promise<T> {
  const source = await fs.readFile(filePath, 'utf8');
  return JSON.parse(source) as T;
}

async function collectTypeScriptFiles(rootDir: string, absolutePath: string): Promise<string[]> {
  const stats = await fs.stat(absolutePath);

  if (stats.isDirectory()) {
    const entries = await fs.readdir(absolutePath, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));

    const collected: string[] = [];
    for (const entry of entries) {
      if (entry.isDirectory() && IGNORED_DIRECTORY_NAMES.has(entry.name)) {
        continue;
      }
      collected.push(
        ...(await collectTypeScriptFiles(rootDir, path.join(absolutePath, entry.name))),
      );
    }
    return collected;
  }

  if (!stats.isFile() || !isTypeScriptSourceFile(absolutePath)) {
    return [];
  }

  return [normalizeRelativePath(path.relative(rootDir, absolutePath))];
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = path.resolve(options.root);
  const policyPath = resolveWithinRoot(rootDir, options.policy);
  const policy = validatePolicy(await readJsonFile<unknown>(policyPath));
  const failures: string[] = [];

  for (const requirement of policy.requiredTsconfigRequirements) {
    const tsconfigPath = resolveWithinRoot(rootDir, requirement.path);
    const tsconfig = await readJsonFile<TsconfigLike>(tsconfigPath);
    const compilerOptions = tsconfig.compilerOptions ?? {};

    for (const [flagName, expectedValue] of Object.entries(requirement.requiredFlags)) {
      if (compilerOptions[flagName] !== expectedValue) {
        failures.push(
          `${requirement.path} compilerOptions.${flagName} must be ` +
            `${String(expectedValue)} (got ${String(compilerOptions[flagName])})`,
        );
      }
    }

    if (requirement.requiredIncludePaths.length > 0) {
      const includePaths = normalizePathList(
        ensureStringArray(tsconfig.include, `${requirement.path}.include`),
      );
      const expectedIncludePaths = normalizePathList(requirement.requiredIncludePaths);
      if (
        includePaths.length !== expectedIncludePaths.length ||
        includePaths.some((entry, index) => entry !== expectedIncludePaths[index])
      ) {
        failures.push(
          `${requirement.path} include must exactly match ` +
            `${JSON.stringify(expectedIncludePaths)} ` +
            `(got ${JSON.stringify(includePaths)})`,
        );
      }
    }
  }

  for (const blocker of policy.documentedBlockers) {
    const requirement = policy.requiredTsconfigRequirements.find(
      (entry) => entry.path === blocker.path,
    );
    if (requirement === undefined) {
      failures.push(
        'documented_blockers entry for ' +
          blocker.path +
          ' does not match any required tsconfig requirement',
      );
      continue;
    }
    if (requirement.requiredFlags[blocker.flag] !== blocker.requiredValue) {
      failures.push(
        `documented_blockers entry for ${blocker.path} requires ` +
          `${blocker.flag}=${String(blocker.requiredValue)} but the policy flag is ` +
          String(requirement.requiredFlags[blocker.flag]),
      );
    }
  }

  for (const policyEntryPath of policy.requiredNoTsNoCheckPaths) {
    const absoluteEntryPath = resolveWithinRoot(rootDir, policyEntryPath);
    let sourceFiles: string[];
    try {
      sourceFiles = await collectTypeScriptFiles(rootDir, absoluteEntryPath);
    } catch (error: unknown) {
      if (isErrnoException(error) && error.code === 'ENOENT') {
        failures.push(`${policyEntryPath}: missing path`);
        continue;
      }
      throw error;
    }

    if (sourceFiles.length === 0) {
      failures.push(`${policyEntryPath}: no TypeScript sources found`);
      continue;
    }

    for (const relativeSourcePath of sourceFiles) {
      const sourceText = await fs.readFile(resolveWithinRoot(rootDir, relativeSourcePath), 'utf8');
      if (containsTsNoCheckDirective(sourceText)) {
        failures.push(`${relativeSourcePath} still contains @ts-nocheck`);
      }
    }
  }

  if (failures.length > 0) {
    throw new Error(`Strict types policy mismatches:\n- ${failures.join('\n- ')}`);
  }

  console.log(`Strict types policy at ${path.relative(rootDir, policyPath)} matches ${rootDir}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
