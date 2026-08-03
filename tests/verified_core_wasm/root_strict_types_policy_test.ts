#!/usr/bin/env node
import assert from 'node:assert/strict';
import type { ExecFileException } from 'node:child_process';
import { execFile as execFileCallback } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL('../..', import.meta.url).pathname);
const SCRIPT_PATH = path.join(ROOT_DIR, 'scripts', 'check-strict-types.ts');
const POLICY_PATH = path.join(ROOT_DIR, 'spec', 'server-strict-types.current.json');

interface TsconfigRequirement {
  path: string;
  required_flags: Record<string, boolean>;
  required_include_paths?: string[];
}

interface StrictTypesPolicy {
  required_tsconfig_requirements: TsconfigRequirement[];
  required_no_tsnocheck_paths: string[];
}

interface ExecFileFailure extends ExecFileException {
  stderr: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function expectString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function expectBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') {
    throw new Error(`Expected boolean for ${label}`);
  }
  return value;
}

function expectBooleanRecord(value: unknown, label: string): Record<string, boolean> {
  if (!isRecord(value)) {
    throw new Error(`Expected object for ${label}`);
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, expectBoolean(entry, `${label}.${key}`)]),
  );
}

function expectStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`Expected ${label} to be an array`);
  }

  const items: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.length === 0) {
      throw new Error(`Expected non-empty strings for ${label}`);
    }
    items.push(entry);
  }
  return items;
}

function parseStrictTypesPolicy(value: unknown): StrictTypesPolicy {
  if (!isRecord(value)) {
    throw new Error('Strict types policy must be an object');
  }

  const requiredTsconfigRequirementsValue = value['required_tsconfig_requirements'];
  const requiredNoTsNoCheckPathsValue = value['required_no_tsnocheck_paths'];
  if (
    !Array.isArray(requiredTsconfigRequirementsValue) ||
    !Array.isArray(requiredNoTsNoCheckPathsValue)
  ) {
    throw new Error('Strict types policy is missing required arrays');
  }

  return {
    required_tsconfig_requirements: requiredTsconfigRequirementsValue.map((entry, index) => {
      if (!isRecord(entry)) {
        throw new Error(`required_tsconfig_requirements[${String(index)}] must be an object`);
      }
      return {
        path: expectString(entry['path'], `required_tsconfig_requirements[${String(index)}].path`),
        required_flags: expectBooleanRecord(
          entry['required_flags'],
          `required_tsconfig_requirements[${String(index)}].required_flags`,
        ),
        required_include_paths: Array.isArray(entry['required_include_paths'])
          ? expectStringArray(
              entry['required_include_paths'],
              `required_tsconfig_requirements[${String(index)}].required_include_paths`,
            )
          : [],
      };
    }),
    required_no_tsnocheck_paths: expectStringArray(
      requiredNoTsNoCheckPathsValue,
      'required_no_tsnocheck_paths',
    ),
  };
}

function expectExecFileFailure(error: unknown): ExecFileFailure {
  if (
    typeof error !== 'object' ||
    error === null ||
    !('code' in error) ||
    !('stderr' in error) ||
    typeof error.stderr !== 'string'
  ) {
    throw new Error(`Expected execFile failure, got ${String(error)}`);
  }
  return error as ExecFileFailure;
}

function isTypeScriptSourcePath(relativePath: string): boolean {
  return ['.ts', '.tsx', '.mts', '.cts'].includes(path.extname(relativePath));
}

function fixturePathForPolicyPath(rootDir: string, relativePath: string): string {
  if (isTypeScriptSourcePath(relativePath)) {
    return path.join(rootDir, relativePath);
  }
  return path.join(rootDir, relativePath, 'fixture.ts');
}

async function main(): Promise<void> {
  console.log('=== root strict types policy test ===');
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), 'aegaeon-root-strict-types-'));

  const policy = parseStrictTypesPolicy(JSON.parse(await readFile(POLICY_PATH, 'utf8')) as unknown);
  for (const requirement of policy.required_tsconfig_requirements) {
    const fullPath = path.join(tempRoot, requirement.path);
    mkdirSync(path.dirname(fullPath), { recursive: true });
    await writeFile(
      fullPath,
      `${JSON.stringify(
        {
          compilerOptions: requirement.required_flags,
          include: requirement.required_include_paths ?? [],
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
  }

  for (const relativePath of policy.required_no_tsnocheck_paths) {
    const fullPath = fixturePathForPolicyPath(tempRoot, relativePath);
    mkdirSync(path.dirname(fullPath), { recursive: true });
    await writeFile(fullPath, 'export {};\n', 'utf8');
  }

  const goodResult = await execFile(
    process.execPath,
    ['--experimental-strip-types', SCRIPT_PATH, '--root', tempRoot, '--policy', POLICY_PATH],
    {
      cwd: ROOT_DIR,
    },
  );
  assert.match(goodResult.stdout, /Strict types policy/);

  const firstPolicyPath = policy.required_no_tsnocheck_paths[0];
  assert.ok(firstPolicyPath, 'strict types policy must define at least one no-ts-nocheck path');
  const firstTarget = fixturePathForPolicyPath(tempRoot, firstPolicyPath);
  await writeFile(firstTarget, '// @ts-nocheck\nexport {};\n', 'utf8');
  await assert.rejects(
    execFile(
      process.execPath,
      ['--experimental-strip-types', SCRIPT_PATH, '--root', tempRoot, '--policy', POLICY_PATH],
      {
        cwd: ROOT_DIR,
      },
    ),
    (error: unknown) => {
      const failure = expectExecFileFailure(error);
      assert.equal(failure.code, 1);
      assert.match(failure.stderr, /ts-nocheck/);
      return true;
    },
  );
  await writeFile(firstTarget, 'export {};\n', 'utf8');

  const firstRequirement = policy.required_tsconfig_requirements[0];
  assert.ok(firstRequirement, 'strict types policy must define at least one tsconfig requirement');
  const tsconfigPath = path.join(tempRoot, firstRequirement.path);
  await writeFile(
    tsconfigPath,
    `${JSON.stringify(
      {
        compilerOptions: {
          ...firstRequirement.required_flags,
          useUnknownInCatchVariables: false,
        },
        include: firstRequirement.required_include_paths ?? [],
      },
      null,
      2,
    )}\n`,
    'utf8',
  );
  await assert.rejects(
    execFile(
      process.execPath,
      ['--experimental-strip-types', SCRIPT_PATH, '--root', tempRoot, '--policy', POLICY_PATH],
      {
        cwd: ROOT_DIR,
      },
    ),
    (error: unknown) => {
      const failure = expectExecFileFailure(error);
      assert.equal(failure.code, 1);
      assert.match(failure.stderr, /useUnknownInCatchVariables/);
      return true;
    },
  );

  await writeFile(
    tsconfigPath,
    `${JSON.stringify(
      {
        compilerOptions: firstRequirement.required_flags,
        include: ['scripts/check-workflow-inventory.ts'],
      },
      null,
      2,
    )}\n`,
    'utf8',
  );
  await assert.rejects(
    execFile(
      process.execPath,
      ['--experimental-strip-types', SCRIPT_PATH, '--root', tempRoot, '--policy', POLICY_PATH],
      {
        cwd: ROOT_DIR,
      },
    ),
    (error: unknown) => {
      const failure = expectExecFileFailure(error);
      assert.equal(failure.code, 1);
      assert.match(failure.stderr, /include must exactly match/);
      return true;
    },
  );

  console.log('root strict types policy tests passed');
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
