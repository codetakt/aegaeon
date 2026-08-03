#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir as fsMkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL('../..', import.meta.url).pathname);
const POLICY_PATH = path.join(ROOT_DIR, 'spec', 'workflow-inventory.current.json');

type WorkflowInventoryPolicy = {
  required_workflows?: Array<{
    path: string;
    name: string;
  }>;
  workflow_reference_defaults?: Array<{
    variable: string;
    filename: string;
    referenced_by?: string[];
  }>;
};

type ExecError = Error & {
  code?: number;
  stderr?: string;
};

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error;
}

function resolveScriptPath(rootDir: string): string {
  const candidates = [
    path.join(rootDir, 'dist-tools', 'check-workflow-inventory.js'),
    path.join(rootDir, 'scripts', 'check-workflow-inventory.ts'),
    path.join(rootDir, 'tools-src', 'check-workflow-inventory.ts'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  const fallbackCandidate = candidates[0];
  if (!fallbackCandidate) {
    throw new Error('Workflow inventory checker candidate list is empty');
  }
  return fallbackCandidate;
}

async function writeText(filePath: string, value: string): Promise<void> {
  await writeFile(filePath, value, 'utf8');
}

async function main(): Promise<void> {
  console.log('=== root workflow inventory policy test ===');
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), 'aegaeon-root-workflows-'));
  const policy = JSON.parse(await readFile(POLICY_PATH, 'utf8')) as WorkflowInventoryPolicy;
  for (const workflow of policy.required_workflows ?? []) {
    const workflowPath = path.join(tempRoot, workflow.path);
    await fsMkdir(path.dirname(workflowPath), { recursive: true });
    await writeText(workflowPath, `name: ${workflow.name}\n`);
  }

  for (const reference of policy.workflow_reference_defaults ?? []) {
    for (const relativePath of reference.referenced_by ?? []) {
      const workflowPath = path.join(tempRoot, relativePath);
      await fsMkdir(path.dirname(workflowPath), { recursive: true });
      let text = '';
      try {
        text = await readFile(workflowPath, 'utf8');
      } catch (error) {
        if (!isErrnoException(error) || error.code !== 'ENOENT') {
          throw error;
        }
      }
      const line =
        `${reference.variable}: ` +
        `\${{ vars.${reference.variable} || '${reference.filename}' }}`;
      if (!text.includes(line)) {
        text = `${text}${line}\n`;
      }
      await writeText(workflowPath, text);
    }
  }

  const scriptPath = resolveScriptPath(ROOT_DIR);
  const goodResult = await execFile(
    process.execPath,
    [scriptPath, '--root', tempRoot, '--policy', POLICY_PATH],
    { cwd: ROOT_DIR },
  );
  assert.match(goodResult.stdout, /matches/);

  const firstWorkflow = policy.required_workflows?.[0];
  assert.ok(firstWorkflow, 'expected at least one required workflow');
  await writeText(path.join(tempRoot, firstWorkflow.path), 'name: Wrong Name\n');
  await assert.rejects(
    execFile(
      process.execPath,
      [scriptPath, '--root', tempRoot, '--policy', POLICY_PATH],
      { cwd: ROOT_DIR },
    ),
    (error) => {
      const execError = error as ExecError;
      assert.equal(execError.code, 1);
      assert.match(execError.stderr ?? '', /expected workflow name/);
      assert.match(execError.stderr ?? '', new RegExp(firstWorkflow.name));
      return true;
    },
  );

  console.log('root workflow inventory policy tests passed');
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
