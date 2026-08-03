#!/usr/bin/env node
import { promises as fs } from 'node:fs';
import path from 'node:path';

const ROOT_DIR = path.resolve(new URL('..', import.meta.url).pathname);
const DEFAULT_POLICY_PATH = path.join(ROOT_DIR, 'spec', 'workflow-inventory.current.json');

type WorkflowPolicy = {
  requiredWorkflows: Array<{
    path: string;
    name: string;
  }>;
};

type WorkflowDescriptor = {
  workflowName: string | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function usage(): string {
  return [
    'Usage:',
    '  node --experimental-strip-types scripts/check-workflow-inventory.ts ' +
      '[--root <repo-root>] [--policy <path>]',
  ].join('\n');
}

function parseArgs(argv: string[]): { root: string; policy: string } {
  const options = { root: ROOT_DIR, policy: DEFAULT_POLICY_PATH };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) {
      continue;
    }
    if (token === '--') continue;
    if (token === '--help' || token === '-h') {
      console.log(usage());
      process.exit(0);
    }
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Missing value for option --${key}`);
    }
    if (key === 'root') {
      options.root = path.resolve(value);
    } else if (key === 'policy') {
      options.policy = path.resolve(value);
    } else {
      throw new Error(`Unknown option --${key}`);
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

function validatePolicy(policy: unknown): WorkflowPolicy {
  if (!isRecord(policy)) {
    throw new Error('Workflow inventory policy must be an object');
  }
  const requiredWorkflows = Array.isArray(policy['required_workflows'])
    ? policy['required_workflows'].map((entry, index) => {
        if (!isRecord(entry)) {
          throw new Error(`Expected object for required_workflows[${String(index)}]`);
        }
        return {
          path: ensureNonEmptyString(entry['path'], `required_workflows[${String(index)}].path`),
          name: ensureNonEmptyString(entry['name'], `required_workflows[${String(index)}].name`),
        };
      })
    : (() => {
        throw new Error('Workflow inventory policy requires `required_workflows`');
      })();
  return { requiredWorkflows };
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, 'utf8')) as T;
}

async function loadWorkflow(repoRoot: string, relativePath: string): Promise<WorkflowDescriptor> {
  const workflowPath = path.join(repoRoot, relativePath);
  const text = await fs.readFile(workflowPath, 'utf8');
  const rawWorkflowName = /^name:\s+(.+)$/m.exec(text)?.[1]?.trim() ?? null;
  const workflowName =
    rawWorkflowName && /^["'].*["']$/.test(rawWorkflowName)
      ? rawWorkflowName.slice(1, -1)
      : rawWorkflowName;
  return { workflowName };
}

function comparePolicy(
  policy: WorkflowPolicy,
  workflows: Map<string, WorkflowDescriptor | null>,
): string[] {
  const mismatches: string[] = [];
  for (const workflow of policy.requiredWorkflows) {
    const actual = workflows.get(workflow.path);
    if (!actual) {
      mismatches.push(`${workflow.path}: missing workflow file`);
      continue;
    }
    if (actual.workflowName !== workflow.name) {
      mismatches.push(
        `${workflow.path}: expected workflow name ` +
          `${JSON.stringify(workflow.name)}, got ${JSON.stringify(actual.workflowName)}`,
      );
    }
  }
  return mismatches;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const policy = validatePolicy(await readJson<unknown>(options.policy));
  const workflows = new Map<string, WorkflowDescriptor | null>();
  for (const workflow of policy.requiredWorkflows) {
    try {
      workflows.set(workflow.path, await loadWorkflow(options.root, workflow.path));
    } catch (error) {
      if (isNodeError(error) && error.code === 'ENOENT') {
        workflows.set(workflow.path, null);
        continue;
      }
      throw error;
    }
  }
  const mismatches = comparePolicy(policy, workflows);
  if (mismatches.length > 0) {
    throw new Error(`Workflow inventory mismatches:\n- ${mismatches.join('\n- ')}`);
  }
  console.log(`[workflow-inventory] ${options.root} matches ${options.policy}`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
