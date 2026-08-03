import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const TOOL_ROOT = path.resolve(MODULE_DIR, "..");
const DEFAULT_POLICY_PATH = path.join(TOOL_ROOT, "spec", "workflow-inventory.current.json");

type WorkflowInventoryOptions = {
  root: string | undefined;
  policy: string;
};

type WorkflowInventoryPolicy = {
  requiredWorkflows: { path: string; name: string }[];
  workflowReferenceDefaults: { variable: string; filename: string; referencedBy: string[] }[];
};

type LoadedWorkflowFile = {
  text: string;
  name: string;
};

type ErrnoLike = {
  code?: string;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/check-workflow-inventory.js [--root <repo-root>] [--policy <path>]",
  ].join("\n");
}

function parseArgs(argv: string[]): WorkflowInventoryOptions {
  const options: WorkflowInventoryOptions = {
    root: undefined,
    policy: DEFAULT_POLICY_PATH,
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
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${key}`);
    }
    if (key === "root") {
      options.root = path.resolve(value);
    } else if (key === "policy") {
      options.policy = path.resolve(value);
    } else {
      throw new Error(`Unknown option --${key}`);
    }
    index += 1;
  }

  return options;
}

async function resolveDefaultRoot(): Promise<string> {
  for (const candidate of [TOOL_ROOT, path.resolve(TOOL_ROOT, "..")]) {
    try {
      const workflowsDir = path.join(candidate, ".github", "workflows");
      const stats = await fs.stat(workflowsDir);
      if (stats.isDirectory()) {
        return candidate;
      }
    } catch (error) {
      if ((error as ErrnoLike | undefined)?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  return TOOL_ROOT;
}

function ensureNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    throw new Error(`Expected array of non-empty strings for ${label}`);
  }
  return value as string[];
}

function validatePolicy(policy: unknown): WorkflowInventoryPolicy {
  if (!policy || typeof policy !== "object") {
    throw new Error("Workflow inventory policy must be an object");
  }
  const policyRecord = policy as Record<string, unknown>;
  const rawRequiredWorkflows = policyRecord.required_workflows;
  if (!Array.isArray(rawRequiredWorkflows)) {
    throw new Error("Workflow inventory policy requires `required_workflows`");
  }
  const requiredWorkflows = rawRequiredWorkflows.map((entry, index) => {
    const workflow = entry as Record<string, unknown> | null;
    return {
      path: ensureNonEmptyString(workflow?.path, `required_workflows[${index}].path`),
      name: ensureNonEmptyString(workflow?.name, `required_workflows[${index}].name`),
    };
  });
  const rawWorkflowReferenceDefaults = policyRecord.workflow_reference_defaults;
  const workflowReferenceDefaults = Array.isArray(rawWorkflowReferenceDefaults)
    ? rawWorkflowReferenceDefaults.map((entry, index) => {
        const reference = entry as Record<string, unknown> | null;
        return {
          variable: ensureNonEmptyString(reference?.variable, `workflow_reference_defaults[${index}].variable`),
          filename: ensureNonEmptyString(reference?.filename, `workflow_reference_defaults[${index}].filename`),
          referencedBy: ensureStringArray(
            reference?.referenced_by,
            `workflow_reference_defaults[${index}].referenced_by`,
          ),
        };
      })
    : [];
  return { requiredWorkflows, workflowReferenceDefaults };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function loadWorkflowFile(repoRoot: string, relativePath: string): Promise<LoadedWorkflowFile> {
  const workflowPath = path.join(repoRoot, relativePath);
  const text = await fs.readFile(workflowPath, "utf8");
  const nameMatch = /^name:\s+(.+)$/m.exec(text);
  const workflowName = nameMatch?.[1];
  if (!workflowName) {
    throw new Error(`${relativePath}: missing top-level workflow name`);
  }
  return { text, name: workflowName.trim() };
}

function comparePolicy(
  policy: WorkflowInventoryPolicy,
  workflowTexts: Map<string, LoadedWorkflowFile | null>,
): string[] {
  const mismatches: string[] = [];

  for (const workflow of policy.requiredWorkflows) {
    const actual = workflowTexts.get(workflow.path);
    if (!actual) {
      mismatches.push(`${workflow.path}: missing workflow file`);
      continue;
    }
    if (actual.name !== workflow.name) {
      mismatches.push(`${workflow.path}: expected workflow name ${JSON.stringify(workflow.name)}, got ${JSON.stringify(actual.name)}`);
    }
  }

  for (const reference of policy.workflowReferenceDefaults) {
    const pattern = new RegExp(
      `${escapeRegex(reference.variable)}:\\s*\\$\\{\\{\\s*vars\\.${escapeRegex(reference.variable)}\\s*\\|\\|\\s*'${escapeRegex(reference.filename)}'\\s*\\}\\}`,
    );
    for (const relativePath of reference.referencedBy) {
      const actual = workflowTexts.get(relativePath);
      if (!actual) {
        mismatches.push(`${relativePath}: missing workflow file for ${reference.variable} default check`);
        continue;
      }
      if (!pattern.test(actual.text)) {
        mismatches.push(
          `${relativePath}: expected ${reference.variable} default to ${JSON.stringify(reference.filename)}`,
        );
      }
    }
  }

  return mismatches;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (!options.root) {
    options.root = await resolveDefaultRoot();
  }
  const policy = validatePolicy(await readJson<unknown>(options.policy));
  const workflowTexts = new Map<string, LoadedWorkflowFile | null>();

  for (const workflow of policy.requiredWorkflows) {
      try {
        workflowTexts.set(workflow.path, await loadWorkflowFile(options.root, workflow.path));
      } catch (error) {
      if ((error as ErrnoLike | undefined)?.code === "ENOENT") {
        workflowTexts.set(workflow.path, null);
        continue;
      }
      throw error;
    }
  }

  for (const reference of policy.workflowReferenceDefaults) {
    for (const relativePath of reference.referencedBy) {
      if (workflowTexts.has(relativePath)) {
        continue;
      }
      try {
        workflowTexts.set(relativePath, await loadWorkflowFile(options.root, relativePath));
      } catch (error) {
        if ((error as ErrnoLike | undefined)?.code === "ENOENT") {
          workflowTexts.set(relativePath, null);
          continue;
        }
        throw error;
      }
    }
  }

  const mismatches = comparePolicy(policy, workflowTexts);
  if (mismatches.length > 0) {
    throw new Error(`Workflow inventory mismatches:\\n- ${mismatches.join("\\n- ")}`);
  }

  console.log(`Workflow inventory at ${options.root} matches ${options.policy}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
