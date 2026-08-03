#!/usr/bin/env node
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..", "..");
const DEFAULT_POLICY_PATH = path.join(MODULE_DIR, "sdk_workflow_inventory.current.json");

function usage() {
  return [
    "Usage:",
    "  node --experimental-strip-types scripts/sdk/check_sdk_workflow_inventory.ts",
    "    [--root <repo-root>] [--policy <path>]",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    root: ROOT_DIR,
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

function ensureNonEmptyString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string for ${label}`);
  }
  return value;
}

function ensureStringArray(value, label) {
  if (
    !Array.isArray(value)
    || value.some((entry) => typeof entry !== "string" || entry.length === 0)
  ) {
    throw new Error(`Expected array of non-empty strings for ${label}`);
  }
  return value;
}

function validatePolicy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new Error("Workflow inventory policy must be an object");
  }
  const requiredWorkflows = Array.isArray(policy.required_workflows)
    ? policy.required_workflows.map((entry, index) => ({
        path: ensureNonEmptyString(entry?.path, `required_workflows[${index}].path`),
        name: ensureNonEmptyString(entry?.name, `required_workflows[${index}].name`),
      }))
    : (() => {
        throw new Error("Workflow inventory policy requires `required_workflows`");
      })();
  const workflowReferenceDefaults = Array.isArray(policy.workflow_reference_defaults)
    ? policy.workflow_reference_defaults.map((entry, index) => ({
        variable: ensureNonEmptyString(
          entry?.variable,
          `workflow_reference_defaults[${index}].variable`,
        ),
        filename: ensureNonEmptyString(
          entry?.filename,
          `workflow_reference_defaults[${index}].filename`,
        ),
        referencedBy: ensureStringArray(
          entry?.referenced_by,
          `workflow_reference_defaults[${index}].referenced_by`,
        ),
      }))
    : [];
  return { requiredWorkflows, workflowReferenceDefaults };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function loadWorkflowFile(repoRoot, relativePath) {
  const workflowPath = path.join(repoRoot, relativePath);
  const text = await fs.readFile(workflowPath, "utf8");
  const nameMatch = /^name:\s+(.+)$/m.exec(text);
  if (!nameMatch) {
    throw new Error(`${relativePath}: missing top-level workflow name`);
  }
  return { text, name: nameMatch[1].trim() };
}

function comparePolicy(policy, workflowTexts) {
  const mismatches = [];

  for (const workflow of policy.requiredWorkflows) {
    const actual = workflowTexts.get(workflow.path);
    if (!actual) {
      mismatches.push(`${workflow.path}: missing workflow file`);
      continue;
    }
    if (actual.name !== workflow.name) {
      mismatches.push(
        `${workflow.path}: expected workflow name ${JSON.stringify(workflow.name)}, got ${
          JSON.stringify(actual.name)
        }`,
      );
    }
  }

  for (const reference of policy.workflowReferenceDefaults) {
    const variablePattern = escapeRegex(reference.variable);
    const filenamePattern = escapeRegex(reference.filename);
    const pattern = new RegExp(
      [
        `${variablePattern}:\\s*\\$\\{\\{`,
        `\\s*vars\\.${variablePattern}\\s*\\|\\|`,
        `\\s*'${filenamePattern}'\\s*\\}\\}`,
      ].join(""),
    );
    for (const relativePath of reference.referencedBy) {
      const actual = workflowTexts.get(relativePath);
      if (!actual) {
        mismatches.push(
          `${relativePath}: missing workflow file for ${reference.variable} default check`,
        );
        continue;
      }
      if (!pattern.test(actual.text)) {
        mismatches.push(
          `${relativePath}: expected ${reference.variable} default to ${
            JSON.stringify(reference.filename)
          }`,
        );
      }
    }
  }

  return mismatches;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const policy = validatePolicy(await readJson(options.policy));
  const workflowTexts = new Map();

  for (const workflow of policy.requiredWorkflows) {
    try {
      workflowTexts.set(workflow.path, await loadWorkflowFile(options.root, workflow.path));
    } catch (error) {
      if (error && error.code === "ENOENT") {
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
        if (error && error.code === "ENOENT") {
          workflowTexts.set(relativePath, null);
          continue;
        }
        throw error;
      }
    }
  }

  const mismatches = comparePolicy(policy, workflowTexts);
  if (mismatches.length > 0) {
    throw new Error(`Workflow inventory mismatches:\n- ${mismatches.join("\n- ")}`);
  }

  console.log(`Workflow inventory at ${options.root} matches ${options.policy}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
