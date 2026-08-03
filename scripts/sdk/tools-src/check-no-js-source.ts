#!/usr/bin/env node

import { readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_ROOT = path.resolve(MODULE_DIR, "..");
const BLOCKED_EXTENSIONS = new Set([".js", ".mjs", ".cjs"]);
const IGNORED_DIRECTORIES = new Set([
  ".artifacts",
  ".cache",
  ".git",
  ".pnpm-store",
  "coverage",
  "dist",
  "dist-test",
  "dist-tests",
  "dist-tools",
  "node_modules",
  "playwright-report",
  "test-results",
]);

type CheckNoJsSourceOptions = {
  root: string;
};

function parseArgs(argv: string[]): CheckNoJsSourceOptions {
  const options: CheckNoJsSourceOptions = {
    root: DEFAULT_ROOT,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token || token === "--") {
      continue;
    }
    if (token !== "--root") {
      throw new Error(`Unknown option: ${token}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error("Missing value for --root");
    }
    options.root = path.resolve(value);
    index += 1;
  }

  return options;
}

async function collectBlockedFiles(
  root: string,
  currentDir: string = root,
  findings: string[] = [],
): Promise<string[]> {
  const entries = await readdir(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    const absolutePath = path.join(currentDir, entry.name);
    const relativePath = path.relative(root, absolutePath);
    if (entry.isDirectory()) {
      if (IGNORED_DIRECTORIES.has(entry.name)) {
        continue;
      }
      await collectBlockedFiles(root, absolutePath, findings);
      continue;
    }
    if (BLOCKED_EXTENSIONS.has(path.extname(entry.name))) {
      findings.push(relativePath);
    }
  }
  return findings;
}

async function main(): Promise<void> {
  const { root } = parseArgs(process.argv.slice(2));
  const blockedFiles = await collectBlockedFiles(root);
  if (blockedFiles.length > 0) {
    const rendered = blockedFiles.map((relativePath) => `  - ${relativePath}`).join("\n");
    throw new Error(
      [
        `handwritten JavaScript is not allowed under ${root}`,
        "remove or migrate these source files:",
        rendered,
      ].join("\n"),
    );
  }
  process.stdout.write(`No handwritten JavaScript sources found under ${root}.\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
