#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { ManagedProviderEvidenceFile } from "./released-client-types.js";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT_PATH = ".artifacts/managed-provider/managed-provider-evidence.json";

type ParsedArgs = {
  root: string | null;
  evidence: string;
  out: string;
};

function usage(): string {
  return [
    "Usage:",
    "  node dist-tools/import-managed-provider-evidence.js --evidence <path> [options]",
    "",
    "Options:",
    "  --root <sdk-root>    Workspace root (autodetected when omitted)",
    "  --evidence <path>    Existing managed-provider evidence JSON",
    "  --out <path>         Default: .artifacts/managed-provider/managed-provider-evidence.json",
  ].join("\n");
}

function parseArgs(argv: string[]): ParsedArgs {
  const options = {
    root: process.env.AEGAEON_SDK_ROOT ?? null,
    evidence: null as string | null,
    out: process.env.AEGAEON_MANAGED_PROVIDER_EVIDENCE_OUT ?? DEFAULT_OUT_PATH,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index] ?? "";
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
    const key = rawKey.replace(
      /-([a-z])/g,
      (_, character) => character.toUpperCase(),
    ) as keyof typeof options;
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for option --${rawKey}`);
    }
    if (!(key in options)) {
      throw new Error(`Unknown option --${rawKey}`);
    }
    options[key] = value as never;
    index += 1;
  }

  if (!options.evidence) {
    throw new Error("--evidence is required");
  }

  return {
    root: options.root,
    evidence: options.evidence,
    out: options.out,
  };
}

function findWorkspaceRoot(explicitRoot: string | null): string {
  if (explicitRoot) {
    return path.resolve(explicitRoot);
  }
  let current = path.resolve(MODULE_DIR);
  while (true) {
    if (
      existsSync(path.join(current, "package.json")) &&
      existsSync(path.join(current, "packages"))
    ) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error("Could not locate sdk workspace root");
    }
    current = parent;
  }
}

async function shaHex(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  hash.update(await fs.readFile(filePath));
  return hash.digest("hex");
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await fs.readFile(filePath, "utf8")) as T;
}

function withHostedSource(
  evidence: ManagedProviderEvidenceFile,
  sourcePath: string,
  sourceSha256: string,
  rootDir: string,
): ManagedProviderEvidenceFile {
  const previousSource = evidence.source ?? {};
  return {
    ...evidence,
    source: {
      ...previousSource,
      imported_evidence_path: path.relative(rootDir, sourcePath),
      imported_evidence_sha256: sourceSha256,
      imported_github_run_id: previousSource.github_run_id ?? null,
      imported_github_workflow: previousSource.github_workflow ?? null,
      imported_github_repository: previousSource.github_repository ?? null,
      imported_github_ref: previousSource.github_ref ?? null,
      imported_github_sha: previousSource.github_sha ?? null,
      imported_github_job: previousSource.github_job ?? null,
      github_run_id: process.env.GITHUB_RUN_ID ?? null,
      github_workflow: process.env.GITHUB_WORKFLOW ?? null,
      github_repository: process.env.GITHUB_REPOSITORY ?? null,
      github_ref: process.env.GITHUB_REF_NAME ?? process.env.GITHUB_REF ?? null,
      github_sha: process.env.GITHUB_SHA ?? null,
      github_job: process.env.GITHUB_JOB ?? null,
    },
    lane: {
      ...(evidence.lane ?? {}),
      hosted: true,
    },
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const rootDir = findWorkspaceRoot(options.root);
  const evidencePath = path.resolve(rootDir, options.evidence);
  const outPath = path.resolve(rootDir, options.out);

  const input = await readJson<ManagedProviderEvidenceFile>(evidencePath);
  const imported = withHostedSource(input, evidencePath, await shaHex(evidencePath), rootDir);

  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, `${JSON.stringify(imported, null, 2)}\n`, "utf8");
  console.log(`[import-managed-provider-evidence] wrote ${path.relative(rootDir, outPath)}`);
}

main().catch((error) => {
  console.error(
    "[import-managed-provider-evidence] error:",
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
});
