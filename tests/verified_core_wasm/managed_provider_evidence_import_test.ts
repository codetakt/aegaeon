#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../..", import.meta.url).pathname);

async function firstExistingPath(candidates: string[]): Promise<string> {
  for (const candidate of candidates) {
    try {
      await stat(candidate);
      return candidate;
    } catch (error: any) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  throw new Error(`No candidate path exists: ${candidates.join(", ")}`);
}

async function shaHex(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  hash.update(await readFile(filePath));
  return hash.digest("hex");
}

async function main(): Promise<void> {
  console.log("=== managed provider evidence import test ===");
  const toolPath = await firstExistingPath([
    path.join(ROOT_DIR, "dist-tools", "import-managed-provider-evidence.js"),
    path.join(ROOT_DIR, "scripts", "sdk", "tools-src", "import-managed-provider-evidence.ts"),
  ]);
  const validatorPath = path.join(
    ROOT_DIR,
    "scripts",
    "validation",
    "validate_managed_provider_evidence.py",
  );
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-managed-evidence-import-"));
  const inputPath = path.join(tempRoot, "managed-provider-input.json");
  const outputPath = path.join(tempRoot, "managed-provider-output.json");
  const input = {
    schema_version: 1,
    generated_at: "2026-03-17T00:00:00Z",
    source: {
      config_path: "tests/providers/managed/managed-provider.example.json",
      config_sha256: "a".repeat(64),
      claim_boundary_path: "spec/client-claim-boundary.current.json",
      claim_boundary_sha256: "b".repeat(64),
      github_run_id: "5150",
      github_workflow: "SDK Managed Provider Evidence",
      github_repository: "openai/aegaeon-sdk",
      github_ref: "refs/heads/feature/manual",
      github_sha: "managedsha",
      github_job: "external-provider-managed",
    },
    provider: {
      name: "commercial-staging",
      class: "commercial",
      issuer: "https://issuer.example.test",
      client_id: "client-123",
      auth_method: "client_secret_post",
    },
    lane: {
      name: "external-provider-managed",
      hosted: false,
      status: "passed",
      browser: "/usr/bin/chromium",
    },
    runtime: {
      default_profile: "aegaeon-rs256",
      claim_phase: "pre-release-client-baseline",
      promoted_client_slices: ["rs256-required-client-slice"],
      compat_only_surfaces: ["es256-interop-surface"],
    },
  };
  await writeFile(inputPath, `${JSON.stringify(input, null, 2)}\n`, "utf8");

  await execFile(
    process.execPath,
    [toolPath, "--root", ROOT_DIR, "--evidence", inputPath, "--out", outputPath],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        GITHUB_RUN_ID: "77777",
        GITHUB_WORKFLOW: "SDK Managed Provider Evidence",
        GITHUB_REPOSITORY: "openai/aegaeon-sdk",
        GITHUB_REF_NAME: "main",
        GITHUB_REF: "refs/heads/main",
        GITHUB_SHA: "newsha",
        GITHUB_JOB: "external-provider-managed",
      },
    },
  );

  await execFile("python3", [validatorPath, outputPath], { cwd: ROOT_DIR });
  const output = JSON.parse(await readFile(outputPath, "utf8"));
  assert.equal(output.generated_at, input.generated_at);
  assert.equal(output.lane.hosted, true);
  assert.equal(output.source.github_run_id, "77777");
  assert.equal(output.source.github_workflow, "SDK Managed Provider Evidence");
  assert.equal(output.source.github_repository, "openai/aegaeon-sdk");
  assert.equal(output.source.github_ref, "main");
  assert.equal(output.source.github_sha, "newsha");
  assert.equal(output.source.github_job, "external-provider-managed");
  assert.equal(output.source.imported_github_run_id, input.source.github_run_id);
  assert.equal(output.source.imported_github_workflow, input.source.github_workflow);
  assert.equal(output.source.imported_github_repository, input.source.github_repository);
  assert.equal(output.source.imported_github_ref, input.source.github_ref);
  assert.equal(output.source.imported_github_sha, input.source.github_sha);
  assert.equal(output.source.imported_github_job, input.source.github_job);
  assert.equal(output.source.imported_evidence_path, path.relative(ROOT_DIR, inputPath));
  assert.equal(output.source.imported_evidence_sha256, await shaHex(inputPath));
  console.log("managed provider evidence import tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
