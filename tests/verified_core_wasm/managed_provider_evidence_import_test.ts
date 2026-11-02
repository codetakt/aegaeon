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
  assert.deepEqual(output.source, input.source);
  assert.deepEqual(output.lane, input.lane);
  assert.deepEqual(output.runtime, input.runtime);
  assert.deepEqual(output.provider, input.provider);
  const receipt = output.import_history[0];
  assert.equal(output.import_history.length, 1);
  assert.equal(receipt.importer.github_run_id, "77777");
  assert.equal(receipt.importer.github_ref, "refs/heads/main");
  assert.equal(receipt.importer.github_sha, "newsha");
  assert.equal(receipt.evidence_path, path.relative(ROOT_DIR, inputPath));
  assert.equal(receipt.evidence_sha256, await shaHex(inputPath));
  assert.ok(Date.parse(receipt.imported_at) > Date.parse(output.generated_at));
  const secondPath = path.join(tempRoot, "second-import.json");
  await execFile(
    process.execPath,
    [toolPath, "--root", ROOT_DIR, "--evidence", outputPath, "--out", secondPath],
    { cwd: ROOT_DIR, env: { ...process.env, GITHUB_RUN_ID: "88888" } },
  );
  const second = JSON.parse(await readFile(secondPath, "utf8"));
  assert.deepEqual(second.source, input.source);
  assert.deepEqual(second.lane, input.lane);
  assert.equal(second.generated_at, input.generated_at);
  assert.equal(second.import_history.length, 2);
  assert.deepEqual(second.import_history[0], receipt);
  assert.equal(second.import_history[1].importer.github_run_id, "88888");
  assert.equal(second.import_history[1].evidence_sha256, await shaHex(outputPath));
  await execFile("python3", [validatorPath, secondPath], { cwd: ROOT_DIR });
  await assert.rejects(
    execFile("python3", [validatorPath, "--require-enterprise-ready", secondPath], {
      cwd: ROOT_DIR,
    }),
    /must be no older/,
  );
  await assert.rejects(
    execFile(
      "python3",
      [validatorPath, "--require-enterprise-ready", "--max-age-hours", "10000000", secondPath],
      { cwd: ROOT_DIR },
    ),
    /hosted=true/,
  );
  const original = await readFile(inputPath, "utf8");
  await assert.rejects(
    execFile(
      process.execPath,
      [toolPath, "--root", ROOT_DIR, "--evidence", inputPath, "--out", inputPath],
      { cwd: ROOT_DIR },
    ),
    /EEXIST/,
  );
  assert.equal(await readFile(inputPath, "utf8"), original);
  for (const malformed of [null, 1, [], { ...input, import_history: {} }]) {
    const malformedPath = path.join(tempRoot, "malformed.json");
    await writeFile(malformedPath, JSON.stringify(malformed));
    await assert.rejects(
      execFile(
        process.execPath,
        [
          toolPath,
          "--root",
          ROOT_DIR,
          "--evidence",
          malformedPath,
          "--out",
          path.join(tempRoot, "rejected.json"),
        ],
        { cwd: ROOT_DIR },
      ),
      /Expected/,
    );
  }
  console.log("managed provider evidence import tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
