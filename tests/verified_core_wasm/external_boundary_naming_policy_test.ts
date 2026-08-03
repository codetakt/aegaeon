#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../..", import.meta.url).pathname);
const SCRIPT_PATH = path.join(
  ROOT_DIR,
  "scripts",
  "sdk",
  "tools-src",
  "check-external-boundary-naming.ts",
);
const POLICY_PATH = path.join(ROOT_DIR, "spec", "external-boundary-naming.current.json");

interface ExecFileFailure extends Error {
  code?: number;
  stderr: string;
}

function expectExecFileFailure(error: unknown): ExecFileFailure {
  if (
    typeof error !== "object" ||
    error === null ||
    !("stderr" in error) ||
    typeof (error as { stderr?: unknown }).stderr !== "string"
  ) {
    throw new Error(`Expected execFile failure, got ${String(error)}`);
  }
  return error as ExecFileFailure;
}

async function main(): Promise<void> {
  console.log("=== external boundary naming policy test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-naming-policy-"));
  await mkdir(path.join(tempRoot, "src"), { recursive: true });
  await writeFile(
    path.join(tempRoot, "src", "example.ts"),
    [
      "const legacyEnv = process.env.AEG_SAMPLE_VALUE;",
      "const targetEnv = process.env.AEGAEON_SAMPLE_VALUE;",
      "const legacyWire = { aeg_sample_toggle: true };",
      "const targetWire = { aegaeon_sample_toggle: true };",
      "",
    ].join("\n"),
    "utf8",
  );

  const success = await execFile(
    process.execPath,
    [SCRIPT_PATH, "--root", tempRoot, "--policy", POLICY_PATH],
    {
      cwd: ROOT_DIR,
    },
  );
  assert.match(success.stdout, /deprecated env prefix \(AEG_\): 1 identifiers \/ 1 occurrences/);
  assert.match(success.stdout, /target env prefix \(AEGAEON_\): 1 identifiers \/ 1 occurrences/);
  assert.match(success.stdout, /deprecated wire prefix \(aeg_\): 1 identifiers \/ 1 occurrences/);
  assert.match(success.stdout, /target wire prefix \(aegaeon_\): 1 identifiers \/ 1 occurrences/);

  const brokenPolicyPath = path.join(tempRoot, "broken-policy.json");
  const policy = JSON.parse(await readFile(POLICY_PATH, "utf8")) as Record<string, unknown>;
  const externalBoundaryEnv = { ...(policy["external_boundary_env"] as Record<string, unknown>) };
  externalBoundaryEnv["target_prefix"] = "BROKEN_";
  policy["external_boundary_env"] = externalBoundaryEnv;
  await writeFile(brokenPolicyPath, JSON.stringify(policy, null, 2), "utf8");

  await assert.rejects(
    execFile(process.execPath, [SCRIPT_PATH, "--root", tempRoot, "--policy", brokenPolicyPath], {
      cwd: ROOT_DIR,
    }),
    (error: unknown) => {
      const failure = expectExecFileFailure(error);
      assert.equal(failure.code, 1);
      assert.match(failure.stderr, /external_boundary_env\.target_prefix/);
      return true;
    },
  );

  console.log("external boundary naming policy tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
