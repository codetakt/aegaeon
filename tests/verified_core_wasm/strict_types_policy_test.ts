#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../..", import.meta.url).pathname);
const POLICY_PATH = path.join(ROOT_DIR, "spec", "strict-types.current.json");

type StrictTypesPolicy = {
  required_base_flags: Record<string, boolean>;
  package_tsconfig_paths: string[];
  additional_tsconfig_requirements: Array<{
    path: string;
    required_flags: Record<string, boolean>;
  }>;
  required_no_tsnocheck_paths: string[];
};

function resolveScriptPath(): string {
  const candidates = [
    path.join(ROOT_DIR, "dist-tools", "check-strict-types.js"),
    path.join(ROOT_DIR, "tools-src", "check-strict-types.ts"),
    path.join(ROOT_DIR, "scripts", "sdk", "check_sdk_strict_types.ts"),
    path.join(ROOT_DIR, "scripts", "sdk", "tools-src", "check-strict-types.ts"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  const fallbackCandidate = candidates[0];
  if (!fallbackCandidate) {
    throw new Error("Strict types checker candidate list is empty");
  }
  return fallbackCandidate;
}

function relativeBaseTsconfigPath(rootDir: string, targetPath: string): string {
  const relativePath = path.relative(
    path.dirname(targetPath),
    path.join(rootDir, "tsconfig.base.json"),
  );
  return relativePath.startsWith(".") ? relativePath : `./${relativePath}`;
}

async function main(): Promise<void> {
  console.log("=== strict types policy test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-strict-types-"));
  mkdirSync(path.join(tempRoot, "packages"), { recursive: true });
  await writeFile(path.join(tempRoot, "package.json"), "{\n  \"name\": \"temp-sdk\"\n}\n", "utf8");

  const policy = JSON.parse(await readFile(POLICY_PATH, "utf8")) as StrictTypesPolicy;
  await writeFile(
    path.join(tempRoot, "tsconfig.base.json"),
    `${JSON.stringify({ compilerOptions: policy.required_base_flags }, null, 2)}\n`,
    "utf8",
  );

  for (const relativePath of policy.package_tsconfig_paths) {
    const fullPath = path.join(tempRoot, relativePath);
    mkdirSync(path.dirname(fullPath), { recursive: true });
    await writeFile(
      fullPath,
      `${JSON.stringify(
        {
          extends: relativeBaseTsconfigPath(tempRoot, fullPath),
          compilerOptions: { rootDir: "src", outDir: "dist" },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
  }

  for (const requirement of policy.additional_tsconfig_requirements) {
    const fullPath = path.join(tempRoot, requirement.path);
    mkdirSync(path.dirname(fullPath), { recursive: true });
    await writeFile(
      fullPath,
      `${JSON.stringify(
        {
          extends: relativeBaseTsconfigPath(tempRoot, fullPath),
          compilerOptions: requirement.required_flags,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
  }

  for (const relativePath of policy.required_no_tsnocheck_paths) {
    const fullPath = path.join(tempRoot, relativePath);
    mkdirSync(path.dirname(fullPath), { recursive: true });
    await writeFile(fullPath, "export {};\n", "utf8");
  }

  const scriptPath = resolveScriptPath();
  const goodResult = await execFile(
    process.execPath,
    [scriptPath, "--root", tempRoot, "--policy", POLICY_PATH],
    { cwd: ROOT_DIR },
  );
  assert.match(goodResult.stdout, /Strict types policy/);

  const firstPolicyPath = policy.required_no_tsnocheck_paths[0];
  assert.ok(firstPolicyPath, "strict types policy must define at least one no-ts-nocheck path");
  const firstTarget = path.join(tempRoot, firstPolicyPath);
  await writeFile(firstTarget, "// @ts-nocheck\nexport {};\n", "utf8");
  await assert.rejects(
    execFile(
      process.execPath,
      [scriptPath, "--root", tempRoot, "--policy", POLICY_PATH],
      { cwd: ROOT_DIR },
    ),
    (error: unknown) => {
      const execError = error as { code?: number; stderr?: string };
      assert.equal(execError.code, 1);
      assert.match(execError.stderr ?? "", /ts-nocheck/);
      return true;
    },
  );

  const firstAdditionalRequirement = policy.additional_tsconfig_requirements[0];
  assert.ok(
    firstAdditionalRequirement,
    "strict types policy must define at least one additional tsconfig requirement",
  );
  const testTsconfigPath = path.join(tempRoot, firstAdditionalRequirement.path);
  await writeFile(
    testTsconfigPath,
    `${JSON.stringify(
      {
        extends: "./tsconfig.base.json",
        compilerOptions: { useUnknownInCatchVariables: false },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await assert.rejects(
    execFile(
      process.execPath,
      [scriptPath, "--root", tempRoot, "--policy", POLICY_PATH],
      { cwd: ROOT_DIR },
    ),
    (error: unknown) => {
      const execError = error as { code?: number; stderr?: string };
      assert.equal(execError.code, 1);
      assert.match(execError.stderr ?? "", /useUnknownInCatchVariables/);
      return true;
    },
  );

  console.log("strict types policy tests passed");
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
