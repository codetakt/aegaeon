#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../..", import.meta.url).pathname);

function resolveScriptPath(rootDir) {
  const candidates = [
    path.join(rootDir, "dist-tools", "download-admin-sdk-evidence.js"),
    path.join(rootDir, "sdk", "dist-tools", "download-admin-sdk-evidence.js"),
    path.join(rootDir, "scripts", "sdk", "download_admin_sdk_evidence.ts"),
    path.join(rootDir, "scripts", "download-admin-sdk-evidence.ts"),
  ];
  const scriptPath = candidates.find((candidate) => existsSync(candidate));
  if (!scriptPath) {
    throw new Error(`Could not locate download-admin-sdk-evidence script under ${rootDir}`);
  }
  return scriptPath;
}

const SCRIPT_PATH = resolveScriptPath(ROOT_DIR);

async function main() {
  console.log("=== admin SDK evidence download test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-admin-sdk-download-"));
  const artifactDir = path.join(tempRoot, "artifact");
  const outDir = path.join(tempRoot, "out");
  const hostedOutDir = path.join(tempRoot, "hosted");
  const fakeBinDir = path.join(tempRoot, "bin");
  const fixturePath = path.join(tempRoot, "fixture.json");
  const logPath = path.join(tempRoot, "gh.log");

  const fixture = {
    schema_version: 1,
    generated_at: "2026-03-16T00:00:00.000Z",
    source: {
      admin_sdk_boundary_path: "spec/admin-sdk-boundary.current.json",
      admin_sdk_boundary_sha256: "deadbeef",
      github_run_id: "1234",
      github_workflow: "Admin Console Stack E2E",
      github_repository: "openai/aegaeon-admin-console",
      github_ref: "refs/heads/main",
      github_sha: "abc123",
      github_job: "stack-e2e",
    },
    lane: {
      name: "admin-console-stack-e2e",
      status: "passed",
      stack_mode: "compose-sibling-aegaeon",
    },
    sdk_boundary: {
      management_sdk_package: "@aegaeon/management-client",
      forbidden_oidc_packages: ["@aegaeon/issuer-spa", "@aegaeon/rp-core"],
    },
    capabilities: ["bootstrap-login-logout", "client-management"],
  };

  await mkdir(artifactDir, { recursive: true });
  await mkdir(fakeBinDir, { recursive: true });
  await writeFile(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`, "utf8");
  await writeFile(
    path.join(artifactDir, "admin-sdk-evidence.json"),
    `${JSON.stringify(fixture, null, 2)}\n`,
    "utf8",
  );

  const fakeGhPath = path.join(fakeBinDir, "gh");
  await writeFile(
    fakeGhPath,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$GH_LOG_PATH"
if [ "$1" = "run" ] && [ "$2" = "list" ]; then
  cat <<'JSON'
[
  {
    "databaseId": 4242,
    "workflowName": "Admin Console Stack E2E",
    "headBranch": "main",
    "headSha": "abc123",
    "url": "https://example.test/runs/4242"
  }
]
JSON
  exit 0
fi
if [ "$1" = "run" ] && [ "$2" = "download" ]; then
  out_dir=
  for ((i=1; i<=$#; i++)); do
    if [ "\${!i}" = "--dir" ]; then
      next=$((i+1))
      out_dir="\${!next}"
      break
    fi
  done
  mkdir -p "$out_dir"
  cp "$TEST_FIXTURE_PATH" "$out_dir/admin-sdk-evidence.json"
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 1
`,
    "utf8",
  );
  await chmod(fakeGhPath, 0o755);

  const localOutPath = path.join(outDir, "admin-sdk-evidence.json");
  await execFile(process.execPath, [
    SCRIPT_PATH,
    "--artifact-dir",
    artifactDir,
    "--out",
    localOutPath,
  ], { cwd: ROOT_DIR });
  assert.deepEqual(JSON.parse(await readFile(localOutPath, "utf8")), fixture);

  const hostedOutPath = path.join(hostedOutDir, "admin-sdk-evidence.json");
  await execFile(
    process.execPath,
    [
      SCRIPT_PATH,
      "--repo",
      "openai/aegaeon-admin-console",
      "--workflow",
      "stack-e2e.yml",
      "--branch",
      "main",
      "--artifact",
      "admin-sdk-evidence",
      "--out",
      hostedOutPath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH}`,
        TEST_FIXTURE_PATH: fixturePath,
        GH_LOG_PATH: logPath,
      },
    },
  );
  assert.deepEqual(JSON.parse(await readFile(hostedOutPath, "utf8")), fixture);

  const ghLog = await readFile(logPath, "utf8");
  assert.match(
    ghLog,
    /run list .*--repo openai\/aegaeon-admin-console .*--workflow stack-e2e\.yml .*--branch main/,
  );
  assert.match(ghLog, /run download 4242 .*--name admin-sdk-evidence/);

  console.log("admin SDK evidence download tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
