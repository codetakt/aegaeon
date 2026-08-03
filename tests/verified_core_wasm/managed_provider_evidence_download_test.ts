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
    path.join(rootDir, "dist-tools", "download-managed-provider-evidence.js"),
    path.join(rootDir, "sdk", "dist-tools", "download-managed-provider-evidence.js"),
    path.join(rootDir, "scripts", "sdk", "download_managed_provider_evidence.ts"),
    path.join(rootDir, "scripts", "download-managed-provider-evidence.ts"),
  ];
  const scriptPath = candidates.find((candidate) => existsSync(candidate));
  if (!scriptPath) {
    throw new Error(`Could not locate download-managed-provider-evidence script under ${rootDir}`);
  }
  return scriptPath;
}

const SCRIPT_PATH = resolveScriptPath(ROOT_DIR);

async function main() {
  console.log("=== managed provider evidence download test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-managed-provider-download-"));
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
      config_path: "tests/providers/managed/managed-provider.example.json",
      config_sha256: "deadbeef",
      claim_boundary_path: "spec/client-claim-boundary.current.json",
      claim_boundary_sha256: "cafebabe",
      github_run_id: "4242",
      github_workflow: "SDK Managed Provider Evidence",
      github_repository: "openai/aegaeon-sdk",
      github_ref: "refs/heads/main",
      github_sha: "abc123",
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
      hosted: true,
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

  await mkdir(artifactDir, { recursive: true });
  await mkdir(fakeBinDir, { recursive: true });
  await writeFile(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`, "utf8");
  await writeFile(
    path.join(artifactDir, "managed-provider-evidence.json"),
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
    "databaseId": 5150,
    "workflowName": "SDK Managed Provider Evidence",
    "headBranch": "main",
    "headSha": "abc123",
    "url": "https://example.test/runs/5150"
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
  cp "$TEST_FIXTURE_PATH" "$out_dir/managed-provider-evidence.json"
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 1
`,
    "utf8",
  );
  await chmod(fakeGhPath, 0o755);

  const localOutPath = path.join(outDir, "managed-provider-evidence.json");
  await execFile(process.execPath, [
    SCRIPT_PATH,
    "--artifact-dir",
    artifactDir,
    "--out",
    localOutPath,
  ], { cwd: ROOT_DIR });
  assert.deepEqual(JSON.parse(await readFile(localOutPath, "utf8")), fixture);

  const hostedOutPath = path.join(hostedOutDir, "managed-provider-evidence.json");
  await execFile(
    process.execPath,
    [
      SCRIPT_PATH,
      "--repo",
      "openai/aegaeon-sdk",
      "--workflow",
      "managed-provider-evidence.yml",
      "--branch",
      "main",
      "--artifact",
      "managed-provider-evidence",
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
    new RegExp(
      "run list .*--repo openai/aegaeon-sdk .*" +
        "--workflow managed-provider-evidence\\.yml .*--branch main",
    ),
  );
  assert.match(ghLog, /run download 5150 .*--name managed-provider-evidence/);

  console.log("managed provider evidence download tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
