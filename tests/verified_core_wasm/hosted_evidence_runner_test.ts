#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { chmod, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("..", import.meta.url).pathname, "..");
const SCRIPT_PATH = path.join(ROOT_DIR, "scripts", "sdk", "tools-src", "run-hosted-evidence.ts");

async function main() {
  console.log("=== hosted evidence runner test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-hosted-evidence-runner-"));
  const nowIso = new Date().toISOString();
  const fakeBinDir = path.join(tempRoot, "bin");
  const stateDir = path.join(tempRoot, "state");
  const adminFixturePath = path.join(tempRoot, "admin-sdk-evidence.json");
  const managedFixturePath = path.join(tempRoot, "managed-provider-evidence.json");
  const logPath = path.join(tempRoot, "gh.log");
  await mkdir(fakeBinDir, { recursive: true });
  await mkdir(stateDir, { recursive: true });

  const adminFixture = {
    schema_version: 1,
    generated_at: nowIso,
    source: {
      admin_sdk_boundary_path: "spec/admin-sdk-boundary.current.json",
      admin_sdk_boundary_sha256: "deadbeef",
      github_run_id: "4242",
      github_workflow: "Admin Console Stack E2E",
      github_repository: "openai/aegaeon-admin-console",
      github_ref: "refs/heads/main",
      github_sha: "adminsha",
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
    capabilities: ["bootstrap-login-logout"],
  };
  const managedFixture = {
    schema_version: 1,
    generated_at: nowIso,
    source: {
      config_path: "tests/providers/managed/managed-provider.example.json",
      config_sha256: "cafebabe",
      claim_boundary_path: "spec/client-claim-boundary.current.json",
      claim_boundary_sha256: "deadbeef",
      github_run_id: "5150",
      github_workflow: "SDK Managed Provider Evidence",
      github_repository: "openai/aegaeon-sdk",
      github_ref: "refs/heads/main",
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

  await writeFile(adminFixturePath, `${JSON.stringify(adminFixture, null, 2)}\n`, "utf8");
  await writeFile(managedFixturePath, `${JSON.stringify(managedFixture, null, 2)}\n`, "utf8");

  const fakeGhPath = path.join(fakeBinDir, "gh");
  await writeFile(
    fakeGhPath,
    `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$GH_LOG_PATH"
if [ "$1" = "workflow" ] && [ "$2" = "run" ]; then
  exit 0
fi
if [ "$1" = "run" ] && [ "$2" = "list" ]; then
  workflow=
  for ((i=1; i<=$#; i++)); do
    if [ "\${!i}" = "--workflow" ]; then
      next=$((i+1))
      workflow="\${!next}"
      break
    fi
  done
  count_file="$GH_STATE_DIR/$workflow.count"
  count=0
  if [ -f "$count_file" ]; then
    count=$(cat "$count_file")
  fi
  count=$((count+1))
  printf '%s' "$count" > "$count_file"
  if [ "$workflow" = "stack-e2e.yml" ]; then
    if [ "$count" -eq 1 ]; then
      printf '%s\\n' \
        '[{"databaseId":4242,"status":"in_progress","conclusion":"","createdAt":"${nowIso}",'\
'"url":"https://example.test/admin/4242"}]'
    else
      printf '%s\\n' \
        '[{"databaseId":4242,"status":"completed","conclusion":"success","createdAt":"${nowIso}",'\
'"url":"https://example.test/admin/4242"}]'
    fi
    exit 0
  fi
  if [ "$workflow" = "managed-provider-evidence.yml" ]; then
    if [ "$count" -eq 1 ]; then
      printf '%s\\n' \
        '[{"databaseId":5150,"status":"in_progress","conclusion":"","createdAt":"${nowIso}",'\
'"url":"https://example.test/managed/5150"}]'
    else
      printf '%s\\n' \
        '[{"databaseId":5150,"status":"completed","conclusion":"success","createdAt":"${nowIso}",'\
'"url":"https://example.test/managed/5150"}]'
    fi
    exit 0
  fi
  printf '%s\\n' '[]'
  exit 0
fi
if [ "$1" = "run" ] && [ "$2" = "download" ]; then
  out_dir=
  artifact=
  for ((i=1; i<=$#; i++)); do
    if [ "\${!i}" = "--dir" ]; then
      next=$((i+1))
      out_dir="\${!next}"
    fi
    if [ "\${!i}" = "--name" ]; then
      next=$((i+1))
      artifact="\${!next}"
    fi
  done
  mkdir -p "$out_dir"
  if [ "$artifact" = "admin-sdk-evidence" ]; then
    cp "$ADMIN_FIXTURE_PATH" "$out_dir/admin-sdk-evidence.json"
    exit 0
  fi
  if [ "$artifact" = "managed-provider-evidence" ]; then
    cp "$MANAGED_FIXTURE_PATH" "$out_dir/managed-provider-evidence.json"
    exit 0
  fi
  echo "unexpected artifact $artifact" >&2
  exit 1
fi
echo "unexpected gh invocation: $*" >&2
exit 1
`,
    "utf8",
  );
  await chmod(fakeGhPath, 0o755);

  const adminOutPath = path.join(tempRoot, "admin-out", "admin-sdk-evidence.json");
  const adminRun = await execFile(
    process.execPath,
    [
      SCRIPT_PATH,
      "--kind",
      "admin-sdk",
      "--repo",
      "openai/aegaeon-admin-console",
      "--ref",
      "main",
      "--poll-seconds",
      "1",
      "--timeout-seconds",
      "10",
      "--out",
      adminOutPath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH}`,
        GH_LOG_PATH: logPath,
        GH_STATE_DIR: stateDir,
        ADMIN_FIXTURE_PATH: adminFixturePath,
        MANAGED_FIXTURE_PATH: managedFixturePath,
      },
    },
  );
  assert.match(adminRun.stdout, /dispatched stack-e2e\.yml/);
  assert.deepEqual(JSON.parse(await readFile(adminOutPath, "utf8")), adminFixture);

  const configPath = path.join(tempRoot, "managed-provider.json");
  await writeFile(configPath, JSON.stringify({ providerName: "managed" }), "utf8");
  const managedOutPath = path.join(tempRoot, "managed-out", "managed-provider-evidence.json");
  const managedRun = await execFile(
    process.execPath,
    [
      SCRIPT_PATH,
      "--kind",
      "managed-provider",
      "--repo",
      "openai/aegaeon-sdk",
      "--ref",
      "main",
      "--poll-seconds",
      "1",
      "--timeout-seconds",
      "10",
      "--config",
      configPath,
      "--provider-class",
      "commercial",
      "--out",
      managedOutPath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH}`,
        GH_LOG_PATH: logPath,
        GH_STATE_DIR: stateDir,
        ADMIN_FIXTURE_PATH: adminFixturePath,
        MANAGED_FIXTURE_PATH: managedFixturePath,
      },
    },
  );
  assert.match(managedRun.stdout, /dispatched managed-provider-evidence\.yml/);
  assert.deepEqual(JSON.parse(await readFile(managedOutPath, "utf8")), managedFixture);

  const ghLog = await readFile(logPath, "utf8");
  assert.match(
    ghLog,
    /workflow run stack-e2e\.yml .*--repo openai\/aegaeon-admin-console .*--ref main/,
  );
  assert.match(
    ghLog,
    /workflow run managed-provider-evidence\.yml .*--repo openai\/aegaeon-sdk .*--ref main/,
  );
  assert.match(ghLog, /-f provider_class=commercial/);
  assert.match(ghLog, /-f managed_provider_config_json=\{"providerName":"managed"\}/);

  const importedManagedOutPath = path.join(
    tempRoot,
    "managed-imported-out",
    "managed-provider-evidence.json",
  );
  const importedManagedRun = await execFile(
    process.execPath,
    [
      SCRIPT_PATH,
      "--kind",
      "managed-provider",
      "--repo",
      "openai/aegaeon-sdk",
      "--ref",
      "main",
      "--poll-seconds",
      "1",
      "--timeout-seconds",
      "10",
      "--evidence",
      managedFixturePath,
      "--out",
      importedManagedOutPath,
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        PATH: `${fakeBinDir}:${process.env.PATH}`,
        GH_LOG_PATH: logPath,
        GH_STATE_DIR: stateDir,
        ADMIN_FIXTURE_PATH: adminFixturePath,
        MANAGED_FIXTURE_PATH: managedFixturePath,
      },
    },
  );
  assert.match(importedManagedRun.stdout, /dispatched managed-provider-evidence\.yml/);
  assert.deepEqual(JSON.parse(await readFile(importedManagedOutPath, "utf8")), managedFixture);

  const importedGhLog = await readFile(logPath, "utf8");
  assert.match(importedGhLog, /-f managed_provider_evidence_json=\{/);
  assert.match(ghLog, /run download 4242 .*--name admin-sdk-evidence/);
  assert.match(ghLog, /run download 5150 .*--name managed-provider-evidence/);

  console.log("hosted evidence runner tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
