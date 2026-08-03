#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { chmod, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
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
  "run-real-tenant-readiness.ts",
);

function readOption(args, name) {
  const index = args.indexOf(name);
  if (index === -1) {
    return null;
  }
  const value = args[index + 1];
  return typeof value === "string" ? value : null;
}

async function main() {
  console.log("=== real tenant readiness runner test ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-real-tenant-readiness-"));
  const distToolsDir = path.join(tempRoot, "dist-tools");
  const callsLogPath = path.join(tempRoot, "calls.jsonl");
  const managedConfigPath = path.join(tempRoot, "managed-provider.json");
  await mkdir(distToolsDir, { recursive: true });
  await mkdir(path.join(tempRoot, "packages"), { recursive: true });
  await writeFile(
    path.join(tempRoot, "package.json"),
    JSON.stringify({ name: "temp-sdk", private: true, type: "module" }, null, 2),
    "utf8",
  );
  await writeFile(
    managedConfigPath,
    JSON.stringify({ issuer: "https://issuer.example.test" }, null, 2),
    "utf8",
  );

  const hostedToolPath = path.join(distToolsDir, "run-hosted-evidence.js");
  await writeFile(
    hostedToolPath,
    `#!/usr/bin/env node
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const args = process.argv.slice(2);
const readOption = (name) => {
  const index = args.indexOf(name);
  if (index === -1) return null;
  return typeof args[index + 1] === "string" ? args[index + 1] : null;
};

const kind = readOption("--kind");
const outPath = readOption("--out");
const logPath = process.env.CALLS_LOG;
if (!kind || !outPath || !logPath) {
  throw new Error("run-hosted-evidence test fixture requires --kind, --out, and CALLS_LOG");
}
await mkdir(path.dirname(outPath), { recursive: true });
await appendFile(
  logPath,
  JSON.stringify({ tool: "run-hosted-evidence", kind, args }) + "\\n",
  "utf8",
);
if (kind === "admin-sdk") {
  await writeFile(
    outPath,
    JSON.stringify({ kind, lane: "admin-console-stack-e2e" }, null, 2) + "\\n",
    "utf8",
  );
} else {
  await writeFile(
    outPath,
    JSON.stringify(
      {
        kind,
        lane: "external-provider-managed",
        config: readOption("--config"),
      },
      null,
      2,
    ) + "\\n",
    "utf8",
  );
}
`,
    "utf8",
  );
  await chmod(hostedToolPath, 0o755);

  const gateToolPath = path.join(distToolsDir, "run-client-evidence-gates.js");
  await writeFile(
    gateToolPath,
    `#!/usr/bin/env node
import { access, appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const args = process.argv.slice(2);
const readOption = (name) => {
  const index = args.indexOf(name);
  if (index === -1) return null;
  return typeof args[index + 1] === "string" ? args[index + 1] : null;
};
const collectOptions = (name) => {
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === name && typeof args[index + 1] === "string") {
      values.push(args[index + 1]);
      index += 1;
    }
  }
  return values;
};

const adminEvidence = readOption("--admin-sdk-evidence");
const managedEvidence = readOption("--managed-provider-evidence");
const promotionReport = readOption("--promotion-report");
const releasedClientReport = readOption("--released-client-report");
const publicationBundle = readOption("--publication-bundle");
const logPath = process.env.CALLS_LOG;
if (
  !adminEvidence ||
  !managedEvidence ||
  !promotionReport ||
  !releasedClientReport ||
  !publicationBundle ||
  !logPath
) {
  throw new Error("run-client-evidence-gates test fixture received incomplete arguments");
}
await access(adminEvidence);
await access(managedEvidence);
await appendFile(
  logPath,
  JSON.stringify({
    tool: "run-client-evidence-gates",
    args,
    mode: readOption("--mode"),
    claimActive: readOption("--claim-active"),
    lanes: collectOptions("--lane"),
    publicationOrgTasks: collectOptions("--publication-org-task"),
  }) + "\\n",
  "utf8",
);
for (const outputPath of [promotionReport, releasedClientReport, publicationBundle]) {
  await mkdir(path.dirname(outputPath), { recursive: true });
}
await writeFile(
  promotionReport,
  JSON.stringify({ ready: false, report: "promotion" }, null, 2) + "\\n",
  "utf8",
);
await writeFile(
  releasedClientReport,
  JSON.stringify({ ready: true, report: "readiness" }, null, 2) + "\\n",
  "utf8",
);
await writeFile(
  publicationBundle,
  JSON.stringify({ adminEvidence, managedEvidence }, null, 2) + "\\n",
  "utf8",
);
`,
    "utf8",
  );
  await chmod(gateToolPath, 0o755);

  const run = await execFile(
    process.execPath,
    [
      SCRIPT_PATH,
      "--root",
      tempRoot,
      "--mode",
      "readiness",
      "--managed-provider-config",
      managedConfigPath,
      "--claim-active",
      "false",
      "--lane",
      "sdk-browser=passed",
      "--publication-org-task",
      "release-custody=pending",
    ],
    {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        CALLS_LOG: callsLogPath,
      },
    },
  );

  assert.match(run.stdout, /admin evidence:/);
  assert.match(run.stdout, /managed evidence:/);
  assert.match(run.stdout, /mode: readiness/);

  const calls = (await readFile(callsLogPath, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(calls.length, 3);
  assert.equal(calls[0]?.tool, "run-hosted-evidence");
  assert.equal(calls[0]?.kind, "admin-sdk");
  assert.equal(calls[1]?.tool, "run-hosted-evidence");
  assert.equal(calls[1]?.kind, "managed-provider");
  assert.equal(readOption(calls[1]?.args ?? [], "--config"), managedConfigPath);
  assert.equal(calls[2]?.tool, "run-client-evidence-gates");
  assert.equal(calls[2]?.mode, "readiness");
  assert.equal(calls[2]?.claimActive, "false");
  assert.deepEqual(calls[2]?.lanes, ["sdk-browser=passed"]);
  assert.deepEqual(calls[2]?.publicationOrgTasks, ["release-custody=pending"]);

  const releasedClientReport = JSON.parse(
    await readFile(
      path.join(
        tempRoot,
        ".artifacts",
        "release",
        "released-client-claim-report.json",
      ),
      "utf8",
    ),
  );
  assert.equal(releasedClientReport.ready, true);

  const publicationBundle = JSON.parse(
    await readFile(
      path.join(
        tempRoot,
        ".artifacts",
        "release",
        "release-publication-bundle.json",
      ),
      "utf8",
    ),
  );
  assert.match(publicationBundle.adminEvidence, /admin-sdk-evidence\.json$/);
  assert.match(publicationBundle.managedEvidence, /managed-provider-evidence\.json$/);
}

main().catch((error) => {
  console.error("real tenant readiness runner test failed");
  console.error(error);
  process.exitCode = 1;
});
