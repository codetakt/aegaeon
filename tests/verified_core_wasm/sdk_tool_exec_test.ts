import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const SDK_DIR = path.resolve(TEST_DIR, "..", "..");
const EXEC_TOOL_SOURCE = path.join(SDK_DIR, "scripts", "sdk", "tools-src", "exec-tool.ts");

/**
 * @param {string[]} args
 * @returns {Promise<{ code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }>}
 */
function runNode(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: SDK_DIR,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

const tempDir = await mkdtemp(path.join(os.tmpdir(), "aegaeon-exec-tool-"));
const EXEC_TOOL = path.join(tempDir, "exec-tool.ts");
await writeFile(EXEC_TOOL, await readFile(EXEC_TOOL_SOURCE, "utf8"), "utf8");

const verifyCorePath = path.join(tempDir, "verify-core.js");
await writeFile(
  verifyCorePath,
  `#!/usr/bin/env node
if (process.argv.includes("--help")) {
  console.log("Usage: node dist-tools/verify-core.js");
  process.exit(0);
}
process.exit(1);
`,
  "utf8",
);
await chmod(verifyCorePath, 0o755);

const readinessPath = path.join(tempDir, "run-real-tenant-readiness.js");
await writeFile(
  readinessPath,
  `#!/usr/bin/env node
if (process.argv.includes("--help")) {
  console.log("Usage: node dist-tools/run-real-tenant-readiness.js");
  process.exit(0);
}
process.exit(1);
`,
  "utf8",
);
await chmod(readinessPath, 0o755);

const helpResult = await runNode([EXEC_TOOL, "verify-core", "--help"]);
assert.equal(helpResult.code, 0);
assert.match(helpResult.stdout, /Usage: node dist-tools\/verify-core\.js/);

const readinessHelpResult = await runNode([EXEC_TOOL, "run:real-tenant-readiness", "--help"]);
assert.equal(readinessHelpResult.code, 0);
assert.match(readinessHelpResult.stdout, /run-real-tenant-readiness/);

const unknownToolResult = await runNode([EXEC_TOOL, "unknown-tool"]);
assert.notEqual(unknownToolResult.code, 0);
assert.match(`${unknownToolResult.stdout}${unknownToolResult.stderr}`, /Unknown tool 'unknown-tool'/);
