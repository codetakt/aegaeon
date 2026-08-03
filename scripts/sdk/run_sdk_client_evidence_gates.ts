#!/usr/bin/env node
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.join(MODULE_DIR, "tools-src", "run-client-evidence-gates.ts");

const child = spawn(
  process.execPath,
  ["--experimental-strip-types", SCRIPT_PATH, ...process.argv.slice(2)],
  {
    cwd: process.cwd(),
    env: process.env,
    stdio: "inherit",
  },
);

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exitCode = code ?? 1;
});
