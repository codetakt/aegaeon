import { spawn } from "node:child_process";
import path from "node:path";
import { test, expect } from "@playwright/test";

const host = process.env.AEGAEON_BROWSER_SMOKE_HOST ?? "127.0.0.1";
const port = Number(process.env.AEGAEON_BROWSER_SMOKE_PORT ?? "41731");
const serverScript = path.join(process.cwd(), "tests", "browser", "runtime_web_reference_server.ts");
let server;

function waitForServer(child) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("timed out waiting for runtime-web smoke server"));
    }, 5000);

    function onChunk(chunk) {
      const text = chunk.toString();
      if (text.includes("sdk browser test server listening")) {
        clearTimeout(timeout);
        resolve();
      }
      if (text.includes("listen EPERM")) {
        clearTimeout(timeout);
        reject(new Error(text.trim()));
      }
    }

    child.stdout.on("data", onChunk);
    child.stderr.on("data", onChunk);
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("exit", (code) => {
      if (code !== 0) {
        clearTimeout(timeout);
        reject(new Error(`runtime-web smoke server exited early with code ${code}`));
      }
    });
  });
}

test.beforeAll(async () => {
  server = spawn(process.execPath, ["--experimental-strip-types", serverScript], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      AEGAEON_BROWSER_SMOKE_HOST: host,
      AEGAEON_BROWSER_SMOKE_PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitForServer(server);
});

test.afterAll(async () => {
  if (server && !server.killed) {
    server.kill("SIGTERM");
  }
});

test("runtime-web harness passes in a real browser", async ({ page }) => {
  await page.goto(`http://${host}:${port}/tests/browser/runtime_web_reference.html`, {
    waitUntil: "networkidle",
  });
  const status = page.locator("#status");
  await expect(status).toHaveAttribute("data-status", "pass", { timeout: 15_000 });
  await expect(page.locator("li.ok").first()).toBeVisible();
});

test("issuer-spa completes a local upstream authorization code flow in a real browser", async ({ page }) => {
  await page.goto(`http://${host}:${port}/tests/browser/issuer_spa_upstream_e2e.html`, {
    waitUntil: "networkidle",
  });
  const status = page.locator("#status");
  await expect(status).toHaveAttribute("data-status", "pass", { timeout: 20_000 });
  await expect(page.locator("#session-record")).toContainText("subject-mock-user-123");
  await expect(page.locator("li.ok").last()).toContainText("logout URL");
});
