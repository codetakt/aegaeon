import { spawn } from "node:child_process";
import path from "node:path";
import { test, expect } from "@playwright/test";

const host = process.env.AEGAEON_BROWSER_SMOKE_HOST ?? "127.0.0.1";
const port = Number(process.env.AEGAEON_BROWSER_SMOKE_PORT ?? "41731");
const serverScript = path.join(process.cwd(), "tests", "browser", "runtime_web_reference_server.ts");
const externalIssuer = process.env.AEGAEON_EXTERNAL_PROVIDER_ISSUER ?? null;
let server;

function waitForServer(child) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("timed out waiting for runtime-web smoke server"));
    }, 5_000);

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

function parseLoginScript() {
  const raw = process.env.AEGAEON_EXTERNAL_PROVIDER_LOGIN_SCRIPT_JSON;
  if (!raw) {
    return null;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`AEGAEON_EXTERNAL_PROVIDER_LOGIN_SCRIPT_JSON is not valid JSON: ${error.message}`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error("AEGAEON_EXTERNAL_PROVIDER_LOGIN_SCRIPT_JSON must be a non-empty JSON array");
  }
  return parsed;
}

async function performScriptedLogin(page, steps) {
  for (const [index, step] of steps.entries()) {
    if (!step || typeof step !== "object" || Array.isArray(step)) {
      throw new Error(`login script step ${index} must be an object`);
    }
    const action = step.action;
    if (typeof action !== "string" || action.length === 0) {
      throw new Error(`login script step ${index} must define a non-empty action`);
    }

    switch (action) {
      case "waitForURL": {
        if (typeof step.pattern !== "string" || step.pattern.length === 0) {
          throw new Error(`login script step ${index} waitForURL requires a pattern`);
        }
        await page.waitForURL(new RegExp(step.pattern, "u"), { timeout: Number(step.timeoutMs ?? 20_000) });
        break;
      }
      case "waitForSelector": {
        if (typeof step.selector !== "string" || step.selector.length === 0) {
          throw new Error(`login script step ${index} waitForSelector requires a selector`);
        }
        await page.locator(step.selector).first().waitFor({ state: "visible", timeout: Number(step.timeoutMs ?? 20_000) });
        break;
      }
      case "fill": {
        if (typeof step.selector !== "string" || step.selector.length === 0) {
          throw new Error(`login script step ${index} fill requires a selector`);
        }
        if (typeof step.value !== "string") {
          throw new Error(`login script step ${index} fill requires a string value`);
        }
        await page.locator(step.selector).fill(step.value);
        break;
      }
      case "click": {
        if (typeof step.selector !== "string" || step.selector.length === 0) {
          throw new Error(`login script step ${index} click requires a selector`);
        }
        await page.locator(step.selector).click();
        break;
      }
      case "clickIfVisible": {
        if (typeof step.selector !== "string" || step.selector.length === 0) {
          throw new Error(`login script step ${index} clickIfVisible requires a selector`);
        }
        const locator = page.locator(step.selector);
        const count = await locator.count();
        if (count > 0 && await locator.first().isVisible({ timeout: Number(step.timeoutMs ?? 3_000) }).catch(() => false)) {
          await locator.first().click();
        }
        break;
      }
      case "press": {
        if (typeof step.key !== "string" || step.key.length === 0) {
          throw new Error(`login script step ${index} press requires a key`);
        }
        if (typeof step.selector === "string" && step.selector.length > 0) {
          await page.locator(step.selector).press(step.key);
        } else {
          await page.keyboard.press(step.key);
        }
        break;
      }
      case "waitForTimeout": {
        const timeoutMs = Number(step.timeoutMs ?? step.ms);
        if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
          throw new Error(`login script step ${index} waitForTimeout requires a non-negative timeout`);
        }
        await page.waitForTimeout(timeoutMs);
        break;
      }
      default:
        throw new Error(`login script step ${index} uses unsupported action ${JSON.stringify(action)}`);
    }
  }
}

async function performExternalProviderLogin(page) {
  const loginScript = parseLoginScript();
  if (loginScript) {
    await performScriptedLogin(page, loginScript);
    return;
  }

  const providerKind = process.env.AEGAEON_EXTERNAL_PROVIDER_KIND ?? "generic";
  if (providerKind === "dex") {
    await page.waitForURL(/\/dex\/auth\/local\/login/u, { timeout: 20_000 });
    await page.locator('input[name="login"]').fill(process.env.AEGAEON_EXTERNAL_PROVIDER_USERNAME ?? "user@example.com");
    await page.locator('input[name="password"]').fill(process.env.AEGAEON_EXTERNAL_PROVIDER_PASSWORD ?? "password");
    await page.locator("#submit-login").click();
    return;
  }
  if (providerKind === "keycloak") {
    await page.waitForURL(/\/realms\/[^/]+\/(protocol\/openid-connect\/auth|login-actions\/authenticate)/u, { timeout: 20_000 }).catch(() => {});
    await page.locator("#username").fill(process.env.AEGAEON_EXTERNAL_PROVIDER_USERNAME ?? "sdk-user");
    await page.locator("#password").fill(process.env.AEGAEON_EXTERNAL_PROVIDER_PASSWORD ?? "password");
    await page.locator("#kc-login").click();
    return;
  }

  const usernameSelector = process.env.AEGAEON_EXTERNAL_PROVIDER_USERNAME_SELECTOR;
  const passwordSelector = process.env.AEGAEON_EXTERNAL_PROVIDER_PASSWORD_SELECTOR;
  const submitSelector = process.env.AEGAEON_EXTERNAL_PROVIDER_SUBMIT_SELECTOR;
  if (!usernameSelector || !passwordSelector || !submitSelector) {
    throw new Error("generic external-provider login requires username/password/submit selectors");
  }
  await page.locator(usernameSelector).fill(process.env.AEGAEON_EXTERNAL_PROVIDER_USERNAME ?? "");
  await page.locator(passwordSelector).fill(process.env.AEGAEON_EXTERNAL_PROVIDER_PASSWORD ?? "");
  await page.locator(submitSelector).click();

  const consentSelector = process.env.AEGAEON_EXTERNAL_PROVIDER_CONSENT_SELECTOR;
  if (consentSelector) {
    const consent = page.locator(consentSelector);
    if (await consent.count()) {
      await consent.click();
    }
  }
}

test.skip(!externalIssuer, "external provider lane is not configured");

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

test("issuer-spa completes a configured external-provider authorization code flow in a real browser", async ({ page }) => {
  await page.goto(`http://${host}:${port}/tests/browser/issuer_spa_external_provider_e2e.html`, {
    waitUntil: "networkidle",
  });
  await performExternalProviderLogin(page);

  const status = page.locator("#status");
  await expect(status).toHaveAttribute("data-status", "pass", { timeout: 60_000 });
  await expect(page.locator("#session-record")).toContainText(externalIssuer);
  await expect(page.locator("li.ok").filter({ hasText: "runtime-web verified" })).toBeVisible();
});
