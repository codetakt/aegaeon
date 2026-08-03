#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const HTML_PATH = path.join(ROOT_DIR, "tests", "verified_core_wasm", "runtime_web_reference.html");
const SERVER_SCRIPT = path.join(
  ROOT_DIR,
  "tests",
  "verified_core_wasm",
  "runtime_web_reference_server.ts",
);
const DEFAULT_HOST = process.env.AEGAEON_BROWSER_SMOKE_HOST ?? "127.0.0.1";
const DEFAULT_PORT = Number(process.env.AEGAEON_BROWSER_SMOKE_PORT ?? "41731");

function parseArgs(argv) {
  const options = {
    required: false,
    artifactDir: process.env.AEGAEON_BROWSER_SMOKE_ARTIFACT_DIR ?? null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--") {
      continue;
    }
    if (token === "--required") {
      options.required = true;
      continue;
    }
    if (token === "--artifact-dir") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("Missing value for option --artifact-dir");
      }
      options.artifactDir = value;
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${token}`);
  }

  return {
    required: options.required,
    artifactDir: options.artifactDir ? path.resolve(process.cwd(), options.artifactDir) : null,
  };
}

const OPTIONS = parseArgs(process.argv.slice(2));
const REQUIRED = OPTIONS.required;
const ARTIFACT_DIR = OPTIONS.artifactDir;

const COMMON_CHROME_ARGS = [
  "--headless=new",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-crash-reporter",
  "--disable-dev-shm-usage",
  "--mute-audio",
  "--remote-debugging-port=0",
];

function findChromeCommand() {
  return process.env.AEGAEON_BROWSER_SMOKE_BIN || "google-chrome-stable";
}

function parseDomStatus(dom) {
  const match = dom.match(/<strong id="status" data-status="([^"]+)">([^<]+)<\/strong>/i);
  const listItems = Array.from(
    dom.matchAll(/<li class="(ok|fail)">([^<]+)<\/li>/g),
  ).map((entry) => ({
    kind: entry[1],
    message: entry[2],
  }));
  return {
    status: match?.[1] ?? null,
    label: match?.[2] ?? null,
    items: listItems,
  };
}

function isUnsupportedEnvironment(error) {
  const combined = `${error?.stderr ?? ""}\n${error?.stdout ?? ""}\n${error?.message ?? ""}`;
  return (
    combined.includes("Operation not permitted") ||
    combined.includes("No usable sandbox") ||
    combined.includes("crashpad") ||
    combined.includes("ENOENT") ||
    combined.includes("not found")
  );
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function targetUrlMatches(candidate, expected) {
  if (!candidate || !expected) {
    return false;
  }
  if (candidate === expected) {
    return true;
  }
  const expectedWithoutSearch = expected.split("?")[0];
  return candidate === expectedWithoutSearch || candidate.startsWith(expectedWithoutSearch);
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`unexpected HTTP ${response.status} from ${url}`);
  }
  return response.json();
}

async function findAvailablePort(host) {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        if (!port) {
          reject(new Error("failed to allocate an ephemeral port"));
          return;
        }
        resolve(port);
      });
    });
  });
}

async function startChrome(targetUrl, { userDataDir, allowFileAccess = false } = {}) {
  return new Promise((resolve, reject) => {
    const chrome = findChromeCommand();
    const args = [
      ...COMMON_CHROME_ARGS,
      `--user-data-dir=${userDataDir}`,
      ...(allowFileAccess ? ["--allow-file-access-from-files"] : []),
      targetUrl,
    ];
    const child = spawn(chrome, args, {
      cwd: ROOT_DIR,
      stdio: ["ignore", "ignore", "pipe"],
    });

    let settled = false;
    let stderr = "";

    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGTERM");
        const error = new Error("timed out waiting for chrome devtools endpoint");
        error.stderr = stderr;
        reject(error);
      }
    }, 15000);

    function finish(browserWsUrl) {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      resolve({ child, browserWsUrl, stderr });
    }

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) {
        finish(match[1]);
      }
    });

    child.on("error", (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      error.stderr = stderr;
      reject(error);
    });

    child.on("exit", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      const error = new Error(`chrome exited early with code ${code}`);
      error.stderr = stderr;
      reject(error);
    });
  });
}

async function waitForPageTarget(browserWsUrl, targetUrl) {
  const browserEndpoint = new URL(browserWsUrl);
  const httpOrigin = `http://${browserEndpoint.host}`;
  const deadline = Date.now() + 15000;

  while (Date.now() < deadline) {
    const targets = await fetchJson(`${httpOrigin}/json/list`);
    const pageTarget = targets.find(
      (target) =>
        target.type === "page" && targetUrlMatches(target.url, targetUrl),
    );
    if (pageTarget?.webSocketDebuggerUrl) {
      return pageTarget.webSocketDebuggerUrl;
    }
    await delay(250);
  }

  throw new Error(`timed out waiting for page target ${targetUrl}`);
}

async function openCdpClient(wsUrl) {
  const WebSocketCtor = globalThis.WebSocket;
  if (typeof WebSocketCtor !== "function") {
    throw new Error("WebSocket is not available in this Node.js runtime");
  }

  return new Promise((resolve, reject) => {
    const socket = new WebSocketCtor(wsUrl);
    const pending = new Map();
    let nextId = 1;
    let settled = false;

    function fail(error) {
      if (settled) {
        return;
      }
      settled = true;
      reject(error);
    }

    socket.addEventListener("open", () => {
      if (settled) {
        return;
      }
      settled = true;
      resolve({
        async send(method, params = {}) {
          const id = nextId;
          nextId += 1;
          return new Promise((resolveMessage, rejectMessage) => {
            pending.set(id, { resolve: resolveMessage, reject: rejectMessage });
            socket.send(JSON.stringify({ id, method, params }));
          });
        },
        async close() {
          socket.close();
        },
      });
    });

    socket.addEventListener("message", (event) => {
      const message = JSON.parse(
        typeof event.data === "string"
          ? event.data
          : Buffer.from(event.data).toString("utf8"),
      );
      if (message.id == null) {
        return;
      }
      const waiter = pending.get(message.id);
      if (!waiter) {
        return;
      }
      pending.delete(message.id);
      if (message.error) {
        waiter.reject(new Error(message.error.message ?? `CDP error for ${message.id}`));
        return;
      }
      waiter.resolve(message.result ?? {});
    });

    socket.addEventListener("error", (event) => {
      const error =
        event?.error instanceof Error
          ? event.error
          : new Error("WebSocket connection failed");
      if (!settled) {
        fail(error);
        return;
      }
      for (const waiter of pending.values()) {
        waiter.reject(error);
      }
      pending.clear();
    });

    socket.addEventListener("close", () => {
      const error = new Error("CDP websocket closed");
      if (!settled) {
        fail(error);
        return;
      }
      for (const waiter of pending.values()) {
        waiter.reject(error);
      }
      pending.clear();
    });
  });
}

async function collectBrowserState(targetWsUrl) {
  const client = await openCdpClient(targetWsUrl);
  try {
    await client.send("Runtime.enable");
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      const smokeState = await client.send("Runtime.evaluate", {
        expression: "globalThis.__AEGAEON_WEB_SMOKE__ ?? null",
        returnByValue: true,
        awaitPromise: true,
      });
      const value = smokeState?.result?.value ?? null;
      if (value?.done === true) {
        const domResult = await client.send("Runtime.evaluate", {
          expression: "document.documentElement.outerHTML",
          returnByValue: true,
          awaitPromise: true,
        });
        const dom = domResult?.result?.value ?? "";
        return {
          state: value,
          dom,
        };
      }
      await delay(250);
    }
    throw new Error("timed out waiting for browser smoke harness to finish");
  } finally {
    await client.close();
  }
}

async function stopChild(child) {
  if (!child) {
    return;
  }
  if (child.exitCode !== null) {
    return;
  }
  await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      resolve();
    };
    const timeout = setTimeout(() => {
      if (child.exitCode === null) {
        child.kill("SIGKILL");
      }
      finish();
    }, 3000);
    child.once("exit", finish);
    child.kill("SIGTERM");
  });
  await delay(100);
}

async function removeDirWithRetries(dirPath) {
  const maxAttempts = 5;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await rm(dirPath, { recursive: true, force: true });
      return;
    } catch (error) {
      if (
        !error ||
        !["ENOTEMPTY", "EBUSY", "EPERM"].includes(error.code) ||
        attempt === maxAttempts
      ) {
        throw error;
      }
      await delay(100 * attempt);
    }
  }
}

async function startSmokeServer(port) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", SERVER_SCRIPT], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        AEGAEON_BROWSER_SMOKE_HOST: DEFAULT_HOST,
        AEGAEON_BROWSER_SMOKE_PORT: String(port),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let settled = false;
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGTERM");
        const error = new Error("timed out waiting for browser smoke server");
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      }
    }, 5000);

    function finishReady() {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      resolve(child);
    }

    function handleChunk(chunk, stream) {
      const text = chunk.toString();
      if (stream === "stdout") {
        stdout += text;
      } else {
        stderr += text;
      }
      if (text.includes("listen EPERM")) {
        if (!settled) {
          settled = true;
          clearTimeout(timeout);
          child.kill("SIGTERM");
          const error = new Error("browser smoke server listen denied");
          error.stdout = stdout;
          error.stderr = stderr;
          reject(error);
        }
        return;
      }
      if (
        text.includes("runtime-web smoke server listening") ||
        text.includes("sdk browser test server listening")
      ) {
        finishReady();
      }
    }

    child.stdout.on("data", (chunk) => handleChunk(chunk, "stdout"));
    child.stderr.on("data", (chunk) => handleChunk(chunk, "stderr"));
    child.on("error", (error) => {
      if (!settled) {
        settled = true;
        clearTimeout(timeout);
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      }
    });
    child.on("exit", (code) => {
      if (!settled && code !== 0) {
        settled = true;
        clearTimeout(timeout);
        const error = new Error(`browser smoke server exited early with code ${code}`);
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      }
    });
  });
}

async function runWithChrome(targetUrl, { userDataDir, allowFileAccess = false } = {}) {
  const chrome = await startChrome(targetUrl, { userDataDir, allowFileAccess });
  try {
    const targetWsUrl = await waitForPageTarget(chrome.browserWsUrl, targetUrl);
    const browserState = await collectBrowserState(targetWsUrl);
    return {
      targetUrl,
      browserWsUrl: chrome.browserWsUrl,
      stdout: browserState.dom,
      mode: allowFileAccess ? "file" : "server",
      smokeState: browserState.state,
      parsed: parseDomStatus(browserState.dom),
    };
  } finally {
    await stopChild(chrome.child);
  }
}

async function runServerMode(userDataDir, port) {
  const server = await startSmokeServer(port);
  try {
    const targetUrl =
      `http://${DEFAULT_HOST}:${port}` +
      "/tests/verified_core_wasm/runtime_web_reference.html";
    return await runWithChrome(targetUrl, { userDataDir });
  } finally {
    await stopChild(server);
  }
}

async function runFileMode(userDataDir) {
  const targetUrl = `${pathToFileURL(HTML_PATH).toString()}?allow_insecure_test_context=1`;
  return runWithChrome(targetUrl, {
    userDataDir,
    allowFileAccess: true,
  });
}

function serializeError(error) {
  return {
    message: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack ?? null : null,
    stdout: error?.stdout ?? "",
    stderr: error?.stderr ?? "",
  };
}

async function writeArtifacts({
  status,
  mode = null,
  parsed = null,
  stdout = "",
  smokeState = null,
  error = null,
  unsupportedEnvironment = false,
  port = DEFAULT_PORT,
}) {
  if (!ARTIFACT_DIR) {
    return;
  }

  await mkdir(ARTIFACT_DIR, { recursive: true });
  const summary = {
    status,
    mode,
    required: REQUIRED,
    unsupportedEnvironment,
    host: DEFAULT_HOST,
    port,
    parsed,
    smokeState,
    error: error ? serializeError(error) : null,
    generatedAt: new Date().toISOString(),
  };
  await writeFile(
    path.join(ARTIFACT_DIR, "summary.json"),
    `${JSON.stringify(summary, null, 2)}\n`,
    "utf8",
  );
  if (stdout) {
    await writeFile(path.join(ARTIFACT_DIR, "dom.html"), stdout, "utf8");
  }
  if (error) {
    await writeFile(
      path.join(ARTIFACT_DIR, "error.txt"),
      `${serializeError(error).message}\n`,
      "utf8",
    );
  }
}

async function main() {
  console.log("=== Browser Runtime-Web Smoke Tests ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-browser-smoke-"));
  const selectedPort = process.env.AEGAEON_BROWSER_SMOKE_PORT
    ? DEFAULT_PORT
    : await findAvailablePort(DEFAULT_HOST);
  let result = null;
  try {
    try {
      result = await runServerMode(path.join(tempRoot, "chrome-server"), selectedPort);
    } catch (error) {
      if (error?.stderr?.includes("listen EPERM")) {
        console.log("[info] server mode unavailable; falling back to file-mode browser smoke");
        result = await runFileMode(path.join(tempRoot, "chrome-file"));
      } else {
        throw error;
      }
    }

    assert.equal(
      result.smokeState?.done,
      true,
      `browser smoke must complete in ${result.mode} mode`,
    );
    assert.equal(
      result.smokeState?.ok,
      true,
      `browser smoke must pass in ${result.mode} mode`,
    );
    assert.equal(
      result.parsed?.status,
      "pass",
      `browser smoke DOM must report pass in ${result.mode} mode`,
    );
    assert.ok(
      result.parsed.items.some((item) => item.kind === "ok"),
      "browser smoke must report passing checks",
    );
    await writeArtifacts({
      status: "pass",
      mode: result.mode,
      parsed: result.parsed,
      stdout: result.stdout,
      smokeState: result.smokeState,
      port: selectedPort,
    });
    console.log(`[ok] browser smoke passed in ${result.mode} mode`);
  } catch (error) {
    if (!REQUIRED && isUnsupportedEnvironment(error)) {
      await writeArtifacts({
        status: "skip",
        mode: result?.mode ?? null,
        parsed: result?.parsed ?? null,
        stdout: result?.stdout ?? "",
        smokeState: result?.smokeState ?? null,
        error,
        unsupportedEnvironment: true,
        port: selectedPort,
      });
      console.log(`[skip] ${error.message}`);
      return;
    }
    await writeArtifacts({
      status: "fail",
      mode: result?.mode ?? null,
      parsed: result?.parsed ?? null,
      stdout: result?.stdout ?? "",
      smokeState: result?.smokeState ?? null,
      error,
      port: selectedPort,
    });
    throw error;
  } finally {
    await removeDirWithRetries(tempRoot);
  }
}

main().catch((error) => {
  console.error("[fail] runtime_web_browser_smoke_test:", error);
  process.exitCode = 1;
});
