#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback, spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { createServer } from "node:net";
import path from "node:path";
import { promisify } from "node:util";

import {
  initCore,
  VC_JWT_FLAGS,
  VC_STATUS,
} from "../../packages/runtime-node/dist/index.js";
import {
  buildEndSessionUrlFromIssuerMetadata,
  createInMemoryAuthorizationTransactionStore,
  createInMemoryFederatedSessionStore,
  fetchIssuerMetadata,
  finishFederatedLogin,
  restoreFederatedSession,
  startFederatedLoginFromIssuerMetadata,
} from "../../packages/rp-core/dist/index.js";

const execFile = promisify(execFileCallback);
const WORKSPACE_ROOT = path.resolve(new URL("../../", import.meta.url).pathname);
const DEFAULT_CORE_REPO = path.resolve(WORKSPACE_ROOT, "..", "..", "aegaeon");
const DEFAULT_CLIENT_ID = "test-client";
const DEFAULT_CLIENT_SECRET = "test-secret";
const DEFAULT_REDIRECT_URI = "https://example.com/callback";
const DEFAULT_SCOPE = "openid profile email";
const DEFAULT_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

function parseArgs(argv) {
  return {
    required: argv.includes("--required"),
  };
}

const OPTIONS = parseArgs(process.argv.slice(2));

function pass(message) {
  console.log(`[ok] ${message}`);
}

function note(message) {
  console.log(`[note] ${message}`);
}

function skip(message) {
  console.log(`[skip] ${message}`);
  process.exitCode = 0;
}

function base64UrlDecode(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, "base64");
}

function decodeJwtPart(jwt, index) {
  const parts = String(jwt).split(".");
  assert.equal(parts.length, 3, "JWT must have three parts");
  return JSON.parse(base64UrlDecode(parts[index]).toString("utf8"));
}

function basicAuth(clientId, clientSecret) {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64")}`;
}

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function commandExists(command) {
  try {
    await execFile("sh", ["-lc", `command -v ${command}`]);
    return true;
  } catch {
    return false;
  }
}

async function pickFreePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("failed to obtain a free port"));
        return;
      }
      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });
}

async function ensureServerBinary(coreRepo, { required }) {
  const explicit = process.env.AEGAEON_SERVER_BIN;
  if (explicit) {
    if (!(await fileExists(explicit))) {
      throw new Error(`AEGAEON_SERVER_BIN does not exist: ${explicit}`);
    }
    return explicit;
  }

  const resultBinary = path.join(coreRepo, "result", "bin", "aegaeon-server");
  if (await fileExists(resultBinary)) {
    return resultBinary;
  }

  if (!(await commandExists("nix"))) {
    if (required) {
      throw new Error("nix is required to build the sibling Aegaeon server");
    }
    return null;
  }

  note("building sibling Aegaeon server with `nix build .#server`");
  await execFile("nix", ["build", ".#server"], {
    cwd: coreRepo,
    env: {
      ...process.env,
      CARGO_INCREMENTAL: "0",
    },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (!(await fileExists(resultBinary))) {
    throw new Error(`nix build completed but server binary was not found at ${resultBinary}`);
  }
  return resultBinary;
}

async function waitForHealth(baseUrl, child, timeoutMs = 20_000) {
  const startedAt = Date.now();
  let stdout = "";
  let stderr = "";

  child.stdout?.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr?.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  while (Date.now() - startedAt < timeoutMs) {
    const exitCode = child.exitCode;
    if (exitCode != null) {
      throw new Error(
        [
          `server exited early with code ${exitCode}`,
          `stdout:\n${stdout}`,
          `stderr:\n${stderr}`,
        ].join("\n"),
      );
    }
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        return;
      }
    } catch {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  throw new Error(
    [
      `server did not become healthy within ${timeoutMs}ms`,
      `stdout:\n${stdout}`,
      `stderr:\n${stderr}`,
    ].join("\n"),
  );
}

async function fetchJson(url, init = {}) {
  const response = await fetch(url, init);
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for ${url}: ${body}`);
  }
  return JSON.parse(body);
}

async function requestAuthorizationCode(url, headers = {}) {
  const response = await fetch(url, {
    method: "GET",
    headers: {
      accept: "application/json",
      ...headers,
    },
    redirect: "manual",
  });

  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location) {
      throw new Error("authorization redirect missing Location header");
    }
    const callback = new URL(location);
    return {
      code: callback.searchParams.get("code"),
      state: callback.searchParams.get("state"),
      iss: callback.searchParams.get("iss"),
    };
  }

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`authorization request failed with ${response.status}: ${body}`);
  }
  return JSON.parse(body);
}

async function main() {
  console.log("=== Local Aegaeon Provider E2E ===");

  const coreRepo = path.resolve(process.env.AEGAEON_CORE_REPO ?? DEFAULT_CORE_REPO);
  if (!(await fileExists(coreRepo))) {
    if (OPTIONS.required) {
      throw new Error(`core repo not found: ${coreRepo}`);
    }
    skip(`core repo not found: ${coreRepo}`);
    return;
  }

  const serverBinary = await ensureServerBinary(coreRepo, OPTIONS);
  if (!serverBinary) {
    skip("server binary unavailable and nix build not possible");
    return;
  }
  note(`using core repo: ${coreRepo}`);
  note(`using server binary: ${serverBinary}`);

  const port = await pickFreePort();
  const localBase = `http://127.0.0.1:${port}`;
  const issuer = process.env.AEGAEON_PUBLIC_ISSUER ?? "https://sdk-local-provider.example";
  const forwardedHeader = "for=127.0.0.1;proto=https";
  const signingKeyPath = path.join(
    coreRepo,
    "crates",
    "server",
    "tests",
    "fixtures",
    "rsa2048-private.pk8.pem",
  );
  const child = spawn(serverBinary, ["--host", "127.0.0.1", "--port", String(port)], {
    cwd: coreRepo,
    env: {
      ...process.env,
      RUST_LOG: "off",
      AEGAEON_OIDC_ENABLED: "1",
      AEGAEON_OIDC_ISSUER: issuer,
      AEGAEON_OIDC_REQUIRE_NONCE: "1",
      AEGAEON_OIDC_ENABLE_USERINFO: "1",
      AEGAEON_OIDC_SIGNING_KEY_PEM_FILE: signingKeyPath,
      AEGAEON_OIDC_SIGNING_KID: "sdk-oidc-e2e-key",
      AEGAEON_POLICY_SENDER_CONSTRAINT: "none",
      AEGAEON_REQUIRE_DPOP_NONCE: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    note(`waiting for health on ${localBase}`);
    await waitForHealth(localBase, child);
    pass("sibling Aegaeon server started in OIDC mode");

    // @ts-ignore fixture intentionally exercises the public package surface
    // without mirroring all SDK internals
    const issuerMetadata = await fetchIssuerMetadata({
      issuer,
      discoveryUrl: `${localBase}/.well-known/openid-configuration`,
      expectedIssuer: issuer,
    });
    assert.equal(issuerMetadata.issuer, issuer);
    assert.equal(issuerMetadata.authorizationEndpoint, `${issuer}/authorize`);
    assert.equal(issuerMetadata.tokenEndpoint, `${issuer}/token`);
    pass("rp-core fetched and normalized discovery metadata from the real provider");

    const localIssuerMetadata = Object.freeze({
      ...issuerMetadata,
      authorizationEndpoint: `${localBase}/authorize`,
      tokenEndpoint: `${localBase}/token`,
      jwksUri: `${localBase}/jwks`,
      endSessionEndpoint: `${localBase}/logout`,
    });

    const { handle } = await initCore();
    const transactionStore = createInMemoryAuthorizationTransactionStore();
    const sessionStore = createInMemoryFederatedSessionStore();

    const login = await startFederatedLoginFromIssuerMetadata({
      runtimeHandle: handle,
      transactionStore,
      issuerMetadata: localIssuerMetadata,
      clientId: DEFAULT_CLIENT_ID,
      redirectUri: DEFAULT_REDIRECT_URI,
      verifier: DEFAULT_VERIFIER,
      scope: DEFAULT_SCOPE,
      state: "sdk-local-provider-state",
      nonce: "sdk-local-provider-nonce",
    });
    assert.match(login.redirectUrl, /^http:\/\/127\.0\.0\.1:\d+\/authorize\?/);
    pass("rp-core built a discovery-driven Authorization Code + PKCE request");

    const authorization = await requestAuthorizationCode(login.redirectUrl, {
      Forwarded: forwardedHeader,
    });
    assert.equal(authorization.state, "sdk-local-provider-state");
    assert.ok(typeof authorization.code === "string" && authorization.code.length > 0);
    pass("the real provider issued an authorization code");

    // @ts-ignore fixture intentionally supplies a narrow exchange callback surface
    const completion = await finishFederatedLogin({
      input: [
        `${DEFAULT_REDIRECT_URI}?code=${encodeURIComponent(authorization.code)}`,
        `state=${encodeURIComponent(authorization.state)}`,
      ].join("&"),
      transactionStore,
      sessionStore,
      issuer,
      exchangeAuthorizationCode: async ({ tokenRequestBody }) =>
        fetchJson(`${localBase}/token`, {
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            authorization: basicAuth(DEFAULT_CLIENT_ID, DEFAULT_CLIENT_SECRET),
            Forwarded: forwardedHeader,
          },
          body: tokenRequestBody.toString(),
        }),
    });
    assert.ok(completion.tokenResponse.accessToken);
    assert.ok(completion.tokenResponse.idToken);
    pass("rp-core completed the callback and token exchange against the real provider");

    const tokenHeader = decodeJwtPart(completion.tokenResponse.idToken, 0);
    const tokenPayload = decodeJwtPart(completion.tokenResponse.idToken, 1);
    assert.equal(tokenHeader.alg, "RS256");
    assert.equal(tokenPayload.iss, issuer);
    assert.equal(tokenPayload.aud, DEFAULT_CLIENT_ID);
    pass("the provider returned an RS256 ID Token with the expected issuer and audience");

    const jwks = await fetchJson(`${localBase}/jwks`);
    const jwk = jwks.keys.find((entry) => entry.kid === tokenHeader.kid);
    assert.ok(jwk, "matching JWK must exist");
    const verified = await handle.jwtVerify({
      jwt: completion.tokenResponse.idToken,
      publicKey: jwk,
      expectedIssuer: issuer,
      expectedAudience: DEFAULT_CLIENT_ID,
      nowUnixTimeSeconds: Math.floor(Date.now() / 1000),
      cryptoProfile: "aegaeon-rs256",
      flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
    });
    assert.equal(verified.statusCode, VC_STATUS.OK);
    pass("runtime-node verified the real provider ID Token through the aegaeon-rs256 client slice");

    // @ts-ignore fixture intentionally reads the public session object
    // without projecting a narrower helper type
    const session = await restoreFederatedSession({
      sessionStore,
      required: true,
    });
    assert.equal(session.issuer, issuer);
    assert.equal(session.idToken, completion.tokenResponse.idToken);
    pass("rp-core persisted the resulting federated session");

    const userinfoResponse = await fetch(`${localBase}/userinfo`, {
      headers: {
        authorization: `Bearer ${completion.tokenResponse.accessToken}`,
        Forwarded: forwardedHeader,
      },
    });
    if (userinfoResponse.ok) {
      const userinfo = await userinfoResponse.json();
      assert.equal(userinfo.sub, tokenPayload.sub);
      pass("the real provider userinfo response matches the ID Token subject");
    } else {
      note(`userinfo check skipped: HTTP ${userinfoResponse.status}`);
    }

    // @ts-ignore fixture intentionally exercises the public logout helper
    // against the discovery-derived metadata snapshot
    const logoutUrl = buildEndSessionUrlFromIssuerMetadata({
      issuerMetadata: localIssuerMetadata,
      idTokenHint: completion.tokenResponse.idToken,
      postLogoutRedirectUri: "https://example.com/post-logout",
      state: "sdk-local-provider-logout",
    });
    assert.match(logoutUrl, /^http:\/\/127\.0\.0\.1:\d+\/logout\?/);
    pass("rp-core derived an RP-initiated logout URL from the real provider metadata");

    console.log("=== local provider checks passed ===");
  } finally {
    if (child.exitCode == null) {
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => child.once("exit", resolve)),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("server did not exit after SIGTERM")), 5_000),
        ),
      ]);
    }
  }
}

try {
  await main();
} catch (error) {
  console.error("[fail] aegaeon_provider_local_e2e_test:", error);
  process.exitCode = 1;
}
