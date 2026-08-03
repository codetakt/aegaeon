#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const stageScript = path.join(ROOT_DIR, "scripts", "sdk", "stage_reference_sdk_workspace.ts");

async function runNode(args, options = {}) {
  return execFile(process.execPath, args, {
    cwd: ROOT_DIR,
    ...options,
  });
}

async function runNpm(args, options = {}) {
  const escapedArgs = args.map((arg) => JSON.stringify(arg)).join(" ");
  return execFile("bash", ["-lc", `npm ${escapedArgs}`], options);
}

async function packPackage(packageDir, cacheDir) {
  await runNpm(["pack", "--silent"], {
    cwd: packageDir,
    env: {
      ...process.env,
      npm_config_cache: cacheDir,
    },
  });
  const tarballs = (await readdir(packageDir))
    .filter((entry) => entry.endsWith(".tgz"))
    .sort();
  assert.equal(tarballs.length, 1);
  const tarballPath = path.join(packageDir, tarballs[0]);
  const { stdout } = await execFile("tar", ["-tf", tarballPath], {
    cwd: packageDir,
  });
  const files = stdout
    .split("\n")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => entry.replace(/^package\//, ""));
  assert.ok(files.includes("README.md"));
  assert.ok(files.includes("LICENSE"));
  return {
    filename: tarballs[0],
    tarballPath,
    files,
  };
}

async function main() {
  console.log("=== Publishable SDK Package Tests ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-publishable-"));
  const workspaceDir = path.join(tempRoot, "workspace");
  const cacheDir = path.join(tempRoot, ".npm-cache");
  const installDir = path.join(tempRoot, "consumer");

  await runNode([stageScript, "--out-dir", workspaceDir]);

  const packageDirs = {
    verifiedCore: path.join(workspaceDir, "packages", "verified-core"),
    runtimeNode: path.join(workspaceDir, "packages", "runtime-node"),
    runtimeWeb: path.join(workspaceDir, "packages", "runtime-web"),
    managementClient: path.join(workspaceDir, "packages", "management-client"),
    issuerSpa: path.join(workspaceDir, "packages", "issuer-spa"),
    rpCore: path.join(workspaceDir, "packages", "rp-core"),
  };

  const verifiedCorePkg = JSON.parse(
    await readFile(path.join(packageDirs.verifiedCore, "package.json"), "utf8"),
  );
  const runtimeNodePkg = JSON.parse(
    await readFile(path.join(packageDirs.runtimeNode, "package.json"), "utf8"),
  );
  const runtimeWebPkg = JSON.parse(
    await readFile(path.join(packageDirs.runtimeWeb, "package.json"), "utf8"),
  );
  const managementClientPkg = JSON.parse(
    await readFile(
      path.join(packageDirs.managementClient, "package.json"),
      "utf8",
    ),
  );
  const issuerSpaPkg = JSON.parse(
    await readFile(path.join(packageDirs.issuerSpa, "package.json"), "utf8"),
  );
  const rpCorePkg = JSON.parse(
    await readFile(path.join(packageDirs.rpCore, "package.json"), "utf8"),
  );

  assert.equal(verifiedCorePkg.private, false);
  assert.equal(runtimeNodePkg.private, false);
  assert.equal(runtimeWebPkg.private, false);
  assert.equal(managementClientPkg.private, false);
  assert.equal(issuerSpaPkg.private, false);
  assert.equal(rpCorePkg.private, false);
  assert.equal(verifiedCorePkg.license, "Apache-2.0");
  assert.equal(runtimeNodePkg.publishConfig.access, "public");
  assert.equal(runtimeWebPkg.publishConfig.access, "public");
  assert.equal(managementClientPkg.publishConfig.access, "public");
  assert.equal(issuerSpaPkg.publishConfig.access, "public");
  assert.equal(rpCorePkg.publishConfig.access, "public");

  const packed = {
    verifiedCore: await packPackage(packageDirs.verifiedCore, cacheDir),
    runtimeNode: await packPackage(packageDirs.runtimeNode, cacheDir),
    runtimeWeb: await packPackage(packageDirs.runtimeWeb, cacheDir),
    managementClient: await packPackage(packageDirs.managementClient, cacheDir),
    issuerSpa: await packPackage(packageDirs.issuerSpa, cacheDir),
    rpCore: await packPackage(packageDirs.rpCore, cacheDir),
  };

  assert.ok(packed.verifiedCore.files.includes("dist/verified_core.wasm"));
  assert.ok(packed.runtimeNode.files.includes("dist/reference.js"));
  assert.ok(packed.runtimeWeb.files.includes("dist/reference.js"));
  assert.ok(packed.runtimeWeb.files.includes("dist/browser-smoke.js"));
  assert.ok(packed.managementClient.files.includes("dist/index.js"));
  assert.ok(packed.managementClient.files.includes("index.d.ts"));
  assert.ok(packed.issuerSpa.files.includes("dist/index.js"));
  assert.ok(packed.rpCore.files.includes("dist/index.js"));

  await mkdir(installDir, { recursive: true });
  await writeFile(
    path.join(installDir, "package.json"),
    `${JSON.stringify(
      {
        name: "aegaeon-sdk-package-consumer",
        private: true,
        type: "module",
      },
      null,
      2,
    )}\n`,
    "utf8",
  );

  await runNpm(
    [
      "install",
      "--offline",
      "--no-audit",
      "--no-fund",
      "--no-package-lock",
      packed.verifiedCore.tarballPath,
    ],
    {
      cwd: installDir,
      env: {
        ...process.env,
        npm_config_cache: cacheDir,
      },
    },
  );

  await runNpm(
    [
      "install",
      "--offline",
      "--no-audit",
      "--no-fund",
      "--no-package-lock",
      packed.runtimeNode.tarballPath,
      packed.runtimeWeb.tarballPath,
      packed.managementClient.tarballPath,
      packed.issuerSpa.tarballPath,
      packed.rpCore.tarballPath,
    ],
    {
      cwd: installDir,
      env: {
        ...process.env,
        npm_config_cache: cacheDir,
      },
    },
  );

  const runnerPath = path.join(installDir, "consumer_smoke.ts");
  await writeFile(
    runnerPath,
    `
      import assert from "node:assert/strict";
      import { readFile } from "node:fs/promises";
      import { fileURLToPath } from "node:url";
      import { loadBundledArtifact as loadNodeArtifact } from "@aegaeon/verified-core/node";
      import { loadBundledArtifact as loadWebArtifact } from "@aegaeon/verified-core/web";
      import {
        createInMemoryManagementSessionStore,
        createManagementClient,
      } from "@aegaeon/management-client";
      import { initCore as initNodeCore, VC_STATUS as NODE_STATUS } from "@aegaeon/runtime-node";
      import {
        DEFAULT_CLIENT_CRYPTO_PROFILE,
        createInMemoryTransactionStore,
        finishLogin,
        initIssuerSpaRuntime,
        startLogin,
      } from "@aegaeon/issuer-spa";
      import { initCore as initWebCore, VC_STATUS as WEB_STATUS } from "@aegaeon/runtime-web";
      import {
        buildAuthorizationUrl,
        buildPkceAuthorizationTransaction,
        buildTokenRequestFromAuthorizationResponse,
      } from "@aegaeon/rp-core";

      async function fileFetch(url) {
        const bytes = await readFile(fileURLToPath(url));
        return new Response(bytes, { status: 200 });
      }

      const nodeArtifact = await loadNodeArtifact();
      assert.equal(typeof nodeArtifact.manifest.sha256, "string");
      assert.ok(nodeArtifact.wasmBytes.length > 0);

      const webArtifact = await loadWebArtifact({ fetchImpl: fileFetch });
      assert.equal(webArtifact.manifest.sha256, nodeArtifact.manifest.sha256);

      const nodeCore = await initNodeCore();
      const generated = nodeCore.handle.pkceGenerate({
        verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      });
      assert.equal(generated.statusCode, NODE_STATUS.OK);
      assert.equal(generated.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

      const webCore = await initWebCore({ secureContext: true, fetchImpl: fileFetch });
      const verified = await webCore.handle.pkceVerify({
        verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      });
      assert.equal(verified.statusCode, WEB_STATUS.OK);

      const authUrl = buildAuthorizationUrl({
        authorizationEndpoint: "https://issuer.example/authorize",
        clientId: "client-123",
        redirectUri: "https://rp.example/callback",
        scope: "openid profile",
        state: "state-123",
        nonce: "nonce-123",
        codeChallenge: generated.challenge,
      });
      assert.ok(authUrl.includes("response_type=code"));

      const rpTransaction = await buildPkceAuthorizationTransaction({
        runtimeHandle: nodeCore,
        authorizationEndpoint: "https://issuer.example/authorize",
        clientId: "client-123",
        redirectUri: "https://rp.example/callback",
        verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        scope: "openid email",
        state: "state-123",
        nonce: "nonce-123",
      });
      assert.equal(rpTransaction.authorizationParameters.get("code_challenge_method"), "S256");

      const tokenExchange = buildTokenRequestFromAuthorizationResponse({
        input: "https://rp.example/callback?code=code-123&state=state-123",
        transaction: rpTransaction.transaction,
      });
      assert.equal(tokenExchange.tokenRequestBody.get("grant_type"), "authorization_code");

      const issuerCore = await initIssuerSpaRuntime({ secureContext: true, fetchImpl: fileFetch });
      assert.equal(DEFAULT_CLIENT_CRYPTO_PROFILE, "aegaeon-rs256");
      const issuerStore = createInMemoryTransactionStore();
      const issuerLogin = await startLogin({
        runtimeHandle: issuerCore,
        transactionStore: issuerStore,
        authorizationEndpoint: "https://issuer.example/authorize",
        clientId: "client-123",
        redirectUri: "https://issuer.example/callback",
        verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        scope: "openid profile",
        state: "issuer-state-123",
        nonce: "issuer-nonce-123",
      });
      assert.equal(issuerLogin.transaction.state, "issuer-state-123");
      const issuerTokenExchange = await finishLogin({
        input: "https://issuer.example/callback?code=issuer-code-123&state=issuer-state-123",
        transactionStore: issuerStore,
      });
      assert.equal(issuerTokenExchange.tokenRequestBody.get("code"), "issuer-code-123");

      let callIndex = 0;
      const managementClient = createManagementClient({
        baseUrl: "https://admin.example.com",
        sessionStore: createInMemoryManagementSessionStore({
          origin: "https://admin.example.com",
          teamId: "team-123",
        }),
        fetchImpl: async (input, init = {}) => {
          callIndex += 1;
          const headers = new Headers(init.headers ?? {});
          if (callIndex === 1) {
            const responseHeaders = new Headers({ "content-type": "text/plain" });
            responseHeaders.getSetCookie = () => ["csrf_token=csrf-123; Path=/; SameSite=Lax"];
            return {
              ok: true,
              status: 200,
              headers: responseHeaders,
              async text() { return "ok"; },
              async json() { throw new Error("unexpected json read"); },
            };
          }
          if (callIndex === 2) {
            assert.equal(headers.get("origin"), "https://admin.example.com");
            assert.equal(headers.get("x-csrf-token"), "csrf-123");
            const responseHeaders = new Headers();
            responseHeaders.getSetCookie = () => [
              "aegaeon_admin_session=sid-123; Path=/api/v1; HttpOnly; SameSite=Lax; Max-Age=28800",
            ];
            return {
              ok: true,
              status: 204,
              headers: responseHeaders,
              async text() { return ""; },
              async json() { return null; },
            };
          }
          assert.match(String(input), /\\/api\\/v1\\/teams\\?pageSize=10$/);
          assert.match(headers.get("cookie"), /aegaeon_admin_session=sid-123/);
          return new Response(JSON.stringify({
            teams: [
              {
                id: "team-123",
                name: "Platform",
                slug: "platform",
                createdAt: "2026-03-11T00:00:00Z",
                updatedAt: "2026-03-11T00:00:00Z",
              },
            ],
            pageInfo: null,
          }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        },
      });
      await managementClient.createAuthenticationSession({
        email: "ops@example.com",
        password: "correct horse battery staple",
      });
      const teams = await managementClient.listTeams({ pageSize: 10 });
      assert.equal(teams.teams[0].name, "Platform");

      console.log("publishable package smoke ok");
    `.replace(/^ {6}/gm, ""),
    "utf8",
  );

  const { stdout, stderr } = await runNode([runnerPath], { cwd: installDir });
  if (stderr.trim().length > 0) {
    process.stderr.write(stderr);
  }
  process.stdout.write(stdout);
  console.log("=== publishable package checks passed ===");
}

main().catch((error) => {
  console.error("[fail] publishable_sdk_package_test:", error);
  process.exitCode = 1;
});
