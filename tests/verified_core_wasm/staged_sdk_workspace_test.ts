#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const execFile = promisify(execFileCallback);
const ROOT_DIR = path.resolve(new URL("../../", import.meta.url).pathname);
const stageScript = path.join(ROOT_DIR, "scripts", "sdk", "stage_reference_sdk_workspace.ts");

async function main() {
  console.log("=== Staged SDK Workspace Tests ===");
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "aegaeon-sdk-staging-"));
  const workspaceDir = path.join(tempRoot, "workspace");

  await execFile(process.execPath, [stageScript, "--out-dir", workspaceDir], {
    cwd: ROOT_DIR,
  });

  const rootPackage = JSON.parse(await readFile(path.join(workspaceDir, "package.json"), "utf8"));
  assert.equal(rootPackage.private, true);
  assert.deepEqual(rootPackage.workspaces, ["packages/*"]);

  const runnerPath = path.join(workspaceDir, "workspace_smoke.ts");
  await writeFile(
    runnerPath,
    `
      import assert from "node:assert/strict";
      import { readFile } from "node:fs/promises";
      import { fileURLToPath } from "node:url";
      import { loadBundledArtifact as loadNodeArtifact } from "@aegaeon/verified-core/node";
      import {
        loadBundledArtifact as loadWebArtifact,
        resolveBundledArtifactUrls,
      } from "@aegaeon/verified-core/web";
      import {
        createInMemoryManagementSessionStore,
        createManagementClient,
      } from "@aegaeon/management-client";
      import { initCore as initNodeCore, VC_STATUS as NODE_STATUS } from "@aegaeon/runtime-node";
      import {
        DEFAULT_CLIENT_CRYPTO_PROFILE,
        initIssuerSpaRuntime,
        createInMemoryTransactionStore,
        finishLogin,
        startLogin,
      } from "@aegaeon/issuer-spa";
      import { initCore as initWebCore, VC_STATUS as WEB_STATUS } from "@aegaeon/runtime-web";
      import {
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

      const webUrls = resolveBundledArtifactUrls();
      assert.ok(webUrls.manifestUrl.startsWith("file:"));
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

      const rpTransaction = await buildPkceAuthorizationTransaction({
        runtimeHandle: nodeCore,
        authorizationEndpoint: "https://issuer.example/authorize",
        clientId: "client-123",
        redirectUri: "https://rp.example/callback",
        verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        scope: "openid profile",
        state: "state-123",
        nonce: "nonce-123",
      });
      assert.equal(rpTransaction.authorizationParameters.get("response_type"), "code");
      const tokenExchange = buildTokenRequestFromAuthorizationResponse({
        input: "https://rp.example/callback?code=code-123&state=state-123",
        transaction: rpTransaction.transaction,
      });
      assert.equal(tokenExchange.tokenRequestBody.get("grant_type"), "authorization_code");

      const webIssuerCore = await initIssuerSpaRuntime({
        secureContext: true,
        fetchImpl: fileFetch,
      });
      assert.equal(DEFAULT_CLIENT_CRYPTO_PROFILE, "aegaeon-rs256");
      const issuerStore = createInMemoryTransactionStore();
      const issuerLogin = await startLogin({
        runtimeHandle: webIssuerCore,
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

      let managementCallIndex = 0;
      const managementClient = createManagementClient({
        baseUrl: "https://admin.example.com",
        sessionStore: createInMemoryManagementSessionStore({
          origin: "https://admin.example.com",
          teamId: "team-123",
        }),
        fetchImpl: async (input, init = {}) => {
          managementCallIndex += 1;
          const headers = new Headers(init.headers ?? {});
          if (managementCallIndex === 1) {
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
          if (managementCallIndex === 2) {
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
      assert.equal(teams.teams[0].id, "team-123");

      console.log("workspace smoke ok");
    `.replace(/^ {6}/gm, ""),
    "utf8",
  );

  const { stdout, stderr } = await execFile(process.execPath, [runnerPath], {
    cwd: workspaceDir,
  });
  if (stderr.trim().length > 0) {
    process.stderr.write(stderr);
  }
  process.stdout.write(stdout);
  console.log("=== staged workspace checks passed ===");
}

main().catch((error) => {
  console.error("[fail] staged_sdk_workspace_test:", error);
  process.exitCode = 1;
});
