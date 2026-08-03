#!/usr/bin/env node
import { createServer } from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

type AuthorizationCodeRecord = {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scope: string | null;
  nonce: string | null;
};

type ExternalProviderDiscovery = {
  issuer?: string;
  jwks_uri: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
};

type FetchJsonResult<T> = {
  ok: boolean;
  status: number;
  headers: Headers;
  value: T | null;
  body: string;
};

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(MODULE_DIR, "..", "..");
const host = process.env.AEGAEON_BROWSER_SMOKE_HOST ?? "127.0.0.1";
const port = Number(process.env.AEGAEON_BROWSER_SMOKE_PORT ?? "41731");
const defaultPath = "/tests/browser/runtime_web_reference.html";

const MIME_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".ts", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".wasm", "application/wasm"],
  [".txt", "text/plain; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
]);
const authorizationCodes = new Map<string, AuthorizationCodeRecord>();
const mockJwks = Object.freeze({
  keys: [
    {
      kty: "RSA",
      kid: "mock-rs256-key-1",
      use: "sig",
      alg: "RS256",
      n: "w7ZdfWZpZ2h0LXNpemVkLW1vY2stbW9kdWx1cw",
      e: "AQAB",
    },
  ],
});
const externalProvider = Object.freeze({
  issuer: process.env.AEGAEON_EXTERNAL_PROVIDER_ISSUER ?? null,
  clientId: process.env.AEGAEON_EXTERNAL_PROVIDER_CLIENT_ID ?? null,
  clientSecret: process.env.AEGAEON_EXTERNAL_PROVIDER_CLIENT_SECRET ?? null,
  authMethod: process.env.AEGAEON_EXTERNAL_PROVIDER_AUTH_METHOD ?? null,
  discoveryUrl: process.env.AEGAEON_EXTERNAL_PROVIDER_DISCOVERY_URL ?? null,
  providerName: process.env.AEGAEON_EXTERNAL_PROVIDER_NAME ?? "external-provider",
});
let externalProviderDiscoveryPromise: Promise<ExternalProviderDiscovery> | null = null;

function base64Url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function derivePkceChallenge(verifier) {
  return base64Url(createHash("sha256").update(verifier, "utf8").digest());
}

function readRequestBody(request: import("node:http").IncomingMessage): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", reject);
  });
}

function normalizeExternalProviderAuthMethod() {
  if (externalProvider.authMethod) {
    return externalProvider.authMethod;
  }
  return externalProvider.clientSecret ? "client_secret_basic" : "none";
}

function defaultDiscoveryUrlForIssuer(issuer) {
  return `${issuer.replace(/\/+$/u, "")}/.well-known/openid-configuration`;
}

async function fetchJson<T>(url: string, options: RequestInit = {}): Promise<FetchJsonResult<T>> {
  const response = await fetch(url, options);
  const body = await response.text();
  let value: T | null = null;
  if (body.length > 0) {
    value = JSON.parse(body) as T;
  }
  return {
    ok: response.ok,
    status: response.status,
    headers: response.headers,
    value,
    body,
  };
}

async function getExternalProviderDiscovery(): Promise<ExternalProviderDiscovery> {
  if (!externalProvider.issuer) {
    throw new Error("external provider is not configured");
  }
  if (!externalProviderDiscoveryPromise) {
    const discoveryUrl =
      externalProvider.discoveryUrl ?? defaultDiscoveryUrlForIssuer(externalProvider.issuer);
    externalProviderDiscoveryPromise = fetchJson<ExternalProviderDiscovery>(discoveryUrl).then(
      (result) => {
        if (!result.ok || !result.value || typeof result.value !== "object") {
          throw new Error(`external provider discovery failed with status ${result.status}`);
        }
        return result.value;
      },
    );
  }
  return externalProviderDiscoveryPromise;
}

function resolveRequestPath(urlPath) {
  const pathname = urlPath === "/" ? defaultPath : decodeURIComponent(urlPath);
  const candidate = path.resolve(ROOT_DIR, `.${pathname}`);
  if (!candidate.startsWith(ROOT_DIR)) {
    return null;
  }
  return candidate;
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? `${host}:${port}`}`);
    const mockIssuer = `http://${host}:${port}/mock`;
    const localOrigin = url.origin;

    if (
      request.method === "GET"
      && url.pathname === "/mock/.well-known/openid-configuration"
    ) {
      response.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(JSON.stringify({
        issuer: mockIssuer,
        authorization_endpoint: `${mockIssuer}/authorize`,
        token_endpoint: `${mockIssuer}/token`,
        jwks_uri: `${mockIssuer}/jwks`,
        end_session_endpoint: `${mockIssuer}/logout`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["RS256"],
        subject_types_supported: ["public"],
        scopes_supported: ["openid", "profile", "email"],
      }));
      return;
    }

    if (request.method === "GET" && url.pathname === "/mock/jwks") {
      response.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(JSON.stringify(mockJwks));
      return;
    }

    if (request.method === "GET" && url.pathname === "/mock/authorize") {
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const responseType = url.searchParams.get("response_type");
      const state = url.searchParams.get("state");
      const codeChallenge = url.searchParams.get("code_challenge");
      const codeChallengeMethod = url.searchParams.get("code_challenge_method");
      const scope = url.searchParams.get("scope");
      const nonce = url.searchParams.get("nonce");

      if (
        !clientId
        || !redirectUri
        || responseType !== "code"
        || !state
        || !codeChallenge
        || codeChallengeMethod !== "S256"
      ) {
        response.writeHead(400, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "invalid_request" }));
        return;
      }

      const code = `mock-code-${randomUUID()}`;
      authorizationCodes.set(code, {
        clientId,
        redirectUri,
        state,
        codeChallenge,
        scope,
        nonce,
      });

      const callback = new URL(redirectUri);
      callback.searchParams.set("code", code);
      callback.searchParams.set("state", state);
      response.writeHead(302, {
        location: callback.toString(),
        "cache-control": "no-store",
      });
      response.end();
      return;
    }

    if (request.method === "POST" && url.pathname === "/mock/token") {
      const body = await readRequestBody(request);
      const params = new URLSearchParams(body);
      const grantType = params.get("grant_type");
      const code = params.get("code");
      const redirectUri = params.get("redirect_uri");
      const clientId = params.get("client_id");
      const codeVerifier = params.get("code_verifier");

      if (
        grantType !== "authorization_code"
        || !code
        || !redirectUri
        || !clientId
        || !codeVerifier
      ) {
        response.writeHead(400, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "invalid_request" }));
        return;
      }

      const authorization = authorizationCodes.get(code);
      if (!authorization) {
        response.writeHead(400, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }

      authorizationCodes.delete(code);
      if (
        authorization.redirectUri !== redirectUri ||
        authorization.clientId !== clientId ||
        derivePkceChallenge(codeVerifier) !== authorization.codeChallenge
      ) {
        response.writeHead(400, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }

      response.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(JSON.stringify({
        access_token: `mock-access-token-${code}`,
        refresh_token: `mock-refresh-token-${code}`,
        id_token: `mock-id-token-${code}`,
        token_type: "Bearer",
        scope: authorization.scope ?? "openid",
        expires_in: 300,
        issuer: mockIssuer,
        subject: "subject-mock-user-123",
        nonce: authorization.nonce,
      }));
      return;
    }

    if (request.method === "GET" && url.pathname === "/mock/logout") {
      const callback = new URL(
        url.searchParams.get("post_logout_redirect_uri") ?? `${mockIssuer}/logged-out`,
      );
      const state = url.searchParams.get("state");
      if (state != null) {
        callback.searchParams.set("state", state);
      }
      response.writeHead(302, {
        location: callback.toString(),
        "cache-control": "no-store",
      });
      response.end();
      return;
    }

    if (request.method === "GET" && url.pathname === "/test-config/external-provider") {
      if (!externalProvider.issuer || !externalProvider.clientId) {
        response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "external_provider_not_configured" }));
        return;
      }
      response.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(JSON.stringify({
        issuer: externalProvider.issuer,
        clientId: externalProvider.clientId,
        providerName: externalProvider.providerName,
        discoveryUrl: `${localOrigin}/proxy/external-provider/discovery`,
        jwksUrl: `${localOrigin}/proxy/external-provider/jwks`,
        tokenProxyUrl: `${localOrigin}/proxy/external-provider/token`,
        userinfoProxyUrl: `${localOrigin}/proxy/external-provider/userinfo`,
      }));
      return;
    }

    if (request.method === "GET" && url.pathname === "/proxy/external-provider/discovery") {
      if (!externalProvider.issuer) {
        response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "external_provider_not_configured" }));
        return;
      }
      const result = await fetchJson<ExternalProviderDiscovery>(
        externalProvider.discoveryUrl ?? defaultDiscoveryUrlForIssuer(externalProvider.issuer),
      );
      response.writeHead(result.status, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(result.body);
      return;
    }

    if (request.method === "GET" && url.pathname === "/proxy/external-provider/jwks") {
      if (!externalProvider.issuer) {
        response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "external_provider_not_configured" }));
        return;
      }
      const discovery = await getExternalProviderDiscovery();
      const result = await fetchJson<Record<string, unknown>>(discovery.jwks_uri);
      response.writeHead(result.status, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(result.body);
      return;
    }

    if (request.method === "POST" && url.pathname === "/proxy/external-provider/token") {
      if (!externalProvider.issuer) {
        response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "external_provider_not_configured" }));
        return;
      }
      const discovery = await getExternalProviderDiscovery();
      const authMethod = normalizeExternalProviderAuthMethod();
      const body = await readRequestBody(request);
      const forwardedHeaders: Record<string, string> = {
        "content-type": "application/x-www-form-urlencoded",
      };
      let tokenBody: string = body;
      if (authMethod === "client_secret_basic") {
        if (!externalProvider.clientSecret) {
          throw new Error("external provider client secret is required for client_secret_basic");
        }
        forwardedHeaders.authorization = `Basic ${Buffer.from(
          `${externalProvider.clientId}:${externalProvider.clientSecret}`,
        ).toString("base64")}`;
      } else if (authMethod === "client_secret_post") {
        if (!externalProvider.clientSecret) {
          throw new Error("external provider client secret is required for client_secret_post");
        }
        const params = new URLSearchParams(body);
        params.set("client_secret", externalProvider.clientSecret);
        tokenBody = params.toString();
      }
      const tokenResponse = await fetch(discovery.token_endpoint, {
        method: "POST",
        headers: forwardedHeaders,
        body: tokenBody,
      });
      const tokenBodyText = await tokenResponse.text();
      response.writeHead(tokenResponse.status, {
        "content-type":
          tokenResponse.headers.get("content-type") ?? "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(tokenBodyText);
      return;
    }

    if (request.method === "GET" && url.pathname === "/proxy/external-provider/userinfo") {
      if (!externalProvider.issuer) {
        response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "external_provider_not_configured" }));
        return;
      }
      const discovery = await getExternalProviderDiscovery();
      if (!discovery.userinfo_endpoint) {
        response.writeHead(404, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "userinfo_endpoint_not_advertised" }));
        return;
      }
      const authz = request.headers.authorization;
      if (!authz) {
        response.writeHead(401, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "missing_authorization" }));
        return;
      }
      const userinfoResponse = await fetch(discovery.userinfo_endpoint, {
        method: "GET",
        headers: {
          authorization: authz,
        },
      });
      const userinfoBody = await userinfoResponse.text();
      response.writeHead(userinfoResponse.status, {
        "content-type":
          userinfoResponse.headers.get("content-type") ?? "application/json; charset=utf-8",
        "cache-control": "no-store",
      });
      response.end(userinfoBody);
      return;
    }

    const filePath = resolveRequestPath(url.pathname);
    if (!filePath) {
      response.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
      response.end("forbidden\n");
      return;
    }

    const body = await readFile(filePath);
    const extension = path.extname(filePath);
    response.writeHead(200, {
      "content-type": MIME_TYPES.get(extension) ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    response.end(body);
  } catch (error) {
    const status = error && error.code === "ENOENT" ? 404 : 500;
    response.writeHead(status, { "content-type": "text/plain; charset=utf-8" });
    response.end(`${status === 404 ? "not found" : "internal error"}\n`);
  }
});

server.listen(port, host, () => {
  console.log(`sdk browser test server listening at http://localhost:${port}${defaultPath}`);
});
