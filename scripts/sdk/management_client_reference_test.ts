#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";

type ManagementClientModule = typeof import("../index.js");
type MockResponse = {
  ok: boolean;
  status: number;
  headers: Headers & { getSetCookie(): string[] };
  json(): Promise<unknown>;
  text(): Promise<string>;
};
type MockResponseOptions = {
  status?: number;
  jsonBody?: unknown;
  textBody?: string | null;
  setCookies?: string[];
  headers?: Record<string, string>;
};
type FetchCall = {
  url: string;
  method: string;
  headers: Headers;
  body: BodyInit | null;
  credentials: RequestCredentials | null;
};
type FetchHandler = (call: FetchCall) => MockResponse | Promise<MockResponse>;

function parseJsonBody(call: FetchCall): unknown {
  if (call.body == null) {
    return undefined;
  }
  return JSON.parse(String(call.body));
}

const MANAGEMENT_CLIENT_MODULE_PATH = fs.existsSync(
  new URL("./management_client_reference.ts", import.meta.url),
)
  ? "./management_client_reference.ts"
  : "../dist/index.js";

const {
  MANAGEMENT_CLIENT_DEFAULTS,
  MANAGEMENT_OPENAPI_METADATA,
  ManagementApiError,
  createInMemoryCookieJar,
  createInMemoryManagementSessionStore,
  createManagementClient,
  readCookieValue,
} = (await import(MANAGEMENT_CLIENT_MODULE_PATH)) as ManagementClientModule;

let passed = 0;

function pass(message: string): void {
  passed += 1;
  console.log(`  [ok] ${message}`);
}

function mockResponse({
  status = 200,
  jsonBody = undefined,
  textBody = null,
  setCookies = [],
  headers: extraHeaders = {},
}: MockResponseOptions = {}): MockResponse {
  const headers = new Headers() as Headers & { getSetCookie(): string[] };
  if (jsonBody !== undefined) {
    headers.set("content-type", "application/json");
  } else {
    headers.set("content-type", "text/plain");
  }
  for (const [name, value] of Object.entries(extraHeaders)) {
    headers.set(name, value);
  }
  headers.getSetCookie = () => [...setCookies];
  if (setCookies.length > 0) {
    headers.set("set-cookie", setCookies.join(", "));
  }
  return {
    ok: status >= 200 && status < 300,
    status,
    headers,
    async json() {
      return jsonBody;
    },
    async text() {
      return textBody ?? (jsonBody === undefined ? "" : JSON.stringify(jsonBody));
    },
  };
}

function createFetchQueue(
  handlers: FetchHandler[],
): { fetchImpl: typeof fetch; calls: FetchCall[] } {
  const queue = [...handlers];
  const calls: FetchCall[] = [];
  const fetchImpl: typeof fetch = async (input, init = {}) => {
    if (queue.length === 0) {
      throw new Error("fetch queue exhausted");
    }
    const url = typeof input === "string" ? input : input.toString();
    const method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers ?? {});
    const call = {
      url,
      method,
      headers,
      body: init.body ?? null,
      credentials: init.credentials ?? null,
    };
    calls.push(call);
    const nextHandler = queue.shift();
    if (!nextHandler) {
      throw new Error("fetch queue exhausted");
    }
    return (await nextHandler(call)) as Response;
  };
  return { fetchImpl, calls };
}

async function main() {
  console.log("=== @aegaeon/management-client Tests ===");

  assert.equal(MANAGEMENT_OPENAPI_METADATA.title, "Aegaeon Management API");
  assert.equal(MANAGEMENT_OPENAPI_METADATA.version, "v1");
  assert.equal(MANAGEMENT_OPENAPI_METADATA.pathCount, 75);
  assert.equal(MANAGEMENT_CLIENT_DEFAULTS.csrfCookieName, "csrf_token");
  assert.equal(MANAGEMENT_CLIENT_DEFAULTS.sessionCookieName, "aegaeon_admin_session");
  pass("exports OpenAPI metadata and default cookie names");

  const cookieJar = createInMemoryCookieJar({
    initialCookies: {
      session: "seed",
    },
  });
  cookieJar.applySetCookieHeaders({
    getSetCookie() {
      return [
        "csrf_token=csrf-123; Path=/; SameSite=Lax",
        "aegaeon_admin_session=sid-123; Path=/api/v1; HttpOnly; SameSite=Lax; Max-Age=28800",
      ];
    },
  });
  assert.equal(cookieJar.get("csrf_token"), "csrf-123");
  assert.equal(cookieJar.get("aegaeon_admin_session"), "sid-123");
  assert.match(cookieJar.toHeader() ?? "", /csrf_token=csrf-123/);
  pass("cookie jar captures Set-Cookie headers and renders a Cookie header");

  assert.equal(readCookieValue("a=1; csrf_token=tok-123; b=2", "csrf_token"), "tok-123");
  pass("readCookieValue extracts the requested cookie");

  const dcrSessionStore = createInMemoryManagementSessionStore({
    origin: "https://admin.example.com",
    teamId: "team-default",
    csrfToken: "csrf-dcr",
    cookieJar: createInMemoryCookieJar({
      initialCookies: {
        csrf_token: "csrf-dcr",
        aegaeon_admin_session: "sid-dcr",
      },
    }),
  });
  const dcrQueue = createFetchQueue([
    (call) => {
      assert.equal(call.method, "GET");
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/dcrBearerToken$/,
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          environmentId: "env-1",
          configured: false,
        },
      });
    },
    async (call) => {
      assert.equal(call.method, "PUT");
      assert.equal(call.headers.get("origin"), "https://admin.example.com");
      assert.equal(call.headers.get("x-csrf-token"), "csrf-dcr");
      assert.deepEqual(JSON.parse(String(call.body)), {
        token: "0123456789abcdef0123456789abcdef",
      });
      return mockResponse({
        status: 200,
        jsonBody: {
          environmentId: "env-1",
          configured: true,
          hashAlgorithm: "sha256",
          updatedAt: "2026-06-07T00:00:00.000Z",
        },
      });
    },
    (call) => {
      assert.equal(call.method, "DELETE");
      assert.equal(call.headers.get("x-csrf-token"), "csrf-dcr");
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/dcrBearerToken$/,
      );
      return mockResponse({ status: 204 });
    },
  ]);
  const dcrClient = createManagementClient({
    baseUrl: "https://issuer.example.com",
    fetchImpl: dcrQueue.fetchImpl,
    sessionStore: dcrSessionStore,
    defaultTeamId: "team-default",
  });
  const dcrStatus = await dcrClient.getDcrBearerTokenStatus({ environmentId: "env-1" });
  assert.equal(dcrStatus.configured, false);
  const configuredDcrStatus = await dcrClient.putDcrBearerToken({
    environmentId: "env-1",
    token: "0123456789abcdef0123456789abcdef",
  });
  assert.equal(configuredDcrStatus.hashAlgorithm, "sha256");
  assert.equal(await dcrClient.deleteDcrBearerToken({ environmentId: "env-1" }), null);
  pass("DCR bearer token operations use the environment control-plane path");

  const browserCookieReader = () => "csrf_token=browser-csrf; other=value";
  const browserSessionStore = createInMemoryManagementSessionStore({
    origin: "https://admin.example.com",
    teamId: "team-default",
    cookieReader: browserCookieReader,
  });
  assert.equal(browserSessionStore.syncCsrfToken(), "browser-csrf");
  assert.equal(browserSessionStore.getState().csrfToken, "browser-csrf");
  pass("session store can derive the CSRF token from a browser cookie reader");

  const { fetchImpl, calls } = createFetchQueue([
    () => mockResponse({
      status: 200,
      textBody: "ok",
      setCookies: ["csrf_token=csrf-123; Path=/; SameSite=Lax"],
    }),
    (call) => {
      assert.equal(call.headers.get("origin"), "https://admin.example.com");
      assert.equal(call.headers.get("x-csrf-token"), "csrf-123");
      assert.match(call.headers.get("cookie") ?? "", /csrf_token=csrf-123/);
      return mockResponse({
        status: 204,
        setCookies: [
          "aegaeon_admin_session=sid-123; Path=/api/v1; HttpOnly; SameSite=Lax; Max-Age=28800",
        ],
      });
    },
    (call) => {
      assert.match(call.url, /\/api\/v1\/teams\?pageSize=25$/);
      assert.match(call.headers.get("cookie") ?? "", /aegaeon_admin_session=sid-123/);
      return mockResponse({
        status: 200,
        jsonBody: {
          teams: [
            {
              id: "team-1",
              name: "Platform",
              slug: "platform",
              createdAt: "2026-03-11T00:00:00Z",
              updatedAt: "2026-03-11T00:00:00Z",
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(call.url, /\/api\/v1\/teams\/team-default\/tenants$/);
      return mockResponse({
        status: 200,
        jsonBody: {
          tenants: [
            {
              id: "tenant-1",
              teamId: "team-default",
              slug: "primary",
              name: "Primary",
              region: "ap-northeast-1",
              createdAt: "2026-03-11T00:00:00Z",
              updatedAt: "2026-03-11T00:00:00Z",
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(call.url, /\/api\/v1\/teams\/team-default\/environments\/env-1\/policies$/);
      assert.equal(call.headers.get("x-csrf-token"), "csrf-123");
      return mockResponse({
        status: 200,
        jsonBody: {
          environment: {
            id: "env-1",
            teamId: "team-default",
            tenantId: "tenant-1",
            name: "Prod",
            slug: "prod",
            issuerHost: "issuer.example.com",
            issuerUrl: "https://issuer.example.com",
            activeConfigurationVersionId: "cfg-1",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
          policy: {
            pkceRequired: true,
            dcrEnabled: true,
            requireStateParameter: true,
            strictAuthorizeRedirect: true,
            requireClientAuthToken: true,
            requireClientAuthPar: true,
            requireClientAuthIntrospection: true,
            requireClientAuthRevocation: true,
            dpopStrict: true,
            dpopIatWindowSeconds: 300,
            dpopRequireNonce: true,
            dpopNonceTtlSeconds: 300,
            parExpiresInSeconds: 90,
            privateKeyJwtEnabled: true,
            clientJwtAllowedAlgs: ["PS256"],
            clientJwtRequireKid: true,
            jwtLeewaySeconds: 60,
            pkjwtJtiWindowSeconds: 300,
            jwtBearerAllowClientSubject: false,
            jwtBearerJtiWindowSeconds: 300,
            requestObjectJtiTtlSeconds: 300,
            jwtAccessTokensEnabled: false,
            jwtIntrospectionEnabled: false,
            jwtIntrospectionExpSeconds: 60,
            authorizationDetailsTypesSupported: ["payment_initiation"],
            acrValuesSupported: ["urn:pwd", "urn:mfa"],
            defaultAcr: "urn:mfa",
            localPasswordAcr: "urn:pwd",
            dcrRequirePkceForPublic: true,
            dcrRequirePkceForConfidential: true,
            dcrRequireSenderConstrained: true,
            dcrAllowedSenderMethods: ["dpop"],
            ssaLeewaySeconds: 60,
            oidcEnabled: true,
            oidcEnableDiscovery: true,
            oidcEnableUserinfo: true,
            oidcEnableLogout: true,
            oidcEnableBackchannelLogout: true,
            oidcLogoutSessionTtlSeconds: 300,
            oidcBackchannelLogoutTimeoutSeconds: 10,
            oidcRequireNonce: true,
            mtlsEnabled: false,
            mtlsAliasParEnabled: false,
            allowedSigningAlgorithms: ["RS256"],
            allowedGrantTypes: ["authorization_code", "refresh_token"],
            allowedResponseTypes: ["code"],
            accessTokenTimeToLiveSeconds: 3600,
            idTokenTimeToLiveSeconds: 600,
            refreshTokenTimeToLiveSeconds: 86400,
            authorizationCodeTimeToLiveSeconds: 600,
            authSessionTtlSeconds: 28800,
            authMaxSessions: 10000,
            stepupChallengeTtlSeconds: 300,
            upstreamAuthTtlSeconds: 300,
            upstreamLogoutRelayTtlSeconds: 300,
          },
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/oauthProfiles",
            "\\?configurationVersionId=cfg-1&pageSize=20$",
          ].join(""),
        ),
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          oauthProfiles: [
            {
              id: "profile-1",
              environmentId: "env-1",
              configurationVersionId: "cfg-1",
              name: "Upstream Profile",
              description: "Initial upstream profile",
              profileType: "UPSTREAM",
              oauthVersion: "OAUTH2_1",
              isDefault: true,
              requirePkce: true,
              requireStateParameter: true,
              requireIssParameter: false,
              allowImplicit: false,
              allowRopc: false,
              senderConstrained: "DPOP",
              enforceRefreshSenderBinding: false,
              allowedGrantTypes: ["authorization_code", "refresh_token"],
              allowedResponseTypes: ["code"],
              tokenEndpointAuthMethodsAllowed: ["client_secret_basic"],
              expiresAt: null,
              status: "ACTIVE",
              createdAt: "2026-03-11T00:00:00Z",
              updatedAt: "2026-03-11T00:00:00Z",
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/oauthProfiles",
            "\\?configurationVersionId=cfg-1$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "POST");
      return mockResponse({
        status: 200,
        jsonBody: {
          oauthProfile: {
            id: "profile-1",
            environmentId: "env-1",
            configurationVersionId: "cfg-1",
            name: "Upstream Profile",
            description: "Initial upstream profile",
            profileType: "UPSTREAM",
            oauthVersion: "OAUTH2_1",
            isDefault: true,
            requirePkce: true,
            requireStateParameter: true,
            requireIssParameter: false,
            allowImplicit: false,
            allowRopc: false,
            senderConstrained: "DPOP",
            enforceRefreshSenderBinding: false,
            allowedGrantTypes: ["authorization_code", "refresh_token"],
            allowedResponseTypes: ["code"],
            tokenEndpointAuthMethodsAllowed: ["client_secret_basic"],
            expiresAt: null,
            status: "ACTIVE",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
          environment: {
            id: "env-1",
            teamId: "team-default",
            tenantId: "tenant-1",
            name: "Prod",
            slug: "prod",
            issuerHost: "issuer.example.com",
            issuerUrl: "https://issuer.example.com",
            activeConfigurationVersionId: "cfg-1",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/oauthProfiles\/profile-1$/,
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "profile-1",
          environmentId: "env-1",
          configurationVersionId: "cfg-1",
          name: "Upstream Profile",
          description: "Initial upstream profile",
          profileType: "UPSTREAM",
          oauthVersion: "OAUTH2_1",
          isDefault: true,
          requirePkce: true,
          requireStateParameter: true,
          requireIssParameter: false,
          allowImplicit: false,
          allowRopc: false,
          senderConstrained: "DPOP",
          enforceRefreshSenderBinding: false,
          allowedGrantTypes: ["authorization_code", "refresh_token"],
          allowedResponseTypes: ["code"],
          tokenEndpointAuthMethodsAllowed: ["client_secret_basic"],
          expiresAt: null,
          status: "ACTIVE",
          createdAt: "2026-03-11T00:00:00Z",
          updatedAt: "2026-03-11T00:00:00Z",
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/oauthProfiles\/profile-1$/,
      );
      assert.equal(call.method, "PATCH");
      return mockResponse({
        status: 200,
        jsonBody: {
          oauthProfile: {
            id: "profile-1",
            environmentId: "env-1",
            configurationVersionId: "cfg-1",
            name: "Upstream Profile Updated",
            description: "Updated upstream profile",
            profileType: "UPSTREAM",
            oauthVersion: "OAUTH2_1",
            isDefault: true,
            requirePkce: true,
            requireStateParameter: true,
            requireIssParameter: false,
            allowImplicit: false,
            allowRopc: false,
            senderConstrained: "DPOP",
            enforceRefreshSenderBinding: true,
            allowedGrantTypes: ["authorization_code", "refresh_token"],
            allowedResponseTypes: ["code"],
            tokenEndpointAuthMethodsAllowed: ["client_secret_basic"],
            expiresAt: null,
            status: "ACTIVE",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-12T00:00:00Z",
          },
          environment: {
            id: "env-1",
            teamId: "team-default",
            tenantId: "tenant-1",
            name: "Prod",
            slug: "prod",
            issuerHost: "issuer.example.com",
            issuerUrl: "https://issuer.example.com",
            activeConfigurationVersionId: "cfg-1",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/connections",
            "\\?configurationVersionId=cfg-1&pageSize=50$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          connections: [],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/connections",
            "\\?configurationVersionId=cfg-1$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "POST");
      return mockResponse({
        status: 200,
        jsonBody: {
          connection: {
            id: "conn-1",
            environmentId: "env-1",
            configurationVersionId: "cfg-1",
            oauthProfileId: "profile-1",
            connectionIdentifier: "upstream-oidc",
            name: "Upstream OIDC",
            connectionType: "OIDC",
            issuerUrl: "https://idp.example.test",
            clientId: "upstream-client",
            clientAuthMethod: "client_secret_basic",
            status: "ACTIVE",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
          environment: {
            id: "env-1",
            teamId: "team-default",
            tenantId: "tenant-1",
            name: "Prod",
            slug: "prod",
            issuerHost: "issuer.example.com",
            issuerUrl: "https://issuer.example.com",
            activeConfigurationVersionId: "cfg-1",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/connections\/conn-1$/,
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "conn-1",
          environmentId: "env-1",
          configurationVersionId: "cfg-1",
          oauthProfileId: "profile-1",
          connectionIdentifier: "upstream-oidc",
          name: "Upstream OIDC",
          connectionType: "OIDC",
          issuerUrl: "https://idp.example.test",
          clientId: "upstream-client",
          clientAuthMethod: "client_secret_basic",
          status: "ACTIVE",
          createdAt: "2026-03-11T00:00:00Z",
          updatedAt: "2026-03-11T00:00:00Z",
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/connections\/conn-1$/,
      );
      assert.equal(call.method, "PATCH");
      return mockResponse({
        status: 200,
        jsonBody: {
          connection: {
            id: "conn-1",
            environmentId: "env-1",
            configurationVersionId: "cfg-1",
            oauthProfileId: "profile-1",
            connectionIdentifier: "upstream-oidc",
            name: "Upstream OIDC Updated",
            connectionType: "OIDC",
            issuerUrl: "https://idp.example.test/issuer",
            clientId: "upstream-client",
            clientAuthMethod: "client_secret_post",
            status: "DISABLED",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-12T00:00:00Z",
          },
          environment: {
            id: "env-1",
            teamId: "team-default",
            tenantId: "tenant-1",
            name: "Prod",
            slug: "prod",
            issuerHost: "issuer.example.com",
            issuerUrl: "https://issuer.example.com",
            activeConfigurationVersionId: "cfg-1",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/connections\/conn-1$/,
      );
      assert.equal(call.method, "DELETE");
      return mockResponse({
        status: 204,
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/accountLinks",
            "\\?pageSize=50",
            "&upstreamIssuer=idp\\.example\\.test",
            "&upstreamSubject=stack-e2e-user-r0w0",
            "&endUserSubject=stack-e2e-user-r0w0",
            "&endUserEmail=stack-e2e-user-r0w0%40example\\.test",
            "&connectionIdentifier=upstream-oidc$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          accountLinks: [
            {
              id: "link-1",
              environmentId: "env-1",
              connectionId: "conn-1",
              connectionIdentifier: "upstream-oidc",
              connectionName: "Upstream OIDC Updated",
              upstreamIssuer: "https://idp.example.test/issuer",
              endUserId: "user-1",
              endUserSubject: "stack-e2e-user-r0w0",
              endUserEmail: "stack-e2e-user-r0w0@example.test",
              endUserStatus: "ACTIVE",
              hasRefreshToken: true,
              createdAt: "2026-03-11T00:00:00Z",
              lastUsedAt: null,
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/accountLinks$/,
      );
      assert.equal(call.method, "POST");
      const body = JSON.parse(String(call.body));
      assert.equal(body.connectionId, "conn-1");
      assert.equal(body.upstreamSubject, "stack-e2e-user-r0w0");
      assert.equal(body.endUserId, "user-1");
      return mockResponse({
        status: 201,
        jsonBody: {
          id: "link-2",
          environmentId: "env-1",
          connectionId: "conn-1",
          connectionIdentifier: "upstream-oidc",
          connectionName: "Upstream OIDC Updated",
          upstreamIssuer: "https://idp.example.test/issuer",
          endUserId: "user-1",
          endUserSubject: "stack-e2e-user-r0w0",
          endUserEmail: "stack-e2e-user-r0w0@example.test",
          endUserStatus: "ACTIVE",
          hasRefreshToken: false,
          createdAt: "2026-03-11T00:00:00Z",
          lastUsedAt: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/accountLinks\/conflictPreview$/,
      );
      assert.equal(call.method, "POST");
      const body = JSON.parse(String(call.body));
      assert.equal(body.connectionId, "conn-1");
      assert.equal(body.upstreamSubject, "stack-e2e-user-r0w0");
      return mockResponse({
        status: 200,
        jsonBody: {
          requestedConnectionId: "conn-1",
          requestedConnectionIdentifier: "upstream-oidc",
          requestedConnectionName: "Upstream OIDC Updated",
          upstreamIssuer: "https://idp.example.test/issuer",
          upstreamSubject: "stack-e2e-user-r0w0",
          existingAccountLink: {
            id: "link-1",
            environmentId: "env-1",
            connectionId: "conn-1",
            connectionIdentifier: "upstream-oidc",
            connectionName: "Upstream OIDC Updated",
            upstreamIssuer: "https://idp.example.test/issuer",
            endUserId: "user-1",
            endUserSubject: "stack-e2e-user-r0w0",
            endUserEmail: "stack-e2e-user-r0w0@example.test",
            endUserStatus: "ACTIVE",
            hasRefreshToken: true,
            createdAt: "2026-03-11T00:00:00Z",
            lastUsedAt: null,
          },
          candidateEndUsers: [
            {
              endUser: {
                id: "user-1",
                environmentId: "env-1",
                subject: "stack-e2e-user-r0w0",
                email: "stack-e2e-user-r0w0@example.test",
                status: "ACTIVE",
                createdAt: "2026-03-11T00:00:00Z",
                updatedAt: "2026-03-11T00:00:00Z",
              },
              matchReasons: ["subject", "email"],
              recommended: true,
            },
            {
              endUser: {
                id: "user-2",
                environmentId: "env-1",
                subject: "stack-e2e-user-r0w0-relinked",
                email: "stack-e2e-user-r0w0@example.test",
                status: "ACTIVE",
                createdAt: "2026-03-11T00:05:00Z",
                updatedAt: "2026-03-11T00:05:00Z",
              },
              matchReasons: ["email"],
              recommended: false,
            },
          ],
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/accountLinks\/resolveConflict$/,
      );
      assert.equal(call.method, "POST");
      const body = JSON.parse(String(call.body));
      assert.equal(body.connectionId, "conn-1");
      assert.equal(body.upstreamSubject, "stack-e2e-user-r0w0");
      assert.equal(body.endUserId, "user-2");
      assert.equal(body.upstreamRefreshTokenHandling, "retain");
      assert.equal(body.lowConfidenceHandling, "allow_low_confidence");
      assert.equal(body.inactiveTargetHandling, "allow_inactive");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "link-1",
          environmentId: "env-1",
          connectionId: "conn-1",
          connectionIdentifier: "upstream-oidc",
          connectionName: "Upstream OIDC Updated",
          upstreamIssuer: "https://idp.example.test/issuer",
          endUserId: "user-2",
          endUserSubject: "stack-e2e-user-r0w0-relinked",
          endUserEmail: "stack-e2e-user-r0w0-relinked@example.test",
          endUserStatus: "ACTIVE",
          hasRefreshToken: true,
          createdAt: "2026-03-11T00:00:00Z",
          lastUsedAt: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/accountLinks\/link-1$/,
      );
      assert.equal(call.method, "DELETE");
      return mockResponse({
        status: 204,
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/accountLinks\/bulkRelink$/,
      );
      assert.equal(call.method, "POST");
      const body = JSON.parse(String(call.body));
      assert.deepEqual(body.accountLinkIds, ["link-1", "link-2"]);
      assert.equal(body.endUserId, "user-2");
      assert.equal(body.upstreamRefreshTokenHandling, "clear");
      assert.equal(body.inactiveTargetHandling, "allow_inactive");
      return mockResponse({
        status: 200,
        jsonBody: {
          accountLinks: [
            {
              id: "link-1",
              environmentId: "env-1",
              connectionId: "conn-1",
              connectionIdentifier: "upstream-oidc",
              connectionName: "Upstream OIDC Updated",
              upstreamIssuer: "https://idp.example.test/issuer",
              endUserId: "user-2",
              endUserSubject: "stack-e2e-user-r0w0-relinked",
              endUserEmail: "stack-e2e-user-r0w0-relinked@example.test",
              endUserStatus: "ACTIVE",
              hasRefreshToken: true,
              createdAt: "2026-03-11T00:00:00Z",
              lastUsedAt: null,
            },
            {
              id: "link-2",
              environmentId: "env-1",
              connectionId: "conn-1",
              connectionIdentifier: "upstream-oidc",
              connectionName: "Upstream OIDC Updated",
              upstreamIssuer: "https://idp.example.test/issuer",
              endUserId: "user-2",
              endUserSubject: "stack-e2e-user-r0w0-relinked",
              endUserEmail: "stack-e2e-user-r0w0-relinked@example.test",
              endUserStatus: "ACTIVE",
              hasRefreshToken: false,
              createdAt: "2026-03-11T00:00:00Z",
              lastUsedAt: null,
            },
          ],
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/accountLinks\/link-1\/relink$/,
      );
      assert.equal(call.method, "POST");
      const body = JSON.parse(String(call.body));
      assert.equal(body.endUserId, "user-2");
      assert.equal(body.upstreamRefreshTokenHandling, "retain");
      assert.equal(body.inactiveTargetHandling, "allow_inactive");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "link-1",
          environmentId: "env-1",
          connectionId: "conn-1",
          connectionIdentifier: "upstream-oidc",
          connectionName: "Upstream OIDC Updated",
          upstreamIssuer: "https://idp.example.test/issuer",
          endUserId: "user-2",
          endUserSubject: "stack-e2e-user-r0w0-relinked",
          endUserEmail: "stack-e2e-user-r0w0-relinked@example.test",
          endUserStatus: "ACTIVE",
          hasRefreshToken: true,
          createdAt: "2026-03-11T00:00:00Z",
          lastUsedAt: null,
        },
      });
    },
    (call) => {
      const url = new URL(call.url);
      assert.equal(
        url.pathname,
        "/api/v1/teams/team-default/environments/env-1/federationLogoutRecoveryIncidents",
      );
      assert.equal(call.method, "GET");
      assert.equal(url.searchParams.get("connectionId"), "conn-1");
      assert.equal(url.searchParams.get("status"), "OPEN");
      assert.equal(url.searchParams.get("recoveryPolicy"), "manual_review");
      assert.equal(url.searchParams.get("pageSize"), "10");
      return mockResponse({
        status: 200,
        jsonBody: {
          incidents: [
            {
              id: "incident-1",
              teamId: "team-default",
              tenantId: "tenant-1",
              environmentId: "env-1",
              connectionId: "conn-1",
              connectionIdentifier: "upstream-oidc",
              connectionName: "Upstream OIDC Updated",
              downstreamClientId: "client-identifier",
              upstreamIssuer: "https://idp.example.test/issuer",
              recoveryPolicy: "manual_review",
              status: "OPEN",
              sessionHintClaim: "sid-claim",
              sessionHintPresent: true,
              downstreamRedirectUri: "https://rp.example.test/logout/callback",
              downstreamStatePresent: true,
              failureReason: "logout_callback_timeout",
              requestId: "req-incident-1",
              createdAt: "2026-03-11T00:00:00Z",
              expiresAt: "2026-03-12T00:00:00Z",
              resolvedAt: null,
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.equal(call.method, "GET");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/" +
          "federationLogoutRecoveryIncidents/incident-1",
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "incident-1",
          teamId: "team-default",
          tenantId: "tenant-1",
          environmentId: "env-1",
          connectionId: "conn-1",
          connectionIdentifier: "upstream-oidc",
          connectionName: "Upstream OIDC Updated",
          downstreamClientId: "client-identifier",
          upstreamIssuer: "https://idp.example.test/issuer",
          recoveryPolicy: "manual_review",
          status: "OPEN",
          sessionHintClaim: "sid-claim",
          sessionHintPresent: true,
          downstreamRedirectUri: "https://rp.example.test/logout/callback",
          downstreamStatePresent: true,
          failureReason: "logout_callback_timeout",
          requestId: "req-incident-1",
          createdAt: "2026-03-11T00:00:00Z",
          expiresAt: "2026-03-12T00:00:00Z",
          resolvedAt: null,
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/" +
          "federationLogoutRecoveryIncidents/incident-1/clear",
      );
      assert.deepEqual(parseJsonBody(call), {
        reason: "confirmed downstream logout completion",
      });
      return mockResponse({
        status: 204,
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/federationTrustAnchors$/,
      );
      assert.equal(call.method, "POST");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "anchor-1",
          environmentId: "env-1",
          entityId: "https://anchor.example.test",
          jwks: { keys: [{ kid: "anchor-key-1", kty: "RSA" }] },
          metadataPolicy: { federationEntity: { contacts: ["ops@example.test"] } },
          createdAt: "2026-03-11T00:00:00Z",
          updatedAt: "2026-03-11T00:00:00Z",
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/federationTrustAnchors\?pageSize=10$/,
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          trustAnchors: [
            {
              id: "anchor-1",
              environmentId: "env-1",
              entityId: "https://anchor.example.test",
              jwks: { keys: [{ kid: "anchor-key-1", kty: "RSA" }] },
              metadataPolicy: { federationEntity: { contacts: ["ops@example.test"] } },
              createdAt: "2026-03-11T00:00:00Z",
              updatedAt: "2026-03-11T00:00:00Z",
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/federationTrustAnchors\/anchor-1$/,
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "anchor-1",
          environmentId: "env-1",
          entityId: "https://anchor.example.test",
          jwks: { keys: [{ kid: "anchor-key-1", kty: "RSA" }] },
          metadataPolicy: { federationEntity: { contacts: ["ops@example.test"] } },
          createdAt: "2026-03-11T00:00:00Z",
          updatedAt: "2026-03-11T00:00:00Z",
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/federationEntityCache\?pageSize=10$/,
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          entityCacheEntries: [
            {
              id: "entity-cache-1",
              environmentId: "env-1",
              entityId: "https://entity.example.test",
              entityConfigurationJws: "eyJhbGciOiJSUzI1NiJ9..signature",
              parsedStatement: { iss: "https://entity.example.test" },
              fetchedAt: "2026-03-11T00:00:00Z",
              expiresAt: "2026-03-12T00:00:00Z",
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/",
            "federationEntityCache/entity-cache-1/refresh$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "POST");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "entity-cache-1",
          environmentId: "env-1",
          entityId: "https://entity.example.test",
          entityConfigurationJws: "eyJhbGciOiJSUzI1NiJ9..signature",
          parsedStatement: {
            iss: "https://entity.example.test",
            refreshed: true,
          },
          fetchedAt: "2026-03-11T00:05:00Z",
          expiresAt: "2026-03-12T00:05:00Z",
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/",
            "federationEntityCache/entity-cache-1$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "DELETE");
      return mockResponse({
        status: 204,
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/federationTrustChains\?pageSize=10$/,
      );
      assert.equal(call.method, "GET");
      return mockResponse({
        status: 200,
        jsonBody: {
          trustChains: [
            {
              id: "trust-chain-1",
              environmentId: "env-1",
              leafEntityId: "https://entity.example.test",
              anchorEntityId: "https://anchor.example.test",
              chainJwts: [
                "eyJhbGciOiJSUzI1NiJ9.payload.signature",
                "eyJhbGciOiJSUzI1NiJ9.anchor.signature",
              ],
              resolvedAt: "2026-03-11T00:00:00Z",
              expiresAt: "2026-03-12T00:00:00Z",
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/",
            "federationTrustChains/trust-chain-1/refresh$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "POST");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "trust-chain-1",
          environmentId: "env-1",
          leafEntityId: "https://entity.example.test",
          anchorEntityId: "https://anchor.example.test",
          chainJwts: [
            "eyJhbGciOiJSUzI1NiJ9.payload.signature",
            "eyJhbGciOiJSUzI1NiJ9.anchor.signature",
          ],
          resolvedAt: "2026-03-11T00:05:00Z",
          expiresAt: "2026-03-12T00:05:00Z",
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/",
            "federationTrustChains/trust-chain-1$",
          ].join(""),
        ),
      );
      assert.equal(call.method, "DELETE");
      return mockResponse({
        status: 204,
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/federationTrustAnchors\/anchor-1$/,
      );
      assert.equal(call.method, "DELETE");
      return mockResponse({
        status: 204,
      });
    },
    (call) => {
      assert.match(
        call.url,
        /\/api\/v1\/teams\/team-default\/environments\/env-1\/oauthProfiles\/profile-1$/,
      );
      assert.equal(call.method, "DELETE");
      return mockResponse({
        status: 204,
      });
    },
    (call) => {
      assert.match(call.url, /\/api\/v1\/teams\/team-default\/environments\/env-1\/clients$/);
      assert.equal(call.method, "POST");
      return mockResponse({
        status: 200,
        jsonBody: {
          client: {
            id: "client-1",
            environmentId: "env-1",
            clientIdentifier: "client-identifier",
            name: "Console",
            clientType: "confidential",
            redirectUris: ["https://console.example.test/callback"],
            allowedGrantTypes: ["authorization_code", "refresh_token"],
            allowedResponseTypes: ["code"],
            allowedScopes: ["openid", "profile"],
            tokenEndpointAuthenticationMethod: "client_secret_post",
            requirePkce: true,
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
          environment: {
            id: "env-1",
            teamId: "team-default",
            tenantId: "tenant-1",
            name: "Prod",
            slug: "prod",
            issuerHost: "issuer.example.com",
            issuerUrl: "https://issuer.example.com",
            activeConfigurationVersionId: "cfg-2",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-11T00:00:00Z",
          },
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/auditEvents",
            "\\?pageSize=10",
            "&eventType=management\\.client\\.created",
            "&from=2026-03-10T00%3A00%3A00\\.000Z",
            "&to=2026-03-17T00%3A00%3A00\\.000Z$",
          ].join(""),
        ),
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          auditEvents: [
            {
              id: "audit-1",
              teamId: "team-default",
              eventType: "management.client.created",
              category: "management",
              outcome: "success",
              severity: "info",
              occurredAt: "2026-03-11T00:00:00Z",
              actor: { actorType: "user", actorId: "user-1" },
              target: { targetType: "client", targetId: "client-1" },
              request: { requestId: "req-audit-1" },
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      const url = new URL(call.url);
      assert.equal(url.pathname, "/api/v1/teams/team-default/auditEvents/export");
      assert.equal(url.searchParams.get("eventType"), "management.client.created");
      assert.equal(url.searchParams.get("format"), "json");
      assert.equal(url.searchParams.get("limit"), "25");
      return mockResponse({
        status: 200,
        jsonBody: {
          totalCount: 1,
          exportedAt: "1760000000",
          timeRange: {
            from: "2026-03-10T00:00:00.000Z",
            to: "2026-03-17T00:00:00.000Z",
          },
          auditEvents: [
            {
              id: "audit-1",
              teamId: "team-default",
              eventType: "management.client.created",
              category: "management",
              outcome: "success",
              severity: "info",
              occurredAt: "2026-03-11T00:00:00Z",
              actor: { actorType: "user", actorId: "user-1" },
              target: { targetType: "client", targetId: "client-1" },
              request: { requestId: "req-audit-1" },
            },
          ],
        },
      });
    },
    (call) => {
      const url = new URL(call.url);
      assert.equal(url.pathname, "/api/v1/teams/team-default/auditEvents/export");
      assert.equal(url.searchParams.get("category"), "CONTROL_PLANE");
      assert.equal(url.searchParams.get("format"), "csv");
      assert.equal(url.searchParams.get("limit"), "50");
      return mockResponse({
        status: 200,
        textBody: [
          "id,event_type,outcome",
          "audit-1,management.client.created,success",
        ].join("\n"),
        headers: {
          "content-type": "text/csv; charset=utf-8",
        },
      });
    },
    (call) => {
      assert.match(
        call.url,
        new RegExp(
          [
            "/api/v1/teams/team-default/environments/env-1/auditEvents",
            "\\?pageSize=5",
            "&category=CONTROL_PLANE",
            "&from=2026-03-10T00%3A00%3A00\\.000Z",
            "&to=2026-03-17T00%3A00%3A00\\.000Z$",
          ].join(""),
        ),
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          auditEvents: [],
          pageInfo: null,
        },
      });
    },
    (call) => {
      const url = new URL(call.url);
      assert.equal(
        url.pathname,
        "/api/v1/teams/team-default/environments/env-1/auditEvents/export",
      );
      assert.equal(url.searchParams.get("category"), "CONTROL_PLANE");
      assert.equal(url.searchParams.get("format"), "json");
      assert.equal(url.searchParams.get("limit"), "10");
      return mockResponse({
        status: 200,
        jsonBody: {
          totalCount: 1,
          exportedAt: "1760000000",
          timeRange: {
            from: "2026-03-10T00:00:00.000Z",
            to: "2026-03-17T00:00:00.000Z",
          },
          auditEvents: [
            {
              id: "audit-env-1",
              teamId: "team-default",
              tenantId: "tenant-1",
              environmentId: "env-1",
              eventType: "management.clientSecret.revokedAll.v1",
              category: "management",
              outcome: "success",
              severity: "info",
              occurredAt: "2026-03-11T00:00:00Z",
              actor: { actorType: "user", actorId: "user-1" },
              target: { targetType: "client", targetId: "client-1" },
              request: { requestId: "req-audit-env-1" },
            },
          ],
        },
      });
    },
    (call) => {
      const url = new URL(call.url);
      assert.equal(
        url.pathname,
        "/api/v1/teams/team-default/environments/env-1/auditEvents/export",
      );
      assert.equal(url.searchParams.get("eventType"), "management.clientSecret.revokedAll.v1");
      assert.equal(url.searchParams.get("format"), "csv");
      assert.equal(url.searchParams.get("limit"), "25");
      return mockResponse({
        status: 200,
        textBody: [
          "id,event_type,outcome",
          "audit-env-1,management.clientSecret.revokedAll.v1,success",
        ].join("\n"),
      });
    },
  ]);

  const sessionStore = createInMemoryManagementSessionStore({
    origin: "https://admin.example.com",
    teamId: "team-default",
  });

  const client = createManagementClient({
    baseUrl: "https://admin.example.com",
    fetchImpl,
    sessionStore,
  });

  await client.createAuthenticationSession({
    email: "ops@example.com",
    password: "correct horse battery staple",
  });
  assert.equal(sessionStore.getState().cookieJar.get("aegaeon_admin_session"), "sid-123");
  pass("createAuthenticationSession primes CSRF state and captures the session cookie");

  const teamList = await client.listTeams({ pageSize: 25 });
  assert.equal(teamList.teams[0]?.name, "Platform");
  pass("listTeams validates the JSON response body");

  const tenantList = await client.listTenants();
  assert.equal(tenantList.tenants[0]?.teamId, "team-default");
  pass("default teamId is auto-inserted into scoped management paths");

  const policyPatch = await client.patchPolicies({
    environmentId: "env-1",
    baseConfigurationVersionId: "cfg-1",
    comment: "tighten defaults",
    dcrEnabled: true,
  });
  assert.equal(policyPatch.environment.id, "env-1");
  const allowedSigningAlgorithms = policyPatch.policy
    .allowedSigningAlgorithms as string[] | undefined;
  assert.equal(allowedSigningAlgorithms?.[0], "RS256");
  pass("patchPolicies validates policy and environment payloads");

  const oauthProfiles = await client.listOAuthProfiles({
    environmentId: "env-1",
    configurationVersionId: "cfg-1",
    pageSize: 20,
  });
  assert.equal(oauthProfiles.oauthProfiles[0]?.profileType, "UPSTREAM");
  pass("listOAuthProfiles validates the upstream profile listing used by connection UIs");

  const createdOAuthProfile = await client.createOAuthProfile({
    environmentId: "env-1",
    configurationVersionId: "cfg-1",
    name: "Upstream Profile",
    description: "Initial upstream profile",
    profileType: "UPSTREAM",
    oauthVersion: "OAUTH2_1",
    isDefault: true,
    requirePkce: true,
    requireStateParameter: true,
    requireIssParameter: false,
    allowImplicit: false,
    allowRopc: false,
    senderConstrained: "DPOP",
    enforceRefreshSenderBinding: false,
    allowedGrantTypes: ["authorization_code", "refresh_token"],
    allowedResponseTypes: ["code"],
    tokenEndpointAuthMethodsAllowed: ["client_secret_basic"],
  });
  assert.equal(createdOAuthProfile.oauthProfile.name, "Upstream Profile");
  assert.equal(createdOAuthProfile.environment.id, "env-1");
  pass(
    "createOAuthProfile returns the mutation payload shape needed " +
      "for upstream profile management",
  );

  const oauthProfile = await client.getOAuthProfile({
    environmentId: "env-1",
    oauthProfileId: "profile-1",
  });
  assert.equal(oauthProfile.id, "profile-1");
  assert.equal(oauthProfile.tokenEndpointAuthMethodsAllowed[0], "client_secret_basic");
  pass("getOAuthProfile resolves a single upstream profile");

  const updatedOAuthProfile = await client.updateOAuthProfile({
    environmentId: "env-1",
    oauthProfileId: "profile-1",
    name: "Upstream Profile Updated",
    description: "Updated upstream profile",
    enforceRefreshSenderBinding: true,
  });
  assert.equal(updatedOAuthProfile.oauthProfile.name, "Upstream Profile Updated");
  assert.equal(updatedOAuthProfile.oauthProfile.enforceRefreshSenderBinding, true);
  pass("updateOAuthProfile returns the updated upstream profile mutation payload");

  const connections = await client.listConnections({
    environmentId: "env-1",
    configurationVersionId: "cfg-1",
    pageSize: 50,
  });
  assert.equal(connections.connections.length, 0);
  pass("listConnections validates the empty upstream connection listing");

  const createdConnection = await client.createConnection({
    environmentId: "env-1",
    configurationVersionId: "cfg-1",
    connectionIdentifier: "upstream-oidc",
    name: "Upstream OIDC",
    issuerUrl: "https://idp.example.test",
    clientId: "upstream-client",
    clientAuthMethod: "client_secret_basic",
    status: "ACTIVE",
    oauthProfileId: "profile-1",
  });
  assert.equal(createdConnection.connection.connectionIdentifier, "upstream-oidc");
  assert.equal(createdConnection.environment.activeConfigurationVersionId, "cfg-1");
  pass("createConnection returns the mutation payload used by upstream connection UIs");

  const connection = await client.getConnection({
    environmentId: "env-1",
    connectionId: "conn-1",
  });
  assert.equal(connection.connectionType, "OIDC");
  assert.equal(connection.clientAuthMethod, "client_secret_basic");
  pass("getConnection resolves a single upstream connection");

  const updatedConnection = await client.updateConnection({
    environmentId: "env-1",
    connectionId: "conn-1",
    name: "Upstream OIDC Updated",
    issuerUrl: "https://idp.example.test/issuer",
    clientAuthMethod: "client_secret_post",
    status: "DISABLED",
    oauthProfileId: "profile-1",
  });
  assert.equal(updatedConnection.connection.name, "Upstream OIDC Updated");
  assert.equal(updatedConnection.connection.status, "DISABLED");
  pass("updateConnection returns the updated upstream connection mutation payload");

  await client.deleteConnection({
    environmentId: "env-1",
    connectionId: "conn-1",
  });
  pass("deleteConnection supports removing an upstream connection");

  const accountLinks = await client.listAccountLinks({
    teamId: "team-default",
    environmentId: "env-1",
    pageSize: 50,
    upstreamIssuer: "idp.example.test",
    upstreamSubject: "stack-e2e-user-r0w0",
    endUserSubject: "stack-e2e-user-r0w0",
    endUserEmail: "stack-e2e-user-r0w0@example.test",
    connectionIdentifier: "upstream-oidc",
  });
  assert.equal(accountLinks.accountLinks.length, 1);
  assert.equal(accountLinks.accountLinks[0]?.connectionName, "Upstream OIDC Updated");
  assert.equal(accountLinks.accountLinks[0]?.hasRefreshToken, true);
  pass("listAccountLinks validates upstream account link inventory");

  const createdAccountLink = await client.createAccountLink({
    teamId: "team-default",
    environmentId: "env-1",
    connectionId: "conn-1",
    upstreamSubject: "stack-e2e-user-r0w0",
    endUserId: "user-1",
  });
  assert.equal(createdAccountLink.connectionIdentifier, "upstream-oidc");
  assert.equal(createdAccountLink.endUserId, "user-1");
  pass("createAccountLink creates explicit upstream account links");

  const accountLinkConflictPreview = await client.previewAccountLinkConflict({
    teamId: "team-default",
    environmentId: "env-1",
    connectionId: "conn-1",
    upstreamSubject: "stack-e2e-user-r0w0",
  });
  assert.equal(accountLinkConflictPreview.requestedConnectionIdentifier, "upstream-oidc");
  assert.equal(accountLinkConflictPreview.upstreamIssuer, "https://idp.example.test/issuer");
  assert.equal(accountLinkConflictPreview.existingAccountLink?.id, "link-1");
  assert.equal(accountLinkConflictPreview.candidateEndUsers.length, 2);
  assert.equal(accountLinkConflictPreview.candidateEndUsers[0]?.endUser.id, "user-1");
  assert.deepEqual(accountLinkConflictPreview.candidateEndUsers[0]?.matchReasons, [
    "subject",
    "email",
  ]);
  assert.equal(accountLinkConflictPreview.candidateEndUsers[0]?.recommended, true);
  assert.equal(accountLinkConflictPreview.candidateEndUsers[1]?.endUser.id, "user-2");
  assert.deepEqual(accountLinkConflictPreview.candidateEndUsers[1]?.matchReasons, ["email"]);
  assert.equal(accountLinkConflictPreview.candidateEndUsers[1]?.recommended, false);
  pass("previewAccountLinkConflict surfaces conflicting upstream account links");

  const resolvedAccountLink = await client.resolveAccountLinkConflict({
    teamId: "team-default",
    environmentId: "env-1",
    connectionId: "conn-1",
    upstreamSubject: "stack-e2e-user-r0w0",
    endUserId: "user-2",
    upstreamRefreshTokenHandling: "retain",
    lowConfidenceHandling: "allow_low_confidence",
    inactiveTargetHandling: "allow_inactive",
  });
  assert.equal(resolvedAccountLink.endUserId, "user-2");
  assert.equal(resolvedAccountLink.endUserSubject, "stack-e2e-user-r0w0-relinked");
  assert.equal(resolvedAccountLink.endUserEmail, "stack-e2e-user-r0w0-relinked@example.test");
  pass("resolveAccountLinkConflict resolves previewed upstream account link conflicts");

  await client.deleteAccountLink({
    teamId: "team-default",
    environmentId: "env-1",
    accountLinkId: "link-1",
  });
  pass("deleteAccountLink supports unlinking upstream accounts");

  const bulkRelinkedAccountLinks = await client.bulkRelinkAccountLinks({
    teamId: "team-default",
    environmentId: "env-1",
    accountLinkIds: ["link-1", "link-2"],
    endUserId: "user-2",
    upstreamRefreshTokenHandling: "clear",
    inactiveTargetHandling: "allow_inactive",
  });
  assert.equal(bulkRelinkedAccountLinks.accountLinks.length, 2);
  assert.equal(bulkRelinkedAccountLinks.accountLinks[0]?.endUserId, "user-2");
  assert.equal(
    bulkRelinkedAccountLinks.accountLinks[1]?.endUserEmail,
    "stack-e2e-user-r0w0-relinked@example.test",
  );
  pass("bulkRelinkAccountLinks reassigns multiple upstream accounts");

  const relinkedAccountLink = await client.relinkAccountLink({
    teamId: "team-default",
    environmentId: "env-1",
    accountLinkId: "link-1",
    endUserId: "user-2",
    upstreamRefreshTokenHandling: "retain",
    inactiveTargetHandling: "allow_inactive",
  });
  assert.equal(relinkedAccountLink.endUserId, "user-2");
  assert.equal(relinkedAccountLink.endUserSubject, "stack-e2e-user-r0w0-relinked");
  assert.equal(relinkedAccountLink.endUserEmail, "stack-e2e-user-r0w0-relinked@example.test");
  pass("relinkAccountLink reassigns upstream accounts");

  const logoutRecoveryIncidents = await client.listFederationLogoutRecoveryIncidents({
    teamId: "team-default",
    environmentId: "env-1",
    connectionId: "conn-1",
    status: "OPEN",
    recoveryPolicy: "manual_review",
    pageSize: 10,
  });
  assert.equal(logoutRecoveryIncidents.incidents.length, 1);
  assert.equal(logoutRecoveryIncidents.incidents[0]?.id, "incident-1");
  assert.equal(logoutRecoveryIncidents.incidents[0]?.sessionHintPresent, true);
  pass("listFederationLogoutRecoveryIncidents validates incident inventory and query encoding");

  const logoutRecoveryIncident = await client.getFederationLogoutRecoveryIncident({
    teamId: "team-default",
    environmentId: "env-1",
    incidentId: "incident-1",
  });
  assert.equal(logoutRecoveryIncident.id, "incident-1");
  assert.equal(logoutRecoveryIncident.downstreamClientId, "client-identifier");
  pass("getFederationLogoutRecoveryIncident resolves a single recovery incident");

  await client.clearFederationLogoutRecoveryIncident({
    teamId: "team-default",
    environmentId: "env-1",
    incidentId: "incident-1",
    reason: "confirmed downstream logout completion",
  });
  pass("clearFederationLogoutRecoveryIncident posts the audit reason and accepts empty success");

  const createdFederationTrustAnchor = await client.createFederationTrustAnchor({
    teamId: "team-default",
    environmentId: "env-1",
    entityId: "https://anchor.example.test",
    jwks: { keys: [{ kid: "anchor-key-1", kty: "RSA" }] },
    metadataPolicy: { federationEntity: { contacts: ["ops@example.test"] } },
  });
  assert.equal(createdFederationTrustAnchor.entityId, "https://anchor.example.test");
  assert.deepEqual(createdFederationTrustAnchor.jwks, {
    keys: [{ kid: "anchor-key-1", kty: "RSA" }],
  });
  pass("createFederationTrustAnchor creates federation trust anchors");

  const federationTrustAnchors = await client.listFederationTrustAnchors({
    teamId: "team-default",
    environmentId: "env-1",
    pageSize: 10,
  });
  assert.equal(federationTrustAnchors.trustAnchors.length, 1);
  assert.equal(federationTrustAnchors.trustAnchors[0]?.entityId, "https://anchor.example.test");
  pass("listFederationTrustAnchors validates federation trust anchor inventory");

  const federationTrustAnchor = await client.getFederationTrustAnchor({
    teamId: "team-default",
    environmentId: "env-1",
    trustAnchorId: "anchor-1",
  });
  assert.equal(federationTrustAnchor.id, "anchor-1");
  assert.deepEqual(federationTrustAnchor.metadataPolicy, {
    federationEntity: { contacts: ["ops@example.test"] },
  });
  pass("getFederationTrustAnchor resolves a single federation trust anchor");

  const federationEntityCache = await client.listFederationEntityCache({
    teamId: "team-default",
    environmentId: "env-1",
    pageSize: 10,
  });
  assert.equal(federationEntityCache.entityCacheEntries.length, 1);
  assert.equal(
    federationEntityCache.entityCacheEntries[0]?.entityId,
    "https://entity.example.test",
  );
  pass("listFederationEntityCache validates federation entity cache inventory");

  const refreshedFederationEntityCacheEntry = await client.refreshFederationEntityCacheEntry({
    teamId: "team-default",
    environmentId: "env-1",
    entityCacheId: "entity-cache-1",
  });
  assert.equal(calls.at(-1)?.method, "POST");
  assert.equal(calls.at(-1)?.headers.get("content-type"), "application/json");
  assert.equal(calls.at(-1)?.body, "{}");
  assert.equal(refreshedFederationEntityCacheEntry.id, "entity-cache-1");
  assert.equal(
    (refreshedFederationEntityCacheEntry.parsedStatement as { refreshed?: boolean }).refreshed,
    true,
  );
  pass("refreshFederationEntityCacheEntry validates federation entity cache refresh");

  await client.deleteFederationEntityCacheEntry({
    teamId: "team-default",
    environmentId: "env-1",
    entityCacheId: "entity-cache-1",
  });
  assert.equal(calls.at(-1)?.method, "DELETE");
  assert.equal(calls.at(-1)?.headers.get("content-type"), "application/json");
  assert.equal(calls.at(-1)?.body, "{}");
  pass("deleteFederationEntityCacheEntry supports removing federation entity cache entries");

  const federationTrustChains = await client.listFederationTrustChains({
    teamId: "team-default",
    environmentId: "env-1",
    pageSize: 10,
  });
  assert.equal(federationTrustChains.trustChains.length, 1);
  assert.equal(
    federationTrustChains.trustChains[0]?.anchorEntityId,
    "https://anchor.example.test",
  );
  pass("listFederationTrustChains validates federation trust chain inventory");

  const refreshedFederationTrustChain = await client.refreshFederationTrustChain({
    teamId: "team-default",
    environmentId: "env-1",
    trustChainId: "trust-chain-1",
  });
  assert.equal(calls.at(-1)?.method, "POST");
  assert.equal(calls.at(-1)?.headers.get("content-type"), "application/json");
  assert.equal(calls.at(-1)?.body, "{}");
  assert.equal(refreshedFederationTrustChain.id, "trust-chain-1");
  assert.equal(
    refreshedFederationTrustChain.anchorEntityId,
    "https://anchor.example.test",
  );
  pass("refreshFederationTrustChain validates federation trust chain refresh");

  await client.deleteFederationTrustChain({
    teamId: "team-default",
    environmentId: "env-1",
    trustChainId: "trust-chain-1",
  });
  assert.equal(calls.at(-1)?.method, "DELETE");
  assert.equal(calls.at(-1)?.headers.get("content-type"), "application/json");
  assert.equal(calls.at(-1)?.body, "{}");
  pass("deleteFederationTrustChain supports removing federation trust chains");

  await client.deleteFederationTrustAnchor({
    teamId: "team-default",
    environmentId: "env-1",
    trustAnchorId: "anchor-1",
  });
  pass("deleteFederationTrustAnchor supports removing trust anchors");

  await client.deleteOAuthProfile({
    environmentId: "env-1",
    oauthProfileId: "profile-1",
  });
  pass("deleteOAuthProfile supports removing an upstream profile");

  const createdClient = await client.createClient({
    environmentId: "env-1",
    baseConfigurationVersionId: "cfg-1",
    name: "Console",
    clientType: "confidential",
    redirectUris: ["https://console.example.test/callback"],
  });
  assert.equal(createdClient.client.clientIdentifier, "client-identifier");
  assert.equal(createdClient.environment.activeConfigurationVersionId, "cfg-2");
  pass("createClient returns the client mutation payload shape used by admin UIs");

  const teamAudit = await client.listTeamAuditEvents({
    pageSize: 10,
    eventType: "management.client.created",
    from: "2026-03-10T00:00:00.000Z",
    to: "2026-03-17T00:00:00.000Z",
  });
  assert.equal(teamAudit.auditEvents[0]?.eventType, "management.client.created");
  pass("listTeamAuditEvents resolves full control-plane audit responses");

  const auditExport = await client.exportTeamAuditEvents({
    eventType: "management.client.created",
    from: "2026-03-10T00:00:00.000Z",
    to: "2026-03-17T00:00:00.000Z",
    format: "json",
    limit: 25,
  });
  assert.equal(auditExport.totalCount, 1);
  assert.equal(auditExport.auditEvents[0]?.eventType, "management.client.created");
  pass("exportTeamAuditEvents returns exported audit payloads for admin tooling");

  const auditExportCsv = await client.exportTeamAuditEventsCsv({
    category: "CONTROL_PLANE",
    from: "2026-03-10T00:00:00.000Z",
    to: "2026-03-17T00:00:00.000Z",
    limit: 50,
  });
  assert.match(auditExportCsv, /^id,event_type,outcome/m);
  assert.match(auditExportCsv, /management\.client\.created/);
  pass("exportTeamAuditEventsCsv returns CSV export payloads for admin tooling");

  const environmentAudit = await client.listEnvironmentAuditEvents({
    environmentId: "env-1",
    pageSize: 5,
    category: "CONTROL_PLANE",
    from: "2026-03-10T00:00:00.000Z",
    to: "2026-03-17T00:00:00.000Z",
  });
  assert.equal(environmentAudit.auditEvents.length, 0);
  pass("audit list helpers encode time-window and filter query parameters");

  const environmentAuditExport = await client.exportEnvironmentAuditEvents({
    environmentId: "env-1",
    category: "CONTROL_PLANE",
    from: "2026-03-10T00:00:00.000Z",
    to: "2026-03-17T00:00:00.000Z",
    format: "json",
    limit: 10,
  });
  assert.equal(environmentAuditExport.totalCount, 1);
  assert.equal(environmentAuditExport.auditEvents[0]?.environmentId, "env-1");
  pass("exportEnvironmentAuditEvents returns environment-scoped audit payloads");

  const environmentAuditExportCsv = await client.exportEnvironmentAuditEventsCsv({
    environmentId: "env-1",
    eventType: "management.clientSecret.revokedAll.v1",
    from: "2026-03-10T00:00:00.000Z",
    to: "2026-03-17T00:00:00.000Z",
    limit: 25,
  });
  assert.match(environmentAuditExportCsv, /^id,event_type,outcome/m);
  assert.match(environmentAuditExportCsv, /management\.clientSecret\.revokedAll\.v1/);
  pass("exportEnvironmentAuditEventsCsv returns CSV export payloads");

  const userLifecycleQueue = createFetchQueue([
    (call) => {
      assert.equal(call.method, "GET");
      const url = new URL(call.url);
      assert.equal(url.pathname, "/api/v1/teams/team-default/environments/env-1/users");
      assert.equal(url.searchParams.get("pageSize"), "50");
      assert.equal(url.searchParams.get("includeDeleted"), "true");
      return mockResponse({
        status: 200,
        jsonBody: {
          users: [
            {
              id: "user-1",
              environmentId: "env-1",
              subject: "local-user",
              status: "ACTIVE",
              createdAt: "2026-03-11T00:00:00Z",
              updatedAt: "2026-03-11T00:00:00Z",
              email: "local-user@example.test",
            },
          ],
          pageInfo: null,
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users",
      );
      const body = parseJsonBody(call) as { subject?: string; email?: string };
      assert.equal(body.subject, "local-user");
      assert.equal(body.email, "local-user@example.test");
      return mockResponse({
        status: 201,
        jsonBody: {
          id: "user-1",
          environmentId: "env-1",
          subject: "local-user",
          status: "ACTIVE",
          createdAt: "2026-03-11T00:00:00Z",
          updatedAt: "2026-03-11T00:00:00Z",
          email: "local-user@example.test",
        },
      });
    },
    (call) => {
      assert.equal(call.method, "PATCH");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1",
      );
      const body = parseJsonBody(call) as { subject?: string; email?: string };
      assert.equal(body.subject, "local-user-updated");
      assert.equal(body.email, "updated@example.test");
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "user-1",
          environmentId: "env-1",
          subject: "local-user-updated",
          status: "ACTIVE",
          createdAt: "2026-03-11T00:00:00Z",
          updatedAt: "2026-03-12T00:00:00Z",
          email: "updated@example.test",
        },
      });
    },
    (call) => {
      assert.equal(call.method, "DELETE");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1",
      );
      return mockResponse({ status: 204 });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/restore",
      );
      assert.deepEqual(parseJsonBody(call), {});
      return mockResponse({
        status: 200,
        jsonBody: {
          id: "user-1",
          environmentId: "env-1",
          subject: "local-user-updated",
          status: "ACTIVE",
          createdAt: "2026-03-11T00:00:00Z",
          updatedAt: "2026-03-12T00:00:00Z",
          email: "updated@example.test",
        },
      });
    },
    (call) => {
      assert.equal(call.method, "GET");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/credentials",
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          password: {
            id: "pwd-1",
            status: "ACTIVE",
            createdAt: "2026-03-11T00:00:00Z",
            updatedAt: "2026-03-12T00:00:00Z",
            lastUsedAt: null,
          },
          recoveryTokens: [],
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/activationTokens",
      );
      assert.deepEqual(parseJsonBody(call), { expiresInSeconds: 3600 });
      return mockResponse({
        status: 200,
        jsonBody: {
          token: "activation-token",
          redeemUrl: "https://issuer.example.test/auth/activate?token=activation-token",
          recoveryToken: {
            id: "rt-activation",
            purpose: "activation",
            status: "ACTIVE",
            expiresAt: "2026-03-12T01:00:00Z",
            redeemedAt: null,
            revokedAt: null,
            createdAt: "2026-03-12T00:00:00Z",
          },
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/passwordResetTokens",
      );
      assert.deepEqual(parseJsonBody(call), { expiresInSeconds: 1800 });
      return mockResponse({
        status: 200,
        jsonBody: {
          token: "reset-token",
          redeemUrl: "https://issuer.example.test/auth/password/reset?token=reset-token",
          recoveryToken: {
            id: "rt-reset",
            purpose: "password_reset",
            status: "ACTIVE",
            expiresAt: "2026-03-12T00:30:00Z",
            redeemedAt: null,
            revokedAt: null,
            createdAt: "2026-03-12T00:00:00Z",
          },
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/credentials/password/revoke",
      );
      assert.deepEqual(parseJsonBody(call), {});
      return mockResponse({
        status: 200,
        jsonBody: {
          password: null,
          recoveryTokens: [
            {
              id: "rt-reset",
              purpose: "password_reset",
              status: "ACTIVE",
              expiresAt: "2026-03-12T00:30:00Z",
              redeemedAt: null,
              revokedAt: null,
              createdAt: "2026-03-12T00:00:00Z",
            },
          ],
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/recoveryTokens/rt-reset/revoke",
      );
      assert.deepEqual(parseJsonBody(call), {});
      return mockResponse({
        status: 200,
        jsonBody: {
          password: null,
          recoveryTokens: [],
        },
      });
    },
    (call) => {
      assert.equal(call.method, "GET");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/profile",
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          userId: "user-1",
          subject: "local-user-updated",
          subjectPolicy: "explicit",
          email: "updated@example.test",
          emailVerified: true,
          displayName: "Local User",
          customClaims: { department: "security" },
          version: 3,
          updatedAt: "2026-03-12T00:00:00Z",
        },
      });
    },
    (call) => {
      assert.equal(call.method, "PATCH");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/profile",
      );
      assert.deepEqual(parseJsonBody(call), {
        baseVersion: 3,
        email: "profile@example.test",
        emailVerified: false,
        displayName: "Profile User",
        customClaims: { department: "platform" },
      });
      return mockResponse({
        status: 200,
        jsonBody: {
          userId: "user-1",
          subject: "local-user-updated",
          subjectPolicy: "explicit",
          email: "profile@example.test",
          emailVerified: false,
          displayName: "Profile User",
          customClaims: { department: "platform" },
          version: 4,
          updatedAt: "2026-03-13T00:00:00Z",
        },
      });
    },
    (call) => {
      assert.equal(call.method, "GET");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/sessions",
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          sessions: [
            {
              id: "session-fingerprint",
              authTimeEpochSeconds: 1710200000,
              acr: "pwd",
            },
          ],
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/" +
          "sessions/session-fingerprint/revoke",
      );
      assert.deepEqual(parseJsonBody(call), {});
      return mockResponse({ status: 204 });
    },
    (call) => {
      assert.equal(call.method, "GET");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/grants",
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          grants: [
            {
              id: "grant-fingerprint",
              source: "refresh_token",
              clientId: "client-1",
              scopes: ["openid", "profile"],
              audience: "api://default",
              authorizationDetails: { type: "example" },
              authTimeEpochSeconds: 1710200000,
              acr: "pwd",
              expiresAtEpochSeconds: 1710300000,
            },
          ],
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/" +
          "grants/grant-fingerprint/revoke",
      );
      assert.deepEqual(parseJsonBody(call), {});
      return mockResponse({ status: 204 });
    },
    (call) => {
      assert.equal(call.method, "GET");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/refreshTokens",
      );
      return mockResponse({
        status: 200,
        jsonBody: {
          refreshTokens: [
            {
              id: "refresh-fingerprint",
              clientId: "client-1",
              scopes: ["openid", "profile"],
              resource: "api://default",
              senderBinding: "bearer",
              authorizationDetails: { type: "example" },
              authTimeEpochSeconds: 1710200000,
              acr: "pwd",
              expiresAtEpochSeconds: 1710400000,
              rotationCount: 2,
            },
          ],
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/user-1/" +
          "refreshTokens/refresh-fingerprint/revoke",
      );
      assert.deepEqual(parseJsonBody(call), {});
      return mockResponse({ status: 204 });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/invitations",
      );
      assert.deepEqual(parseJsonBody(call), {
        subject: "invited-user",
        email: "invited@example.test",
        expiresInSeconds: 7200,
      });
      return mockResponse({
        status: 200,
        jsonBody: {
          user: {
            id: "user-2",
            environmentId: "env-1",
            subject: "invited-user",
            status: "INVITED",
            createdAt: "2026-03-13T00:00:00Z",
            updatedAt: "2026-03-13T00:00:00Z",
            email: "invited@example.test",
          },
          activation: {
            token: "invite-activation-token",
            redeemUrl: "https://issuer.example.test/auth/activate?token=invite-activation-token",
            recoveryToken: {
              id: "rt-invite",
              purpose: "activation",
              status: "ACTIVE",
              expiresAt: "2026-03-13T02:00:00Z",
              redeemedAt: null,
              revokedAt: null,
              createdAt: "2026-03-13T00:00:00Z",
            },
          },
        },
      });
    },
    (call) => {
      assert.equal(call.method, "POST");
      assert.equal(
        new URL(call.url).pathname,
        "/api/v1/teams/team-default/environments/env-1/users/importCsv",
      );
      assert.deepEqual(parseJsonBody(call), {
        csv: "subject,email\\nimported-user,imported@example.test\\n",
        issueActivationTokens: true,
        activationTokenExpiresInSeconds: 7200,
      });
      return mockResponse({
        status: 200,
        jsonBody: {
          importedUsers: [
            {
              rowNumber: 2,
              user: {
                id: "user-3",
                environmentId: "env-1",
                subject: "imported-user",
                status: "INVITED",
                createdAt: "2026-03-13T00:00:00Z",
                updatedAt: "2026-03-13T00:00:00Z",
                email: "imported@example.test",
              },
              activation: {
                token: "import-activation-token",
                redeemUrl:
                  "https://issuer.example.test/auth/activate" +
                  "?token=import-activation-token",
                recoveryToken: {
                  id: "rt-import",
                  purpose: "activation",
                  status: "ACTIVE",
                  expiresAt: "2026-03-13T02:00:00Z",
                  redeemedAt: null,
                  revokedAt: null,
                  createdAt: "2026-03-13T00:00:00Z",
                },
              },
            },
          ],
        },
      });
    },
  ]);
  const userLifecycleClient = createManagementClient({
    baseUrl: "https://admin.example.test",
    fetchImpl: userLifecycleQueue.fetchImpl,
    sessionStore,
    defaultTeamId: "team-default",
  });
  const listedUsers = await userLifecycleClient.listUsers({
    environmentId: "env-1",
    pageSize: 50,
    includeDeleted: true,
  });
  assert.equal(listedUsers.users.length, 1);
  assert.equal(listedUsers.users[0]?.subject, "local-user");
  const createdUser = await userLifecycleClient.createUser({
    environmentId: "env-1",
    subject: "local-user",
    email: "local-user@example.test",
  });
  assert.equal(createdUser.email, "local-user@example.test");
  const updatedUser = await userLifecycleClient.updateUser({
    environmentId: "env-1",
    userId: "user-1",
    subject: "local-user-updated",
    email: "updated@example.test",
  });
  assert.equal(updatedUser.subject, "local-user-updated");
  const deletedUser = await userLifecycleClient.deleteUser({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(deletedUser, null);
  const restoredUser = await userLifecycleClient.restoreUser({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(restoredUser.status, "ACTIVE");
  const credentials = await userLifecycleClient.getUserCredentials({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(credentials.password?.id, "pwd-1");
  const activationToken = await userLifecycleClient.issueActivationToken({
    environmentId: "env-1",
    userId: "user-1",
    expiresInSeconds: 3600,
  });
  assert.equal(activationToken.recoveryToken.purpose, "activation");
  const passwordResetToken = await userLifecycleClient.issuePasswordResetToken({
    environmentId: "env-1",
    userId: "user-1",
    expiresInSeconds: 1800,
  });
  assert.equal(passwordResetToken.recoveryToken.purpose, "password_reset");
  const revokedPassword = await userLifecycleClient.revokeUserPasswordCredential({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(revokedPassword.password, null);
  const revokedRecovery = await userLifecycleClient.revokeUserRecoveryToken({
    environmentId: "env-1",
    userId: "user-1",
    tokenId: "rt-reset",
  });
  assert.equal(revokedRecovery.recoveryTokens.length, 0);
  const profile = await userLifecycleClient.getUserProfile({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(profile.customClaims.department, "security");
  const updatedProfile = await userLifecycleClient.updateUserProfile({
    environmentId: "env-1",
    userId: "user-1",
    baseVersion: 3,
    email: "profile@example.test",
    emailVerified: false,
    displayName: "Profile User",
    customClaims: { department: "platform" },
  });
  assert.equal(updatedProfile.version, 4);
  const sessions = await userLifecycleClient.listUserSessions({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(sessions.sessions[0]?.id, "session-fingerprint");
  const revokedSession = await userLifecycleClient.revokeUserSession({
    environmentId: "env-1",
    userId: "user-1",
    sessionId: "session-fingerprint",
  });
  assert.equal(revokedSession, null);
  const grants = await userLifecycleClient.listUserGrants({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(grants.grants[0]?.id, "grant-fingerprint");
  const revokedGrant = await userLifecycleClient.revokeUserGrant({
    environmentId: "env-1",
    userId: "user-1",
    grantId: "grant-fingerprint",
  });
  assert.equal(revokedGrant, null);
  const refreshInventory = await userLifecycleClient.listUserRefreshTokens({
    environmentId: "env-1",
    userId: "user-1",
  });
  assert.equal(refreshInventory.refreshTokens[0]?.rotationCount, 2);
  const revokedRefreshInventory = await userLifecycleClient.revokeUserRefreshToken({
    environmentId: "env-1",
    userId: "user-1",
    refreshTokenId: "refresh-fingerprint",
  });
  assert.equal(revokedRefreshInventory, null);
  const invitedUser = await userLifecycleClient.inviteUser({
    environmentId: "env-1",
    subject: "invited-user",
    email: "invited@example.test",
    expiresInSeconds: 7200,
  });
  assert.equal(invitedUser.activation.recoveryToken.id, "rt-invite");
  const importedUsers = await userLifecycleClient.importUsersCsv({
    environmentId: "env-1",
    csv: "subject,email\\nimported-user,imported@example.test\\n",
    issueActivationTokens: true,
    activationTokenExpiresInSeconds: 7200,
  });
  assert.equal(importedUsers.importedUsers[0]?.activation?.recoveryToken.id, "rt-import");
  pass("supports end-user lifecycle operations");

  assert.equal(calls[0]?.credentials, "include");
  assert.equal(calls[1]?.method, "POST");
  pass("requests default to credentialed fetch semantics");

  const failureQueue = createFetchQueue([
    () => mockResponse({
      status: 401,
      jsonBody: {
        errorCode: "unauthenticated",
        message: "Session cookie required",
        requestId: "req-123",
      },
    }),
  ]);
  const failingClient = createManagementClient({
    baseUrl: "https://admin.example.com",
    fetchImpl: failureQueue.fetchImpl,
    sessionStore: createInMemoryManagementSessionStore({
      origin: "https://admin.example.com",
    }),
  });

  await assert.rejects(
    () => failingClient.listTeams(),
    (error) => {
      assert.ok(error instanceof ManagementApiError);
      assert.equal(error.status, 401);
      assert.equal(error.errorCode, "unauthenticated");
      assert.equal(error.requestId, "req-123");
      assert.equal(error.error?.requestId, "req-123");
      const raw = error.raw as { requestId?: string } | null | undefined;
      assert.equal(raw?.requestId, "req-123");
      return true;
    },
  );
  pass("non-2xx JSON responses raise ManagementApiError with UI-friendly error fields");

  console.log(`=== ${passed} management-client checks passed ===`);
}

main().catch((error) => {
  console.error("[fail] management_client_test:", error);
  process.exitCode = 1;
});
