#!/usr/bin/env node
import assert from "node:assert/strict";

const {
  CLIENT_CRYPTO_PROFILES,
  DEFAULT_CLIENT_CRYPTO_PROFILE,
  ISSUER_SPA_DEFAULTS,
  buildLogoutUrl,
  buildLogoutUrlFromIssuerMetadata,
  clearLoginTransaction,
  clearLoginSession,
  completeLogin,
  createInMemoryTransactionStore,
  createInMemorySessionStore,
  createSessionStorageSessionStore,
  createSessionStorageTransactionStore,
  fetchIssuerMetadata,
  finishLogin,
  persistLoginSession,
  restoreLoginTransaction,
  restoreLoginSession,
  startLogin,
  startLoginFromIssuerMetadata,
  startLoginWithDiscovery,
} = await import("../dist/index.js");

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

let passed = 0;

function pass(message: string): void {
  passed += 1;
  console.log(`  [ok] ${message}`);
}

function createFakeStorage(): StorageLike {
  const entries = new Map<string, string>();
  return {
    getItem(key: string) {
      return entries.has(key) ? (entries.get(key) ?? null) : null;
    },
    setItem(key: string, value: string) {
      entries.set(key, value);
    },
    removeItem(key: string) {
      entries.delete(key);
    },
  };
}

function createDiscoveryResponse(): Response {
  return new Response(
    JSON.stringify({
      issuer: "https://issuer.example",
      authorization_endpoint: "https://issuer.example/authorize",
      token_endpoint: "https://issuer.example/token",
      end_session_endpoint: "https://issuer.example/logout",
      response_types_supported: ["code"],
      code_challenge_methods_supported: ["S256"],
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json",
      },
    },
  );
}

async function main() {
  console.log("=== @aegaeon/issuer-spa Tests ===");

  assert.equal(DEFAULT_CLIENT_CRYPTO_PROFILE, CLIENT_CRYPTO_PROFILES.AEGAEON_RS256);
  assert.equal(ISSUER_SPA_DEFAULTS.transactionStorageKey, "aegaeon.issuer-spa.transaction");
  assert.equal(ISSUER_SPA_DEFAULTS.sessionStorageKey, "aegaeon.issuer-spa.session");
  pass("exports the expected issuer-spa defaults");

  const memoryStore = createInMemoryTransactionStore();
  assert.equal(await restoreLoginTransaction({ transactionStore: memoryStore }), null);
  pass("in-memory transaction store is empty by default");

  const loginResult = await startLogin({
    runtimeHandle: {
      pkceGenerate({ verifier }: { verifier: string }) {
        assert.equal(verifier, "verifier-123");
        return {
          statusCode: 0,
          challenge: "derived-challenge-123",
        };
      },
    },
    transactionStore: memoryStore,
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://issuer.example/callback",
    verifier: "verifier-123",
    scope: "openid email",
    state: "state-123",
    nonce: "nonce-123",
    prompt: "login",
  });
  assert.equal(loginResult.redirectUrl, loginResult.authorizationUrl);
  assert.equal(loginResult.transaction.codeChallenge, "derived-challenge-123");
  const restoredMemoryTransaction = await restoreLoginTransaction({
    transactionStore: memoryStore,
  });
  assert.ok(restoredMemoryTransaction);
  assert.equal(restoredMemoryTransaction.state, "state-123");
  pass("startLogin persists the PKCE transaction and returns the redirect URL");

  const fetchedIssuerMetadata = await fetchIssuerMetadata({
    issuer: "https://issuer.example",
    fetch: async (input) => {
      assert.equal(input, "https://issuer.example/.well-known/openid-configuration");
      return createDiscoveryResponse();
    },
  });
  assert.equal(fetchedIssuerMetadata.authorizationEndpoint, "https://issuer.example/authorize");
  pass("fetchIssuerMetadata resolves and validates issuer discovery metadata");

  const metadataTransactionStore = createInMemoryTransactionStore();
  const metadataLogin = await startLoginFromIssuerMetadata({
    runtimeHandle: {
      pkceGenerate() {
        return {
          statusCode: 0,
          challenge: "metadata-challenge-123",
        };
      },
    },
    transactionStore: metadataTransactionStore,
    issuerMetadata: fetchedIssuerMetadata,
    clientId: "client-123",
    redirectUri: "https://issuer.example/callback",
    verifier: "verifier-metadata-123",
    scope: "openid profile",
    state: "state-metadata-123",
    nonce: "nonce-metadata-123",
  });
  assert.equal(new URL(metadataLogin.redirectUrl).pathname, "/authorize");
  const restoredMetadataTransaction = await restoreLoginTransaction({
    transactionStore: metadataTransactionStore,
    required: true,
  });
  assert.ok(restoredMetadataTransaction);
  assert.equal(restoredMetadataTransaction.state, "state-metadata-123");
  pass("startLoginFromIssuerMetadata builds a redirect from discovery metadata");

  const discoveryTransactionStore = createInMemoryTransactionStore();
  const discoveryLogin = await startLoginWithDiscovery({
    runtimeHandle: {
      pkceGenerate() {
        return {
          statusCode: 0,
          challenge: "discovery-challenge-123",
        };
      },
    },
    transactionStore: discoveryTransactionStore,
    issuer: "https://issuer.example",
    fetch: async () => createDiscoveryResponse(),
    clientId: "client-123",
    redirectUri: "https://issuer.example/callback",
    verifier: "verifier-discovery-123",
    scope: "openid profile",
    state: "state-discovery-123",
    nonce: "nonce-discovery-123",
  });
  assert.equal(discoveryLogin.issuerMetadata.issuer, "https://issuer.example");
  assert.equal(new URL(discoveryLogin.redirectUrl).pathname, "/authorize");
  pass("startLoginWithDiscovery fetches metadata and starts the login transaction");

  const tokenExchange = await finishLogin({
    input: "https://issuer.example/callback?code=code-123&state=state-123",
    transactionStore: memoryStore,
  });
  assert.equal(tokenExchange.tokenRequestBody.get("grant_type"), "authorization_code");
  assert.equal(tokenExchange.tokenRequestBody.get("code_verifier"), "verifier-123");
  assert.equal(await restoreLoginTransaction({ transactionStore: memoryStore }), null);
  pass("finishLogin validates the callback, builds the token request, and clears the transaction");

  await startLogin({
    runtimeHandle: {
      pkceGenerate() {
        return {
          statusCode: 0,
          challenge: "derived-challenge-456",
        };
      },
    },
    transactionStore: memoryStore,
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://issuer.example/callback",
    verifier: "verifier-456",
    scope: "openid",
    state: "state-456",
    nonce: "nonce-456",
  });
  await assert.rejects(
    finishLogin({
      input: "https://issuer.example/callback?code=code-456&state=wrong-state",
      transactionStore: memoryStore,
    }),
    /state mismatch/,
  );
  const restoredFailedTransaction = await restoreLoginTransaction({
    transactionStore: memoryStore,
    required: true,
  });
  assert.ok(restoredFailedTransaction);
  assert.equal(restoredFailedTransaction.state, "state-456");
  pass("finishLogin fails closed on callback state mismatch and keeps the stored transaction");

  await clearLoginTransaction({ transactionStore: memoryStore });
  await assert.rejects(
    finishLogin({
      input: "https://issuer.example/callback?code=code-789&state=state-789",
      transactionStore: memoryStore,
    }),
    /login transaction not found/,
  );
  pass("finishLogin rejects when no transaction is stored");

  const fakeStorage = createFakeStorage();
  const sessionStore = createSessionStorageTransactionStore({
    storage: fakeStorage,
    key: "issuer-spa-login",
  });
  await sessionStore.save({
    clientId: "client-123",
    redirectUri: "https://issuer.example/callback",
    scope: "openid",
    state: "state-session",
    nonce: "nonce-session",
    verifier: "verifier-session",
    codeChallenge: "challenge-session",
    codeChallengeMethod: "S256",
    responseType: "code",
    responseMode: null,
    prompt: null,
    audience: null,
    extraParams: {},
  });
  const storedSessionTransaction = await sessionStore.load();
  assert.ok(storedSessionTransaction && typeof storedSessionTransaction === "object");
  assert.equal((storedSessionTransaction as { state: string }).state, "state-session");
  await sessionStore.clear();
  assert.equal(await sessionStore.load(), null);
  pass("session storage adapter round-trips transaction state");

  const loginSessionStore = createInMemorySessionStore();
  assert.equal(await restoreLoginSession({ sessionStore: loginSessionStore }), null);
  pass("in-memory session store is empty by default");

  const persistedSession = await persistLoginSession({
    sessionStore: loginSessionStore,
    transaction: {
      clientId: "client-123",
      redirectUri: "https://issuer.example/callback",
      scope: "openid email",
      state: "state-persisted-123",
      nonce: "nonce-persisted-123",
      verifier: "verifier-persisted-123",
      codeChallenge: "challenge-persisted-123",
      codeChallengeMethod: "S256",
      responseType: "code",
      responseMode: null,
      prompt: null,
      audience: null,
      extraParams: {},
    },
    authorizationResponse: {
      code: "code-persisted-123",
      state: "state-persisted-123",
    },
    tokenResponse: {
      access_token: "access-token-persisted-123",
      id_token: "id-token-persisted-123",
      token_type: "Bearer",
      expires_in: 300,
    },
    issuer: "https://issuer.example",
    subject: "subject-persisted-123",
    extra: {
      connectionId: "connection-persisted-123",
    },
  });
  assert.equal(persistedSession.accessToken, "access-token-persisted-123");
  const restoredPersistedSession = await restoreLoginSession({
    sessionStore: loginSessionStore,
    required: true,
  });
  assert.ok(restoredPersistedSession);
  assert.equal(restoredPersistedSession.subject, "subject-persisted-123");
  pass("persistLoginSession stores a normalized federated session snapshot");

  const sessionStorageStore = createSessionStorageSessionStore({
    storage: fakeStorage,
    key: "issuer-spa-session",
  });
  await sessionStorageStore.save(persistedSession);
  const storedPersistedSession = await sessionStorageStore.load();
  assert.ok(storedPersistedSession && typeof storedPersistedSession === "object");
  assert.equal((storedPersistedSession as { idToken: string }).idToken, "id-token-persisted-123");
  await sessionStorageStore.clear();
  assert.equal(await sessionStorageStore.load(), null);
  pass("session storage session adapter round-trips federated session state");

  const completedTransactionStore = createInMemoryTransactionStore();
  const completedSessionStore = createInMemorySessionStore();
  await startLogin({
    runtimeHandle: {
      pkceGenerate() {
        return {
          statusCode: 0,
          challenge: "complete-challenge-123",
        };
      },
    },
    transactionStore: completedTransactionStore,
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://issuer.example/callback",
    verifier: "verifier-complete-123",
    scope: "openid profile",
    state: "state-complete-123",
    nonce: "nonce-complete-123",
  });
  const completedSession = await completeLogin({
    input: "https://issuer.example/callback?code=code-complete-123&state=state-complete-123",
    transactionStore: completedTransactionStore,
    sessionStore: completedSessionStore,
    issuer: "https://issuer.example",
    subject: "subject-complete-123",
    sessionExtra: {
      tenantId: "tenant-complete-123",
    },
    async exchangeAuthorizationCode({ tokenRequestBody }: { tokenRequestBody: URLSearchParams }) {
      assert.equal(tokenRequestBody.get("code_verifier"), "verifier-complete-123");
      return {
        access_token: "access-token-complete-123",
        refresh_token: "refresh-token-complete-123",
        id_token: "id-token-complete-123",
        token_type: "DPoP",
        scope: "openid profile",
        expires_in: 600,
      };
    },
  });
  assert.ok(completedSession.session);
  assert.equal(completedSession.session.idToken, "id-token-complete-123");
  assert.equal(
    await restoreLoginTransaction({ transactionStore: completedTransactionStore }),
    null,
  );
  const restoredCompletedSession = await restoreLoginSession({
    sessionStore: completedSessionStore,
    required: true,
  });
  assert.ok(restoredCompletedSession);
  assert.equal(
    (restoredCompletedSession.extra as { tenantId?: string }).tenantId,
    "tenant-complete-123",
  );
  pass(
    "completeLogin exchanges the code via callback, stores the session, and clears the transaction",
  );

  await clearLoginSession({ sessionStore: completedSessionStore });
  assert.equal(await restoreLoginSession({ sessionStore: completedSessionStore }), null);
  pass("clearLoginSession removes the stored federated session");

  const logoutUrl = buildLogoutUrl({
    endSessionEndpoint: "https://issuer.example/logout",
    idTokenHint: "id-token",
    postLogoutRedirectUri: "https://issuer.example/post-logout",
    state: "logout-state-123",
  });
  const logout = new URL(logoutUrl);
  assert.equal(logout.searchParams.get("id_token_hint"), "id-token");
  assert.equal(logout.searchParams.get("state"), "logout-state-123");
  pass("buildLogoutUrl produces RP-initiated logout parameters");

  const discoveryLogoutUrl = buildLogoutUrlFromIssuerMetadata({
    issuerMetadata: fetchedIssuerMetadata,
    idTokenHint: "id-token",
    postLogoutRedirectUri: "https://issuer.example/post-logout",
    state: "logout-discovery-123",
  });
  assert.equal(new URL(discoveryLogoutUrl).pathname, "/logout");
  pass("buildLogoutUrlFromIssuerMetadata derives logout parameters from issuer metadata");

  console.log(`=== ${passed} issuer-spa checks passed ===`);
}

main().catch((error) => {
  console.error("[fail] issuer_spa_test:", error);
  process.exitCode = 1;
});
