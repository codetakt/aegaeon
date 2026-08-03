#!/usr/bin/env node
import assert from "node:assert/strict";

import {
  RP_DEFAULTS,
  buildAuthorizationParameters,
  buildAuthorizationUrl,
  buildAuthorizationUrlFromIssuerMetadata,
  buildEndSessionUrl,
  buildEndSessionUrlFromIssuerMetadata,
  buildFederatedSessionRecord,
  buildPkceAuthorizationRequest,
  buildPkceAuthorizationTransaction,
  fetchIssuerMetadata,
  buildTokenRequestBody,
  buildTokenRequestFromAuthorizationResponse,
  clearAuthorizationTransaction,
  clearFederatedSession,
  createInMemoryAuthorizationTransactionStore,
  createInMemoryFederatedSessionStore,
  finishFederatedLogin,
  normalizeIssuerMetadata,
  parseAuthorizationResponse,
  restoreAuthorizationTransaction,
  restoreFederatedSession,
  startFederatedLogin,
  startFederatedLoginFromIssuerMetadata,
  validateAuthorizationResponse,
} from "../dist/index.js";

let passed = 0;

function pass(message) {
  passed += 1;
  console.log(`  [ok] ${message}`);
}

async function main() {
  console.log("=== @aegaeon/rp-core Tests ===");

  assert.equal(RP_DEFAULTS.scope, "openid");
  assert.equal(RP_DEFAULTS.responseType, "code");
  assert.equal(RP_DEFAULTS.codeChallengeMethod, "S256");
  pass("exports the expected RP defaults");

  const authorizationUrl = buildAuthorizationUrl({
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    scope: ["openid", "profile"],
    state: "state-123",
    nonce: "nonce-123",
    codeChallenge: "challenge-123",
    prompt: "login",
    responseMode: "query",
  });
  const authorization = new URL(authorizationUrl);
  assert.equal(authorization.searchParams.get("response_type"), "code");
  assert.equal(authorization.searchParams.get("scope"), "openid profile");
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.equal(authorization.searchParams.get("nonce"), "nonce-123");
  assert.equal(authorization.searchParams.get("prompt"), "login");
  pass("buildAuthorizationUrl produces an Authorization Code + PKCE request");

  assert.throws(() => buildAuthorizationParameters({
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    scope: "openid profile",
    state: "state-123",
    codeChallenge: "challenge-123",
  }), /nonce/);
  pass("openid requests fail closed when nonce is missing");

  const pkceRequest = await buildPkceAuthorizationRequest({
    runtimeHandle: {
      pkceGenerate({ verifier }) {
        assert.equal(verifier, "verifier-123");
        return {
          statusCode: 0,
          challenge: "derived-challenge-123",
        };
      },
    },
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    verifier: "verifier-123",
    scope: "openid email",
    state: "state-123",
    nonce: "nonce-123",
  });
  assert.equal(pkceRequest.codeChallenge, "derived-challenge-123");
  assert.equal(pkceRequest.authorizationParameters.get("code_challenge"), "derived-challenge-123");
  assert.equal(pkceRequest.authorizationParameters.get("code_challenge_method"), "S256");
  pass("buildPkceAuthorizationRequest delegates code_challenge derivation to the runtime handle");

  const transaction = await buildPkceAuthorizationTransaction({
    runtimeHandle: {
      pkceGenerate() {
        return {
          statusCode: 0,
          challenge: "tx-derived-challenge-123",
        };
      },
    },
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    verifier: "verifier-123",
    scope: "openid email",
    state: "state-123",
    nonce: "nonce-123",
  });
  assert.equal(transaction.transaction.clientId, "client-123");
  assert.equal(transaction.transaction.redirectUri, "https://rp.example/callback");
  assert.equal(transaction.transaction.verifier, "verifier-123");
  assert.equal(transaction.transaction.codeChallenge, "tx-derived-challenge-123");
  pass("buildPkceAuthorizationTransaction captures a reusable RP session snapshot");


  const issuerMetadata = normalizeIssuerMetadata({
    issuer: "https://issuer.example",
    authorization_endpoint: "https://issuer.example/authorize",
    token_endpoint: "https://issuer.example/token",
    end_session_endpoint: "https://issuer.example/logout",
    jwks_uri: "https://issuer.example/jwks",
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256", "plain"],
    id_token_signing_alg_values_supported: ["RS256"],
  });
  assert.equal(issuerMetadata.issuer, "https://issuer.example");
  assert.equal(issuerMetadata.authorizationEndpoint, "https://issuer.example/authorize");
  assert.equal(issuerMetadata.endSessionEndpoint, "https://issuer.example/logout");
  pass("normalizeIssuerMetadata validates OIDC discovery metadata for Authorization Code + PKCE");

  await assert.rejects(
    Promise.resolve().then(() => normalizeIssuerMetadata({
      issuer: "https://issuer.example",
      authorization_endpoint: "https://issuer.example/authorize",
      response_types_supported: ["id_token"],
      code_challenge_methods_supported: ["plain"],
    })),
    /response_type=code/,
  );
  pass("normalizeIssuerMetadata fails closed when code flow support is absent");

  const fetchedIssuerMetadata = await fetchIssuerMetadata({
    issuer: "https://issuer.example",
    fetch: async (input, init) => {
      assert.equal(input, "https://issuer.example/.well-known/openid-configuration");
      assert.equal(init.method, "GET");
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            issuer: "https://issuer.example",
            authorization_endpoint: "https://issuer.example/authorize",
            token_endpoint: "https://issuer.example/token",
            end_session_endpoint: "https://issuer.example/logout",
            jwks_uri: "https://issuer.example/jwks",
            response_types_supported: ["code"],
            code_challenge_methods_supported: ["S256"],
          };
        },
      };
    },
  });
  assert.equal(fetchedIssuerMetadata.tokenEndpoint, "https://issuer.example/token");
  pass("fetchIssuerMetadata resolves and validates the discovery document");

  await fetchIssuerMetadata({
    issuer: "https://issuer.example/mock",
    fetch: async (input) => {
      assert.equal(input, "https://issuer.example/mock/.well-known/openid-configuration");
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            issuer: "https://issuer.example/mock",
            authorization_endpoint: "https://issuer.example/mock/authorize",
            token_endpoint: "https://issuer.example/mock/token",
            response_types_supported: ["code"],
            code_challenge_methods_supported: ["S256"],
          };
        },
      };
    },
  });
  pass("fetchIssuerMetadata preserves issuer path segments when resolving discovery");

  const metadataUrl = buildAuthorizationUrlFromIssuerMetadata({
    issuerMetadata,
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    scope: "openid profile",
    state: "metadata-state-123",
    nonce: "metadata-nonce-123",
    codeChallenge: "metadata-challenge-123",
  });
  assert.equal(new URL(metadataUrl).pathname, "/authorize");
  pass(
    "buildAuthorizationUrlFromIssuerMetadata derives the authorization URL from issuer metadata",
  );

  const metadataLogoutUrl = buildEndSessionUrlFromIssuerMetadata({
    issuerMetadata,
    idTokenHint: "id-token-123",
    postLogoutRedirectUri: "https://rp.example/post-logout",
    state: "logout-state-123",
  });
  assert.equal(new URL(metadataLogoutUrl).pathname, "/logout");
  pass("buildEndSessionUrlFromIssuerMetadata derives the logout URL from issuer metadata");

  const transactionStore = createInMemoryAuthorizationTransactionStore();
  const sessionStore = createInMemoryFederatedSessionStore();
  const federatedLogin = await startFederatedLogin({
    runtimeHandle: {
      pkceGenerate() {
        return {
          statusCode: 0,
          challenge: "federated-challenge-123",
        };
      },
    },
    transactionStore,
    authorizationEndpoint: "https://issuer.example/authorize",
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    verifier: "verifier-federated-123",
    scope: "openid email",
    state: "state-federated-123",
    nonce: "nonce-federated-123",
  });
  assert.equal(federatedLogin.redirectUrl, federatedLogin.authorizationUrl);
  assert.equal(
    (
      await restoreAuthorizationTransaction({
        transactionStore,
        required: true,
      })
    ).state,
    "state-federated-123",
  );
  pass("startFederatedLogin persists the authorization transaction and returns the redirect URL");


  const metadataDrivenLogin = await startFederatedLoginFromIssuerMetadata({
    runtimeHandle: {
      pkceGenerate() {
        return {
          statusCode: 0,
          challenge: "metadata-federated-challenge-123",
        };
      },
    },
    issuerMetadata,
    transactionStore: createInMemoryAuthorizationTransactionStore(),
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    verifier: "verifier-metadata-123",
    scope: "openid email",
    state: "state-metadata-123",
    nonce: "nonce-metadata-123",
  });
  assert.equal(new URL(metadataDrivenLogin.redirectUrl).pathname, "/authorize");
  assert.equal(metadataDrivenLogin.transaction.codeChallenge, "metadata-federated-challenge-123");
  pass("startFederatedLoginFromIssuerMetadata uses discovery metadata for redirect generation");

  const completedFederatedLogin = await finishFederatedLogin({
    input: "https://rp.example/callback?code=code-federated-123&state=state-federated-123",
    transactionStore,
    sessionStore,
    issuer: "https://issuer.example",
    subject: "subject-123",
    sessionExtra: {
      connectionId: "connection-123",
    },
    async exchangeAuthorizationCode({
      tokenRequestBody,
      authorizationResponse,
      transaction: storedTransaction,
    }) {
      assert.equal(tokenRequestBody.get("code"), "code-federated-123");
      assert.equal(tokenRequestBody.get("code_verifier"), "verifier-federated-123");
      assert.equal(authorizationResponse.code, "code-federated-123");
      assert.equal(storedTransaction.clientId, "client-123");
      return {
        access_token: "access-token-123",
        refresh_token: "refresh-token-123",
        id_token: "id-token-123",
        token_type: "DPoP",
        scope: "openid email",
        expires_in: 300,
      };
    },
  });
  assert.equal(completedFederatedLogin.tokenResponse.accessToken, "access-token-123");
  assert.equal(completedFederatedLogin.tokenResponse.idToken, "id-token-123");
  assert.equal(completedFederatedLogin.session.issuer, "https://issuer.example");
  assert.equal(completedFederatedLogin.session.extra.connectionId, "connection-123");
  assert.equal(await restoreAuthorizationTransaction({ transactionStore }), null);
  assert.equal(
    (await restoreFederatedSession({ sessionStore, required: true }))
      .authorizationCode,
    "code-federated-123",
  );
  pass("finishFederatedLogin exchanges the code, stores the session, and clears the transaction");

  const sessionRecord = buildFederatedSessionRecord({
    transaction: completedFederatedLogin.transaction,
    authorizationResponse: completedFederatedLogin.response,
    tokenResponse: {
      access_token: "access-token-456",
      token_type: "Bearer",
    },
    issuer: "https://issuer.example",
    subject: "subject-456",
    createdAt: "2026-03-11T00:00:00.000Z",
    extra: {
      tenantId: "tenant-123",
    },
  });
  assert.equal(sessionRecord.subject, "subject-456");
  assert.equal(sessionRecord.createdAt, "2026-03-11T00:00:00.000Z");
  assert.equal(sessionRecord.extra.tenantId, "tenant-123");
  pass("buildFederatedSessionRecord normalizes a reusable RP session snapshot");

  await clearFederatedSession({ sessionStore });
  assert.equal(await restoreFederatedSession({ sessionStore }), null);
  pass("clearFederatedSession removes the stored RP session");

  const missingTransactionStore = createInMemoryAuthorizationTransactionStore();
  await assert.rejects(
    finishFederatedLogin({
      input: "https://rp.example/callback?code=code-missing-123&state=state-missing-123",
      transactionStore: missingTransactionStore,
      async exchangeAuthorizationCode() {
        return {
          access_token: "access-token-missing",
        };
      },
    }),
    /authorization transaction not found/,
  );
  pass("finishFederatedLogin fails closed when no authorization transaction is stored");

  const staleTransactionStore = createInMemoryAuthorizationTransactionStore();
  await staleTransactionStore.save({
    clientId: "client-123",
    redirectUri: "https://rp.example/callback",
    scope: "openid",
    state: "state-stale-123",
    nonce: "nonce-stale-123",
    verifier: "verifier-stale-123",
    codeChallenge: "challenge-stale-123",
    codeChallengeMethod: "S256",
    responseType: "code",
    responseMode: null,
    prompt: null,
    audience: null,
    extraParams: {},
  });
  await assert.rejects(
    finishFederatedLogin({
      input: "https://rp.example/callback?code=code-stale-123&state=state-stale-123",
      transactionStore: staleTransactionStore,
    }),
    /exchangeAuthorizationCode must be a function/,
  );
  await clearAuthorizationTransaction({ transactionStore: staleTransactionStore });
  assert.equal(
    await restoreAuthorizationTransaction({
      transactionStore: staleTransactionStore,
    }),
    null,
  );
  pass("finishFederatedLogin requires an exchangeAuthorizationCode callback");

  const tokenBody = buildTokenRequestBody({
    code: "code-123",
    redirectUri: "https://rp.example/callback",
    clientId: "client-123",
    codeVerifier: "verifier-123",
  });
  assert.equal(tokenBody.get("grant_type"), "authorization_code");
  assert.equal(tokenBody.get("code_verifier"), "verifier-123");
  pass("buildTokenRequestBody produces an Authorization Code token exchange body");

  const callbackSuccess = parseAuthorizationResponse(
    "https://rp.example/callback?code=code-123&state=state-123",
  );
  assert.equal(callbackSuccess.code, "code-123");
  assert.equal(callbackSuccess.state, "state-123");
  assert.equal(callbackSuccess.error, null);
  pass("parseAuthorizationResponse decodes successful callback parameters");

  const callbackError = parseAuthorizationResponse({
    error: "access_denied",
    error_description: "user denied",
    state: "state-123",
  });
  assert.equal(callbackError.error, "access_denied");
  assert.equal(callbackError.errorDescription, "user denied");
  pass("parseAuthorizationResponse decodes error callback parameters");

  const validated = validateAuthorizationResponse({
    input: "https://rp.example/callback?code=code-123&state=state-123",
    expectedState: "state-123",
  });
  assert.equal(validated.code, "code-123");
  pass("validateAuthorizationResponse enforces expected state");

  assert.throws(() => validateAuthorizationResponse({
    input: "https://rp.example/callback?code=code-123&state=wrong-state",
    expectedState: "state-123",
  }), /state mismatch/);
  pass("validateAuthorizationResponse fails closed on state mismatch");

  const exchange = buildTokenRequestFromAuthorizationResponse({
    input: "https://rp.example/callback?code=code-123&state=state-123",
    transaction: transaction.transaction,
    extraParams: {
      resource: "https://api.example/resource",
    },
  });
  assert.equal(exchange.response.code, "code-123");
  assert.equal(exchange.tokenRequestBody.get("code_verifier"), "verifier-123");
  assert.equal(exchange.tokenRequestBody.get("resource"), "https://api.example/resource");
  pass(
    "buildTokenRequestFromAuthorizationResponse derives a token request " +
      "from the stored transaction",
  );

  assert.throws(() => buildTokenRequestFromAuthorizationResponse({
    input: {
      error: "access_denied",
      state: "state-123",
    },
    transaction: transaction.transaction,
  }), /authorization response returned error/);
  pass("buildTokenRequestFromAuthorizationResponse rejects authorization errors");

  const logoutUrl = buildEndSessionUrl({
    endSessionEndpoint: "https://issuer.example/logout",
    idTokenHint: "id-token",
    postLogoutRedirectUri: "https://rp.example/post-logout",
    state: "logout-state-123",
  });
  const logout = new URL(logoutUrl);
  assert.equal(logout.searchParams.get("id_token_hint"), "id-token");
  assert.equal(
    logout.searchParams.get("post_logout_redirect_uri"),
    "https://rp.example/post-logout",
  );
  assert.equal(logout.searchParams.get("state"), "logout-state-123");
  pass("buildEndSessionUrl produces RP-initiated logout parameters");

  console.log(`=== ${passed} rp-core checks passed ===`);
}

main().catch((error) => {
  console.error("[fail] rp_core_test:", error);
  process.exitCode = 1;
});
