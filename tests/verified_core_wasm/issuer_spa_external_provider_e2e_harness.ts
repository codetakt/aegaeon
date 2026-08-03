import * as issuerSpa from "@aegaeon/issuer-spa";
import { VC_JWT_FLAGS, VC_STATUS } from "@aegaeon/runtime-web";

const {
  createSessionStorageSessionStore,
  createSessionStorageTransactionStore,
  fetchIssuerMetadata,
  finishLogin,
  initIssuerSpaRuntime,
  persistLoginSession,
  restoreLoginSession,
  startLoginFromIssuerMetadata,
  buildLogoutUrlFromIssuerMetadata,
} = issuerSpa as any;

const statusNode = document.getElementById("status");
const resultsNode = document.getElementById("results");
const sessionNode = document.getElementById("session-record");

const state = {
  passed: 0,
  failed: 0,
};

function appendResult(kind, message) {
  const item = document.createElement("li");
  item.className = kind;
  item.textContent = message;
  resultsNode.appendChild(item);
}

function pass(message) {
  state.passed += 1;
  appendResult("ok", `[ok] ${message}`);
}

function fail(message) {
  state.failed += 1;
  appendResult("fail", `[fail] ${message}`);
}

function note(message) {
  appendResult("note", `[note] ${message}`);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function updateStatus(ok) {
  statusNode.textContent = ok ? `PASS (${state.passed} checks)` : `FAIL (${state.failed} failures)`;
  statusNode.dataset.status = ok ? "pass" : "fail";
  window.__AEGAEON_EXTERNAL_PROVIDER_E2E__ = {
    done: true,
    ok,
    passed: state.passed,
    failed: state.failed,
  };
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function decodeJwtPart(token, index, label) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(`${label} must be a compact JWT`);
  }
  return JSON.parse(decodeBase64Url(parts[index]));
}

function selectJwk(jwks, kid) {
  if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error("jwks must contain at least one signing key");
  }
  if (kid == null) {
    return jwks.keys[0];
  }
  return jwks.keys.find((entry) => entry.kid === kid) ?? null;
}

async function fetchExternalProviderConfig() {
  const response = await fetch("/test-config/external-provider", {
    headers: {
      accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`external provider config unavailable: HTTP ${response.status}`);
  }
  return response.json();
}

async function exchangeAuthorizationCode({ tokenRequestBody, tokenProxyUrl }) {
  const response = await fetch(tokenProxyUrl, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: tokenRequestBody.toString(),
  });
  if (!response.ok) {
    throw new Error(`token endpoint proxy failed with status ${response.status}`);
  }
  return response.json();
}

async function main() {
  const transactionStore = createSessionStorageTransactionStore();
  const sessionStore = createSessionStorageSessionStore();
  const callbackUrl = new URL(window.location.href);
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const redirectUri = `${window.location.origin}/tests/browser/issuer_spa_external_provider_e2e.html`;

  try {
    const config = await fetchExternalProviderConfig();
    assert(typeof config.issuer === "string" && config.issuer.length > 0, "config.issuer must be present");
    assert(typeof config.clientId === "string" && config.clientId.length > 0, "config.clientId must be present");

    const { handle } = await initIssuerSpaRuntime();
    pass("issuer-spa runtime initialized for the external provider lane");

    const callbackCode = callbackUrl.searchParams.get("code");
    const callbackState = callbackUrl.searchParams.get("state");

    if (!callbackCode || !callbackState) {
      sessionStorage.removeItem("aegaeon.issuer-spa.session");

      const issuerMetadata = await fetchIssuerMetadata({
        issuer: config.issuer,
        discoveryUrl: config.discoveryUrl,
        expectedIssuer: config.issuer,
      });
      assert(issuerMetadata.issuer === config.issuer, "issuer metadata must preserve the configured issuer");
      pass("issuer-spa fetched upstream issuer metadata from a proxied external discovery document");

      const login = await startLoginFromIssuerMetadata({
        runtimeHandle: handle,
        transactionStore,
        issuerMetadata,
        clientId: config.clientId,
        redirectUri,
        verifier,
        scope: "openid profile email",
        state: "state-external-provider-123",
        nonce: "nonce-external-provider-123",
        prompt: "login",
      });
      assert(typeof login.redirectUrl === "string" && login.redirectUrl.length > 0, "redirectUrl must be present");
      pass("issuer-spa startLoginFromIssuerMetadata produced an external-provider authorization redirect");
      window.location.assign(login.redirectUrl);
      return;
    }

    const completion = await finishLogin({
      input: window.location.href,
      transactionStore,
    });
    pass("issuer-spa resumed the callback and rebuilt the token exchange request");

    const tokenResponse = await exchangeAuthorizationCode({
      tokenRequestBody: completion.tokenRequestBody,
      tokenProxyUrl: config.tokenProxyUrl,
    });
    assert(typeof tokenResponse.id_token === "string" && tokenResponse.id_token.length > 0, "id_token must be present");
    assert(typeof tokenResponse.access_token === "string" && tokenResponse.access_token.length > 0, "access_token must be present");
    pass("issuer-spa completed the token exchange through the local proxy");

    const header = decodeJwtPart(tokenResponse.id_token, 0, "protected header");
    const payload = decodeJwtPart(tokenResponse.id_token, 1, "payload");
    const jwksResponse = await fetch(config.jwksUrl, {
      headers: {
        accept: "application/json",
      },
    });
    if (!jwksResponse.ok) {
      throw new Error(`jwks proxy failed with status ${jwksResponse.status}`);
    }
    const jwks = await jwksResponse.json();
    const jwk = selectJwk(jwks, header.kid);
    assert(jwk != null, "matching JWK must exist for the external provider id_token");

    const verified = await handle.jwtVerify({
      jwt: tokenResponse.id_token,
      publicKey: jwk,
      expectedIssuer: config.issuer,
      expectedAudience: config.clientId,
      nowUnixTimeSeconds: Math.floor(Date.now() / 1000),
      flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
    });
    assert(verified.statusCode === VC_STATUS.OK, `runtime-web jwtVerify failed with status ${verified.statusCode}`);
    pass("runtime-web verified the external-provider RS256 ID Token through the promoted client slice");

    const session = await persistLoginSession({
      sessionStore,
      transaction: completion.transaction,
      authorizationResponse: completion.response,
      tokenResponse,
      issuer: config.issuer,
      subject: payload.sub ?? null,
      extra: {
        provider: config.providerName ?? "external-provider",
      },
    });
    assert(session.subject === payload.sub, "session subject must match the verified id_token subject");
    pass("issuer-spa persisted the external-provider federated session in browser session storage");

    if (typeof config.userinfoProxyUrl === "string" && config.userinfoProxyUrl.length > 0) {
      const userinfoResponse = await fetch(config.userinfoProxyUrl, {
        headers: {
          authorization: `Bearer ${tokenResponse.access_token}`,
        },
      });
      if (userinfoResponse.ok) {
        const userinfo = await userinfoResponse.json();
        assert(userinfo.sub === payload.sub, "userinfo subject must match the verified id_token subject");
        pass("issuer-spa confirmed that the external-provider userinfo subject matches the verified id_token");
      } else {
        note(`userinfo check skipped: HTTP ${userinfoResponse.status}`);
      }
    }

    const issuerMetadata = await fetchIssuerMetadata({
      issuer: config.issuer,
      discoveryUrl: config.discoveryUrl,
      expectedIssuer: config.issuer,
    });
    if (issuerMetadata.endSessionEndpoint) {
      const logoutUrl = buildLogoutUrlFromIssuerMetadata({
        issuerMetadata,
        idTokenHint: tokenResponse.id_token,
        postLogoutRedirectUri: `${window.location.origin}/post-logout`,
        state: "logout-external-provider-123",
      });
      assert(typeof logoutUrl === "string" && logoutUrl.length > 0, "logout URL must be present");
      pass("issuer-spa derived an RP-initiated logout URL from external provider metadata");
    } else {
      note("logout derivation skipped: external provider does not advertise end_session_endpoint");
    }

    const restoredSession = await restoreLoginSession({
      sessionStore,
      required: true,
    });
    sessionNode.textContent = JSON.stringify(restoredSession, null, 2);
    callbackUrl.searchParams.delete("code");
    callbackUrl.searchParams.delete("state");
    window.history.replaceState({}, "", callbackUrl.toString());
    updateStatus(true);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
    updateStatus(false);
    console.error("[issuer-spa-external-provider-e2e]", error);
  }
}

window.__AEGAEON_EXTERNAL_PROVIDER_E2E__ = {
  done: false,
  ok: false,
  passed: 0,
  failed: 0,
};

main();
