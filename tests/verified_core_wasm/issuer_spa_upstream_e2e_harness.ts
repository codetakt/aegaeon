import * as issuerSpa from "@aegaeon/issuer-spa";

const {
  completeLogin,
  createSessionStorageSessionStore,
  createSessionStorageTransactionStore,
  fetchIssuerMetadata,
  initIssuerSpaRuntime,
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

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function updateStatus(ok) {
  statusNode.textContent = ok ? `PASS (${state.passed} checks)` : `FAIL (${state.failed} failures)`;
  statusNode.dataset.status = ok ? "pass" : "fail";
  window.__AEGAEON_ISSUER_E2E__ = {
    done: true,
    ok,
    passed: state.passed,
    failed: state.failed,
  };
}

async function exchangeAuthorizationCode({ tokenRequestBody }) {
  const response = await fetch("/mock/token", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: tokenRequestBody.toString(),
  });
  if (!response.ok) {
    throw new Error(`token endpoint failed with status ${response.status}`);
  }
  return response.json();
}

async function main() {
  const transactionStore = createSessionStorageTransactionStore();
  const sessionStore = createSessionStorageSessionStore();
  const callbackUrl = new URL(window.location.href);
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const issuer = `${window.location.origin}/mock`;

  try {
    const callbackCode = callbackUrl.searchParams.get("code");
    const callbackState = callbackUrl.searchParams.get("state");

    if (!callbackCode || !callbackState) {
      sessionStorage.removeItem("aegaeon.issuer-spa.session");
      const { handle } = await initIssuerSpaRuntime();
      pass("issuer-spa runtime initialized");

      const issuerMetadata = await fetchIssuerMetadata({
        issuer,
      });
      assert(issuerMetadata.authorizationEndpoint === `${issuer}/authorize`, "issuer metadata must advertise the mock authorization endpoint");
      pass("issuer-spa fetched upstream issuer metadata from discovery");

      const login = await startLoginFromIssuerMetadata({
        runtimeHandle: handle,
        transactionStore,
        issuerMetadata,
        clientId: "client-spa-123",
        redirectUri: `${window.location.origin}/tests/browser/issuer_spa_upstream_e2e.html`,
        verifier,
        scope: "openid profile email",
        state: "state-spa-123",
        nonce: "nonce-spa-123",
        prompt: "login",
      });
      assert(login.redirectUrl.includes("/mock/authorize"), "redirectUrl must target the mock authorization endpoint");
      pass("issuer-spa startLoginFromIssuerMetadata produced an authorization redirect");
      window.location.assign(login.redirectUrl);
      return;
    }

    const completion = await completeLogin({
      input: window.location.href,
      transactionStore,
      sessionStore,
      issuer,
      subject: "subject-mock-user-123",
      sessionExtra: {
        provider: "local-mock-upstream",
      },
      exchangeAuthorizationCode,
    });
    assert(completion.tokenResponse.accessToken?.startsWith("mock-access-token-"), "access token must come from the mock upstream");
    pass("issuer-spa completed the callback-driven authorization code exchange");

    const session = await restoreLoginSession({
      sessionStore,
      required: true,
    });
    assert(session.subject === "subject-mock-user-123", "session subject must match the mock upstream");
    assert(session.extra.provider === "local-mock-upstream", "session extra must preserve provider metadata");
    pass("issuer-spa persisted the federated session in browser session storage");

    const issuerMetadata = await fetchIssuerMetadata({
      issuer,
    });
    const logoutUrl = buildLogoutUrlFromIssuerMetadata({
      issuerMetadata,
      idTokenHint: session.idToken,
      postLogoutRedirectUri: `${window.location.origin}/post-logout`,
      state: "logout-spa-123",
    });
    assert(logoutUrl.includes("/mock/logout"), "logout URL must target the mock end-session endpoint");
    pass("issuer-spa can derive a follow-on RP-initiated logout URL from discovery metadata");

    sessionNode.textContent = JSON.stringify(session, null, 2);
    callbackUrl.searchParams.delete("code");
    callbackUrl.searchParams.delete("state");
    window.history.replaceState({}, "", callbackUrl.toString());
    updateStatus(true);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
    updateStatus(false);
    console.error("[issuer-spa-local-upstream-e2e]", error);
  }
}

window.__AEGAEON_ISSUER_E2E__ = {
  done: false,
  ok: false,
  passed: 0,
  failed: 0,
};

main();
