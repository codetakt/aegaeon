import {
  initCore,
  VC_ALG,
  VC_DPOP_FLAGS,
  VC_JWT_FLAGS,
  VC_STATUS,
} from "../../scripts/sdk/runtime_web_reference.ts";

const statusNode = document.getElementById("status");
const resultsNode = document.getElementById("results");
const textEncoder = new TextEncoder();
const subtle = globalThis.crypto?.subtle;

const state = {
  passed: 0,
  failed: 0,
};
const searchParams = new URLSearchParams(globalThis.location?.search ?? "");
const allowInsecureTestContext = searchParams.get("allow_insecure_test_context") === "1";

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

function b64urlJson(value) {
  return encodeBase64Url(textEncoder.encode(JSON.stringify(value)));
}

function encodeBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function encodeBase64Url(bytes) {
  return encodeBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256(bytes) {
  assert(subtle, "SubtleCrypto must be available");
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function signCompact({
  header,
  payload,
  privateKey,
}) {
  assert(subtle, "SubtleCrypto must be available");
  const headerB64 = b64urlJson(header);
  const payloadB64 = b64urlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = new Uint8Array(
    await subtle.sign(
      { name: "Ed25519" },
      privateKey,
      textEncoder.encode(signingInput),
    ),
  );
  return {
    compact: `${signingInput}.${encodeBase64Url(signature)}`,
    signingInput: textEncoder.encode(signingInput),
    signature,
  };
}

function updateStatus(ok) {
  statusNode.textContent = ok ? `PASS (${state.passed} checks)` : `FAIL (${state.failed} failures)`;
  statusNode.dataset.status = ok ? "pass" : "fail";
  window.__AEGAEON_WEB_SMOKE__ = {
    done: true,
    ok,
    passed: state.passed,
    failed: state.failed,
    allowInsecureTestContext,
  };
}

async function main() {
  try {
    assert(Boolean(subtle), "SubtleCrypto must be available");
    if (!allowInsecureTestContext) {
      assert(globalThis.isSecureContext === true, "runtime-web smoke must run in a secure context");
    }

    const { manifest, handle } = await initCore(
      allowInsecureTestContext ? { requireSecureContext: false } : {},
    );
    assert(
      typeof manifest.sha256 === "string" && manifest.sha256.length > 0,
      "manifest sha256 must be present",
    );
    assert(handle.abiVersion() === 2, "ABI version must be 2");
    pass(
      allowInsecureTestContext
        ? "runtime-web loads the packaged artefact in browser smoke fallback mode"
        : "runtime-web loads the packaged artefact in a secure browser context",
    );

    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const pkceGenerated = await handle.pkceGenerate({ verifier });
    assert(pkceGenerated.statusCode === VC_STATUS.OK, "pkceGenerate must return OK");
    assert(pkceGenerated.challenge === challenge, "PKCE challenge must match RFC 7636 vector");
    const pkceVerified = await handle.pkceVerify({ verifier, challenge });
    assert(pkceVerified.statusCode === VC_STATUS.OK, "pkceVerify must return OK");
    pass("runtime-web exposes PKCE generation and verification");

    const now = 1_710_000_000;
    const jwtKeys = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const jwtPublicJwk = await subtle.exportKey("jwk", jwtKeys.publicKey);
    const jwt = await signCompact({
      header: { alg: "EdDSA", kid: "browser-kid-1" },
      payload: {
        iss: "https://issuer.example",
        aud: ["client-123", "other"],
        exp: now + 300,
        iat: now,
      },
      privateKey: jwtKeys.privateKey,
    });

    const jwtVerified = await handle.jwtVerify({
      jwt: jwt.compact,
      publicKey: jwtPublicJwk,
      expectedIssuer: "https://issuer.example",
      expectedAudience: "client-123",
      nowUnixTimeSeconds: now,
      allowedAlgorithmsBitmask: VC_ALG.EDDSA,
      flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
    });
    assert(jwtVerified.statusCode === VC_STATUS.OK, "jwtVerify must return OK");
    assert(
      toHex(jwtVerified.payloadHash) === toHex(await sha256(jwt.signingInput)),
      "payload hash must match",
    );
    pass("runtime-web verifies compact JWT inputs on the EdDSA path");

    handle.clearReplayStore();
    const accessToken = "browser-access-token";
    const dpopNow = now + 30;
    const dpop = await signCompact({
      header: { typ: "dpop+jwt", alg: "EdDSA", jwk: jwtPublicJwk },
      payload: {
        htm: "GET",
        htu: "https://rp.example/resource",
        iat: dpopNow,
        jti: "browser-jti-1",
        ath: encodeBase64Url(await sha256(textEncoder.encode(accessToken))),
      },
      privateKey: jwtKeys.privateKey,
    });

    const dpopVerified = await handle.dpopVerify({
      dpopProof: dpop.compact,
      httpMethod: "GET",
      httpUri: "https://rp.example/resource",
      accessToken,
      replayNamespace: "browser-issuer-a",
      nowUnixTimeSeconds: dpopNow,
      maxAgeSeconds: 300,
      maxFutureSkewSeconds: 60,
      allowedAlgorithmsBitmask: VC_ALG.EDDSA,
      flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
    });
    assert(dpopVerified.statusCode === VC_STATUS.OK, "dpopVerify must return OK");
    pass("runtime-web verifies compact DPoP proofs");

    handle.clearReplayStore();
    const dpopClaims = await signCompact({
      header: { typ: "dpop+jwt", alg: "EdDSA", jwk: jwtPublicJwk },
      payload: {
        htm: "POST",
        htu: "https://rp.example/token",
        iat: dpopNow + 1,
        jti: "browser-jti-claims",
        ath: encodeBase64Url(await sha256(textEncoder.encode("claims-token"))),
      },
      privateKey: jwtKeys.privateKey,
    });

    const dpopClaimsVerified = await handle.dpopVerifyClaims({
      httpMethod: "POST",
      httpUri: "https://rp.example/token",
      signingInput: dpopClaims.signingInput,
      signature: dpopClaims.signature,
      publicKey: jwtPublicJwk,
      replayNamespace: "browser-issuer-b",
      accessToken: "claims-token",
      ath: encodeBase64Url(await sha256(textEncoder.encode("claims-token"))),
      jti: "browser-jti-claims",
      iatSeconds: BigInt(dpopNow + 1),
      nowUnixTimeSeconds: BigInt(dpopNow + 1),
      maxAgeSeconds: 300,
      maxFutureSkewSeconds: 60,
      allowedAlgorithmsBitmask: VC_ALG.EDDSA,
      flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
    });
    assert(dpopClaimsVerified.statusCode === VC_STATUS.OK, "dpopVerifyClaims must return OK");
    pass("runtime-web verifies claims-based DPoP inputs");

    updateStatus(true);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
    updateStatus(false);
    console.error("[runtime-web-harness]", error);
  }
}

window.__AEGAEON_WEB_SMOKE__ = {
  done: false,
  ok: false,
  passed: 0,
  failed: 0,
  allowInsecureTestContext,
};
main();
