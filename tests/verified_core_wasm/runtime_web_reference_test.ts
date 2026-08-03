#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash, generateKeyPairSync, sign as signBytes } from "node:crypto";

import {
  CLIENT_CRYPTO_PROFILES,
  DEFAULT_CLIENT_CRYPTO_PROFILE,
  initCore,
  resolveDefaultArtifactUrls,
  resolveDpopAllowedAlgorithmsBitmaskForProfile,
  resolveJwtAllowedAlgorithmsBitmaskForProfile,
  VC_ALG,
  VC_DPOP_FLAGS,
  VC_JWT_FLAGS,
  VC_STATUS,
} from "../../scripts/sdk/runtime_web_reference.ts";

let passed = 0;
const subtle = globalThis.crypto?.subtle;
const textEncoder = new TextEncoder();

function pass(message) {
  passed += 1;
  console.log(`  [ok] ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(Buffer.from(bytes)).digest();
}

function sha256Base64Url(bytes) {
  return createHash("sha256").update(Buffer.from(bytes)).digest("base64url");
}

function b64urlJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

async function signCompact({ header, payload, privateKey }) {
  const headerB64 = b64urlJson(header);
  const payloadB64 = b64urlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  let signature;
  switch (header.alg) {
    case "EdDSA":
      signature = new Uint8Array(signBytes(null, Buffer.from(signingInput, "utf8"), privateKey));
      break;
    case "RS256":
      signature = new Uint8Array(
        signBytes("RSA-SHA256", Buffer.from(signingInput, "utf8"), privateKey),
      );
      break;
    case "ES256":
      signature = new Uint8Array(
        signBytes("sha256", Buffer.from(signingInput, "utf8"), {
          key: privateKey,
          dsaEncoding: "ieee-p1363",
        }),
      );
      break;
    default:
      throw new TypeError(`unsupported signing algorithm ${header.alg}`);
  }
  return {
    compact: `${signingInput}.${Buffer.from(signature).toString("base64url")}`,
    signingInput: textEncoder.encode(signingInput),
    signature,
  };
}

async function main() {
  console.log("=== Verified Core Web Reference Adapter Tests ===");

  assert.ok(subtle, "SubtleCrypto must be available in Node.js 24+");

  const { manifestUrl, wasmUrl } = resolveDefaultArtifactUrls();
  const manifest = JSON.parse(await readFile(new URL(manifestUrl), "utf8"));
  const wasmBytes = new Uint8Array(await readFile(new URL(wasmUrl)));

  await assert.rejects(
    () => initCore({ manifest, wasmBytes, secureContext: false, subtle }),
    /secure context/i,
  );
  pass("initCore fails closed without a secure context");

  const signingKeys = generateKeyPairSync("ed25519");
  const signedManifest = { ...manifest };
  const signedSignature = signBytes(null, Buffer.from(wasmBytes), signingKeys.privateKey);
  const signedInit = await initCore({
    manifest: signedManifest,
    wasmBytes,
    signatureBytes: signedSignature,
    publicKeyJwk: signingKeys.publicKey.export({ format: "jwk" }),
    secureContext: true,
    subtle,
  });
  assert.equal(signedInit.handle.abiVersion(), 2);
  pass("initCore verifies manifest hashes and optional Ed25519 signatures in runtime-web");

  const { handle } = await initCore({ manifest, wasmBytes, secureContext: true, subtle });
  assert.equal(handle.abiVersion(), 2);
  pass("runtime-web instantiates the Verified Core artefact");

  assert.equal(DEFAULT_CLIENT_CRYPTO_PROFILE, CLIENT_CRYPTO_PROFILES.AEGAEON_RS256);
  assert.equal(resolveJwtAllowedAlgorithmsBitmaskForProfile(), VC_ALG.EDDSA | VC_ALG.RS256);
  assert.equal(
    resolveJwtAllowedAlgorithmsBitmaskForProfile(CLIENT_CRYPTO_PROFILES.VERIFIED_CORE),
    VC_ALG.EDDSA,
  );
  assert.equal(
    resolveJwtAllowedAlgorithmsBitmaskForProfile(CLIENT_CRYPTO_PROFILES.COMPAT_INTEROP),
    VC_ALG.EDDSA | VC_ALG.RS256 | VC_ALG.ES256,
  );
  assert.equal(resolveDpopAllowedAlgorithmsBitmaskForProfile(), VC_ALG.EDDSA);
  assert.equal(
    resolveDpopAllowedAlgorithmsBitmaskForProfile(CLIENT_CRYPTO_PROFILES.AEGAEON_RS256),
    VC_ALG.EDDSA,
  );
  assert.equal(
    resolveDpopAllowedAlgorithmsBitmaskForProfile(CLIENT_CRYPTO_PROFILES.COMPAT_INTEROP),
    VC_ALG.EDDSA | VC_ALG.ES256,
  );
  pass("runtime-web exports the expected client crypto profile masks");

  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  const pkceGenerated = await handle.pkceGenerate({ verifier });
  assert.equal(pkceGenerated.statusCode, VC_STATUS.OK);
  assert.equal(pkceGenerated.challenge, challenge);
  const pkceVerified = await handle.pkceVerify({ verifier, challenge });
  assert.equal(pkceVerified.statusCode, VC_STATUS.OK);
  pass("runtime-web exposes PKCE generation and verification");

  const now = 1_710_000_000;
  const jwtPublicJwk = signingKeys.publicKey.export({ format: "jwk" });
  const jwt = await signCompact({
    header: { alg: "EdDSA", kid: "browser-kid-1" },
    payload: {
      iss: "https://issuer.example",
      aud: ["client-123", "other"],
      exp: now + 300,
      iat: now,
    },
    privateKey: signingKeys.privateKey,
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
  assert.equal(jwtVerified.statusCode, VC_STATUS.OK);
  assert.deepEqual(Buffer.from(jwtVerified.payloadHash), sha256(jwt.signingInput));
  assert.deepEqual(Buffer.from(jwtVerified.kidHash), sha256(textEncoder.encode("browser-kid-1")));
  pass("runtime-web verifies compact JWTs on the current EdDSA path");

  const jwtClaimsVerified = await handle.jwtVerifyClaims({
    signingInput: jwt.signingInput,
    signature: jwt.signature,
    publicKey: jwtPublicJwk,
    claimsIssuer: "https://issuer.example",
    claimsAudience: ["client-123", "other"],
    expectedIssuer: "https://issuer.example",
    expectedAudience: "client-123",
    expSeconds: BigInt(now + 300),
    iatSeconds: BigInt(now),
    nowUnixTimeSeconds: BigInt(now),
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
  });
  assert.equal(jwtClaimsVerified.statusCode, VC_STATUS.OK);
  pass("runtime-web verifies claims-based JWT inputs");

  const rsaKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPublicJwk = rsaKeys.publicKey.export({ format: "jwk" });
  const rsaJwt = await signCompact({
    header: { alg: "RS256", kid: "web-rsa-kid-1" },
    payload: {
      iss: "https://issuer.example",
      aud: "client-123",
      exp: now + 300,
      iat: now,
    },
    privateKey: rsaKeys.privateKey,
  });

  const rsaJwtVerified = await handle.jwtVerify({
    jwt: rsaJwt.compact,
    publicKey: rsaPublicJwk,
    expectedIssuer: "https://issuer.example",
    expectedAudience: "client-123",
    nowUnixTimeSeconds: now,
    allowedAlgorithmsBitmask: VC_ALG.RS256,
    flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
  });
  assert.equal(rsaJwtVerified.statusCode, VC_STATUS.OK);
  assert.deepEqual(Buffer.from(rsaJwtVerified.payloadHash), sha256(rsaJwt.signingInput));
  pass("runtime-web verifies RS256 JWTs through the preverified client path");

  const rsaJwtVerifiedByDefaultProfile = await handle.jwtVerify({
    jwt: rsaJwt.compact,
    publicKey: rsaPublicJwk,
    expectedIssuer: "https://issuer.example",
    expectedAudience: "client-123",
    nowUnixTimeSeconds: now,
    flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
  });
  assert.equal(rsaJwtVerifiedByDefaultProfile.statusCode, VC_STATUS.OK);
  pass("runtime-web defaults to the aegaeon-rs256 client profile");

  const rsaJwtClaimsVerified = await handle.jwtVerifyClaims({
    algorithm: "RS256",
    signingInput: rsaJwt.signingInput,
    signature: rsaJwt.signature,
    publicKey: rsaPublicJwk,
    claimsIssuer: "https://issuer.example",
    claimsAudience: "client-123",
    expectedIssuer: "https://issuer.example",
    expectedAudience: "client-123",
    expSeconds: BigInt(now + 300),
    iatSeconds: BigInt(now),
    nowUnixTimeSeconds: BigInt(now),
    allowedAlgorithmsBitmask: VC_ALG.RS256,
    flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
  });
  assert.equal(rsaJwtClaimsVerified.statusCode, VC_STATUS.OK);
  pass("runtime-web verifies RS256 claims inputs");

  handle.clearReplayStore();
  const dpopAccessToken = "browser-access-token";
  const dpopNow = now + 30;
  const dpop = await signCompact({
    header: { typ: "dpop+jwt", alg: "EdDSA", jwk: jwtPublicJwk },
    payload: {
      htm: "GET",
      htu: "https://rp.example/resource",
      iat: dpopNow,
      jti: "browser-jti-1",
      ath: sha256Base64Url(textEncoder.encode(dpopAccessToken)),
    },
    privateKey: signingKeys.privateKey,
  });

  const dpopVerified = await handle.dpopVerify({
    dpopProof: dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/resource",
    accessToken: dpopAccessToken,
    replayNamespace: "browser-issuer-a",
    nowUnixTimeSeconds: dpopNow,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(dpopVerified.statusCode, VC_STATUS.OK);
  assert.deepEqual(Buffer.from(dpopVerified.replayKeyHash), sha256(dpop.signingInput));
  pass("runtime-web verifies compact DPoP proofs");

  handle.clearReplayStore();
  const dpopClaims = await signCompact({
    header: { typ: "dpop+jwt", alg: "EdDSA", jwk: jwtPublicJwk },
    payload: {
      htm: "POST",
      htu: "https://rp.example/token",
      iat: dpopNow + 1,
      jti: "browser-jti-claims",
      ath: sha256Base64Url(textEncoder.encode("claims-token")),
    },
    privateKey: signingKeys.privateKey,
  });

  const dpopClaimsVerified = await handle.dpopVerifyClaims({
    httpMethod: "POST",
    httpUri: "https://rp.example/token",
    signingInput: dpopClaims.signingInput,
    signature: dpopClaims.signature,
    publicKey: jwtPublicJwk,
    replayNamespace: "browser-issuer-b",
    accessToken: "claims-token",
    ath: sha256Base64Url(textEncoder.encode("claims-token")),
    jti: "browser-jti-claims",
    iatSeconds: BigInt(dpopNow + 1),
    nowUnixTimeSeconds: BigInt(dpopNow + 1),
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(dpopClaimsVerified.statusCode, VC_STATUS.OK);
  pass("runtime-web verifies claims-based DPoP inputs");

  const dpopClaimsBadAth = await handle.dpopVerifyClaims({
    httpMethod: "POST",
    httpUri: "https://rp.example/token",
    signingInput: dpopClaims.signingInput,
    signature: dpopClaims.signature,
    publicKey: jwtPublicJwk,
    replayNamespace: "browser-issuer-c",
    accessToken: "claims-token",
    ath: "wrong-ath",
    jti: "browser-jti-claims",
    iatSeconds: BigInt(dpopNow + 1),
    nowUnixTimeSeconds: BigInt(dpopNow + 1),
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(dpopClaimsBadAth.statusCode, VC_STATUS.INVALID_CLAIMS);
  pass("runtime-web fails closed on host-side ath mismatches");

  handle.clearReplayStore();
  const es256Keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const es256PublicJwk = es256Keys.publicKey.export({ format: "jwk" });
  const es256Dpop = await signCompact({
    header: { typ: "dpop+jwt", alg: "ES256", jwk: es256PublicJwk },
    payload: {
      htm: "GET",
      htu: "https://rp.example/es256-resource",
      iat: dpopNow + 2,
      jti: "web-es256-jti-1",
      ath: sha256Base64Url(textEncoder.encode("web-es256-token")),
    },
    privateKey: es256Keys.privateKey,
  });

  const es256DpopVerified = await handle.dpopVerify({
    dpopProof: es256Dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    accessToken: "web-es256-token",
    replayNamespace: "browser-es256",
    nowUnixTimeSeconds: dpopNow + 2,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.ES256,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopVerified.statusCode, VC_STATUS.OK);
  pass("runtime-web verifies ES256 DPoP compact inputs");

  handle.clearReplayStore();
  const es256DpopDefaultProfile = await handle.dpopVerify({
    dpopProof: es256Dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    accessToken: "web-es256-token",
    replayNamespace: "browser-es256-default-profile",
    nowUnixTimeSeconds: dpopNow + 2,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopDefaultProfile.statusCode, VC_STATUS.UNSUPPORTED);
  pass("runtime-web keeps ES256 outside the default client profile");

  handle.clearReplayStore();
  const es256DpopCompatProfile = await handle.dpopVerify({
    dpopProof: es256Dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    accessToken: "web-es256-token",
    replayNamespace: "browser-es256-compat-profile",
    nowUnixTimeSeconds: dpopNow + 2,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    cryptoProfile: CLIENT_CRYPTO_PROFILES.COMPAT_INTEROP,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopCompatProfile.statusCode, VC_STATUS.OK);
  pass("runtime-web enables ES256 only under the compat-interop profile");

  handle.clearReplayStore();
  const es256DpopClaims = await handle.dpopVerifyClaims({
    algorithm: "ES256",
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    signingInput: es256Dpop.signingInput,
    signature: es256Dpop.signature,
    publicKey: es256PublicJwk,
    replayNamespace: "browser-es256-claims",
    accessToken: "web-es256-token",
    ath: sha256Base64Url(textEncoder.encode("web-es256-token")),
    jti: "web-es256-jti-1",
    iatSeconds: BigInt(dpopNow + 2),
    nowUnixTimeSeconds: BigInt(dpopNow + 2),
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.ES256,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopClaims.statusCode, VC_STATUS.OK);
  pass("runtime-web verifies ES256 DPoP claims inputs");

  console.log(`=== ${passed} adapter checks passed ===`);
}

main().catch((error) => {
  console.error("[fail] runtime_web_reference_test:", error);
  process.exitCode = 1;
});
