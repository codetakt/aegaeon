#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { generateKeyPairSync, sign as signBytes, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  CLIENT_CRYPTO_PROFILES,
  DEFAULT_CLIENT_CRYPTO_PROFILE,
  initCore,
  resolveDefaultArtifactPaths,
  resolveDpopAllowedAlgorithmsBitmaskForProfile,
  resolveJwtAllowedAlgorithmsBitmaskForProfile,
  VC_ALG,
  VC_DPOP_FLAGS,
  VC_JWT_FLAGS,
  VC_STATUS,
} from "../../scripts/sdk/runtime_node_reference.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let passed = 0;

function pass(message) {
  passed += 1;
  console.log(`  [ok] ${message}`);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

function sha256Base64Url(bytes) {
  return createHash("sha256").update(bytes).digest("base64url");
}

function b64urlJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function signCompact({ header, payload, privateKey }) {
  const headerB64 = b64urlJson(header);
  const payloadB64 = b64urlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  let signature;
  switch (header.alg) {
    case "EdDSA":
      signature = Buffer.from(signBytes(null, Buffer.from(signingInput, "utf8"), privateKey));
      break;
    case "RS256":
      signature = Buffer.from(
        signBytes("RSA-SHA256", Buffer.from(signingInput, "utf8"), privateKey),
      );
      break;
    case "ES256":
      signature = Buffer.from(
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
    compact: `${signingInput}.${signature.toString("base64url")}`,
    signingInput: Buffer.from(signingInput, "utf8"),
    signature,
  };
}

async function main() {
  console.log("=== Verified Core Node Reference Adapter Tests ===");

  const { wasmPath, manifestPath } = resolveDefaultArtifactPaths();
  const pkceVectorsPath = path.join(__dirname, "vectors", "pkce_s256.json");
  const pkceVectors = JSON.parse(readFileSync(pkceVectorsPath, "utf8"));

  const { manifest, handle } = await initCore({ wasmPath, manifestPath });
  assert.equal(handle.abiVersion(), 2);
  assert.equal(typeof manifest.sha256, "string");
  pass("initCore verifies the artefact manifest and exposes ABI v2");

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
  pass("node adapter exports the expected client crypto profile masks");

  const pkceVector = pkceVectors.vectors[0];
  const generated = handle.pkceGenerate({ verifier: pkceVector.verifier });
  assert.equal(generated.statusCode, VC_STATUS.OK);
  assert.equal(generated.challenge, pkceVector.challenge);
  const verified = handle.pkceVerify({
    verifier: pkceVector.verifier,
    challenge: pkceVector.challenge,
  });
  assert.equal(verified.statusCode, VC_STATUS.OK);
  pass("pkceGenerate/pkceVerify work through the reference adapter");

  const now = 1_710_000_000;
  const jwtKeys = generateKeyPairSync("ed25519");
  const jwt = signCompact({
    header: { alg: "EdDSA", kid: "kid-1" },
    payload: {
      iss: "https://issuer.example",
      aud: ["client-123", "other"],
      exp: now + 300,
      iat: now,
    },
    privateKey: jwtKeys.privateKey,
  });

  const jwtVerified = handle.jwtVerify({
    jwt: jwt.compact,
    publicKey: jwtKeys.publicKey,
    expectedIssuer: "https://issuer.example",
    expectedAudience: "client-123",
    nowUnixTimeSeconds: now,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
  });
  assert.equal(jwtVerified.statusCode, VC_STATUS.OK);
  assert.deepEqual(jwtVerified.payloadHash, sha256(jwt.signingInput));
  assert.deepEqual(jwtVerified.kidHash, sha256(Buffer.from("kid-1", "utf8")));
  pass("jwtVerify parses compact JWS and verifies EdDSA signatures end-to-end");

  const jwtWrongIssuer = handle.jwtVerify({
    jwt: jwt.compact,
    publicKey: jwtKeys.publicKey,
    expectedIssuer: "https://wrong.example",
    expectedAudience: "client-123",
    nowUnixTimeSeconds: now,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_JWT_FLAGS.REQUIRE_EXP,
  });
  assert.equal(jwtWrongIssuer.statusCode, VC_STATUS.INVALID_CLAIMS);
  pass("jwtVerify fails closed on issuer mismatches");

  const jwtClaimsVerified = handle.jwtVerifyClaims({
    signingInput: jwt.signingInput,
    signature: jwt.signature,
    publicKey: jwtKeys.publicKey,
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
  assert.deepEqual(jwtClaimsVerified.payloadHash, sha256(jwt.signingInput));
  pass("jwtVerifyClaims works through the reference adapter");

  const rsaKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPublicJwk = rsaKeys.publicKey.export({ format: "jwk" });
  const rsaJwt = signCompact({
    header: { alg: "RS256", kid: "rsa-kid-1" },
    payload: {
      iss: "https://issuer.example",
      aud: "client-123",
      exp: now + 300,
      iat: now,
    },
    privateKey: rsaKeys.privateKey,
  });

  const rsaJwtVerified = handle.jwtVerify({
    jwt: rsaJwt.compact,
    publicKey: rsaPublicJwk,
    expectedIssuer: "https://issuer.example",
    expectedAudience: "client-123",
    nowUnixTimeSeconds: now,
    allowedAlgorithmsBitmask: VC_ALG.RS256,
    flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
  });
  assert.equal(rsaJwtVerified.statusCode, VC_STATUS.OK);
  assert.deepEqual(rsaJwtVerified.payloadHash, sha256(rsaJwt.signingInput));
  assert.deepEqual(rsaJwtVerified.kidHash, sha256(Buffer.from("rsa-kid-1", "utf8")));
  pass("jwtVerify accepts the RS256 required slice through the reference adapter");

  const rsaJwtVerifiedByDefaultProfile = handle.jwtVerify({
    jwt: rsaJwt.compact,
    publicKey: rsaPublicJwk,
    expectedIssuer: "https://issuer.example",
    expectedAudience: "client-123",
    nowUnixTimeSeconds: now,
    flags: VC_JWT_FLAGS.REQUIRE_EXP | VC_JWT_FLAGS.REQUIRE_IAT,
  });
  assert.equal(rsaJwtVerifiedByDefaultProfile.statusCode, VC_STATUS.OK);
  pass("jwtVerify defaults to the aegaeon-rs256 client profile");

  const rsaJwtClaimsVerified = handle.jwtVerifyClaims({
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
  pass("jwtVerifyClaims accepts RS256 through the preverified client path");

  const rsaJwtTampered = Buffer.from(rsaJwt.signature);
  rsaJwtTampered[rsaJwtTampered.length - 1] ^= 0x01;
  const rsaJwtInvalid = handle.jwtVerifyClaims({
    algorithm: "RS256",
    signingInput: rsaJwt.signingInput,
    signature: rsaJwtTampered,
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
  assert.equal(rsaJwtInvalid.statusCode, VC_STATUS.INVALID_SIGNATURE);
  pass("jwtVerifyClaims fails closed on tampered RS256 signatures");

  handle.clearReplayStore();
  const dpopKeys = generateKeyPairSync("ed25519");
  const dpopPublicJwk = dpopKeys.publicKey.export({ format: "jwk" });
  const dpopAccessToken = "access-token-123";
  const dpopNow = now + 100;
  const dpop = signCompact({
    header: { typ: "dpop+jwt", alg: "EdDSA", jwk: dpopPublicJwk },
    payload: {
      htm: "GET",
      htu: "https://rp.example/resource",
      iat: dpopNow,
      jti: "jti-1",
      ath: sha256Base64Url(Buffer.from(dpopAccessToken, "utf8")),
    },
    privateKey: dpopKeys.privateKey,
  });

  const dpopFirst = handle.dpopVerify({
    dpopProof: dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/resource",
    accessToken: dpopAccessToken,
    replayNamespace: "issuer-a",
    nowUnixTimeSeconds: dpopNow,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(dpopFirst.statusCode, VC_STATUS.OK);
  assert.deepEqual(dpopFirst.jktHash, sha256(Buffer.from(dpopPublicJwk.x, "base64url")));
  assert.deepEqual(dpopFirst.replayKeyHash, sha256(dpop.signingInput));
  pass("dpopVerify parses compact proofs, checks ath, and verifies EdDSA signatures");

  const dpopReplay = handle.dpopVerify({
    dpopProof: dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/resource",
    accessToken: dpopAccessToken,
    replayNamespace: "issuer-a",
    nowUnixTimeSeconds: dpopNow,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(dpopReplay.statusCode, VC_STATUS.REPLAY);
  pass("dpopVerify preserves replay-store semantics across calls");

  handle.clearReplayStore();
  const dpopClaims = signCompact({
    header: { typ: "dpop+jwt", alg: "EdDSA", jwk: dpopPublicJwk },
    payload: {
      htm: "POST",
      htu: "https://rp.example/token",
      iat: dpopNow + 1,
      jti: "jti-claims",
      ath: sha256Base64Url(Buffer.from("claims-token", "utf8")),
    },
    privateKey: dpopKeys.privateKey,
  });

  const dpopClaimsResult = handle.dpopVerifyClaims({
    httpMethod: "POST",
    httpUri: "https://rp.example/token",
    signingInput: dpopClaims.signingInput,
    signature: dpopClaims.signature,
    publicKey: dpopKeys.publicKey,
    replayNamespace: "issuer-b",
    accessToken: "claims-token",
    ath: sha256Base64Url(Buffer.from("claims-token", "utf8")),
    jti: "jti-claims",
    iatSeconds: BigInt(dpopNow + 1),
    nowUnixTimeSeconds: BigInt(dpopNow + 1),
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(dpopClaimsResult.statusCode, VC_STATUS.OK);
  assert.deepEqual(dpopClaimsResult.replayKeyHash, sha256(dpopClaims.signingInput));
  pass("dpopVerifyClaims works through the reference adapter");

  const dpopClaimsBadAth = handle.dpopVerifyClaims({
    httpMethod: "POST",
    httpUri: "https://rp.example/token",
    signingInput: dpopClaims.signingInput,
    signature: dpopClaims.signature,
    publicKey: dpopKeys.publicKey,
    replayNamespace: "issuer-c",
    accessToken: "claims-token",
    ath: "wrong-ath",
    jti: "jti-claims",
    iatSeconds: BigInt(dpopNow + 1),
    nowUnixTimeSeconds: BigInt(dpopNow + 1),
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.EDDSA,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(dpopClaimsBadAth.statusCode, VC_STATUS.INVALID_CLAIMS);
  pass("dpopVerifyClaims fails closed on host-side ath mismatches");

  handle.clearReplayStore();
  const es256Keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const es256PublicJwk = es256Keys.publicKey.export({ format: "jwk" });
  const es256Dpop = signCompact({
    header: { typ: "dpop+jwt", alg: "ES256", jwk: es256PublicJwk },
    payload: {
      htm: "GET",
      htu: "https://rp.example/es256-resource",
      iat: dpopNow + 2,
      jti: "es256-jti-1",
      ath: sha256Base64Url(Buffer.from("es256-access-token", "utf8")),
    },
    privateKey: es256Keys.privateKey,
  });

  const es256DpopVerified = handle.dpopVerify({
    dpopProof: es256Dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    accessToken: "es256-access-token",
    replayNamespace: "issuer-es256",
    nowUnixTimeSeconds: dpopNow + 2,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.ES256,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopVerified.statusCode, VC_STATUS.OK);
  assert.deepEqual(es256DpopVerified.replayKeyHash, sha256(es256Dpop.signingInput));
  pass("dpopVerify accepts ES256 through the preverified client path");

  handle.clearReplayStore();
  const es256DpopDefaultProfile = handle.dpopVerify({
    dpopProof: es256Dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    accessToken: "es256-access-token",
    replayNamespace: "issuer-es256-default-profile",
    nowUnixTimeSeconds: dpopNow + 2,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopDefaultProfile.statusCode, VC_STATUS.UNSUPPORTED);
  pass("dpopVerify keeps ES256 outside the default client profile");

  handle.clearReplayStore();
  const es256DpopCompatProfile = handle.dpopVerify({
    dpopProof: es256Dpop.compact,
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    accessToken: "es256-access-token",
    replayNamespace: "issuer-es256-compat-profile",
    nowUnixTimeSeconds: dpopNow + 2,
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    cryptoProfile: CLIENT_CRYPTO_PROFILES.COMPAT_INTEROP,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopCompatProfile.statusCode, VC_STATUS.OK);
  pass("dpopVerify enables ES256 only under the compat-interop profile");

  handle.clearReplayStore();
  const es256DpopClaims = handle.dpopVerifyClaims({
    algorithm: "ES256",
    httpMethod: "GET",
    httpUri: "https://rp.example/es256-resource",
    signingInput: es256Dpop.signingInput,
    signature: es256Dpop.signature,
    publicKey: es256PublicJwk,
    replayNamespace: "issuer-es256-claims",
    accessToken: "es256-access-token",
    ath: sha256Base64Url(Buffer.from("es256-access-token", "utf8")),
    jti: "es256-jti-1",
    iatSeconds: BigInt(dpopNow + 2),
    nowUnixTimeSeconds: BigInt(dpopNow + 2),
    maxAgeSeconds: 300,
    maxFutureSkewSeconds: 60,
    allowedAlgorithmsBitmask: VC_ALG.ES256,
    flags: VC_DPOP_FLAGS.REQUIRE_ATH | VC_DPOP_FLAGS.REQUIRE_JTI,
  });
  assert.equal(es256DpopClaims.statusCode, VC_STATUS.OK);
  pass("dpopVerifyClaims accepts ES256 through the preverified client path");

  console.log(`=== ${passed} adapter checks passed ===`);
}

main().catch((error) => {
  console.error("[fail] runtime_node_reference_test:", error);
  process.exitCode = 1;
});
