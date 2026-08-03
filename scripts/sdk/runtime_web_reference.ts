const MODULE_URL = new URL(import.meta.url);
const SCRATCH_BASE = 2 * 1024 * 1024;
const VC_PKCE_METHOD_S256 = 1;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export const VC_STATUS = Object.freeze({
  OK: 0,
  INVALID_ARGUMENT: 1,
  INVALID_FORMAT: 2,
  INVALID_SIGNATURE: 3,
  INVALID_CLAIMS: 4,
  REPLAY: 5,
  UNAVAILABLE: 6,
  UNSUPPORTED: 7,
  INTERNAL_ERROR: 8,
});

export const VC_ALG = Object.freeze({
  ES256: 1 << 0,
  RS256: 1 << 1,
  EDDSA: 1 << 2,
});

export const VC_PUBLIC_KEY_FORMAT = Object.freeze({
  RAW_ED25519: 0,
  JWK_JSON_UTF8: 1,
  SPKI_DER: 2,
  RAW_EC_P256_UNCOMPRESSED: 3,
});

export const VC_DPOP_FLAGS = Object.freeze({
  REQUIRE_ATH: 1 << 0,
  REQUIRE_JTI: 1 << 1,
  SIGNATURE_PREVERIFIED: 1 << 2,
});

export const VC_JWT_FLAGS = Object.freeze({
  REQUIRE_EXP: 1 << 0,
  REQUIRE_IAT: 1 << 1,
  REQUIRE_NBF: 1 << 2,
  SIGNATURE_PREVERIFIED: 1 << 3,
});

export const CLIENT_CRYPTO_PROFILES = Object.freeze({
  VERIFIED_CORE: "verified-core",
  AEGAEON_RS256: "aegaeon-rs256",
  COMPAT_INTEROP: "compat-interop",
});

export const DEFAULT_CLIENT_CRYPTO_PROFILE = CLIENT_CRYPTO_PROFILES.AEGAEON_RS256;

export function resolveJwtAllowedAlgorithmsBitmaskForProfile(
  profile = DEFAULT_CLIENT_CRYPTO_PROFILE,
) {
  switch (profile) {
    case CLIENT_CRYPTO_PROFILES.VERIFIED_CORE:
      return VC_ALG.EDDSA;
    case CLIENT_CRYPTO_PROFILES.AEGAEON_RS256:
      return VC_ALG.EDDSA | VC_ALG.RS256;
    case CLIENT_CRYPTO_PROFILES.COMPAT_INTEROP:
      return VC_ALG.EDDSA | VC_ALG.RS256 | VC_ALG.ES256;
    default:
      throw new TypeError(`unsupported cryptoProfile: ${profile}`);
  }
}

export function resolveDpopAllowedAlgorithmsBitmaskForProfile(
  profile = DEFAULT_CLIENT_CRYPTO_PROFILE,
) {
  switch (profile) {
    case CLIENT_CRYPTO_PROFILES.VERIFIED_CORE:
    case CLIENT_CRYPTO_PROFILES.AEGAEON_RS256:
      return VC_ALG.EDDSA;
    case CLIENT_CRYPTO_PROFILES.COMPAT_INTEROP:
      return VC_ALG.EDDSA | VC_ALG.ES256;
    default:
      throw new TypeError(`unsupported cryptoProfile: ${profile}`);
  }
}

function defaultArtifactUrls() {
  return {
    manifestUrl: new URL(
      "../../artifacts/verified-core/manifest.json",
      MODULE_URL,
    ).toString(),
    wasmUrl: new URL(
      "../../artifacts/verified-core/verified_core.wasm",
      MODULE_URL,
    ).toString(),
    signatureUrl: new URL(
      "../../artifacts/verified-core/verified_core.wasm.sig",
      MODULE_URL,
    ).toString(),
  };
}

function requireSubtle(subtle = globalThis.crypto?.subtle) {
  if (!subtle) {
    throw new Error("Web Crypto SubtleCrypto is required for runtime-web");
  }
  return subtle;
}

function isByteArray(value) {
  return value instanceof Uint8Array;
}

function toUint8Array(value, label) {
  if (value == null) {
    return null;
  }
  if (isByteArray(value)) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(
      value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    );
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value.slice(0));
  }
  if (typeof value === "string") {
    return textEncoder.encode(value);
  }
  throw new TypeError(`${label} must be a string, Uint8Array, or ArrayBuffer`);
}

function requireBytes(value, label) {
  const bytes = toUint8Array(value, label);
  if (bytes == null) {
    throw new TypeError(`${label} is required`);
  }
  return bytes;
}

function encodeUtf8(value) {
  return textEncoder.encode(value);
}

function decodeUtf8(bytes) {
  return textDecoder.decode(bytes);
}

function base64Encode(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return globalThis.btoa(binary);
}

function base64Decode(base64) {
  const binary = globalThis.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodeBase64Url(value, label = "base64url") {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty base64url string`);
  }
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64Decode(base64);
}

function encodeBase64Url(bytes) {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function parseJsonUtf8(bytes, label) {
  try {
    return JSON.parse(decodeUtf8(bytes));
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8 JSON: ${error.message}`);
  }
}

function parseCompactJws(compactBytes, label) {
  const compact = decodeUtf8(compactBytes);
  const parts = compact.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error(`${label} must be a compact JWS with three base64url parts`);
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  const headerBytes = decodeBase64Url(headerB64, `${label} header`);
  const payloadBytes = decodeBase64Url(payloadB64, `${label} payload`);
  const signatureBytes = decodeBase64Url(signatureB64, `${label} signature`);
  const header = parseJsonUtf8(headerBytes, `${label} header`);
  const payload = parseJsonUtf8(payloadBytes, `${label} payload`);
  return {
    compact,
    header,
    payload,
    signingInput: encodeUtf8(`${headerB64}.${payloadB64}`),
    signatureBytes,
  };
}

function normalizeIntegerSeconds(value, fieldName, { required = false } = {}) {
  if (value == null) {
    if (required) {
      throw new TypeError(`${fieldName} is required`);
    }
    return { present: false, seconds: 0n };
  }
  if (typeof value === "bigint") {
    if (value < 0n) {
      throw new RangeError(`${fieldName} must be non-negative`);
    }
    return { present: true, seconds: value };
  }
  if (
    typeof value === "number" &&
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    value >= 0
  ) {
    return { present: true, seconds: BigInt(value) };
  }
  throw new TypeError(`${fieldName} must be a non-negative integer number or bigint`);
}

function parseMaybeString(value, fieldName) {
  if (value == null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new TypeError(`${fieldName} must be a string`);
  }
  return value;
}

function requireString(value, fieldName) {
  const parsed = parseMaybeString(value, fieldName);
  if (parsed == null) {
    throw new TypeError(`${fieldName} is required`);
  }
  return parsed;
}

const JOSE_ALGORITHM_TO_BIT = Object.freeze({
  ES256: VC_ALG.ES256,
  RS256: VC_ALG.RS256,
  EdDSA: VC_ALG.EDDSA,
});

function isJwkLike(value) {
  return (
    Boolean(value) &&
    typeof value === "object" &&
    ("kty" in value ||
      "x" in value ||
      "n" in value ||
      "e" in value ||
      "crv" in value ||
      "y" in value)
  );
}

function algorithmNameToBit(algorithm, fieldName = "algorithm") {
  if (typeof algorithm !== "string" || algorithm.length === 0) {
    throw new TypeError(`${fieldName} must be a non-empty JOSE algorithm string`);
  }
  const bit = JOSE_ALGORITHM_TO_BIT[algorithm];
  if (!bit) {
    throw new TypeError(`${fieldName} ${algorithm} is not supported by the reference adapter`);
  }
  return bit;
}

function singleAlgorithmBitFromMask(bitmask) {
  const knownMask = VC_ALG.ES256 | VC_ALG.RS256 | VC_ALG.EDDSA;
  const masked = (bitmask ?? 0) & knownMask;
  if (masked === VC_ALG.ES256 || masked === VC_ALG.RS256 || masked === VC_ALG.EDDSA) {
    return masked;
  }
  return null;
}

function resolveAlgorithmBit({
  algorithm = null,
  allowedAlgorithmsBitmask = 0,
  fieldName = "algorithm",
} = {}) {
  if (algorithm != null) {
    const bit = algorithmNameToBit(algorithm, fieldName);
    if ((allowedAlgorithmsBitmask & bit) === 0) {
      return null;
    }
    return bit;
  }
  return singleAlgorithmBitFromMask(allowedAlgorithmsBitmask);
}

function normalizeAudienceValue(value) {
  if (value == null) {
    return null;
  }
  if (typeof value === "string") {
    return encodeUtf8(value);
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
    return encodeUtf8(JSON.stringify(value));
  }
  throw new TypeError("audience must be a string or an array of strings");
}

function normalizeEd25519Jwk(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new TypeError("public key JWK must be an object");
  }
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new TypeError("public key JWK must be an Ed25519 OKP key with an x member");
  }
  return decodeBase64Url(jwk.x, "public key x");
}

function normalizeEd25519PublicKey(publicKey) {
  if (publicKey == null) {
    throw new TypeError("publicKey is required");
  }
  if (isByteArray(publicKey) || ArrayBuffer.isView(publicKey) || publicKey instanceof ArrayBuffer) {
    const bytes = requireBytes(publicKey, "publicKey");
    if (bytes.length !== 32) {
      throw new TypeError("raw Ed25519 public keys must be 32 bytes");
    }
    return bytes;
  }
  if (typeof publicKey === "string") {
    const trimmed = publicKey.trim();
    if (trimmed.startsWith("{")) {
      return normalizeEd25519Jwk(JSON.parse(trimmed));
    }
    throw new TypeError("runtime-web publicKey strings must be raw JWK JSON, not PEM");
  }
  if (typeof publicKey === "object") {
    if ("kty" in publicKey || "x" in publicKey || "crv" in publicKey) {
      return normalizeEd25519Jwk(publicKey);
    }
  }
  throw new TypeError("unsupported publicKey format for runtime-web Ed25519 normalization");
}

function normalizeP256Jwk(jwk) {
  if (!jwk || typeof jwk !== "object") {
    throw new TypeError("public key JWK must be an object");
  }
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string"
  ) {
    throw new TypeError("public key JWK must be an ES256 P-256 key with x and y members");
  }
  const x = decodeBase64Url(jwk.x, "public key x");
  const y = decodeBase64Url(jwk.y, "public key y");
  if (x.length !== 32 || y.length !== 32) {
    throw new TypeError("P-256 public key coordinates must be 32 bytes each");
  }
  const bytes = new Uint8Array(65);
  bytes[0] = 0x04;
  bytes.set(x, 1);
  bytes.set(y, 33);
  return bytes;
}

function serializeJwkUtf8(jwk) {
  return encodeUtf8(JSON.stringify(jwk));
}

function normalizePublicKeyForCore(publicKey, algorithmBit, label = "publicKey") {
  if (algorithmBit === VC_ALG.EDDSA) {
    return {
      bytes: normalizeEd25519PublicKey(publicKey),
      format: VC_PUBLIC_KEY_FORMAT.RAW_ED25519,
    };
  }
  if (typeof publicKey === "string") {
    const trimmed = publicKey.trim();
    if (trimmed.startsWith("{")) {
      const jwk = JSON.parse(trimmed);
      if (algorithmBit === VC_ALG.ES256) {
        return {
          bytes: normalizeP256Jwk(jwk),
          format: VC_PUBLIC_KEY_FORMAT.RAW_EC_P256_UNCOMPRESSED,
        };
      }
      return {
        bytes: serializeJwkUtf8(jwk),
        format: VC_PUBLIC_KEY_FORMAT.JWK_JSON_UTF8,
      };
    }
    if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
      return {
        bytes: pemToDerBytes(trimmed),
        format: VC_PUBLIC_KEY_FORMAT.SPKI_DER,
      };
    }
    throw new TypeError(`${label} strings must be JWK JSON or PEM`);
  }
  if (isJwkLike(publicKey)) {
    if (algorithmBit === VC_ALG.ES256) {
      return {
        bytes: normalizeP256Jwk(publicKey),
        format: VC_PUBLIC_KEY_FORMAT.RAW_EC_P256_UNCOMPRESSED,
      };
    }
    return {
      bytes: serializeJwkUtf8(publicKey),
      format: VC_PUBLIC_KEY_FORMAT.JWK_JSON_UTF8,
    };
  }
  if (isByteArray(publicKey) || ArrayBuffer.isView(publicKey) || publicKey instanceof ArrayBuffer) {
    return {
      bytes: requireBytes(publicKey, label),
      format: VC_PUBLIC_KEY_FORMAT.SPKI_DER,
    };
  }
  throw new TypeError(`unsupported ${label} format for runtime-web core normalization`);
}

function parseOptionalSignatureBytes(input) {
  if (input == null) {
    return null;
  }
  if (isByteArray(input) || ArrayBuffer.isView(input) || input instanceof ArrayBuffer) {
    return requireBytes(input, "signatureBytes");
  }
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.length === 0) {
      return null;
    }
    return base64Decode(trimmed);
  }
  throw new TypeError("signatureBytes must be a Uint8Array, ArrayBuffer, or base64 string");
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function pemToDerBytes(pem) {
  const trimmed = pem.trim();
  const body = trimmed
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return base64Decode(body);
}

async function importEd25519VerifyKey(publicKey, subtle) {
  if (publicKey instanceof CryptoKey) {
    return publicKey;
  }
  if (typeof publicKey === "string") {
    const trimmed = publicKey.trim();
    if (trimmed.startsWith("{")) {
      return subtle.importKey("jwk", JSON.parse(trimmed), { name: "Ed25519" }, false, ["verify"]);
    }
    if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
      return subtle.importKey(
        "spki",
        pemToDerBytes(trimmed),
        { name: "Ed25519" },
        false,
        ["verify"],
      );
    }
    throw new TypeError("publicKey strings must be JWK JSON or PEM");
  }
  if (publicKey && typeof publicKey === "object") {
    if ("kty" in publicKey || "x" in publicKey || "crv" in publicKey) {
      return subtle.importKey("jwk", publicKey, { name: "Ed25519" }, false, ["verify"]);
    }
  }
  if (isByteArray(publicKey) || ArrayBuffer.isView(publicKey) || publicKey instanceof ArrayBuffer) {
    return subtle.importKey(
      "raw",
      requireBytes(publicKey, "publicKey"),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  }
  throw new TypeError("unsupported public key format for Ed25519 verification");
}

async function importVerifyKey(publicKey, algorithmBit, subtle) {
  if (algorithmBit === VC_ALG.EDDSA) {
    return importEd25519VerifyKey(publicKey, subtle);
  }
  if (publicKey instanceof CryptoKey) {
    return publicKey;
  }

  if (typeof publicKey === "string") {
    const trimmed = publicKey.trim();
    if (trimmed.startsWith("{")) {
      const jwk = JSON.parse(trimmed);
      if (algorithmBit === VC_ALG.RS256) {
        return subtle.importKey(
          "jwk",
          jwk,
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["verify"],
        );
      }
      if (algorithmBit === VC_ALG.ES256) {
        return subtle.importKey(
          "jwk",
          jwk,
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["verify"],
        );
      }
    }
    if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
      const der = pemToDerBytes(trimmed);
      if (algorithmBit === VC_ALG.RS256) {
        return subtle.importKey(
          "spki",
          der,
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["verify"],
        );
      }
      if (algorithmBit === VC_ALG.ES256) {
        return subtle.importKey(
          "spki",
          der,
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["verify"],
        );
      }
    }
    throw new TypeError("publicKey strings must be JWK JSON or PEM");
  }

  if (isJwkLike(publicKey)) {
    if (algorithmBit === VC_ALG.RS256) {
      return subtle.importKey(
        "jwk",
        publicKey,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
    }
    if (algorithmBit === VC_ALG.ES256) {
      return subtle.importKey(
        "jwk",
        publicKey,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
    }
  }

  if (isByteArray(publicKey) || ArrayBuffer.isView(publicKey) || publicKey instanceof ArrayBuffer) {
    const spki = requireBytes(publicKey, "publicKey");
    if (algorithmBit === VC_ALG.RS256) {
      return subtle.importKey(
        "spki",
        spki,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
    }
    if (algorithmBit === VC_ALG.ES256) {
      return subtle.importKey(
        "spki",
        spki,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
    }
  }

  throw new TypeError("unsupported public key format for runtime-web verification");
}

async function verifyJoseSignatureWeb({
  algorithmBit,
  publicKey,
  signingInput,
  signature,
  subtle,
}) {
  const verificationKey = await importVerifyKey(publicKey, algorithmBit, subtle);
  if (algorithmBit === VC_ALG.EDDSA) {
    return subtle.verify({ name: "Ed25519" }, verificationKey, signature, signingInput);
  }
  if (algorithmBit === VC_ALG.RS256) {
    return subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, verificationKey, signature, signingInput);
  }
  if (algorithmBit === VC_ALG.ES256) {
    return subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verificationKey,
      signature,
      signingInput,
    );
  }
  throw new TypeError("unsupported verification algorithm");
}

function emptyJwtVerificationOutput(statusCode) {
  return {
    payloadHash: new Uint8Array(32),
    kidHash: new Uint8Array(32),
    flags: 0,
    statusCode,
    ok: statusCode === VC_STATUS.OK,
  };
}

function emptyDpopVerificationOutput(statusCode) {
  return {
    jktHash: new Uint8Array(32),
    replayKeyHash: new Uint8Array(32),
    jtiHash: new Uint8Array(32),
    proofIatSeconds: 0n,
    flags: 0,
    statusCode,
    ok: statusCode === VC_STATUS.OK,
  };
}

async function digestBytes(bytes, algorithm, subtle) {
  const digest = await subtle.digest(algorithm, bytes);
  return new Uint8Array(digest);
}

async function digestHex(bytes, algorithm, subtle) {
  return toHex(await digestBytes(bytes, algorithm, subtle));
}

function pickPublicKey(options) {
  return options.publicKey ?? options.publicKeyJwk ?? options.publicKeyPem ?? null;
}

async function verifyArtifact({ wasmBytes, manifest, signatureBytes, publicKey, subtle }) {
  if (!manifest || typeof manifest !== "object") {
    throw new TypeError("manifest must be an object");
  }
  if (typeof manifest.sha256 !== "string" || manifest.sha256.length === 0) {
    throw new Error("manifest.sha256 is required");
  }

  const actualSha256 = await digestHex(wasmBytes, "SHA-256", subtle);
  if (actualSha256 !== manifest.sha256) {
    throw new Error(`sha256 mismatch: expected ${manifest.sha256}, got ${actualSha256}`);
  }

  if (typeof manifest.size_bytes === "number" && manifest.size_bytes !== wasmBytes.length) {
    throw new Error(`size mismatch: expected ${manifest.size_bytes}, got ${wasmBytes.length}`);
  }

  if (typeof manifest.sha512 === "string" && manifest.sha512.length > 0) {
    const actualSha512 = await digestHex(wasmBytes, "SHA-512", subtle);
    if (actualSha512 !== manifest.sha512) {
      throw new Error(`sha512 mismatch: expected ${manifest.sha512}, got ${actualSha512}`);
    }
  }

  if (typeof manifest.sri === "string" && manifest.sri.length > 0) {
    const sriDigest = await digestBytes(wasmBytes, "SHA-256", subtle);
    const sri = `sha256-${base64Encode(sriDigest)}`;
    if (sri !== manifest.sri) {
      throw new Error(`sri mismatch: expected ${manifest.sri}, got ${sri}`);
    }
  }

  if (signatureBytes != null || publicKey != null) {
    if (signatureBytes == null || publicKey == null) {
      throw new Error("signatureBytes and publicKey must be provided together");
    }
    const verificationKey = await importEd25519VerifyKey(publicKey, subtle);
    const verified = await subtle.verify(
      { name: "Ed25519" },
      verificationKey,
      signatureBytes,
      wasmBytes,
    );
    if (!verified) {
      throw new Error("verified_core.wasm signature verification failed");
    }
  }
}

function isLocalhostLike(hostname) {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]"
  );
}

function ensureSecureContext(options = {}) {
  if (options.requireSecureContext === false) {
    return;
  }
  if (options.secureContext === true) {
    return;
  }
  if (options.secureContext === false) {
    throw new Error("runtime-web requires a secure context (https:// or localhost)");
  }
  if (globalThis.isSecureContext === true) {
    return;
  }
  const locationLike = options.location ?? globalThis.location ?? null;
  if (
    locationLike &&
    (locationLike.protocol === "https:" ||
      isLocalhostLike(locationLike.hostname))
  ) {
    return;
  }
  throw new Error("runtime-web requires a secure context (https:// or localhost)");
}

async function fetchJson(url, fetchImpl) {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`failed to fetch ${url}: ${response.status}`);
  }
  return response.json();
}

async function fetchBytes(url, fetchImpl) {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`failed to fetch ${url}: ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function loadArtifact(options = {}) {
  const subtle = requireSubtle(options.subtle);
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  const defaults = defaultArtifactUrls();
  const manifestUrl = options.manifestUrl ?? defaults.manifestUrl;
  const manifest = options.manifest ?? (await fetchJson(manifestUrl, fetchImpl));
  const wasmUrl =
    options.wasmUrl ??
    new URL(manifest.artifact ?? "verified_core.wasm", manifestUrl).toString();
  const wasmBytes = options.wasmBytes
    ? requireBytes(options.wasmBytes, "wasmBytes")
    : await fetchBytes(wasmUrl, fetchImpl);

  let signatureBytes = parseOptionalSignatureBytes(options.signatureBytes ?? null);
  if (signatureBytes == null) {
    const signatureUrl =
      options.signatureUrl ??
      (manifest.signature?.file ? new URL(manifest.signature.file, manifestUrl).toString() : null);
    if (signatureUrl) {
      try {
        signatureBytes = parseOptionalSignatureBytes(await fetchBytes(signatureUrl, fetchImpl));
      } catch {
        signatureBytes = null;
      }
    }
  }

  await verifyArtifact({
    wasmBytes,
    manifest,
    signatureBytes,
    publicKey: pickPublicKey(options),
    subtle,
  });

  return { wasmBytes, manifest, manifestUrl, wasmUrl };
}

class InMemoryReplayStore {
  constructor() {
    this.entries = new Set();
  }

  clear() {
    this.entries.clear();
  }

  checkAndStore(namespaceBytes, keyHashBytes, ttlMs) {
    const cacheKey = `${toHex(namespaceBytes)}:${toHex(keyHashBytes)}:${ttlMs >>> 0}`;
    if (this.entries.has(cacheKey)) {
      return true;
    }
    this.entries.add(cacheKey);
    return false;
  }
}

class WebReferenceCoreRuntime {
  constructor(wasmBytes, manifest, options = {}) {
    this.wasmBytes = wasmBytes;
    this.manifest = manifest;
    this.replayStore = options.replayStore ?? new InMemoryReplayStore();
    this.handleTable = new Map();
    this.nextHandleId = 1;
    this.scratchPtr = SCRATCH_BASE;
    this.instance = null;
    this.memory = null;
    this.subtle = requireSubtle(options.subtle);
  }

  async instantiate() {
    const module = await WebAssembly.compile(this.wasmBytes);
    const instance = await WebAssembly.instantiate(module, this.buildImports());
    this.instance = instance;
    this.memory = instance.exports.memory;
    this.ensureMemory(this.scratchPtr + 1024);
    return this;
  }

  buildImports() {
    const fallbackStub = () => 0;
    const env = {
      VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store: (
        nsPtr,
        nsLen,
        keyHashPtr,
        ttlMs,
      ) => {
        const namespace = this.readBytes(nsPtr >>> 0, nsLen >>> 0);
        const keyHash = this.readBytes(keyHashPtr >>> 0, 32);
        const replayed = this.replayStore.checkAndStore(namespace, keyHash, ttlMs >>> 0);
        return replayed ? 1 : 0;
      },
      vc_host_register_bytes: (ptr, len) => this.registerHandleFromMemory(ptr >>> 0, len >>> 0),
      vc_host_release_handle: (handle) => {
        this.handleTable.delete(handle >>> 0);
      },
      Host_handle_data_ptr: (handle) => {
        const entry = this.handleTable.get(handle >>> 0);
        return entry ? entry.ptr : 0;
      },
      Host_handle_data_len: (handle) => {
        const entry = this.handleTable.get(handle >>> 0);
        return entry ? entry.len : 0;
      },
      Host_parse_jwt_compact: (handle, resultPtr) =>
        this.hostParseJwtCompact(handle >>> 0, resultPtr >>> 0),
      Host_parse_dpop_compact: (handle, resultPtr) =>
        this.hostParseDpopCompact(handle >>> 0, resultPtr >>> 0),
    };

    return {
      env: new Proxy(env, {
        get(target, prop) {
          if (prop in target) {
            return target[prop];
          }
          return fallbackStub;
        },
      }),
    };
  }

  resetScratch() {
    this.ensureMemory(SCRATCH_BASE + 1024);
    this.scratchPtr = SCRATCH_BASE;
    this.handleTable.clear();
    this.nextHandleId = 1;
  }

  ensureMemory(bytesNeeded) {
    if (!this.memory) {
      return;
    }
    const pageSize = 64 * 1024;
    const currentBytes = this.memory.buffer.byteLength;
    if (currentBytes >= bytesNeeded) {
      return;
    }
    const missing = bytesNeeded - currentBytes;
    const pages = Math.ceil(missing / pageSize);
    this.memory.grow(pages);
  }

  alloc(size) {
    const aligned = (size + 7) & ~7;
    const ptr = this.scratchPtr;
    this.scratchPtr += aligned;
    this.ensureMemory(this.scratchPtr + 1024);
    return ptr;
  }

  writeU32(ptr, value) {
    new DataView(this.memory.buffer).setUint32(ptr, value >>> 0, true);
  }

  writeU64(ptr, value) {
    new DataView(this.memory.buffer).setBigUint64(ptr, BigInt(value), true);
  }

  readU32(ptr) {
    return new DataView(this.memory.buffer).getUint32(ptr, true);
  }

  readU64(ptr) {
    return new DataView(this.memory.buffer).getBigUint64(ptr, true);
  }

  writeBytes(bytes) {
    const buffer = requireBytes(bytes, "bytes");
    const ptr = this.alloc(buffer.length + 1);
    const view = new Uint8Array(this.memory.buffer, ptr, buffer.length + 1);
    view.fill(0);
    view.set(buffer);
    return { ptr, len: buffer.length };
  }

  readBytes(ptr, len) {
    if (len === 0) {
      return new Uint8Array(0);
    }
    return new Uint8Array(this.memory.buffer.slice(ptr, ptr + len));
  }

  writeSlice(ptr, buffer) {
    this.writeU32(ptr, buffer?.ptr ?? 0);
    this.writeU32(ptr + 4, buffer?.len ?? 0);
  }

  registerHandleBytes(bytes) {
    const { ptr, len } = this.writeBytes(bytes);
    const handle = this.nextHandleId++;
    this.handleTable.set(handle, { ptr, len });
    return handle;
  }

  registerHandleString(value) {
    if (value == null) {
      return 0;
    }
    if (typeof value !== "string") {
      throw new TypeError("expected a string handle value");
    }
    return this.registerHandleBytes(encodeUtf8(value));
  }

  registerHandleAudience(value) {
    const bytes = normalizeAudienceValue(value);
    return bytes ? this.registerHandleBytes(bytes) : 0;
  }

  registerHandleFromMemory(ptr, len) {
    const bytes = this.readBytes(ptr, len);
    return this.registerHandleBytes(bytes);
  }

  requireExport(name) {
    const fn = this.instance?.exports?.[name];
    if (typeof fn !== "function") {
      throw new Error(`${name} export is unavailable`);
    }
    return fn;
  }

  encodeJwtParsedComponents(resultPtr, parsed) {
    this.writeU32(resultPtr + 0, parsed.signingInputHandle);
    this.writeU32(resultPtr + 4, parsed.signatureBytesHandle);
    this.writeU32(resultPtr + 8, parsed.issHandle);
    this.writeU32(resultPtr + 12, parsed.audHandle);
    this.writeU64(resultPtr + 16, parsed.expSeconds);
    this.writeU64(resultPtr + 24, parsed.nbfSeconds);
    this.writeU64(resultPtr + 32, parsed.iatSeconds);
    this.writeU32(resultPtr + 40, parsed.hasExp);
    this.writeU32(resultPtr + 44, parsed.hasNbf);
    this.writeU32(resultPtr + 48, parsed.hasIat);
    this.writeU32(resultPtr + 52, parsed.kidHandle);
    this.writeU32(resultPtr + 56, parsed.statusCode);
    this.writeU32(resultPtr + 60, 0);
  }

  encodeDpopParsedComponents(resultPtr, parsed) {
    this.writeU32(resultPtr + 0, parsed.signingInputHandle);
    this.writeU32(resultPtr + 4, parsed.signatureBytesHandle);
    this.writeU32(resultPtr + 8, parsed.publicKeyHandle);
    this.writeU32(resultPtr + 12, parsed.publicKeyFormat);
    this.writeU32(resultPtr + 16, parsed.htmHandle);
    this.writeU32(resultPtr + 20, parsed.htuHandle);
    this.writeU32(resultPtr + 24, parsed.jtiHandle);
    this.writeU32(resultPtr + 28, parsed.athHandle);
    this.writeU64(resultPtr + 32, parsed.iatSeconds);
    this.writeU32(resultPtr + 40, parsed.statusCode);
    this.writeU32(resultPtr + 44, 0);
  }

  hostParseJwtCompact(handle, resultPtr) {
    try {
      const compactBytes = this.getHandleBytes(handle, "jwtCompactJwsHandle");
      const parsed = parseCompactJws(compactBytes, "jwt compact JWS");
      const header = parsed.header;
      const payload = parsed.payload;
      const iss = parseMaybeString(payload.iss, "jwt payload iss");
      const aud = payload.aud == null ? null : normalizeAudienceValue(payload.aud);
      const exp = normalizeIntegerSeconds(payload.exp, "jwt payload exp");
      const nbf = normalizeIntegerSeconds(payload.nbf, "jwt payload nbf");
      const iat = normalizeIntegerSeconds(payload.iat, "jwt payload iat");
      const kid = parseMaybeString(header.kid, "jwt protected header kid");

      this.encodeJwtParsedComponents(resultPtr, {
        signingInputHandle: this.registerHandleBytes(parsed.signingInput),
        signatureBytesHandle: this.registerHandleBytes(parsed.signatureBytes),
        issHandle: iss == null ? 0 : this.registerHandleString(iss),
        audHandle: aud == null ? 0 : this.registerHandleBytes(aud),
        expSeconds: exp.seconds,
        nbfSeconds: nbf.seconds,
        iatSeconds: iat.seconds,
        hasExp: exp.present ? 1 : 0,
        hasNbf: nbf.present ? 1 : 0,
        hasIat: iat.present ? 1 : 0,
        kidHandle: kid == null ? 0 : this.registerHandleString(kid),
        statusCode: 0,
      });
      return 0;
    } catch {
      this.encodeJwtParsedComponents(resultPtr, {
        signingInputHandle: 0,
        signatureBytesHandle: 0,
        issHandle: 0,
        audHandle: 0,
        expSeconds: 0n,
        nbfSeconds: 0n,
        iatSeconds: 0n,
        hasExp: 0,
        hasNbf: 0,
        hasIat: 0,
        kidHandle: 0,
        statusCode: 1,
      });
      return 1;
    }
  }

  hostParseDpopCompact(handle, resultPtr) {
    try {
      const compactBytes = this.getHandleBytes(handle, "dpopCompactJwsHandle");
      const parsed = parseCompactJws(compactBytes, "dpop compact JWS");
      const header = parsed.header;
      const payload = parsed.payload;
      const algorithmBit = resolveAlgorithmBit({
        algorithm: parseMaybeString(header.alg, "dpop protected header alg"),
        allowedAlgorithmsBitmask: VC_ALG.ES256 | VC_ALG.RS256 | VC_ALG.EDDSA,
        fieldName: "dpop protected header alg",
      });
      const htm = parseMaybeString(payload.htm, "dpop payload htm");
      const htu = parseMaybeString(payload.htu, "dpop payload htu");
      const jti = parseMaybeString(payload.jti, "dpop payload jti");
      const ath = parseMaybeString(payload.ath, "dpop payload ath");
      const iat = normalizeIntegerSeconds(payload.iat, "dpop payload iat", { required: true });
      if (algorithmBit == null) {
        throw new TypeError("dpop protected header alg is not supported");
      }
      const { bytes: publicKeyBytes, format: publicKeyFormat } = normalizePublicKeyForCore(
        header.jwk,
        algorithmBit,
        "dpop protected header jwk",
      );

      if (htm == null || htu == null) {
        throw new TypeError("dpop payload must include string htm and htu claims");
      }

      this.encodeDpopParsedComponents(resultPtr, {
        signingInputHandle: this.registerHandleBytes(parsed.signingInput),
        signatureBytesHandle: this.registerHandleBytes(parsed.signatureBytes),
        publicKeyHandle: this.registerHandleBytes(publicKeyBytes),
        publicKeyFormat,
        htmHandle: this.registerHandleString(htm),
        htuHandle: this.registerHandleString(htu),
        jtiHandle: jti == null ? 0 : this.registerHandleString(jti),
        athHandle: ath == null ? 0 : this.registerHandleString(ath),
        iatSeconds: iat.seconds,
        statusCode: 0,
      });
      return 0;
    } catch {
      this.encodeDpopParsedComponents(resultPtr, {
        signingInputHandle: 0,
        signatureBytesHandle: 0,
        publicKeyHandle: 0,
        publicKeyFormat: 0,
        htmHandle: 0,
        htuHandle: 0,
        jtiHandle: 0,
        athHandle: 0,
        iatSeconds: 0n,
        statusCode: 1,
      });
      return 1;
    }
  }

  getHandleBytes(handle, fieldName) {
    const entry = this.handleTable.get(handle >>> 0);
    if (!entry) {
      throw new Error(`${fieldName} does not reference a live handle`);
    }
    return this.readBytes(entry.ptr, entry.len);
  }

  writeJwtClaimsInput(fields) {
    const ptr = this.alloc(72);
    this.writeU32(ptr + 0, fields.signingInputHandle ?? 0);
    this.writeU32(ptr + 4, fields.signatureBytesHandle ?? 0);
    this.writeU32(ptr + 8, fields.publicKeyBytesHandle ?? 0);
    this.writeU32(ptr + 12, fields.publicKeyFormat ?? 0);
    this.writeU32(ptr + 16, fields.claimsIssuerHandle ?? 0);
    this.writeU32(ptr + 20, fields.claimsAudienceHandle ?? 0);
    this.writeU32(ptr + 24, fields.allowedAlgorithmsBitmask ?? 0);
    this.writeU32(ptr + 28, fields.flags ?? 0);
    this.writeU32(ptr + 32, fields.expectedIssuerHandle ?? 0);
    this.writeU32(ptr + 36, fields.expectedAudienceHandle ?? 0);
    this.writeU64(ptr + 40, fields.expSeconds ?? 0n);
    this.writeU64(ptr + 48, fields.nbfSeconds ?? 0n);
    this.writeU64(ptr + 56, fields.iatSeconds ?? 0n);
    this.writeU64(ptr + 64, fields.nowUnixTimeSeconds ?? 0n);
    return ptr;
  }

  writeDpopClaimsInput(fields) {
    const ptr = this.alloc(72);
    this.writeU32(ptr + 0, fields.httpMethodBytesHandle ?? 0);
    this.writeU32(ptr + 4, fields.httpUriBytesHandle ?? 0);
    this.writeU32(ptr + 8, fields.signingInputHandle ?? 0);
    this.writeU32(ptr + 12, fields.signatureBytesHandle ?? 0);
    this.writeU32(ptr + 16, fields.publicKeyBytesHandle ?? 0);
    this.writeU32(ptr + 20, fields.publicKeyFormat ?? 0);
    this.writeU32(ptr + 24, fields.replayNamespaceHandle ?? 0);
    this.writeU32(ptr + 28, fields.accessTokenHashHandle ?? 0);
    this.writeU32(ptr + 32, fields.jtiBytesHandle ?? 0);
    this.writeU32(ptr + 36, fields.allowedAlgorithmsBitmask ?? 0);
    this.writeU32(ptr + 40, fields.flags ?? 0);
    this.writeU32(ptr + 44, fields.reserved0 ?? 0);
    this.writeU64(ptr + 48, fields.iatSeconds ?? 0n);
    this.writeU64(ptr + 56, fields.nowUnixTimeSeconds ?? 0n);
    this.writeU32(ptr + 64, fields.maxAgeSeconds ?? 0);
    this.writeU32(ptr + 68, fields.maxFutureSkewSeconds ?? 0);
    return ptr;
  }

  writeJwtVerificationInput(fields) {
    const ptr = this.alloc(40);
    this.writeU32(ptr + 0, fields.jwtCompactJwsHandle ?? 0);
    this.writeU32(ptr + 4, fields.expectedIssuerHandle ?? 0);
    this.writeU32(ptr + 8, fields.expectedAudienceHandle ?? 0);
    this.writeU32(ptr + 12, fields.publicKeyBytesHandle ?? 0);
    this.writeU64(ptr + 16, fields.nowUnixTimeSeconds ?? 0n);
    this.writeU32(ptr + 24, fields.allowedAlgorithmsBitmask ?? 0);
    this.writeU32(ptr + 28, fields.publicKeyFormat ?? 0);
    this.writeU32(ptr + 32, fields.flags ?? 0);
    this.writeU32(ptr + 36, fields.reserved0 ?? 0);
    return ptr;
  }

  writeDpopVerificationInput(fields) {
    const ptr = this.alloc(56);
    this.writeU32(ptr + 0, fields.httpMethodBytesHandle ?? 0);
    this.writeU32(ptr + 4, fields.httpUriBytesHandle ?? 0);
    this.writeU32(ptr + 8, fields.dpopCompactJwsHandle ?? 0);
    this.writeU32(ptr + 12, fields.accessTokenHandle ?? 0);
    this.writeU32(ptr + 16, fields.replayNamespaceHandle ?? 0);
    this.writeU32(ptr + 20, fields.padding0 ?? 0);
    this.writeU64(ptr + 24, fields.nowUnixTimeSeconds ?? 0n);
    this.writeU32(ptr + 32, fields.maxAgeSeconds ?? 0);
    this.writeU32(ptr + 36, fields.maxFutureSkewSeconds ?? 0);
    this.writeU32(ptr + 40, fields.flags ?? 0);
    this.writeU32(ptr + 44, fields.allowedAlgorithmsBitmask ?? 0);
    this.writeU32(ptr + 48, fields.reserved0 ?? 0);
    this.writeU32(ptr + 52, fields.reserved1 ?? 0);
    return ptr;
  }

  readJwtVerificationOutput(outputPtr) {
    return {
      payloadHash: this.readBytes(outputPtr + 0, 32),
      kidHash: this.readBytes(outputPtr + 32, 32),
      flags: this.readU32(outputPtr + 64),
      statusCode: this.readU32(outputPtr + 68),
      ok: this.readU32(outputPtr + 68) === VC_STATUS.OK,
    };
  }

  readDpopVerificationOutput(outputPtr) {
    return {
      jktHash: this.readBytes(outputPtr + 0, 32),
      replayKeyHash: this.readBytes(outputPtr + 32, 32),
      jtiHash: this.readBytes(outputPtr + 64, 32),
      proofIatSeconds: this.readU64(outputPtr + 96),
      flags: this.readU32(outputPtr + 104),
      statusCode: this.readU32(outputPtr + 108),
      ok: this.readU32(outputPtr + 108) === VC_STATUS.OK,
    };
  }

  nowSecondsOrDefault(value) {
    return normalizeIntegerSeconds(
      value ?? Math.floor(Date.now() / 1000),
      "nowUnixTimeSeconds",
      { required: true },
    ).seconds;
  }

  pkceGenerate({ verifier }) {
    this.resetScratch();
    const vcPkceGenerate = this.requireExport("vc_pkce_challenge_generate");
    const verifierSlice = this.writeBytes(requireBytes(verifier, "verifier"));
    const verifierSlicePtr = this.alloc(8);
    this.writeSlice(verifierSlicePtr, verifierSlice);
    const resultPtr = this.alloc(16);
    vcPkceGenerate(resultPtr, verifierSlicePtr, VC_PKCE_METHOD_S256);
    const statusCode = this.readU32(resultPtr + 0);
    const dataPtr = this.readU32(resultPtr + 4);
    const dataLen = this.readU32(resultPtr + 8);
    return {
      statusCode,
      ok: statusCode === VC_STATUS.OK,
      challenge:
        statusCode === VC_STATUS.OK && dataPtr !== 0 && dataLen > 0
          ? decodeUtf8(this.readBytes(dataPtr, dataLen))
          : null,
    };
  }

  pkceVerify({ verifier, challenge }) {
    this.resetScratch();
    const vcPkceVerify = this.requireExport("vc_pkce_challenge_verify");
    const verifierSlice = this.writeBytes(requireBytes(verifier, "verifier"));
    const challengeSlice = this.writeBytes(requireBytes(challenge, "challenge"));
    const verifierSlicePtr = this.alloc(8);
    this.writeSlice(verifierSlicePtr, verifierSlice);
    const challengeSlicePtr = this.alloc(8);
    this.writeSlice(challengeSlicePtr, challengeSlice);
    const resultPtr = this.alloc(16);
    vcPkceVerify(resultPtr, verifierSlicePtr, challengeSlicePtr, VC_PKCE_METHOD_S256);
    const statusCode = this.readU32(resultPtr + 0);
    return { statusCode, ok: statusCode === VC_STATUS.OK };
  }

  async jwtVerifyClaims(input) {
    this.resetScratch();
    const verifyJwtClaims = this.requireExport("VerifiedCore_jwt_verify_claims_v1");
    const outputPtr = this.alloc(80);
    const signingInput = requireBytes(input.signingInput, "signingInput");
    const signature = requireBytes(input.signature, "signature");
    const allowedAlgorithmsBitmask =
      input.allowedAlgorithmsBitmask ??
      resolveJwtAllowedAlgorithmsBitmaskForProfile(input.cryptoProfile);
    const algorithmBit = resolveAlgorithmBit({
      algorithm: input.algorithm ?? input.alg ?? null,
      allowedAlgorithmsBitmask,
      fieldName: "jwt algorithm",
    });
    if (algorithmBit == null) {
      return emptyJwtVerificationOutput(VC_STATUS.UNSUPPORTED);
    }
    let flags = input.flags ?? 0;
    let publicKeyMaterial;
    if (algorithmBit !== VC_ALG.EDDSA) {
      const verified = await verifyJoseSignatureWeb({
        algorithmBit,
        publicKey: input.publicKey,
        signingInput,
        signature,
        subtle: this.subtle,
      });
      if (!verified) {
        return emptyJwtVerificationOutput(VC_STATUS.INVALID_SIGNATURE);
      }
      flags |= VC_JWT_FLAGS.SIGNATURE_PREVERIFIED;
      publicKeyMaterial = normalizePublicKeyForCore(
        input.publicKey,
        algorithmBit,
        "publicKey",
      );
    } else {
      publicKeyMaterial = {
        bytes: normalizeEd25519PublicKey(input.publicKey),
        format: VC_PUBLIC_KEY_FORMAT.RAW_ED25519,
      };
    }
    const claimsIssuerHandle =
      input.claimsIssuer == null
        ? 0
        : this.registerHandleString(input.claimsIssuer);
    const claimsAudienceHandle = this.registerHandleAudience(input.claimsAudience ?? null);
    const expectedIssuerHandle =
      input.expectedIssuer == null
        ? 0
        : this.registerHandleString(input.expectedIssuer);
    const expectedAudienceHandle = this.registerHandleAudience(input.expectedAudience ?? null);

    const inputPtr = this.writeJwtClaimsInput({
      signingInputHandle: this.registerHandleBytes(signingInput),
      signatureBytesHandle: this.registerHandleBytes(signature),
      publicKeyBytesHandle: this.registerHandleBytes(publicKeyMaterial.bytes),
      publicKeyFormat: publicKeyMaterial.format,
      claimsIssuerHandle,
      claimsAudienceHandle,
      allowedAlgorithmsBitmask: algorithmBit,
      flags,
      expectedIssuerHandle,
      expectedAudienceHandle,
      expSeconds: normalizeIntegerSeconds(input.expSeconds, "expSeconds").seconds,
      nbfSeconds: normalizeIntegerSeconds(input.nbfSeconds, "nbfSeconds").seconds,
      iatSeconds: normalizeIntegerSeconds(input.iatSeconds, "iatSeconds").seconds,
      nowUnixTimeSeconds: this.nowSecondsOrDefault(input.nowUnixTimeSeconds),
    });

    verifyJwtClaims(inputPtr, outputPtr);
    return this.readJwtVerificationOutput(outputPtr);
  }

  async jwtVerify(input) {
    this.resetScratch();
    const verifyJwt = this.requireExport("VerifiedCore_jwt_verify_v1");
    const outputPtr = this.alloc(80);
    let parsed;
    try {
      parsed = parseCompactJws(requireBytes(input.jwt, "jwt"), "jwt compact JWS");
    } catch {
      return emptyJwtVerificationOutput(VC_STATUS.INVALID_FORMAT);
    }
    const allowedAlgorithmsBitmask =
      input.allowedAlgorithmsBitmask ??
      resolveJwtAllowedAlgorithmsBitmaskForProfile(input.cryptoProfile);
    const algorithmBit = resolveAlgorithmBit({
      algorithm: parseMaybeString(parsed.header.alg, "jwt protected header alg"),
      allowedAlgorithmsBitmask,
      fieldName: "jwt protected header alg",
    });
    if (algorithmBit == null) {
      return emptyJwtVerificationOutput(VC_STATUS.UNSUPPORTED);
    }
    let flags = input.flags ?? 0;
    let publicKeyMaterial;
    if (algorithmBit !== VC_ALG.EDDSA) {
      const verified = await verifyJoseSignatureWeb({
        algorithmBit,
        publicKey: input.publicKey,
        signingInput: parsed.signingInput,
        signature: parsed.signatureBytes,
        subtle: this.subtle,
      });
      if (!verified) {
        return emptyJwtVerificationOutput(VC_STATUS.INVALID_SIGNATURE);
      }
      flags |= VC_JWT_FLAGS.SIGNATURE_PREVERIFIED;
      publicKeyMaterial = normalizePublicKeyForCore(
        input.publicKey,
        algorithmBit,
        "publicKey",
      );
    } else {
      publicKeyMaterial = {
        bytes: normalizeEd25519PublicKey(input.publicKey),
        format: VC_PUBLIC_KEY_FORMAT.RAW_ED25519,
      };
    }
    const inputPtr = this.writeJwtVerificationInput({
      jwtCompactJwsHandle: this.registerHandleBytes(requireBytes(input.jwt, "jwt")),
      expectedIssuerHandle:
        input.expectedIssuer == null
          ? 0
          : this.registerHandleString(input.expectedIssuer),
      expectedAudienceHandle: this.registerHandleAudience(input.expectedAudience ?? null),
      publicKeyBytesHandle: this.registerHandleBytes(publicKeyMaterial.bytes),
      nowUnixTimeSeconds: this.nowSecondsOrDefault(input.nowUnixTimeSeconds),
      allowedAlgorithmsBitmask: algorithmBit,
      publicKeyFormat: publicKeyMaterial.format,
      flags,
    });
    verifyJwt(inputPtr, outputPtr);
    return this.readJwtVerificationOutput(outputPtr);
  }

  async dpopVerifyClaims(input) {
    this.resetScratch();
    const verifyDpopClaims = this.requireExport("VerifiedCore_dpop_verify_claims_v1");
    const outputPtr = this.alloc(112);

    const signingInput = requireBytes(input.signingInput, "signingInput");
    const signature = requireBytes(input.signature, "signature");
    const allowedAlgorithmsBitmask =
      input.allowedAlgorithmsBitmask ??
      resolveDpopAllowedAlgorithmsBitmaskForProfile(input.cryptoProfile);
    const algorithmBit = resolveAlgorithmBit({
      algorithm: input.algorithm ?? input.alg ?? null,
      allowedAlgorithmsBitmask,
      fieldName: "dpop algorithm",
    });
    if (algorithmBit == null) {
      return emptyDpopVerificationOutput(VC_STATUS.UNSUPPORTED);
    }

    let accessTokenHashHandle = 0;
    if (input.ath != null) {
      const ath = parseMaybeString(input.ath, "ath");
      if (input.accessToken != null) {
        const expectedAth = encodeBase64Url(
          await digestBytes(
            requireBytes(input.accessToken, "accessToken"),
            "SHA-256",
            this.subtle,
          ),
        );
        if (ath !== expectedAth) {
          return emptyDpopVerificationOutput(VC_STATUS.INVALID_CLAIMS);
        }
      }
      accessTokenHashHandle = this.registerHandleString(ath);
    }

    let flags = input.flags ?? 0;
    let publicKeyMaterial;
    if (algorithmBit !== VC_ALG.EDDSA) {
      const verified = await verifyJoseSignatureWeb({
        algorithmBit,
        publicKey: input.publicKey,
        signingInput,
        signature,
        subtle: this.subtle,
      });
      if (!verified) {
        return emptyDpopVerificationOutput(VC_STATUS.INVALID_SIGNATURE);
      }
      flags |= VC_DPOP_FLAGS.SIGNATURE_PREVERIFIED;
      publicKeyMaterial = normalizePublicKeyForCore(
        input.publicKey,
        algorithmBit,
        "publicKey",
      );
    } else {
      publicKeyMaterial = {
        bytes: normalizeEd25519PublicKey(input.publicKey),
        format: VC_PUBLIC_KEY_FORMAT.RAW_ED25519,
      };
    }

    const inputPtr = this.writeDpopClaimsInput({
      httpMethodBytesHandle:
        input.httpMethod == null
          ? 0
          : this.registerHandleString(input.httpMethod),
      httpUriBytesHandle: input.httpUri == null ? 0 : this.registerHandleString(input.httpUri),
      signingInputHandle: this.registerHandleBytes(signingInput),
      signatureBytesHandle: this.registerHandleBytes(signature),
      publicKeyBytesHandle: this.registerHandleBytes(publicKeyMaterial.bytes),
      publicKeyFormat: publicKeyMaterial.format,
      replayNamespaceHandle:
        input.replayNamespace == null
          ? 0
          : this.registerHandleString(input.replayNamespace),
      accessTokenHashHandle,
      jtiBytesHandle: input.jti == null ? 0 : this.registerHandleString(input.jti),
      allowedAlgorithmsBitmask: algorithmBit,
      flags,
      iatSeconds: normalizeIntegerSeconds(input.iatSeconds, "iatSeconds", {
        required: true,
      }).seconds,
      nowUnixTimeSeconds: this.nowSecondsOrDefault(input.nowUnixTimeSeconds),
      maxAgeSeconds: input.maxAgeSeconds ?? 300,
      maxFutureSkewSeconds: input.maxFutureSkewSeconds ?? 60,
    });

    verifyDpopClaims(inputPtr, outputPtr);
    return this.readDpopVerificationOutput(outputPtr);
  }

  async dpopVerify(input) {
    this.resetScratch();
    const verifyDpop = this.requireExport("VerifiedCore_dpop_verify_v1");
    const outputPtr = this.alloc(112);
    let parsed;
    try {
      parsed = parseCompactJws(requireBytes(input.dpopProof, "dpopProof"), "dpop compact JWS");
    } catch {
      return emptyDpopVerificationOutput(VC_STATUS.INVALID_FORMAT);
    }
    const allowedAlgorithmsBitmask =
      input.allowedAlgorithmsBitmask ??
      resolveDpopAllowedAlgorithmsBitmaskForProfile(input.cryptoProfile);
    const algorithmBit = resolveAlgorithmBit({
      algorithm: parseMaybeString(parsed.header.alg, "dpop protected header alg"),
      allowedAlgorithmsBitmask,
      fieldName: "dpop protected header alg",
    });
    if (algorithmBit == null) {
      return emptyDpopVerificationOutput(VC_STATUS.UNSUPPORTED);
    }
    let flags = input.flags ?? 0;
    if (algorithmBit !== VC_ALG.EDDSA) {
      const verified = await verifyJoseSignatureWeb({
        algorithmBit,
        publicKey: parsed.header.jwk,
        signingInput: parsed.signingInput,
        signature: parsed.signatureBytes,
        subtle: this.subtle,
      });
      if (!verified) {
        return emptyDpopVerificationOutput(VC_STATUS.INVALID_SIGNATURE);
      }
      flags |= VC_DPOP_FLAGS.SIGNATURE_PREVERIFIED;
    }
    const inputPtr = this.writeDpopVerificationInput({
      httpMethodBytesHandle: this.registerHandleString(
        requireString(input.httpMethod, "httpMethod"),
      ),
      httpUriBytesHandle: this.registerHandleString(requireString(input.httpUri, "httpUri")),
      dpopCompactJwsHandle: this.registerHandleBytes(requireBytes(input.dpopProof, "dpopProof")),
      accessTokenHandle:
        input.accessToken == null
          ? 0
          : this.registerHandleBytes(
              requireBytes(input.accessToken, "accessToken"),
            ),
      replayNamespaceHandle:
        input.replayNamespace == null
          ? 0
          : this.registerHandleString(input.replayNamespace),
      nowUnixTimeSeconds: this.nowSecondsOrDefault(input.nowUnixTimeSeconds),
      maxAgeSeconds: input.maxAgeSeconds ?? 300,
      maxFutureSkewSeconds: input.maxFutureSkewSeconds ?? 60,
      flags,
      allowedAlgorithmsBitmask: algorithmBit,
    });
    verifyDpop(inputPtr, outputPtr);
    return this.readDpopVerificationOutput(outputPtr);
  }

  clearReplayStore() {
    if (typeof this.replayStore.clear === "function") {
      this.replayStore.clear();
    }
  }

  createHandle() {
    return {
      pkceGenerate: async (input) => this.pkceGenerate(input),
      pkceVerify: async (input) => this.pkceVerify(input),
      jwtVerify: async (input) => this.jwtVerify(input),
      jwtVerifyClaims: async (input) => this.jwtVerifyClaims(input),
      dpopVerify: async (input) => this.dpopVerify(input),
      dpopVerifyClaims: async (input) => this.dpopVerifyClaims(input),
      clearReplayStore: () => this.clearReplayStore(),
      abiVersion: () => Number(this.instance.exports.vc_abi_version?.() ?? 0),
    };
  }
}

export async function initCore(options = {}) {
  ensureSecureContext(options);
  const { wasmBytes, manifest } = await loadArtifact(options);
  const runtime = new WebReferenceCoreRuntime(wasmBytes, manifest, options);
  await runtime.instantiate();
  return {
    manifest,
    instance: runtime.instance,
    handle: runtime.createHandle(),
    runtime,
  };
}

export function createInMemoryReplayStore() {
  return new InMemoryReplayStore();
}

export function resolveDefaultArtifactUrls() {
  return defaultArtifactUrls();
}
