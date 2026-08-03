/**
 * Verified Core TypeScript Definitions
 * Auto-generated from ABI specification
 * ABI Version: 1.0.0
 */

// ============================================================
// Enums
// ============================================================

/** VerifiedCoreStatusCode enum (u32) */
export type VerifiedCoreStatusCode =
  | 0 // OK
  | 1 // INVALID_ARGUMENT
  | 2 // INVALID_FORMAT
  | 3 // INVALID_SIGNATURE
  | 4 // INVALID_CLAIMS
  | 5 // REPLAY
  | 6 // UNAVAILABLE
  | 7 // UNSUPPORTED
  | 8 // INTERNAL_ERROR;

/** ReplayStoreResult enum (u32) */
export type ReplayStoreResult =
  | 0 // OK
  | 1 // REPLAY
  | 2 // UNAVAILABLE;

/** HostCryptoVerifyResult enum (u32) */
export type HostCryptoVerifyResult =
  | 0 // VALID
  | 1 // INVALID
  | 2 // UNSUPPORTED
  | 3 // ERROR;

/** SignatureAlgorithm enum (u32) */
export type SignatureAlgorithm =
  | 1 // ES256
  | 2 // RS256
  | 3 // EdDSA;

/** PublicKeyFormat enum (u32) */
export type PublicKeyFormat =
  | 1 // JWK_JSON_UTF8
  | 2 // SPKI_DER
  | 3 // RAW_EC_P256_UNCOMPRESSED;

// ============================================================
// Enum Constants
// ============================================================

export const VerifiedCoreStatusCode = {
  OK: 0,
  INVALID_ARGUMENT: 1,
  INVALID_FORMAT: 2,
  INVALID_SIGNATURE: 3,
  INVALID_CLAIMS: 4,
  REPLAY: 5,
  UNAVAILABLE: 6,
  UNSUPPORTED: 7,
  INTERNAL_ERROR: 8,
} as const;

export const ReplayStoreResult = {
  OK: 0,
  REPLAY: 1,
  UNAVAILABLE: 2,
} as const;

export const HostCryptoVerifyResult = {
  VALID: 0,
  INVALID: 1,
  UNSUPPORTED: 2,
  ERROR: 3,
} as const;

export const SignatureAlgorithm = {
  ES256: 1,
  RS256: 2,
  EdDSA: 3,
} as const;

export const PublicKeyFormat = {
  JWK_JSON_UTF8: 1,
  SPKI_DER: 2,
  RAW_EC_P256_UNCOMPRESSED: 3,
} as const;

// ============================================================
// Structs (for reference - actual memory layout in ABI JSON)
// ============================================================

/** FStar_Bytes_bytes (8 bytes) */
export interface FStar_Bytes_bytes {
  /** Offset: 0 - Number of bytes in the data buffer. */
  length: number;
  /** Offset: 4 - Pointer to byte data in wasm linear memory. */
  dataPtr: unknown;
}

/** Bytes32 (32 bytes) */
export interface Bytes32 {
  /** Offset: 0 */
  bytes: unknown;
}

/** DpopVerificationInputV1 (56 bytes) */
export interface DpopVerificationInputV1 {
  /** Offset: 0 - Uppercase ASCII, e.g., "GET". */
  httpMethodBytesHandle: unknown;
  /** Offset: 4 - Absolute URL UTF-8. */
  httpUriBytesHandle: unknown;
  /** Offset: 8 - DPoP proof (JWS compact) UTF-8. */
  dpopCompactJwsHandle: unknown;
  /** Offset: 12 - Optional. 0 means absent. */
  accessTokenHandle: unknown;
  /** Offset: 16 - Recommended: environment_id canonical string. */
  replayNamespaceHandle: unknown;
  /** Offset: 20 - Must be 0. */
  padding0: number;
  /** Offset: 24 */
  nowUnixTimeSeconds: bigint;
  /** Offset: 32 - Recommended default: 300. */
  maxAgeSeconds: number;
  /** Offset: 36 - Recommended default: 60. */
  maxFutureSkewSeconds: number;
  /** Offset: 40 - Bitmask. See dpopFlags. */
  flags: number;
  /** Offset: 44 - Bit0 ES256, Bit1 RS256, Bit2 EdDSA. */
  allowedAlgorithmsBitmask: number;
  /** Offset: 48 - Must be 0. */
  reserved0: number;
  /** Offset: 52 - Must be 0. */
  reserved1: number;
}

/** DpopClaimsInputV1 (72 bytes) */
export interface DpopClaimsInputV1 {
  /** Offset: 0 - Uppercase ASCII method. */
  httpMethodBytesHandle: unknown;
  /** Offset: 4 - Absolute URI (UTF-8). */
  httpUriBytesHandle: unknown;
  /** Offset: 8 - ASCII `base64url(header)`.`base64url(payload)`. */
  signingInputHandle: unknown;
  /** Offset: 12 - JOSE/P1363 signature bytes. */
  signatureBytesHandle: unknown;
  /** Offset: 16 - Public key material (format specified below). */
  publicKeyBytesHandle: unknown;
  /** Offset: 20 */
  publicKeyFormat: unknown;
  /** Offset: 24 - Environment/issuer namespace for replay store. */
  replayNamespaceHandle: unknown;
  /** Offset: 28 - Optional `ath` value (base64url). Zero means absent. */
  accessTokenHashHandle: unknown;
  /** Offset: 32 - Optional jti string (UTF-8). Zero means absent. */
  jtiBytesHandle: unknown;
  /** Offset: 36 - Bit0 ES256, Bit1 RS256, Bit2 EdDSA. */
  allowedAlgorithmsBitmask: number;
  /** Offset: 40 - Bitmask. See dpopFlags. */
  flags: number;
  /** Offset: 44 - Must be 0. */
  reserved0: number;
  /** Offset: 48 */
  iatSeconds: bigint;
  /** Offset: 56 - Current time for iat window validation. */
  nowUnixTimeSeconds: bigint;
  /** Offset: 64 */
  maxAgeSeconds: number;
  /** Offset: 68 */
  maxFutureSkewSeconds: number;
}

/** DpopVerificationOutputV1 (112 bytes) */
export interface DpopVerificationOutputV1 {
  /** Offset: 0 - SHA-256(JWK thumbprint) or equivalent key ID hash. Zeroed if proof lacks jwk. */
  jktHash: unknown;
  /** Offset: 32 - Fixed 32-byte replay key hash passed to ReplayStore. */
  replayKeyHash: unknown;
  /** Offset: 64 - Optional: SHA-256(jti). Zero if missing. */
  jtiHash: unknown;
  /** Offset: 96 */
  proofIatSeconds: bigint;
  /** Offset: 104 - Bitmask. See dpopResultFlags. */
  flags: number;
  /** Offset: 108 */
  statusCode: unknown;
}

/** JwtClaimsInputV1 (72 bytes) */
export interface JwtClaimsInputV1 {
  /** Offset: 0 - ASCII `base64url(header)`.`base64url(payload)`. */
  signingInputHandle: unknown;
  /** Offset: 4 - Signature bytes (JOSE/P1363 for ES256). */
  signatureBytesHandle: unknown;
  /** Offset: 8 */
  publicKeyBytesHandle: unknown;
  /** Offset: 12 */
  publicKeyFormat: unknown;
  /** Offset: 16 - Optional issuer string. Zero means absent. */
  claimsIssuerHandle: unknown;
  /** Offset: 20 - Optional audience (JSON array string). Zero means absent. */
  claimsAudienceHandle: unknown;
  /** Offset: 24 */
  allowedAlgorithmsBitmask: number;
  /** Offset: 28 - Bitmask. See jwtFlags. */
  flags: number;
  /** Offset: 32 - Optional expected issuer string. Zero disables the check. */
  expectedIssuerHandle: unknown;
  /** Offset: 36 - Optional expected audience string. Zero disables the check. */
  expectedAudienceHandle: unknown;
  /** Offset: 40 - Optional. Zero when absent, check flags. */
  expSeconds: bigint;
  /** Offset: 48 - Optional. Zero when absent. */
  nbfSeconds: bigint;
  /** Offset: 56 - Optional. Zero when absent. */
  iatSeconds: bigint;
  /** Offset: 64 */
  nowUnixTimeSeconds: bigint;
}

/** JwtVerificationInputV1 (40 bytes) */
export interface JwtVerificationInputV1 {
  /** Offset: 0 - JWT JWS compact UTF-8. */
  jwtCompactJwsHandle: unknown;
  /** Offset: 4 - Optional. 0 means absent. */
  expectedIssuerHandle: unknown;
  /** Offset: 8 - Optional. 0 means absent. */
  expectedAudienceHandle: unknown;
  /** Offset: 12 - Public key in format specified by publicKeyFormat. */
  publicKeyBytesHandle: unknown;
  /** Offset: 16 */
  nowUnixTimeSeconds: bigint;
  /** Offset: 24 - Bit0 ES256, Bit1 RS256, Bit2 EdDSA. */
  allowedAlgorithmsBitmask: number;
  /** Offset: 28 */
  publicKeyFormat: unknown;
  /** Offset: 32 - Bitmask. See jwtFlags. */
  flags: number;
  /** Offset: 36 - Must be 0. */
  reserved0: number;
}

/** JwtVerificationOutputV1 (80 bytes) */
export interface JwtVerificationOutputV1 {
  /** Offset: 0 - SHA-256 of the signing-input bytes (`base64url(header).base64url(payload)`), computed inside the current verified WASM path for audit correlation. */
  payloadHash: unknown;
  /** Offset: 32 - SHA-256(kid) if present; zero otherwise. */
  kidHash: unknown;
  /** Offset: 64 - Bitmask. See jwtResultFlags. */
  flags: number;
  /** Offset: 68 */
  statusCode: unknown;
  /** Offset: 72 - Must be 0. */
  reserved0: number;
  /** Offset: 76 - Must be 0. */
  reserved1: number;
}

// ============================================================
// WASM Exports
// ============================================================

export interface VerifiedCoreExports {
  /** Validate PKCE verifier format: 43-128 characters from unreserved charset [A-Za-z0-9._~-]. */
  Pkce_verifier_ok(verifierPtr: number): number;
  /** Verify PKCE challenge against verifier using specified method. For S256: challenge == base64url(sha256(verifier)). */
  Pkce_verify_pkce(methodPtr: number, verifierPtr: number, challengePtr: number): number;
  /** Verify DPoP proof. On success returns OK and fills output. On replay returns REPLAY. On store/crypto failure returns UNAVAILABLE. */
  VerifiedCore_dpop_verify_v1(inputPtr: number, outputPtr: number): number;
  /** Verify DPoP proof from pre-parsed claims and signature components. Flags reuse dpopFlags. */
  VerifiedCore_dpop_verify_claims_v1(inputPtr: number, outputPtr: number): number;
  /** Verify JWT JWS compact using provided public key and claim constraints. Returns INVALID_SIGNATURE or INVALID_CLAIMS as appropriate. */
  VerifiedCore_jwt_verify_v1(inputPtr: number, outputPtr: number): number;
  /** Verify JWT signature and standard claims from pre-parsed inputs, including optional expected issuer/audience checks. */
  VerifiedCore_jwt_verify_claims_v1(inputPtr: number, outputPtr: number): number;
}

// ============================================================
// WASM Imports (host must provide)
// ============================================================

export interface envImports {
  /** Atomically check replay and store. Returns OK, REPLAY, or UNAVAILABLE. */
  VerifiedCore_Api_Claims_Runtime_host_replay_store_check_and_store(namespaceHandle: number, keyHashPtr: number, ttlMilliseconds: number): number;
  /** Register a byte region from wasm linear memory as a host-managed handle. Returns 0 on failure. */
  vc_host_register_bytes(dataPtr: number, len: number): number;
  /** Release a handle returned by `vc_host_register_bytes`. */
  vc_host_release_handle(handle: number): void;
  /** Parse DPoP compact JWS into components struct. Returns 0 on success. */
  Host_parse_dpop_compact(compactJwsHandle: number, outputPtr: number): number;
  /** Resolve a bytes handle to a pointer in wasm linear memory. Returns 0 for invalid handles. */
  Host_handle_data_ptr(handle: number): number;
  /** Resolve a bytes handle to its byte length. Returns 0 for invalid handles. */
  Host_handle_data_len(handle: number): number;
  /** Parse JWT compact JWS into components struct. Returns 0 on success. */
  Host_parse_jwt_compact(compactJwsHandle: number, outputPtr: number): number;
}

// ============================================================
// Bitmask Constants
// ============================================================

export const dpopFlags = {
  REQUIRE_ACCESS_TOKEN_HASH: 1 << 0, // bit 0
  REQUIRE_JTI: 1 << 1, // bit 1
  SIGNATURE_PREVERIFIED: 1 << 2, // bit 2
} as const;

export const dpopResultFlags = {
  HAS_JTI: 1 << 0, // bit 0
  HAS_ATH: 1 << 1, // bit 1
} as const;

export const jwtFlags = {
  REQUIRE_EXP: 1 << 0, // bit 0
  REQUIRE_IAT: 1 << 1, // bit 1
  REQUIRE_NBF: 1 << 2, // bit 2
  SIGNATURE_PREVERIFIED: 1 << 3, // bit 3
} as const;

export const jwtResultFlags = {
  HAS_KID: 1 << 0, // bit 0
} as const;
