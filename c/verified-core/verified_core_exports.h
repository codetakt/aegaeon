#ifndef VERIFIED_CORE_EXPORTS_H
#define VERIFIED_CORE_EXPORTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum VerifiedCoreStatusCode {
  VerifiedCoreStatusCode_OK = 0,
  VerifiedCoreStatusCode_INVALID_ARGUMENT = 1,
  VerifiedCoreStatusCode_INVALID_FORMAT = 2,
  VerifiedCoreStatusCode_INVALID_SIGNATURE = 3,
  VerifiedCoreStatusCode_INVALID_CLAIMS = 4,
  VerifiedCoreStatusCode_REPLAY = 5,
  VerifiedCoreStatusCode_UNAVAILABLE = 6,
  VerifiedCoreStatusCode_UNSUPPORTED = 7,
  VerifiedCoreStatusCode_INTERNAL_ERROR = 8
} VerifiedCoreStatusCode;

typedef struct DpopVerificationInputV1 {
  uint32_t httpMethodBytesHandle;
  uint32_t httpUriBytesHandle;
  uint32_t dpopCompactJwsHandle;
  uint32_t accessTokenHandle;
  uint32_t replayNamespaceHandle;
  uint32_t padding0;
  uint64_t nowUnixTimeSeconds;
  uint32_t maxAgeSeconds;
  uint32_t maxFutureSkewSeconds;
  uint32_t flags;
  uint32_t allowedAlgorithmsBitmask;
  uint32_t reserved0;
  uint32_t reserved1;
} DpopVerificationInputV1;

typedef struct DpopVerificationOutputV1 {
  uint8_t jktHash[32];
  uint8_t replayKeyHash[32];
  uint8_t jtiHash[32];
  uint64_t proofIatSeconds;
  uint32_t flags;
  uint32_t statusCode;
} DpopVerificationOutputV1;

/* Host callback result for parsing DPoP compact JWS */
typedef struct DpopParsedComponents {
  uint32_t signingInputHandle;
  uint32_t signatureBytesHandle;
  uint32_t publicKeyHandle;       /* JWK from header */
  uint32_t publicKeyFormat;       /* Always JWK_JSON_UTF8 (1) for DPoP */
  uint32_t htmHandle;             /* HTTP method from claims */
  uint32_t htuHandle;             /* HTTP URI from claims */
  uint32_t jtiHandle;             /* Optional, 0 if absent */
  uint32_t athHandle;             /* Optional, 0 if absent */
  uint64_t iatSeconds;
  uint32_t statusCode;            /* 0 = OK, non-zero = parse error */
  uint32_t reserved0;
} DpopParsedComponents;

/* Host callback result for parsing JWT compact JWS */
typedef struct JwtParsedComponents {
  uint32_t signingInputHandle;
  uint32_t signatureBytesHandle;
  uint32_t issHandle;             /* Optional, 0 if absent */
  uint32_t audHandle;             /* Optional, 0 if absent (JSON array string) */
  uint64_t expSeconds;            /* 0 if absent, check hasExp */
  uint64_t nbfSeconds;            /* 0 if absent, check hasNbf */
  uint64_t iatSeconds;            /* 0 if absent, check hasIat */
  uint32_t hasExp;                /* 1 if exp present, 0 otherwise */
  uint32_t hasNbf;                /* 1 if nbf present, 0 otherwise */
  uint32_t hasIat;                /* 1 if iat present, 0 otherwise */
  uint32_t kidHandle;             /* Optional key ID, 0 if absent */
  uint32_t statusCode;            /* 0 = OK, non-zero = parse error */
} JwtParsedComponents;

typedef struct DpopClaimsInputV1 {
  uint32_t httpMethodBytesHandle;
  uint32_t httpUriBytesHandle;
  uint32_t signingInputHandle;
  uint32_t signatureBytesHandle;
  uint32_t publicKeyBytesHandle;
  uint32_t publicKeyFormat;
  uint32_t replayNamespaceHandle;
  uint32_t accessTokenHashHandle;
  uint32_t jtiBytesHandle;
  uint32_t allowedAlgorithmsBitmask;
  uint32_t flags;
  uint32_t reserved0;
  uint64_t iatSeconds;
  uint64_t nowUnixTimeSeconds;
  uint32_t maxAgeSeconds;
  uint32_t maxFutureSkewSeconds;
} DpopClaimsInputV1;

typedef struct JwtVerificationInputV1 {
  uint32_t jwtCompactJwsHandle;
  uint32_t expectedIssuerHandle;
  uint32_t expectedAudienceHandle;
  uint32_t publicKeyBytesHandle;
  uint64_t nowUnixTimeSeconds;
  uint32_t allowedAlgorithmsBitmask;
  uint32_t publicKeyFormat;
  uint32_t flags;
  uint32_t reserved0;
} JwtVerificationInputV1;

typedef struct JwtClaimsInputV1 {
  uint32_t signingInputHandle;
  uint32_t signatureBytesHandle;
  uint32_t publicKeyBytesHandle;
  uint32_t publicKeyFormat;
  uint32_t claimsIssuerHandle;       /* Optional issuer claim value, 0 if absent */
  uint32_t claimsAudienceHandle;     /* Optional audience claim JSON/string, 0 if absent */
  uint32_t allowedAlgorithmsBitmask;
  uint32_t flags;
  uint32_t expectedIssuerHandle;     /* Optional expected issuer, 0 disables the check */
  uint32_t expectedAudienceHandle;   /* Optional expected audience, 0 disables the check */
  uint64_t expSeconds;
  uint64_t nbfSeconds;
  uint64_t iatSeconds;
  uint64_t nowUnixTimeSeconds;
} JwtClaimsInputV1;

typedef struct JwtVerificationOutputV1 {
  uint8_t payloadHash[32];
  uint8_t kidHash[32];
  uint32_t flags;
  uint32_t statusCode;
  uint32_t reserved0;
  uint32_t reserved1;
} JwtVerificationOutputV1;

uint32_t VerifiedCore_dpop_verify_v1(
  const DpopVerificationInputV1 *input,
  DpopVerificationOutputV1 *output
);

uint32_t VerifiedCore_dpop_verify_claims_v1(
  const DpopClaimsInputV1 *input,
  DpopVerificationOutputV1 *output
);

uint32_t VerifiedCore_jwt_verify_v1(
  const JwtVerificationInputV1 *input,
  JwtVerificationOutputV1 *output
);

uint32_t VerifiedCore_jwt_verify_claims_v1(
  const JwtClaimsInputV1 *input,
  JwtVerificationOutputV1 *output
);

/* Host callbacks for JWS compact format parsing */
extern uint32_t Host_parse_dpop_compact(
  uint32_t dpopCompactJwsHandle,
  DpopParsedComponents *result
);

extern uint32_t Host_parse_jwt_compact(
  uint32_t jwtCompactJwsHandle,
  JwtParsedComponents *result
);

/* Host callback: resolve handle to WASM linear memory pointer.
 * Returns the data pointer for the given handle, or NULL (0) if invalid.
 * The pointer remains valid until the handle is released. */
extern uint8_t *Host_handle_data_ptr(uint32_t handle);

/* Host callback: resolve handle to data length.
 * Returns the byte length for the given handle, or 0 if invalid. */
extern uint32_t Host_handle_data_len(uint32_t handle);

#ifdef __cplusplus
}
#endif

#endif /* VERIFIED_CORE_EXPORTS_H */
