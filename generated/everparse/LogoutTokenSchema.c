

#include "LogoutTokenSchema.h"

static inline uint64_t
ValidateLenPrefixedBytes(
  uint8_t *Ctxt,
  void
  (*ErrorHandlerFn)(
    EVERPARSE_STRING x0,
    EVERPARSE_STRING x1,
    EVERPARSE_STRING x2,
    uint64_t x3,
    uint8_t *x4,
    uint8_t *x5,
    uint64_t x6
  ),
  uint8_t *Input,
  uint64_t InputLength,
  uint64_t StartPosition
)
{
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes0 = 4ULL <= (InputLength - StartPosition);
  uint64_t positionAfterLenPrefixedBytes;
  if (hasBytes0)
  {
    positionAfterLenPrefixedBytes = StartPosition + 4ULL;
  }
  else
  {
    positionAfterLenPrefixedBytes =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterlen;
  if (EverParseIsSuccess(positionAfterLenPrefixedBytes))
  {
    positionAfterlen = positionAfterLenPrefixedBytes;
  }
  else
  {
    ErrorHandlerFn("_len_prefixed_bytes",
      "len",
      EverParseErrorReasonOfResult(positionAfterLenPrefixedBytes),
      EverParseGetValidatorErrorKind(positionAfterLenPrefixedBytes),
      Ctxt,
      Input,
      StartPosition);
    positionAfterlen = positionAfterLenPrefixedBytes;
  }
  if (EverParseIsError(positionAfterlen))
  {
    return positionAfterlen;
  }
  uint32_t len = Load32Le(Input + (uint32_t)StartPosition);
  /* Validating field bytes */
  BOOLEAN hasBytes = (uint64_t)len <= (InputLength - positionAfterlen);
  uint64_t res;
  if (hasBytes)
  {
    res = positionAfterlen + (uint64_t)len;
  }
  else
  {
    res =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterlen);
  }
  uint64_t positionAfterLenPrefixedBytes0 = res;
  if (EverParseIsSuccess(positionAfterLenPrefixedBytes0))
  {
    return positionAfterLenPrefixedBytes0;
  }
  ErrorHandlerFn("_len_prefixed_bytes",
    "bytes",
    EverParseErrorReasonOfResult(positionAfterLenPrefixedBytes0),
    EverParseGetValidatorErrorKind(positionAfterLenPrefixedBytes0),
    Ctxt,
    Input,
    positionAfterlen);
  return positionAfterLenPrefixedBytes0;
}

static inline uint64_t
ValidateMaybeString(
  uint8_t *Ctxt,
  void
  (*ErrorHandlerFn)(
    EVERPARSE_STRING x0,
    EVERPARSE_STRING x1,
    EVERPARSE_STRING x2,
    uint64_t x3,
    uint8_t *x4,
    uint8_t *x5,
    uint64_t x6
  ),
  uint8_t *Input,
  uint64_t InputLength,
  uint64_t StartPosition
)
{
  /* Validating field present */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes = 1ULL <= (InputLength - StartPosition);
  uint64_t positionAfterMaybeString;
  if (hasBytes)
  {
    positionAfterMaybeString = StartPosition + 1ULL;
  }
  else
  {
    positionAfterMaybeString =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t res;
  if (EverParseIsSuccess(positionAfterMaybeString))
  {
    res = positionAfterMaybeString;
  }
  else
  {
    ErrorHandlerFn("_maybe_string",
      "present",
      EverParseErrorReasonOfResult(positionAfterMaybeString),
      EverParseGetValidatorErrorKind(positionAfterMaybeString),
      Ctxt,
      Input,
      StartPosition);
    res = positionAfterMaybeString;
  }
  uint64_t positionAfterpresent = res;
  if (EverParseIsError(positionAfterpresent))
  {
    return positionAfterpresent;
  }
  /* Validating field value */
  uint64_t
  positionAfterMaybeString0 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterpresent);
  if (EverParseIsSuccess(positionAfterMaybeString0))
  {
    return positionAfterMaybeString0;
  }
  ErrorHandlerFn("_maybe_string",
    "value",
    EverParseErrorReasonOfResult(positionAfterMaybeString0),
    EverParseGetValidatorErrorKind(positionAfterMaybeString0),
    Ctxt,
    Input,
    positionAfterpresent);
  return positionAfterMaybeString0;
}

uint64_t
LogoutTokenSchemaValidateLogoutTokenJwtEntry(
  uint8_t *Ctxt,
  void
  (*ErrorHandlerFn)(
    EVERPARSE_STRING x0,
    EVERPARSE_STRING x1,
    EVERPARSE_STRING x2,
    uint64_t x3,
    uint8_t *x4,
    uint8_t *x5,
    uint64_t x6
  ),
  uint8_t *Input,
  uint64_t InputLength,
  uint64_t StartPosition
)
{
  /* Validating field header */
  uint64_t
  positionAfterLogoutTokenJwtEntry =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      StartPosition);
  uint64_t positionAfterheader;
  if (EverParseIsSuccess(positionAfterLogoutTokenJwtEntry))
  {
    positionAfterheader = positionAfterLogoutTokenJwtEntry;
  }
  else
  {
    ErrorHandlerFn("_logout_token_jwt_entry",
      "header",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenJwtEntry),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenJwtEntry),
      Ctxt,
      Input,
      StartPosition);
    positionAfterheader = positionAfterLogoutTokenJwtEntry;
  }
  if (EverParseIsError(positionAfterheader))
  {
    return positionAfterheader;
  }
  /* Validating field payload */
  uint64_t
  positionAfterLogoutTokenJwtEntry0 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterheader);
  uint64_t positionAfterpayload;
  if (EverParseIsSuccess(positionAfterLogoutTokenJwtEntry0))
  {
    positionAfterpayload = positionAfterLogoutTokenJwtEntry0;
  }
  else
  {
    ErrorHandlerFn("_logout_token_jwt_entry",
      "payload",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenJwtEntry0),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenJwtEntry0),
      Ctxt,
      Input,
      positionAfterheader);
    positionAfterpayload = positionAfterLogoutTokenJwtEntry0;
  }
  if (EverParseIsError(positionAfterpayload))
  {
    return positionAfterpayload;
  }
  /* Validating field signature */
  uint64_t
  positionAfterLogoutTokenJwtEntry1 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterpayload);
  if (EverParseIsSuccess(positionAfterLogoutTokenJwtEntry1))
  {
    return positionAfterLogoutTokenJwtEntry1;
  }
  ErrorHandlerFn("_logout_token_jwt_entry",
    "signature",
    EverParseErrorReasonOfResult(positionAfterLogoutTokenJwtEntry1),
    EverParseGetValidatorErrorKind(positionAfterLogoutTokenJwtEntry1),
    Ctxt,
    Input,
    positionAfterpayload);
  return positionAfterLogoutTokenJwtEntry1;
}

uint64_t
LogoutTokenSchemaValidateLogoutTokenClaimsEntry(
  uint8_t *Ctxt,
  void
  (*ErrorHandlerFn)(
    EVERPARSE_STRING x0,
    EVERPARSE_STRING x1,
    EVERPARSE_STRING x2,
    uint64_t x3,
    uint8_t *x4,
    uint8_t *x5,
    uint64_t x6
  ),
  uint8_t *Input,
  uint64_t InputLength,
  uint64_t StartPosition
)
{
  /* Validating field iss */
  uint64_t
  positionAfterLogoutTokenClaimsEntry =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      StartPosition);
  uint64_t positionAfteriss;
  if (EverParseIsSuccess(positionAfterLogoutTokenClaimsEntry))
  {
    positionAfteriss = positionAfterLogoutTokenClaimsEntry;
  }
  else
  {
    ErrorHandlerFn("_logout_token_claims_entry",
      "iss",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenClaimsEntry),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenClaimsEntry),
      Ctxt,
      Input,
      StartPosition);
    positionAfteriss = positionAfterLogoutTokenClaimsEntry;
  }
  if (EverParseIsError(positionAfteriss))
  {
    return positionAfteriss;
  }
  /* Validating field aud */
  uint64_t
  positionAfterLogoutTokenClaimsEntry0 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteriss);
  uint64_t positionAfteraud;
  if (EverParseIsSuccess(positionAfterLogoutTokenClaimsEntry0))
  {
    positionAfteraud = positionAfterLogoutTokenClaimsEntry0;
  }
  else
  {
    ErrorHandlerFn("_logout_token_claims_entry",
      "aud",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenClaimsEntry0),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenClaimsEntry0),
      Ctxt,
      Input,
      positionAfteriss);
    positionAfteraud = positionAfterLogoutTokenClaimsEntry0;
  }
  if (EverParseIsError(positionAfteraud))
  {
    return positionAfteraud;
  }
  /* Validating field iat */
  /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
  BOOLEAN hasBytes = 8ULL <= (InputLength - positionAfteraud);
  uint64_t positionAfterLogoutTokenClaimsEntry1;
  if (hasBytes)
  {
    positionAfterLogoutTokenClaimsEntry1 = positionAfteraud + 8ULL;
  }
  else
  {
    positionAfterLogoutTokenClaimsEntry1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfteraud);
  }
  uint64_t res;
  if (EverParseIsSuccess(positionAfterLogoutTokenClaimsEntry1))
  {
    res = positionAfterLogoutTokenClaimsEntry1;
  }
  else
  {
    ErrorHandlerFn("_logout_token_claims_entry",
      "iat",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenClaimsEntry1),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenClaimsEntry1),
      Ctxt,
      Input,
      positionAfteraud);
    res = positionAfterLogoutTokenClaimsEntry1;
  }
  uint64_t positionAfteriat = res;
  if (EverParseIsError(positionAfteriat))
  {
    return positionAfteriat;
  }
  /* Validating field jti */
  uint64_t
  positionAfterLogoutTokenClaimsEntry2 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteriat);
  uint64_t positionAfterjti;
  if (EverParseIsSuccess(positionAfterLogoutTokenClaimsEntry2))
  {
    positionAfterjti = positionAfterLogoutTokenClaimsEntry2;
  }
  else
  {
    ErrorHandlerFn("_logout_token_claims_entry",
      "jti",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenClaimsEntry2),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenClaimsEntry2),
      Ctxt,
      Input,
      positionAfteriat);
    positionAfterjti = positionAfterLogoutTokenClaimsEntry2;
  }
  if (EverParseIsError(positionAfterjti))
  {
    return positionAfterjti;
  }
  /* Validating field sid */
  uint64_t
  positionAfterLogoutTokenClaimsEntry3 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterjti);
  uint64_t positionAftersid;
  if (EverParseIsSuccess(positionAfterLogoutTokenClaimsEntry3))
  {
    positionAftersid = positionAfterLogoutTokenClaimsEntry3;
  }
  else
  {
    ErrorHandlerFn("_logout_token_claims_entry",
      "sid",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenClaimsEntry3),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenClaimsEntry3),
      Ctxt,
      Input,
      positionAfterjti);
    positionAftersid = positionAfterLogoutTokenClaimsEntry3;
  }
  if (EverParseIsError(positionAftersid))
  {
    return positionAftersid;
  }
  /* Validating field sub */
  uint64_t
  positionAfterLogoutTokenClaimsEntry4 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftersid);
  uint64_t positionAftersub;
  if (EverParseIsSuccess(positionAfterLogoutTokenClaimsEntry4))
  {
    positionAftersub = positionAfterLogoutTokenClaimsEntry4;
  }
  else
  {
    ErrorHandlerFn("_logout_token_claims_entry",
      "sub",
      EverParseErrorReasonOfResult(positionAfterLogoutTokenClaimsEntry4),
      EverParseGetValidatorErrorKind(positionAfterLogoutTokenClaimsEntry4),
      Ctxt,
      Input,
      positionAftersid);
    positionAftersub = positionAfterLogoutTokenClaimsEntry4;
  }
  if (EverParseIsError(positionAftersub))
  {
    return positionAftersub;
  }
  /* Validating field events */
  uint64_t
  positionAfterLogoutTokenClaimsEntry5 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftersub);
  if (EverParseIsSuccess(positionAfterLogoutTokenClaimsEntry5))
  {
    return positionAfterLogoutTokenClaimsEntry5;
  }
  ErrorHandlerFn("_logout_token_claims_entry",
    "events",
    EverParseErrorReasonOfResult(positionAfterLogoutTokenClaimsEntry5),
    EverParseGetValidatorErrorKind(positionAfterLogoutTokenClaimsEntry5),
    Ctxt,
    Input,
    positionAftersub);
  return positionAfterLogoutTokenClaimsEntry5;
}
