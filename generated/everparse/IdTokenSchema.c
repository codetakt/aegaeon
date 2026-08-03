

#include "IdTokenSchema.h"

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

static inline uint64_t ValidateMaybeBool(uint64_t InputLength, uint64_t StartPosition)
{
  BOOLEAN hasBytes = 2ULL <= (InputLength - StartPosition);
  if (hasBytes)
  {
    return StartPosition + 2ULL;
  }
  return EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
}

static inline uint64_t ValidateMaybeTimestamp(uint64_t InputLength, uint64_t StartPosition)
{
  BOOLEAN hasBytes = 9ULL <= (InputLength - StartPosition);
  if (hasBytes)
  {
    return StartPosition + 9ULL;
  }
  return EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA, StartPosition);
}

static inline uint64_t
ValidateHashClaim(
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
  uint64_t positionAfterHashClaim;
  if (hasBytes)
  {
    positionAfterHashClaim = StartPosition + 1ULL;
  }
  else
  {
    positionAfterHashClaim =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t res;
  if (EverParseIsSuccess(positionAfterHashClaim))
  {
    res = positionAfterHashClaim;
  }
  else
  {
    ErrorHandlerFn("_hash_claim",
      "present",
      EverParseErrorReasonOfResult(positionAfterHashClaim),
      EverParseGetValidatorErrorKind(positionAfterHashClaim),
      Ctxt,
      Input,
      StartPosition);
    res = positionAfterHashClaim;
  }
  uint64_t positionAfterpresent = res;
  if (EverParseIsError(positionAfterpresent))
  {
    return positionAfterpresent;
  }
  /* Validating field value */
  uint64_t
  positionAfterHashClaim0 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterpresent);
  if (EverParseIsSuccess(positionAfterHashClaim0))
  {
    return positionAfterHashClaim0;
  }
  ErrorHandlerFn("_hash_claim",
    "value",
    EverParseErrorReasonOfResult(positionAfterHashClaim0),
    EverParseGetValidatorErrorKind(positionAfterHashClaim0),
    Ctxt,
    Input,
    positionAfterpresent);
  return positionAfterHashClaim0;
}

uint64_t
IdTokenSchemaValidateIdTokenJwtEntry(
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
  positionAfterIdTokenJwtEntry =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      StartPosition);
  uint64_t positionAfterheader;
  if (EverParseIsSuccess(positionAfterIdTokenJwtEntry))
  {
    positionAfterheader = positionAfterIdTokenJwtEntry;
  }
  else
  {
    ErrorHandlerFn("_id_token_jwt_entry",
      "header",
      EverParseErrorReasonOfResult(positionAfterIdTokenJwtEntry),
      EverParseGetValidatorErrorKind(positionAfterIdTokenJwtEntry),
      Ctxt,
      Input,
      StartPosition);
    positionAfterheader = positionAfterIdTokenJwtEntry;
  }
  if (EverParseIsError(positionAfterheader))
  {
    return positionAfterheader;
  }
  /* Validating field payload */
  uint64_t
  positionAfterIdTokenJwtEntry0 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterheader);
  uint64_t positionAfterpayload;
  if (EverParseIsSuccess(positionAfterIdTokenJwtEntry0))
  {
    positionAfterpayload = positionAfterIdTokenJwtEntry0;
  }
  else
  {
    ErrorHandlerFn("_id_token_jwt_entry",
      "payload",
      EverParseErrorReasonOfResult(positionAfterIdTokenJwtEntry0),
      EverParseGetValidatorErrorKind(positionAfterIdTokenJwtEntry0),
      Ctxt,
      Input,
      positionAfterheader);
    positionAfterpayload = positionAfterIdTokenJwtEntry0;
  }
  if (EverParseIsError(positionAfterpayload))
  {
    return positionAfterpayload;
  }
  /* Validating field signature */
  uint64_t
  positionAfterIdTokenJwtEntry1 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterpayload);
  if (EverParseIsSuccess(positionAfterIdTokenJwtEntry1))
  {
    return positionAfterIdTokenJwtEntry1;
  }
  ErrorHandlerFn("_id_token_jwt_entry",
    "signature",
    EverParseErrorReasonOfResult(positionAfterIdTokenJwtEntry1),
    EverParseGetValidatorErrorKind(positionAfterIdTokenJwtEntry1),
    Ctxt,
    Input,
    positionAfterpayload);
  return positionAfterIdTokenJwtEntry1;
}

uint64_t
IdTokenSchemaValidateIdTokenClaimsEntry(
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
  positionAfterIdTokenClaimsEntry =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      StartPosition);
  uint64_t positionAfteriss;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry))
  {
    positionAfteriss = positionAfterIdTokenClaimsEntry;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "iss",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry),
      Ctxt,
      Input,
      StartPosition);
    positionAfteriss = positionAfterIdTokenClaimsEntry;
  }
  if (EverParseIsError(positionAfteriss))
  {
    return positionAfteriss;
  }
  /* Validating field sub */
  uint64_t
  positionAfterIdTokenClaimsEntry0 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteriss);
  uint64_t positionAftersub;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry0))
  {
    positionAftersub = positionAfterIdTokenClaimsEntry0;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "sub",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry0),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry0),
      Ctxt,
      Input,
      positionAfteriss);
    positionAftersub = positionAfterIdTokenClaimsEntry0;
  }
  if (EverParseIsError(positionAftersub))
  {
    return positionAftersub;
  }
  /* Validating field aud */
  uint64_t
  positionAfterIdTokenClaimsEntry1 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftersub);
  uint64_t positionAfteraud;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry1))
  {
    positionAfteraud = positionAfterIdTokenClaimsEntry1;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "aud",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry1),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry1),
      Ctxt,
      Input,
      positionAftersub);
    positionAfteraud = positionAfterIdTokenClaimsEntry1;
  }
  if (EverParseIsError(positionAfteraud))
  {
    return positionAfteraud;
  }
  /* Validating field exp */
  /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
  BOOLEAN hasBytes0 = 8ULL <= (InputLength - positionAfteraud);
  uint64_t positionAfterIdTokenClaimsEntry2;
  if (hasBytes0)
  {
    positionAfterIdTokenClaimsEntry2 = positionAfteraud + 8ULL;
  }
  else
  {
    positionAfterIdTokenClaimsEntry2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfteraud);
  }
  uint64_t res0;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry2))
  {
    res0 = positionAfterIdTokenClaimsEntry2;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "exp",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry2),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry2),
      Ctxt,
      Input,
      positionAfteraud);
    res0 = positionAfterIdTokenClaimsEntry2;
  }
  uint64_t positionAfterexp = res0;
  if (EverParseIsError(positionAfterexp))
  {
    return positionAfterexp;
  }
  /* Validating field iat */
  /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
  BOOLEAN hasBytes = 8ULL <= (InputLength - positionAfterexp);
  uint64_t positionAfterIdTokenClaimsEntry3;
  if (hasBytes)
  {
    positionAfterIdTokenClaimsEntry3 = positionAfterexp + 8ULL;
  }
  else
  {
    positionAfterIdTokenClaimsEntry3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterexp);
  }
  uint64_t res;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry3))
  {
    res = positionAfterIdTokenClaimsEntry3;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "iat",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry3),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry3),
      Ctxt,
      Input,
      positionAfterexp);
    res = positionAfterIdTokenClaimsEntry3;
  }
  uint64_t positionAfteriat = res;
  if (EverParseIsError(positionAfteriat))
  {
    return positionAfteriat;
  }
  /* Validating field nonce */
  uint64_t
  positionAfterIdTokenClaimsEntry4 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteriat);
  uint64_t positionAfternonce;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry4))
  {
    positionAfternonce = positionAfterIdTokenClaimsEntry4;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "nonce",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry4),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry4),
      Ctxt,
      Input,
      positionAfteriat);
    positionAfternonce = positionAfterIdTokenClaimsEntry4;
  }
  if (EverParseIsError(positionAfternonce))
  {
    return positionAfternonce;
  }
  /* Validating field nbf */
  uint64_t
  positionAfterIdTokenClaimsEntry5 = ValidateMaybeTimestamp(InputLength, positionAfternonce);
  uint64_t positionAfternbf;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry5))
  {
    positionAfternbf = positionAfterIdTokenClaimsEntry5;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "nbf",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry5),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry5),
      Ctxt,
      Input,
      positionAfternonce);
    positionAfternbf = positionAfterIdTokenClaimsEntry5;
  }
  if (EverParseIsError(positionAfternbf))
  {
    return positionAfternbf;
  }
  /* Validating field auth_time */
  uint64_t
  positionAfterIdTokenClaimsEntry6 = ValidateMaybeTimestamp(InputLength, positionAfternbf);
  uint64_t positionAfterauthTime;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry6))
  {
    positionAfterauthTime = positionAfterIdTokenClaimsEntry6;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "auth_time",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry6),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry6),
      Ctxt,
      Input,
      positionAfternbf);
    positionAfterauthTime = positionAfterIdTokenClaimsEntry6;
  }
  if (EverParseIsError(positionAfterauthTime))
  {
    return positionAfterauthTime;
  }
  /* Validating field azp */
  uint64_t
  positionAfterIdTokenClaimsEntry7 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterauthTime);
  uint64_t positionAfterazp;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry7))
  {
    positionAfterazp = positionAfterIdTokenClaimsEntry7;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "azp",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry7),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry7),
      Ctxt,
      Input,
      positionAfterauthTime);
    positionAfterazp = positionAfterIdTokenClaimsEntry7;
  }
  if (EverParseIsError(positionAfterazp))
  {
    return positionAfterazp;
  }
  /* Validating field acr */
  uint64_t
  positionAfterIdTokenClaimsEntry8 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterazp);
  uint64_t positionAfteracr;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry8))
  {
    positionAfteracr = positionAfterIdTokenClaimsEntry8;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "acr",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry8),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry8),
      Ctxt,
      Input,
      positionAfterazp);
    positionAfteracr = positionAfterIdTokenClaimsEntry8;
  }
  if (EverParseIsError(positionAfteracr))
  {
    return positionAfteracr;
  }
  /*  JSON-encoded AMR list */
  uint64_t
  positionAfterIdTokenClaimsEntry9 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteracr);
  uint64_t positionAfteramr;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry9))
  {
    positionAfteramr = positionAfterIdTokenClaimsEntry9;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "amr",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry9),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry9),
      Ctxt,
      Input,
      positionAfteracr);
    positionAfteramr = positionAfterIdTokenClaimsEntry9;
  }
  if (EverParseIsError(positionAfteramr))
  {
    return positionAfteramr;
  }
  /* Validating field at_hash */
  uint64_t
  positionAfterIdTokenClaimsEntry10 =
    ValidateHashClaim(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteramr);
  uint64_t positionAfteratHash;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry10))
  {
    positionAfteratHash = positionAfterIdTokenClaimsEntry10;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "at_hash",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry10),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry10),
      Ctxt,
      Input,
      positionAfteramr);
    positionAfteratHash = positionAfterIdTokenClaimsEntry10;
  }
  if (EverParseIsError(positionAfteratHash))
  {
    return positionAfteratHash;
  }
  /* Validating field c_hash */
  uint64_t
  positionAfterIdTokenClaimsEntry11 =
    ValidateHashClaim(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteratHash);
  uint64_t positionAftercHash;
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry11))
  {
    positionAftercHash = positionAfterIdTokenClaimsEntry11;
  }
  else
  {
    ErrorHandlerFn("_id_token_claims_entry",
      "c_hash",
      EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry11),
      EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry11),
      Ctxt,
      Input,
      positionAfteratHash);
    positionAftercHash = positionAfterIdTokenClaimsEntry11;
  }
  if (EverParseIsError(positionAftercHash))
  {
    return positionAftercHash;
  }
  /* Validating field sid */
  uint64_t
  positionAfterIdTokenClaimsEntry12 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftercHash);
  if (EverParseIsSuccess(positionAfterIdTokenClaimsEntry12))
  {
    return positionAfterIdTokenClaimsEntry12;
  }
  ErrorHandlerFn("_id_token_claims_entry",
    "sid",
    EverParseErrorReasonOfResult(positionAfterIdTokenClaimsEntry12),
    EverParseGetValidatorErrorKind(positionAfterIdTokenClaimsEntry12),
    Ctxt,
    Input,
    positionAftercHash);
  return positionAfterIdTokenClaimsEntry12;
}

uint64_t
IdTokenSchemaValidateUserinfoResponseEntry(
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
  /* Validating field sub */
  uint64_t
  positionAfterUserinfoResponseEntry =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      StartPosition);
  uint64_t positionAftersub;
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry))
  {
    positionAftersub = positionAfterUserinfoResponseEntry;
  }
  else
  {
    ErrorHandlerFn("_userinfo_response_entry",
      "sub",
      EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry),
      EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry),
      Ctxt,
      Input,
      StartPosition);
    positionAftersub = positionAfterUserinfoResponseEntry;
  }
  if (EverParseIsError(positionAftersub))
  {
    return positionAftersub;
  }
  /* Validating field name */
  uint64_t
  positionAfterUserinfoResponseEntry0 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftersub);
  uint64_t positionAftername;
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry0))
  {
    positionAftername = positionAfterUserinfoResponseEntry0;
  }
  else
  {
    ErrorHandlerFn("_userinfo_response_entry",
      "name",
      EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry0),
      EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry0),
      Ctxt,
      Input,
      positionAftersub);
    positionAftername = positionAfterUserinfoResponseEntry0;
  }
  if (EverParseIsError(positionAftername))
  {
    return positionAftername;
  }
  /* Validating field preferred_username */
  uint64_t
  positionAfterUserinfoResponseEntry1 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftername);
  uint64_t positionAfterpreferredUsername;
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry1))
  {
    positionAfterpreferredUsername = positionAfterUserinfoResponseEntry1;
  }
  else
  {
    ErrorHandlerFn("_userinfo_response_entry",
      "preferred_username",
      EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry1),
      EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry1),
      Ctxt,
      Input,
      positionAftername);
    positionAfterpreferredUsername = positionAfterUserinfoResponseEntry1;
  }
  if (EverParseIsError(positionAfterpreferredUsername))
  {
    return positionAfterpreferredUsername;
  }
  /* Validating field email */
  uint64_t
  positionAfterUserinfoResponseEntry2 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterpreferredUsername);
  uint64_t positionAfteremail;
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry2))
  {
    positionAfteremail = positionAfterUserinfoResponseEntry2;
  }
  else
  {
    ErrorHandlerFn("_userinfo_response_entry",
      "email",
      EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry2),
      EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry2),
      Ctxt,
      Input,
      positionAfterpreferredUsername);
    positionAfteremail = positionAfterUserinfoResponseEntry2;
  }
  if (EverParseIsError(positionAfteremail))
  {
    return positionAfteremail;
  }
  /* Validating field email_verified */
  uint64_t
  positionAfterUserinfoResponseEntry3 = ValidateMaybeBool(InputLength, positionAfteremail);
  uint64_t positionAfteremailVerified;
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry3))
  {
    positionAfteremailVerified = positionAfterUserinfoResponseEntry3;
  }
  else
  {
    ErrorHandlerFn("_userinfo_response_entry",
      "email_verified",
      EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry3),
      EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry3),
      Ctxt,
      Input,
      positionAfteremail);
    positionAfteremailVerified = positionAfterUserinfoResponseEntry3;
  }
  if (EverParseIsError(positionAfteremailVerified))
  {
    return positionAfteremailVerified;
  }
  /* Validating field address */
  uint64_t
  positionAfterUserinfoResponseEntry4 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteremailVerified);
  uint64_t positionAfteraddress;
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry4))
  {
    positionAfteraddress = positionAfterUserinfoResponseEntry4;
  }
  else
  {
    ErrorHandlerFn("_userinfo_response_entry",
      "address",
      EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry4),
      EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry4),
      Ctxt,
      Input,
      positionAfteremailVerified);
    positionAfteraddress = positionAfterUserinfoResponseEntry4;
  }
  if (EverParseIsError(positionAfteraddress))
  {
    return positionAfteraddress;
  }
  /* Validating field phone_number */
  uint64_t
  positionAfterUserinfoResponseEntry5 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteraddress);
  uint64_t positionAfterphoneNumber;
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry5))
  {
    positionAfterphoneNumber = positionAfterUserinfoResponseEntry5;
  }
  else
  {
    ErrorHandlerFn("_userinfo_response_entry",
      "phone_number",
      EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry5),
      EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry5),
      Ctxt,
      Input,
      positionAfteraddress);
    positionAfterphoneNumber = positionAfterUserinfoResponseEntry5;
  }
  if (EverParseIsError(positionAfterphoneNumber))
  {
    return positionAfterphoneNumber;
  }
  /* Validating field updated_at */
  uint64_t
  positionAfterUserinfoResponseEntry6 =
    ValidateMaybeTimestamp(InputLength,
      positionAfterphoneNumber);
  if (EverParseIsSuccess(positionAfterUserinfoResponseEntry6))
  {
    return positionAfterUserinfoResponseEntry6;
  }
  ErrorHandlerFn("_userinfo_response_entry",
    "updated_at",
    EverParseErrorReasonOfResult(positionAfterUserinfoResponseEntry6),
    EverParseGetValidatorErrorKind(positionAfterUserinfoResponseEntry6),
    Ctxt,
    Input,
    positionAfterphoneNumber);
  return positionAfterUserinfoResponseEntry6;
}
