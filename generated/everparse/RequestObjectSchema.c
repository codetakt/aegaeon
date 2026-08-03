

#include "RequestObjectSchema.h"

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
RequestObjectSchemaValidateRequestObjectClaimsEntry(
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
  /* Validating field aud */
  uint64_t
  positionAfterRequestObjectClaimsEntry =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      StartPosition);
  uint64_t positionAfteraud;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry))
  {
    positionAfteraud = positionAfterRequestObjectClaimsEntry;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "aud",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry),
      Ctxt,
      Input,
      StartPosition);
    positionAfteraud = positionAfterRequestObjectClaimsEntry;
  }
  if (EverParseIsError(positionAfteraud))
  {
    return positionAfteraud;
  }
  /* Validating field exp */
  /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
  BOOLEAN hasBytes0 = 8ULL <= (InputLength - positionAfteraud);
  uint64_t positionAfterRequestObjectClaimsEntry0;
  if (hasBytes0)
  {
    positionAfterRequestObjectClaimsEntry0 = positionAfteraud + 8ULL;
  }
  else
  {
    positionAfterRequestObjectClaimsEntry0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfteraud);
  }
  uint64_t res0;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry0))
  {
    res0 = positionAfterRequestObjectClaimsEntry0;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "exp",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry0),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry0),
      Ctxt,
      Input,
      positionAfteraud);
    res0 = positionAfterRequestObjectClaimsEntry0;
  }
  uint64_t positionAfterexp = res0;
  if (EverParseIsError(positionAfterexp))
  {
    return positionAfterexp;
  }
  /* Validating field nbf */
  /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
  BOOLEAN hasBytes = 8ULL <= (InputLength - positionAfterexp);
  uint64_t positionAfterRequestObjectClaimsEntry1;
  if (hasBytes)
  {
    positionAfterRequestObjectClaimsEntry1 = positionAfterexp + 8ULL;
  }
  else
  {
    positionAfterRequestObjectClaimsEntry1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterexp);
  }
  uint64_t res;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry1))
  {
    res = positionAfterRequestObjectClaimsEntry1;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "nbf",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry1),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry1),
      Ctxt,
      Input,
      positionAfterexp);
    res = positionAfterRequestObjectClaimsEntry1;
  }
  uint64_t positionAfternbf = res;
  if (EverParseIsError(positionAfternbf))
  {
    return positionAfternbf;
  }
  /* Validating field client_id */
  uint64_t
  positionAfterRequestObjectClaimsEntry2 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfternbf);
  uint64_t positionAfterclientId;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry2))
  {
    positionAfterclientId = positionAfterRequestObjectClaimsEntry2;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "client_id",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry2),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry2),
      Ctxt,
      Input,
      positionAfternbf);
    positionAfterclientId = positionAfterRequestObjectClaimsEntry2;
  }
  if (EverParseIsError(positionAfterclientId))
  {
    return positionAfterclientId;
  }
  /* Validating field redirect_uri */
  uint64_t
  positionAfterRequestObjectClaimsEntry3 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterclientId);
  uint64_t positionAfterredirectUri;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry3))
  {
    positionAfterredirectUri = positionAfterRequestObjectClaimsEntry3;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "redirect_uri",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry3),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry3),
      Ctxt,
      Input,
      positionAfterclientId);
    positionAfterredirectUri = positionAfterRequestObjectClaimsEntry3;
  }
  if (EverParseIsError(positionAfterredirectUri))
  {
    return positionAfterredirectUri;
  }
  /* Validating field response_type */
  uint64_t
  positionAfterRequestObjectClaimsEntry4 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterredirectUri);
  uint64_t positionAfterresponseType;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry4))
  {
    positionAfterresponseType = positionAfterRequestObjectClaimsEntry4;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "response_type",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry4),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry4),
      Ctxt,
      Input,
      positionAfterredirectUri);
    positionAfterresponseType = positionAfterRequestObjectClaimsEntry4;
  }
  if (EverParseIsError(positionAfterresponseType))
  {
    return positionAfterresponseType;
  }
  /* Validating field scope */
  uint64_t
  positionAfterRequestObjectClaimsEntry5 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterresponseType);
  uint64_t positionAfterscope;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry5))
  {
    positionAfterscope = positionAfterRequestObjectClaimsEntry5;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "scope",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry5),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry5),
      Ctxt,
      Input,
      positionAfterresponseType);
    positionAfterscope = positionAfterRequestObjectClaimsEntry5;
  }
  if (EverParseIsError(positionAfterscope))
  {
    return positionAfterscope;
  }
  /* Validating field state */
  uint64_t
  positionAfterRequestObjectClaimsEntry6 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterscope);
  uint64_t positionAfterstate;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry6))
  {
    positionAfterstate = positionAfterRequestObjectClaimsEntry6;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "state",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry6),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry6),
      Ctxt,
      Input,
      positionAfterscope);
    positionAfterstate = positionAfterRequestObjectClaimsEntry6;
  }
  if (EverParseIsError(positionAfterstate))
  {
    return positionAfterstate;
  }
  /* Validating field nonce */
  uint64_t
  positionAfterRequestObjectClaimsEntry7 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterstate);
  uint64_t positionAfternonce;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry7))
  {
    positionAfternonce = positionAfterRequestObjectClaimsEntry7;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "nonce",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry7),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry7),
      Ctxt,
      Input,
      positionAfterstate);
    positionAfternonce = positionAfterRequestObjectClaimsEntry7;
  }
  if (EverParseIsError(positionAfternonce))
  {
    return positionAfternonce;
  }
  /* Validating field code_challenge */
  uint64_t
  positionAfterRequestObjectClaimsEntry8 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfternonce);
  uint64_t positionAftercodeChallenge;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry8))
  {
    positionAftercodeChallenge = positionAfterRequestObjectClaimsEntry8;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "code_challenge",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry8),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry8),
      Ctxt,
      Input,
      positionAfternonce);
    positionAftercodeChallenge = positionAfterRequestObjectClaimsEntry8;
  }
  if (EverParseIsError(positionAftercodeChallenge))
  {
    return positionAftercodeChallenge;
  }
  /* Validating field code_challenge_method */
  uint64_t
  positionAfterRequestObjectClaimsEntry9 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftercodeChallenge);
  uint64_t positionAftercodeChallengeMethod;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry9))
  {
    positionAftercodeChallengeMethod = positionAfterRequestObjectClaimsEntry9;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "code_challenge_method",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry9),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry9),
      Ctxt,
      Input,
      positionAftercodeChallenge);
    positionAftercodeChallengeMethod = positionAfterRequestObjectClaimsEntry9;
  }
  if (EverParseIsError(positionAftercodeChallengeMethod))
  {
    return positionAftercodeChallengeMethod;
  }
  /* Validating field response_mode */
  uint64_t
  positionAfterRequestObjectClaimsEntry10 =
    ValidateMaybeString(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAftercodeChallengeMethod);
  uint64_t positionAfterresponseMode;
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry10))
  {
    positionAfterresponseMode = positionAfterRequestObjectClaimsEntry10;
  }
  else
  {
    ErrorHandlerFn("_request_object_claims_entry",
      "response_mode",
      EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry10),
      EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry10),
      Ctxt,
      Input,
      positionAftercodeChallengeMethod);
    positionAfterresponseMode = positionAfterRequestObjectClaimsEntry10;
  }
  if (EverParseIsError(positionAfterresponseMode))
  {
    return positionAfterresponseMode;
  }
  /* Validating field jti */
  uint64_t
  positionAfterRequestObjectClaimsEntry11 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterresponseMode);
  if (EverParseIsSuccess(positionAfterRequestObjectClaimsEntry11))
  {
    return positionAfterRequestObjectClaimsEntry11;
  }
  ErrorHandlerFn("_request_object_claims_entry",
    "jti",
    EverParseErrorReasonOfResult(positionAfterRequestObjectClaimsEntry11),
    EverParseGetValidatorErrorKind(positionAfterRequestObjectClaimsEntry11),
    Ctxt,
    Input,
    positionAfterresponseMode);
  return positionAfterRequestObjectClaimsEntry11;
}
