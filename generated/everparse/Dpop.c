

#include "Dpop.h"

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

uint64_t
DpopValidateDpopClaims(
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
  /* Validating field htm */
  uint64_t
  positionAfterDpopClaims =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      StartPosition);
  uint64_t positionAfterhtm;
  if (EverParseIsSuccess(positionAfterDpopClaims))
  {
    positionAfterhtm = positionAfterDpopClaims;
  }
  else
  {
    ErrorHandlerFn("_dpop_claims",
      "htm",
      EverParseErrorReasonOfResult(positionAfterDpopClaims),
      EverParseGetValidatorErrorKind(positionAfterDpopClaims),
      Ctxt,
      Input,
      StartPosition);
    positionAfterhtm = positionAfterDpopClaims;
  }
  if (EverParseIsError(positionAfterhtm))
  {
    return positionAfterhtm;
  }
  /* Validating field htu */
  uint64_t
  positionAfterDpopClaims0 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterhtm);
  uint64_t positionAfterhtu;
  if (EverParseIsSuccess(positionAfterDpopClaims0))
  {
    positionAfterhtu = positionAfterDpopClaims0;
  }
  else
  {
    ErrorHandlerFn("_dpop_claims",
      "htu",
      EverParseErrorReasonOfResult(positionAfterDpopClaims0),
      EverParseGetValidatorErrorKind(positionAfterDpopClaims0),
      Ctxt,
      Input,
      positionAfterhtm);
    positionAfterhtu = positionAfterDpopClaims0;
  }
  if (EverParseIsError(positionAfterhtu))
  {
    return positionAfterhtu;
  }
  /* Validating field iat */
  /* Checking that we have enough space for a UINT64, i.e., 8 bytes */
  BOOLEAN hasBytes = 8ULL <= (InputLength - positionAfterhtu);
  uint64_t positionAfterDpopClaims1;
  if (hasBytes)
  {
    positionAfterDpopClaims1 = positionAfterhtu + 8ULL;
  }
  else
  {
    positionAfterDpopClaims1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhtu);
  }
  uint64_t res;
  if (EverParseIsSuccess(positionAfterDpopClaims1))
  {
    res = positionAfterDpopClaims1;
  }
  else
  {
    ErrorHandlerFn("_dpop_claims",
      "iat",
      EverParseErrorReasonOfResult(positionAfterDpopClaims1),
      EverParseGetValidatorErrorKind(positionAfterDpopClaims1),
      Ctxt,
      Input,
      positionAfterhtu);
    res = positionAfterDpopClaims1;
  }
  uint64_t positionAfteriat = res;
  if (EverParseIsError(positionAfteriat))
  {
    return positionAfteriat;
  }
  /* Validating field jti */
  uint64_t
  positionAfterDpopClaims2 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfteriat);
  uint64_t positionAfterjti;
  if (EverParseIsSuccess(positionAfterDpopClaims2))
  {
    positionAfterjti = positionAfterDpopClaims2;
  }
  else
  {
    ErrorHandlerFn("_dpop_claims",
      "jti",
      EverParseErrorReasonOfResult(positionAfterDpopClaims2),
      EverParseGetValidatorErrorKind(positionAfterDpopClaims2),
      Ctxt,
      Input,
      positionAfteriat);
    positionAfterjti = positionAfterDpopClaims2;
  }
  if (EverParseIsError(positionAfterjti))
  {
    return positionAfterjti;
  }
  /* Validating field ath */
  uint64_t
  positionAfterDpopClaims3 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterjti);
  uint64_t positionAfterath;
  if (EverParseIsSuccess(positionAfterDpopClaims3))
  {
    positionAfterath = positionAfterDpopClaims3;
  }
  else
  {
    ErrorHandlerFn("_dpop_claims",
      "ath",
      EverParseErrorReasonOfResult(positionAfterDpopClaims3),
      EverParseGetValidatorErrorKind(positionAfterDpopClaims3),
      Ctxt,
      Input,
      positionAfterjti);
    positionAfterath = positionAfterDpopClaims3;
  }
  if (EverParseIsError(positionAfterath))
  {
    return positionAfterath;
  }
  /* Validating field nonce */
  uint64_t
  positionAfterDpopClaims4 =
    ValidateLenPrefixedBytes(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterath);
  if (EverParseIsSuccess(positionAfterDpopClaims4))
  {
    return positionAfterDpopClaims4;
  }
  ErrorHandlerFn("_dpop_claims",
    "nonce",
    EverParseErrorReasonOfResult(positionAfterDpopClaims4),
    EverParseGetValidatorErrorKind(positionAfterDpopClaims4),
    Ctxt,
    Input,
    positionAfterath);
  return positionAfterDpopClaims4;
}
