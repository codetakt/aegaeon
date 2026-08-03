

#include "JoseHeader.h"

uint64_t
JoseHeaderValidateJoseHeaderEntry(
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
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes0 = 1ULL <= (InputLength - StartPosition);
  uint64_t positionAfterJoseHeaderEntry;
  if (hasBytes0)
  {
    positionAfterJoseHeaderEntry = StartPosition + 1ULL;
  }
  else
  {
    positionAfterJoseHeaderEntry =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterkeyLen;
  if (EverParseIsSuccess(positionAfterJoseHeaderEntry))
  {
    positionAfterkeyLen = positionAfterJoseHeaderEntry;
  }
  else
  {
    ErrorHandlerFn("_jose_header_entry",
      "key_len",
      EverParseErrorReasonOfResult(positionAfterJoseHeaderEntry),
      EverParseGetValidatorErrorKind(positionAfterJoseHeaderEntry),
      Ctxt,
      Input,
      StartPosition);
    positionAfterkeyLen = positionAfterJoseHeaderEntry;
  }
  if (EverParseIsError(positionAfterkeyLen))
  {
    return positionAfterkeyLen;
  }
  uint8_t keyLen = Input[(uint32_t)StartPosition];
  /* Validating field key */
  BOOLEAN hasBytes1 = (uint64_t)(uint32_t)keyLen <= (InputLength - positionAfterkeyLen);
  uint64_t res0;
  if (hasBytes1)
  {
    res0 = positionAfterkeyLen + (uint64_t)(uint32_t)keyLen;
  }
  else
  {
    res0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterkeyLen);
  }
  uint64_t positionAfterJoseHeaderEntry0 = res0;
  uint64_t positionAfterkey;
  if (EverParseIsSuccess(positionAfterJoseHeaderEntry0))
  {
    positionAfterkey = positionAfterJoseHeaderEntry0;
  }
  else
  {
    ErrorHandlerFn("_jose_header_entry",
      "key",
      EverParseErrorReasonOfResult(positionAfterJoseHeaderEntry0),
      EverParseGetValidatorErrorKind(positionAfterJoseHeaderEntry0),
      Ctxt,
      Input,
      positionAfterkeyLen);
    positionAfterkey = positionAfterJoseHeaderEntry0;
  }
  if (EverParseIsError(positionAfterkey))
  {
    return positionAfterkey;
  }
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterkey);
  uint64_t positionAfterJoseHeaderEntry1;
  if (hasBytes2)
  {
    positionAfterJoseHeaderEntry1 = positionAfterkey + 1ULL;
  }
  else
  {
    positionAfterJoseHeaderEntry1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterkey);
  }
  uint64_t positionAftervalueLen;
  if (EverParseIsSuccess(positionAfterJoseHeaderEntry1))
  {
    positionAftervalueLen = positionAfterJoseHeaderEntry1;
  }
  else
  {
    ErrorHandlerFn("_jose_header_entry",
      "value_len",
      EverParseErrorReasonOfResult(positionAfterJoseHeaderEntry1),
      EverParseGetValidatorErrorKind(positionAfterJoseHeaderEntry1),
      Ctxt,
      Input,
      positionAfterkey);
    positionAftervalueLen = positionAfterJoseHeaderEntry1;
  }
  if (EverParseIsError(positionAftervalueLen))
  {
    return positionAftervalueLen;
  }
  uint8_t valueLen = Input[(uint32_t)positionAfterkey];
  /* Validating field value */
  BOOLEAN hasBytes = (uint64_t)(uint32_t)valueLen <= (InputLength - positionAftervalueLen);
  uint64_t res;
  if (hasBytes)
  {
    res = positionAftervalueLen + (uint64_t)(uint32_t)valueLen;
  }
  else
  {
    res =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftervalueLen);
  }
  uint64_t positionAfterJoseHeaderEntry2 = res;
  if (EverParseIsSuccess(positionAfterJoseHeaderEntry2))
  {
    return positionAfterJoseHeaderEntry2;
  }
  ErrorHandlerFn("_jose_header_entry",
    "value",
    EverParseErrorReasonOfResult(positionAfterJoseHeaderEntry2),
    EverParseGetValidatorErrorKind(positionAfterJoseHeaderEntry2),
    Ctxt,
    Input,
    positionAftervalueLen);
  return positionAfterJoseHeaderEntry2;
}
