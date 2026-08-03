

#include "DcrRegistration.h"

uint64_t
DcrRegistrationValidateDcrRegistrationPayload(
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
  uint64_t positionAfterDcrRegistrationPayload;
  if (hasBytes0)
  {
    positionAfterDcrRegistrationPayload = StartPosition + 4ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterredirectUrisLength;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload))
  {
    positionAfterredirectUrisLength = positionAfterDcrRegistrationPayload;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "redirect_uris_length",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload),
      Ctxt,
      Input,
      StartPosition);
    positionAfterredirectUrisLength = positionAfterDcrRegistrationPayload;
  }
  if (EverParseIsError(positionAfterredirectUrisLength))
  {
    return positionAfterredirectUrisLength;
  }
  uint32_t redirectUrisLength = Load32Le(Input + (uint32_t)StartPosition);
  /*  Optional: token_endpoint_auth_method (enum) */
  BOOLEAN
  hasBytes1 = (uint64_t)redirectUrisLength <= (InputLength - positionAfterredirectUrisLength);
  uint64_t res0;
  if (hasBytes1)
  {
    res0 = positionAfterredirectUrisLength + (uint64_t)redirectUrisLength;
  }
  else
  {
    res0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterredirectUrisLength);
  }
  uint64_t positionAfterDcrRegistrationPayload0 = res0;
  uint64_t positionAfterredirectUris;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload0))
  {
    positionAfterredirectUris = positionAfterDcrRegistrationPayload0;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "redirect_uris",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload0),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload0),
      Ctxt,
      Input,
      positionAfterredirectUrisLength);
    positionAfterredirectUris = positionAfterDcrRegistrationPayload0;
  }
  if (EverParseIsError(positionAfterredirectUris))
  {
    return positionAfterredirectUris;
  }
  /* Validating field has_token_endpoint_auth_method */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterredirectUris);
  uint64_t positionAfterDcrRegistrationPayload1;
  if (hasBytes2)
  {
    positionAfterDcrRegistrationPayload1 = positionAfterredirectUris + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterredirectUris);
  }
  uint64_t res1;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload1))
  {
    res1 = positionAfterDcrRegistrationPayload1;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "has_token_endpoint_auth_method",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload1),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload1),
      Ctxt,
      Input,
      positionAfterredirectUris);
    res1 = positionAfterDcrRegistrationPayload1;
  }
  uint64_t positionAfterhasTokenEndpointAuthMethod = res1;
  if (EverParseIsError(positionAfterhasTokenEndpointAuthMethod))
  {
    return positionAfterhasTokenEndpointAuthMethod;
  }
  /*  PKCE declaration (required) */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterhasTokenEndpointAuthMethod);
  uint64_t positionAfterDcrRegistrationPayload2;
  if (hasBytes3)
  {
    positionAfterDcrRegistrationPayload2 = positionAfterhasTokenEndpointAuthMethod + 4ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasTokenEndpointAuthMethod);
  }
  uint64_t res2;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload2))
  {
    res2 = positionAfterDcrRegistrationPayload2;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "token_endpoint_auth_method",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload2),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload2),
      Ctxt,
      Input,
      positionAfterhasTokenEndpointAuthMethod);
    res2 = positionAfterDcrRegistrationPayload2;
  }
  uint64_t positionAftertokenEndpointAuthMethod = res2;
  if (EverParseIsError(positionAftertokenEndpointAuthMethod))
  {
    return positionAftertokenEndpointAuthMethod;
  }
  /*  Optional: sender-constrained token requirement */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAftertokenEndpointAuthMethod);
  uint64_t positionAfterDcrRegistrationPayload3;
  if (hasBytes4)
  {
    positionAfterDcrRegistrationPayload3 = positionAftertokenEndpointAuthMethod + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftertokenEndpointAuthMethod);
  }
  uint64_t res3;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload3))
  {
    res3 = positionAfterDcrRegistrationPayload3;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "requires_pkce",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload3),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload3),
      Ctxt,
      Input,
      positionAftertokenEndpointAuthMethod);
    res3 = positionAfterDcrRegistrationPayload3;
  }
  uint64_t positionAfterrequiresPkce = res3;
  if (EverParseIsError(positionAfterrequiresPkce))
  {
    return positionAfterrequiresPkce;
  }
  /* Validating field has_require_sender_constrained_tokens */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes5 = 1ULL <= (InputLength - positionAfterrequiresPkce);
  uint64_t positionAfterDcrRegistrationPayload4;
  if (hasBytes5)
  {
    positionAfterDcrRegistrationPayload4 = positionAfterrequiresPkce + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequiresPkce);
  }
  uint64_t res4;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload4))
  {
    res4 = positionAfterDcrRegistrationPayload4;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "has_require_sender_constrained_tokens",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload4),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload4),
      Ctxt,
      Input,
      positionAfterrequiresPkce);
    res4 = positionAfterDcrRegistrationPayload4;
  }
  uint64_t positionAfterhasRequireSenderConstrainedTokens = res4;
  if (EverParseIsError(positionAfterhasRequireSenderConstrainedTokens))
  {
    return positionAfterhasRequireSenderConstrainedTokens;
  }
  /*  Optional: allowed sender constraint methods (canonical bytes) */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes6 = 1ULL <= (InputLength - positionAfterhasRequireSenderConstrainedTokens);
  uint64_t positionAfterDcrRegistrationPayload5;
  if (hasBytes6)
  {
    positionAfterDcrRegistrationPayload5 = positionAfterhasRequireSenderConstrainedTokens + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload5 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasRequireSenderConstrainedTokens);
  }
  uint64_t res5;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload5))
  {
    res5 = positionAfterDcrRegistrationPayload5;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "require_sender_constrained_tokens",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload5),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload5),
      Ctxt,
      Input,
      positionAfterhasRequireSenderConstrainedTokens);
    res5 = positionAfterDcrRegistrationPayload5;
  }
  uint64_t positionAfterrequireSenderConstrainedTokens = res5;
  if (EverParseIsError(positionAfterrequireSenderConstrainedTokens))
  {
    return positionAfterrequireSenderConstrainedTokens;
  }
  /* Validating field has_sender_constrained_methods */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes7 = 1ULL <= (InputLength - positionAfterrequireSenderConstrainedTokens);
  uint64_t positionAfterDcrRegistrationPayload6;
  if (hasBytes7)
  {
    positionAfterDcrRegistrationPayload6 = positionAfterrequireSenderConstrainedTokens + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload6 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequireSenderConstrainedTokens);
  }
  uint64_t res6;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload6))
  {
    res6 = positionAfterDcrRegistrationPayload6;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "has_sender_constrained_methods",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload6),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload6),
      Ctxt,
      Input,
      positionAfterrequireSenderConstrainedTokens);
    res6 = positionAfterDcrRegistrationPayload6;
  }
  uint64_t positionAfterhasSenderConstrainedMethods = res6;
  if (EverParseIsError(positionAfterhasSenderConstrainedMethods))
  {
    return positionAfterhasSenderConstrainedMethods;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes8 = 4ULL <= (InputLength - positionAfterhasSenderConstrainedMethods);
  uint64_t positionAfterDcrRegistrationPayload7;
  if (hasBytes8)
  {
    positionAfterDcrRegistrationPayload7 = positionAfterhasSenderConstrainedMethods + 4ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasSenderConstrainedMethods);
  }
  uint64_t positionAftersenderConstrainedMethodsLength;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload7))
  {
    positionAftersenderConstrainedMethodsLength = positionAfterDcrRegistrationPayload7;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "sender_constrained_methods_length",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload7),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload7),
      Ctxt,
      Input,
      positionAfterhasSenderConstrainedMethods);
    positionAftersenderConstrainedMethodsLength = positionAfterDcrRegistrationPayload7;
  }
  if (EverParseIsError(positionAftersenderConstrainedMethodsLength))
  {
    return positionAftersenderConstrainedMethodsLength;
  }
  uint32_t
  senderConstrainedMethodsLength =
    Load32Le(Input + (uint32_t)positionAfterhasSenderConstrainedMethods);
  /*  Optional: DPoP requirement flag */
  BOOLEAN
  hasBytes9 =
    (uint64_t)senderConstrainedMethodsLength <=
      (InputLength - positionAftersenderConstrainedMethodsLength);
  uint64_t res7;
  if (hasBytes9)
  {
    res7 = positionAftersenderConstrainedMethodsLength + (uint64_t)senderConstrainedMethodsLength;
  }
  else
  {
    res7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersenderConstrainedMethodsLength);
  }
  uint64_t positionAfterDcrRegistrationPayload8 = res7;
  uint64_t positionAftersenderConstrainedMethods;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload8))
  {
    positionAftersenderConstrainedMethods = positionAfterDcrRegistrationPayload8;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "sender_constrained_methods",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload8),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload8),
      Ctxt,
      Input,
      positionAftersenderConstrainedMethodsLength);
    positionAftersenderConstrainedMethods = positionAfterDcrRegistrationPayload8;
  }
  if (EverParseIsError(positionAftersenderConstrainedMethods))
  {
    return positionAftersenderConstrainedMethods;
  }
  /* Validating field has_require_dpop */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes10 = 1ULL <= (InputLength - positionAftersenderConstrainedMethods);
  uint64_t positionAfterDcrRegistrationPayload9;
  if (hasBytes10)
  {
    positionAfterDcrRegistrationPayload9 = positionAftersenderConstrainedMethods + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload9 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersenderConstrainedMethods);
  }
  uint64_t res8;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload9))
  {
    res8 = positionAfterDcrRegistrationPayload9;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "has_require_dpop",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload9),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload9),
      Ctxt,
      Input,
      positionAftersenderConstrainedMethods);
    res8 = positionAfterDcrRegistrationPayload9;
  }
  uint64_t positionAfterhasRequireDpop = res8;
  if (EverParseIsError(positionAfterhasRequireDpop))
  {
    return positionAfterhasRequireDpop;
  }
  /*  Optional: mTLS requirement flag */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterhasRequireDpop);
  uint64_t positionAfterDcrRegistrationPayload10;
  if (hasBytes11)
  {
    positionAfterDcrRegistrationPayload10 = positionAfterhasRequireDpop + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload10 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasRequireDpop);
  }
  uint64_t res9;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload10))
  {
    res9 = positionAfterDcrRegistrationPayload10;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "require_dpop",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload10),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload10),
      Ctxt,
      Input,
      positionAfterhasRequireDpop);
    res9 = positionAfterDcrRegistrationPayload10;
  }
  uint64_t positionAfterrequireDpop = res9;
  if (EverParseIsError(positionAfterrequireDpop))
  {
    return positionAfterrequireDpop;
  }
  /* Validating field has_require_mtls */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes12 = 1ULL <= (InputLength - positionAfterrequireDpop);
  uint64_t positionAfterDcrRegistrationPayload11;
  if (hasBytes12)
  {
    positionAfterDcrRegistrationPayload11 = positionAfterrequireDpop + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload11 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequireDpop);
  }
  uint64_t res10;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload11))
  {
    res10 = positionAfterDcrRegistrationPayload11;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "has_require_mtls",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload11),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload11),
      Ctxt,
      Input,
      positionAfterrequireDpop);
    res10 = positionAfterDcrRegistrationPayload11;
  }
  uint64_t positionAfterhasRequireMtls = res10;
  if (EverParseIsError(positionAfterhasRequireMtls))
  {
    return positionAfterhasRequireMtls;
  }
  /*  Optional: client display name */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes13 = 1ULL <= (InputLength - positionAfterhasRequireMtls);
  uint64_t positionAfterDcrRegistrationPayload12;
  if (hasBytes13)
  {
    positionAfterDcrRegistrationPayload12 = positionAfterhasRequireMtls + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload12 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasRequireMtls);
  }
  uint64_t res11;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload12))
  {
    res11 = positionAfterDcrRegistrationPayload12;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "require_mtls",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload12),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload12),
      Ctxt,
      Input,
      positionAfterhasRequireMtls);
    res11 = positionAfterDcrRegistrationPayload12;
  }
  uint64_t positionAfterrequireMtls = res11;
  if (EverParseIsError(positionAfterrequireMtls))
  {
    return positionAfterrequireMtls;
  }
  /* Validating field has_client_name */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterrequireMtls);
  uint64_t positionAfterDcrRegistrationPayload13;
  if (hasBytes14)
  {
    positionAfterDcrRegistrationPayload13 = positionAfterrequireMtls + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequireMtls);
  }
  uint64_t res12;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload13))
  {
    res12 = positionAfterDcrRegistrationPayload13;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "has_client_name",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload13),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload13),
      Ctxt,
      Input,
      positionAfterrequireMtls);
    res12 = positionAfterDcrRegistrationPayload13;
  }
  uint64_t positionAfterhasClientName = res12;
  if (EverParseIsError(positionAfterhasClientName))
  {
    return positionAfterhasClientName;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes15 = 4ULL <= (InputLength - positionAfterhasClientName);
  uint64_t positionAfterDcrRegistrationPayload14;
  if (hasBytes15)
  {
    positionAfterDcrRegistrationPayload14 = positionAfterhasClientName + 4ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload14 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasClientName);
  }
  uint64_t positionAfterclientNameLength;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload14))
  {
    positionAfterclientNameLength = positionAfterDcrRegistrationPayload14;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "client_name_length",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload14),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload14),
      Ctxt,
      Input,
      positionAfterhasClientName);
    positionAfterclientNameLength = positionAfterDcrRegistrationPayload14;
  }
  if (EverParseIsError(positionAfterclientNameLength))
  {
    return positionAfterclientNameLength;
  }
  uint32_t clientNameLength = Load32Le(Input + (uint32_t)positionAfterhasClientName);
  /*  Optional: software_id */
  BOOLEAN
  hasBytes16 = (uint64_t)clientNameLength <= (InputLength - positionAfterclientNameLength);
  uint64_t res13;
  if (hasBytes16)
  {
    res13 = positionAfterclientNameLength + (uint64_t)clientNameLength;
  }
  else
  {
    res13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientNameLength);
  }
  uint64_t positionAfterDcrRegistrationPayload15 = res13;
  uint64_t positionAfterclientName;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload15))
  {
    positionAfterclientName = positionAfterDcrRegistrationPayload15;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "client_name",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload15),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload15),
      Ctxt,
      Input,
      positionAfterclientNameLength);
    positionAfterclientName = positionAfterDcrRegistrationPayload15;
  }
  if (EverParseIsError(positionAfterclientName))
  {
    return positionAfterclientName;
  }
  /* Validating field has_software_id */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes17 = 1ULL <= (InputLength - positionAfterclientName);
  uint64_t positionAfterDcrRegistrationPayload16;
  if (hasBytes17)
  {
    positionAfterDcrRegistrationPayload16 = positionAfterclientName + 1ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientName);
  }
  uint64_t res14;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload16))
  {
    res14 = positionAfterDcrRegistrationPayload16;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "has_software_id",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload16),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload16),
      Ctxt,
      Input,
      positionAfterclientName);
    res14 = positionAfterDcrRegistrationPayload16;
  }
  uint64_t positionAfterhasSoftwareId = res14;
  if (EverParseIsError(positionAfterhasSoftwareId))
  {
    return positionAfterhasSoftwareId;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes18 = 4ULL <= (InputLength - positionAfterhasSoftwareId);
  uint64_t positionAfterDcrRegistrationPayload17;
  if (hasBytes18)
  {
    positionAfterDcrRegistrationPayload17 = positionAfterhasSoftwareId + 4ULL;
  }
  else
  {
    positionAfterDcrRegistrationPayload17 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasSoftwareId);
  }
  uint64_t positionAftersoftwareIdLength;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload17))
  {
    positionAftersoftwareIdLength = positionAfterDcrRegistrationPayload17;
  }
  else
  {
    ErrorHandlerFn("_dcr_registration_payload",
      "software_id_length",
      EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload17),
      EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload17),
      Ctxt,
      Input,
      positionAfterhasSoftwareId);
    positionAftersoftwareIdLength = positionAfterDcrRegistrationPayload17;
  }
  if (EverParseIsError(positionAftersoftwareIdLength))
  {
    return positionAftersoftwareIdLength;
  }
  uint32_t softwareIdLength = Load32Le(Input + (uint32_t)positionAfterhasSoftwareId);
  /* Validating field software_id */
  BOOLEAN hasBytes = (uint64_t)softwareIdLength <= (InputLength - positionAftersoftwareIdLength);
  uint64_t res;
  if (hasBytes)
  {
    res = positionAftersoftwareIdLength + (uint64_t)softwareIdLength;
  }
  else
  {
    res =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersoftwareIdLength);
  }
  uint64_t positionAfterDcrRegistrationPayload18 = res;
  if (EverParseIsSuccess(positionAfterDcrRegistrationPayload18))
  {
    return positionAfterDcrRegistrationPayload18;
  }
  ErrorHandlerFn("_dcr_registration_payload",
    "software_id",
    EverParseErrorReasonOfResult(positionAfterDcrRegistrationPayload18),
    EverParseGetValidatorErrorKind(positionAfterDcrRegistrationPayload18),
    Ctxt,
    Input,
    positionAftersoftwareIdLength);
  return positionAfterDcrRegistrationPayload18;
}
