

#include "DCR.h"

static inline uint64_t
ValidateClientMetadata(
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
  uint64_t positionAfterClientMetadata;
  if (hasBytes0)
  {
    positionAfterClientMetadata = StartPosition + 4ULL;
  }
  else
  {
    positionAfterClientMetadata =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterredirectUrisLength;
  if (EverParseIsSuccess(positionAfterClientMetadata))
  {
    positionAfterredirectUrisLength = positionAfterClientMetadata;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "redirect_uris_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata),
      Ctxt,
      Input,
      StartPosition);
    positionAfterredirectUrisLength = positionAfterClientMetadata;
  }
  if (EverParseIsError(positionAfterredirectUrisLength))
  {
    return positionAfterredirectUrisLength;
  }
  uint32_t redirectUrisLength = Load32Le(Input + (uint32_t)StartPosition);
  /*  Concatenated URI strings;  Optional fields with presence flags */
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
  uint64_t positionAfterClientMetadata0 = res0;
  uint64_t positionAfterredirectUris;
  if (EverParseIsSuccess(positionAfterClientMetadata0))
  {
    positionAfterredirectUris = positionAfterClientMetadata0;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "redirect_uris",
      EverParseErrorReasonOfResult(positionAfterClientMetadata0),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata0),
      Ctxt,
      Input,
      positionAfterredirectUrisLength);
    positionAfterredirectUris = positionAfterClientMetadata0;
  }
  if (EverParseIsError(positionAfterredirectUris))
  {
    return positionAfterredirectUris;
  }
  /* Validating field has_token_endpoint_auth_method */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterredirectUris);
  uint64_t positionAfterClientMetadata1;
  if (hasBytes2)
  {
    positionAfterClientMetadata1 = positionAfterredirectUris + 1ULL;
  }
  else
  {
    positionAfterClientMetadata1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterredirectUris);
  }
  uint64_t res1;
  if (EverParseIsSuccess(positionAfterClientMetadata1))
  {
    res1 = positionAfterClientMetadata1;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_token_endpoint_auth_method",
      EverParseErrorReasonOfResult(positionAfterClientMetadata1),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata1),
      Ctxt,
      Input,
      positionAfterredirectUris);
    res1 = positionAfterClientMetadata1;
  }
  uint64_t positionAfterhasTokenEndpointAuthMethod = res1;
  if (EverParseIsError(positionAfterhasTokenEndpointAuthMethod))
  {
    return positionAfterhasTokenEndpointAuthMethod;
  }
  /*  0=none, 1=client_secret_post, 2=client_secret_basic, 3=private_key_jwt */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterhasTokenEndpointAuthMethod);
  uint64_t positionAfterClientMetadata2;
  if (hasBytes3)
  {
    positionAfterClientMetadata2 = positionAfterhasTokenEndpointAuthMethod + 4ULL;
  }
  else
  {
    positionAfterClientMetadata2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasTokenEndpointAuthMethod);
  }
  uint64_t res2;
  if (EverParseIsSuccess(positionAfterClientMetadata2))
  {
    res2 = positionAfterClientMetadata2;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "token_endpoint_auth_method",
      EverParseErrorReasonOfResult(positionAfterClientMetadata2),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata2),
      Ctxt,
      Input,
      positionAfterhasTokenEndpointAuthMethod);
    res2 = positionAfterClientMetadata2;
  }
  uint64_t positionAftertokenEndpointAuthMethod = res2;
  if (EverParseIsError(positionAftertokenEndpointAuthMethod))
  {
    return positionAftertokenEndpointAuthMethod;
  }
  /* Validating field has_grant_types */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAftertokenEndpointAuthMethod);
  uint64_t positionAfterClientMetadata3;
  if (hasBytes4)
  {
    positionAfterClientMetadata3 = positionAftertokenEndpointAuthMethod + 1ULL;
  }
  else
  {
    positionAfterClientMetadata3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftertokenEndpointAuthMethod);
  }
  uint64_t res3;
  if (EverParseIsSuccess(positionAfterClientMetadata3))
  {
    res3 = positionAfterClientMetadata3;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_grant_types",
      EverParseErrorReasonOfResult(positionAfterClientMetadata3),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata3),
      Ctxt,
      Input,
      positionAftertokenEndpointAuthMethod);
    res3 = positionAfterClientMetadata3;
  }
  uint64_t positionAfterhasGrantTypes = res3;
  if (EverParseIsError(positionAfterhasGrantTypes))
  {
    return positionAfterhasGrantTypes;
  }
  /*  Bitmask: 1=authorization_code, 2=refresh_token, 4=client_credentials, 8=urn:ietf:params:oauth:grant-type:jwt-bearer */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes5 = 4ULL <= (InputLength - positionAfterhasGrantTypes);
  uint64_t positionAfterClientMetadata4;
  if (hasBytes5)
  {
    positionAfterClientMetadata4 = positionAfterhasGrantTypes + 4ULL;
  }
  else
  {
    positionAfterClientMetadata4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasGrantTypes);
  }
  uint64_t res4;
  if (EverParseIsSuccess(positionAfterClientMetadata4))
  {
    res4 = positionAfterClientMetadata4;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "grant_types",
      EverParseErrorReasonOfResult(positionAfterClientMetadata4),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata4),
      Ctxt,
      Input,
      positionAfterhasGrantTypes);
    res4 = positionAfterClientMetadata4;
  }
  uint64_t positionAftergrantTypes = res4;
  if (EverParseIsError(positionAftergrantTypes))
  {
    return positionAftergrantTypes;
  }
  /* Validating field has_response_types */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes6 = 1ULL <= (InputLength - positionAftergrantTypes);
  uint64_t positionAfterClientMetadata5;
  if (hasBytes6)
  {
    positionAfterClientMetadata5 = positionAftergrantTypes + 1ULL;
  }
  else
  {
    positionAfterClientMetadata5 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftergrantTypes);
  }
  uint64_t res5;
  if (EverParseIsSuccess(positionAfterClientMetadata5))
  {
    res5 = positionAfterClientMetadata5;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_response_types",
      EverParseErrorReasonOfResult(positionAfterClientMetadata5),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata5),
      Ctxt,
      Input,
      positionAftergrantTypes);
    res5 = positionAfterClientMetadata5;
  }
  uint64_t positionAfterhasResponseTypes = res5;
  if (EverParseIsError(positionAfterhasResponseTypes))
  {
    return positionAfterhasResponseTypes;
  }
  /*  Bitmask: 1=code, 2=token (deprecated) */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes7 = 4ULL <= (InputLength - positionAfterhasResponseTypes);
  uint64_t positionAfterClientMetadata6;
  if (hasBytes7)
  {
    positionAfterClientMetadata6 = positionAfterhasResponseTypes + 4ULL;
  }
  else
  {
    positionAfterClientMetadata6 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasResponseTypes);
  }
  uint64_t res6;
  if (EverParseIsSuccess(positionAfterClientMetadata6))
  {
    res6 = positionAfterClientMetadata6;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "response_types",
      EverParseErrorReasonOfResult(positionAfterClientMetadata6),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata6),
      Ctxt,
      Input,
      positionAfterhasResponseTypes);
    res6 = positionAfterClientMetadata6;
  }
  uint64_t positionAfterresponseTypes = res6;
  if (EverParseIsError(positionAfterresponseTypes))
  {
    return positionAfterresponseTypes;
  }
  /* Validating field has_client_name */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterresponseTypes);
  uint64_t positionAfterClientMetadata7;
  if (hasBytes8)
  {
    positionAfterClientMetadata7 = positionAfterresponseTypes + 1ULL;
  }
  else
  {
    positionAfterClientMetadata7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterresponseTypes);
  }
  uint64_t res7;
  if (EverParseIsSuccess(positionAfterClientMetadata7))
  {
    res7 = positionAfterClientMetadata7;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_client_name",
      EverParseErrorReasonOfResult(positionAfterClientMetadata7),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata7),
      Ctxt,
      Input,
      positionAfterresponseTypes);
    res7 = positionAfterClientMetadata7;
  }
  uint64_t positionAfterhasClientName = res7;
  if (EverParseIsError(positionAfterhasClientName))
  {
    return positionAfterhasClientName;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterhasClientName);
  uint64_t positionAfterClientMetadata8;
  if (hasBytes9)
  {
    positionAfterClientMetadata8 = positionAfterhasClientName + 4ULL;
  }
  else
  {
    positionAfterClientMetadata8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasClientName);
  }
  uint64_t positionAfterclientNameLength;
  if (EverParseIsSuccess(positionAfterClientMetadata8))
  {
    positionAfterclientNameLength = positionAfterClientMetadata8;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "client_name_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata8),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata8),
      Ctxt,
      Input,
      positionAfterhasClientName);
    positionAfterclientNameLength = positionAfterClientMetadata8;
  }
  if (EverParseIsError(positionAfterclientNameLength))
  {
    return positionAfterclientNameLength;
  }
  uint32_t clientNameLength = Load32Le(Input + (uint32_t)positionAfterhasClientName);
  /* Validating field client_name */
  BOOLEAN
  hasBytes10 = (uint64_t)clientNameLength <= (InputLength - positionAfterclientNameLength);
  uint64_t res8;
  if (hasBytes10)
  {
    res8 = positionAfterclientNameLength + (uint64_t)clientNameLength;
  }
  else
  {
    res8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientNameLength);
  }
  uint64_t positionAfterClientMetadata9 = res8;
  uint64_t positionAfterclientName;
  if (EverParseIsSuccess(positionAfterClientMetadata9))
  {
    positionAfterclientName = positionAfterClientMetadata9;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "client_name",
      EverParseErrorReasonOfResult(positionAfterClientMetadata9),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata9),
      Ctxt,
      Input,
      positionAfterclientNameLength);
    positionAfterclientName = positionAfterClientMetadata9;
  }
  if (EverParseIsError(positionAfterclientName))
  {
    return positionAfterclientName;
  }
  /* Validating field has_client_uri */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterclientName);
  uint64_t positionAfterClientMetadata10;
  if (hasBytes11)
  {
    positionAfterClientMetadata10 = positionAfterclientName + 1ULL;
  }
  else
  {
    positionAfterClientMetadata10 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientName);
  }
  uint64_t res9;
  if (EverParseIsSuccess(positionAfterClientMetadata10))
  {
    res9 = positionAfterClientMetadata10;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_client_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata10),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata10),
      Ctxt,
      Input,
      positionAfterclientName);
    res9 = positionAfterClientMetadata10;
  }
  uint64_t positionAfterhasClientUri = res9;
  if (EverParseIsError(positionAfterhasClientUri))
  {
    return positionAfterhasClientUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterhasClientUri);
  uint64_t positionAfterClientMetadata11;
  if (hasBytes12)
  {
    positionAfterClientMetadata11 = positionAfterhasClientUri + 4ULL;
  }
  else
  {
    positionAfterClientMetadata11 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasClientUri);
  }
  uint64_t positionAfterclientUriLength;
  if (EverParseIsSuccess(positionAfterClientMetadata11))
  {
    positionAfterclientUriLength = positionAfterClientMetadata11;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "client_uri_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata11),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata11),
      Ctxt,
      Input,
      positionAfterhasClientUri);
    positionAfterclientUriLength = positionAfterClientMetadata11;
  }
  if (EverParseIsError(positionAfterclientUriLength))
  {
    return positionAfterclientUriLength;
  }
  uint32_t clientUriLength = Load32Le(Input + (uint32_t)positionAfterhasClientUri);
  /* Validating field client_uri */
  BOOLEAN hasBytes13 = (uint64_t)clientUriLength <= (InputLength - positionAfterclientUriLength);
  uint64_t res10;
  if (hasBytes13)
  {
    res10 = positionAfterclientUriLength + (uint64_t)clientUriLength;
  }
  else
  {
    res10 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientUriLength);
  }
  uint64_t positionAfterClientMetadata12 = res10;
  uint64_t positionAfterclientUri;
  if (EverParseIsSuccess(positionAfterClientMetadata12))
  {
    positionAfterclientUri = positionAfterClientMetadata12;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "client_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata12),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata12),
      Ctxt,
      Input,
      positionAfterclientUriLength);
    positionAfterclientUri = positionAfterClientMetadata12;
  }
  if (EverParseIsError(positionAfterclientUri))
  {
    return positionAfterclientUri;
  }
  /* Validating field has_logo_uri */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes14 = 1ULL <= (InputLength - positionAfterclientUri);
  uint64_t positionAfterClientMetadata13;
  if (hasBytes14)
  {
    positionAfterClientMetadata13 = positionAfterclientUri + 1ULL;
  }
  else
  {
    positionAfterClientMetadata13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientUri);
  }
  uint64_t res11;
  if (EverParseIsSuccess(positionAfterClientMetadata13))
  {
    res11 = positionAfterClientMetadata13;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_logo_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata13),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata13),
      Ctxt,
      Input,
      positionAfterclientUri);
    res11 = positionAfterClientMetadata13;
  }
  uint64_t positionAfterhasLogoUri = res11;
  if (EverParseIsError(positionAfterhasLogoUri))
  {
    return positionAfterhasLogoUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes15 = 4ULL <= (InputLength - positionAfterhasLogoUri);
  uint64_t positionAfterClientMetadata14;
  if (hasBytes15)
  {
    positionAfterClientMetadata14 = positionAfterhasLogoUri + 4ULL;
  }
  else
  {
    positionAfterClientMetadata14 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasLogoUri);
  }
  uint64_t positionAfterlogoUriLength;
  if (EverParseIsSuccess(positionAfterClientMetadata14))
  {
    positionAfterlogoUriLength = positionAfterClientMetadata14;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "logo_uri_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata14),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata14),
      Ctxt,
      Input,
      positionAfterhasLogoUri);
    positionAfterlogoUriLength = positionAfterClientMetadata14;
  }
  if (EverParseIsError(positionAfterlogoUriLength))
  {
    return positionAfterlogoUriLength;
  }
  uint32_t logoUriLength = Load32Le(Input + (uint32_t)positionAfterhasLogoUri);
  /* Validating field logo_uri */
  BOOLEAN hasBytes16 = (uint64_t)logoUriLength <= (InputLength - positionAfterlogoUriLength);
  uint64_t res12;
  if (hasBytes16)
  {
    res12 = positionAfterlogoUriLength + (uint64_t)logoUriLength;
  }
  else
  {
    res12 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterlogoUriLength);
  }
  uint64_t positionAfterClientMetadata15 = res12;
  uint64_t positionAfterlogoUri;
  if (EverParseIsSuccess(positionAfterClientMetadata15))
  {
    positionAfterlogoUri = positionAfterClientMetadata15;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "logo_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata15),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata15),
      Ctxt,
      Input,
      positionAfterlogoUriLength);
    positionAfterlogoUri = positionAfterClientMetadata15;
  }
  if (EverParseIsError(positionAfterlogoUri))
  {
    return positionAfterlogoUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes17 = 4ULL <= (InputLength - positionAfterlogoUri);
  uint64_t positionAfterClientMetadata16;
  if (hasBytes17)
  {
    positionAfterClientMetadata16 = positionAfterlogoUri + 4ULL;
  }
  else
  {
    positionAfterClientMetadata16 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterlogoUri);
  }
  uint64_t positionAfterscopesLength;
  if (EverParseIsSuccess(positionAfterClientMetadata16))
  {
    positionAfterscopesLength = positionAfterClientMetadata16;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "scopes_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata16),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata16),
      Ctxt,
      Input,
      positionAfterlogoUri);
    positionAfterscopesLength = positionAfterClientMetadata16;
  }
  if (EverParseIsError(positionAfterscopesLength))
  {
    return positionAfterscopesLength;
  }
  uint32_t scopesLength = Load32Le(Input + (uint32_t)positionAfterlogoUri);
  /*  Concatenated scope strings */
  BOOLEAN hasBytes18 = (uint64_t)scopesLength <= (InputLength - positionAfterscopesLength);
  uint64_t res13;
  if (hasBytes18)
  {
    res13 = positionAfterscopesLength + (uint64_t)scopesLength;
  }
  else
  {
    res13 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterscopesLength);
  }
  uint64_t positionAfterClientMetadata17 = res13;
  uint64_t positionAfterscopes;
  if (EverParseIsSuccess(positionAfterClientMetadata17))
  {
    positionAfterscopes = positionAfterClientMetadata17;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "scopes",
      EverParseErrorReasonOfResult(positionAfterClientMetadata17),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata17),
      Ctxt,
      Input,
      positionAfterscopesLength);
    positionAfterscopes = positionAfterClientMetadata17;
  }
  if (EverParseIsError(positionAfterscopes))
  {
    return positionAfterscopes;
  }
  /* Validating field has_contacts */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes19 = 1ULL <= (InputLength - positionAfterscopes);
  uint64_t positionAfterClientMetadata18;
  if (hasBytes19)
  {
    positionAfterClientMetadata18 = positionAfterscopes + 1ULL;
  }
  else
  {
    positionAfterClientMetadata18 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterscopes);
  }
  uint64_t res14;
  if (EverParseIsSuccess(positionAfterClientMetadata18))
  {
    res14 = positionAfterClientMetadata18;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_contacts",
      EverParseErrorReasonOfResult(positionAfterClientMetadata18),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata18),
      Ctxt,
      Input,
      positionAfterscopes);
    res14 = positionAfterClientMetadata18;
  }
  uint64_t positionAfterhasContacts = res14;
  if (EverParseIsError(positionAfterhasContacts))
  {
    return positionAfterhasContacts;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes20 = 4ULL <= (InputLength - positionAfterhasContacts);
  uint64_t positionAfterClientMetadata19;
  if (hasBytes20)
  {
    positionAfterClientMetadata19 = positionAfterhasContacts + 4ULL;
  }
  else
  {
    positionAfterClientMetadata19 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasContacts);
  }
  uint64_t positionAftercontactsLength;
  if (EverParseIsSuccess(positionAfterClientMetadata19))
  {
    positionAftercontactsLength = positionAfterClientMetadata19;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "contacts_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata19),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata19),
      Ctxt,
      Input,
      positionAfterhasContacts);
    positionAftercontactsLength = positionAfterClientMetadata19;
  }
  if (EverParseIsError(positionAftercontactsLength))
  {
    return positionAftercontactsLength;
  }
  uint32_t contactsLength = Load32Le(Input + (uint32_t)positionAfterhasContacts);
  /*  Concatenated email addresses */
  BOOLEAN hasBytes21 = (uint64_t)contactsLength <= (InputLength - positionAftercontactsLength);
  uint64_t res15;
  if (hasBytes21)
  {
    res15 = positionAftercontactsLength + (uint64_t)contactsLength;
  }
  else
  {
    res15 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftercontactsLength);
  }
  uint64_t positionAfterClientMetadata20 = res15;
  uint64_t positionAftercontacts;
  if (EverParseIsSuccess(positionAfterClientMetadata20))
  {
    positionAftercontacts = positionAfterClientMetadata20;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "contacts",
      EverParseErrorReasonOfResult(positionAfterClientMetadata20),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata20),
      Ctxt,
      Input,
      positionAftercontactsLength);
    positionAftercontacts = positionAfterClientMetadata20;
  }
  if (EverParseIsError(positionAftercontacts))
  {
    return positionAftercontacts;
  }
  /* Validating field has_tos_uri */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes22 = 1ULL <= (InputLength - positionAftercontacts);
  uint64_t positionAfterClientMetadata21;
  if (hasBytes22)
  {
    positionAfterClientMetadata21 = positionAftercontacts + 1ULL;
  }
  else
  {
    positionAfterClientMetadata21 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftercontacts);
  }
  uint64_t res16;
  if (EverParseIsSuccess(positionAfterClientMetadata21))
  {
    res16 = positionAfterClientMetadata21;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_tos_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata21),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata21),
      Ctxt,
      Input,
      positionAftercontacts);
    res16 = positionAfterClientMetadata21;
  }
  uint64_t positionAfterhasTosUri = res16;
  if (EverParseIsError(positionAfterhasTosUri))
  {
    return positionAfterhasTosUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes23 = 4ULL <= (InputLength - positionAfterhasTosUri);
  uint64_t positionAfterClientMetadata22;
  if (hasBytes23)
  {
    positionAfterClientMetadata22 = positionAfterhasTosUri + 4ULL;
  }
  else
  {
    positionAfterClientMetadata22 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasTosUri);
  }
  uint64_t positionAftertosUriLength;
  if (EverParseIsSuccess(positionAfterClientMetadata22))
  {
    positionAftertosUriLength = positionAfterClientMetadata22;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "tos_uri_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata22),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata22),
      Ctxt,
      Input,
      positionAfterhasTosUri);
    positionAftertosUriLength = positionAfterClientMetadata22;
  }
  if (EverParseIsError(positionAftertosUriLength))
  {
    return positionAftertosUriLength;
  }
  uint32_t tosUriLength = Load32Le(Input + (uint32_t)positionAfterhasTosUri);
  /* Validating field tos_uri */
  BOOLEAN hasBytes24 = (uint64_t)tosUriLength <= (InputLength - positionAftertosUriLength);
  uint64_t res17;
  if (hasBytes24)
  {
    res17 = positionAftertosUriLength + (uint64_t)tosUriLength;
  }
  else
  {
    res17 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftertosUriLength);
  }
  uint64_t positionAfterClientMetadata23 = res17;
  uint64_t positionAftertosUri;
  if (EverParseIsSuccess(positionAfterClientMetadata23))
  {
    positionAftertosUri = positionAfterClientMetadata23;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "tos_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata23),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata23),
      Ctxt,
      Input,
      positionAftertosUriLength);
    positionAftertosUri = positionAfterClientMetadata23;
  }
  if (EverParseIsError(positionAftertosUri))
  {
    return positionAftertosUri;
  }
  /* Validating field has_policy_uri */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes25 = 1ULL <= (InputLength - positionAftertosUri);
  uint64_t positionAfterClientMetadata24;
  if (hasBytes25)
  {
    positionAfterClientMetadata24 = positionAftertosUri + 1ULL;
  }
  else
  {
    positionAfterClientMetadata24 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftertosUri);
  }
  uint64_t res18;
  if (EverParseIsSuccess(positionAfterClientMetadata24))
  {
    res18 = positionAfterClientMetadata24;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_policy_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata24),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata24),
      Ctxt,
      Input,
      positionAftertosUri);
    res18 = positionAfterClientMetadata24;
  }
  uint64_t positionAfterhasPolicyUri = res18;
  if (EverParseIsError(positionAfterhasPolicyUri))
  {
    return positionAfterhasPolicyUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes26 = 4ULL <= (InputLength - positionAfterhasPolicyUri);
  uint64_t positionAfterClientMetadata25;
  if (hasBytes26)
  {
    positionAfterClientMetadata25 = positionAfterhasPolicyUri + 4ULL;
  }
  else
  {
    positionAfterClientMetadata25 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasPolicyUri);
  }
  uint64_t positionAfterpolicyUriLength;
  if (EverParseIsSuccess(positionAfterClientMetadata25))
  {
    positionAfterpolicyUriLength = positionAfterClientMetadata25;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "policy_uri_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata25),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata25),
      Ctxt,
      Input,
      positionAfterhasPolicyUri);
    positionAfterpolicyUriLength = positionAfterClientMetadata25;
  }
  if (EverParseIsError(positionAfterpolicyUriLength))
  {
    return positionAfterpolicyUriLength;
  }
  uint32_t policyUriLength = Load32Le(Input + (uint32_t)positionAfterhasPolicyUri);
  /* Validating field policy_uri */
  BOOLEAN hasBytes27 = (uint64_t)policyUriLength <= (InputLength - positionAfterpolicyUriLength);
  uint64_t res19;
  if (hasBytes27)
  {
    res19 = positionAfterpolicyUriLength + (uint64_t)policyUriLength;
  }
  else
  {
    res19 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterpolicyUriLength);
  }
  uint64_t positionAfterClientMetadata26 = res19;
  uint64_t positionAfterpolicyUri;
  if (EverParseIsSuccess(positionAfterClientMetadata26))
  {
    positionAfterpolicyUri = positionAfterClientMetadata26;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "policy_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata26),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata26),
      Ctxt,
      Input,
      positionAfterpolicyUriLength);
    positionAfterpolicyUri = positionAfterClientMetadata26;
  }
  if (EverParseIsError(positionAfterpolicyUri))
  {
    return positionAfterpolicyUri;
  }
  /* Validating field has_jwks_uri */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes28 = 1ULL <= (InputLength - positionAfterpolicyUri);
  uint64_t positionAfterClientMetadata27;
  if (hasBytes28)
  {
    positionAfterClientMetadata27 = positionAfterpolicyUri + 1ULL;
  }
  else
  {
    positionAfterClientMetadata27 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterpolicyUri);
  }
  uint64_t res20;
  if (EverParseIsSuccess(positionAfterClientMetadata27))
  {
    res20 = positionAfterClientMetadata27;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_jwks_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata27),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata27),
      Ctxt,
      Input,
      positionAfterpolicyUri);
    res20 = positionAfterClientMetadata27;
  }
  uint64_t positionAfterhasJwksUri = res20;
  if (EverParseIsError(positionAfterhasJwksUri))
  {
    return positionAfterhasJwksUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes29 = 4ULL <= (InputLength - positionAfterhasJwksUri);
  uint64_t positionAfterClientMetadata28;
  if (hasBytes29)
  {
    positionAfterClientMetadata28 = positionAfterhasJwksUri + 4ULL;
  }
  else
  {
    positionAfterClientMetadata28 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasJwksUri);
  }
  uint64_t positionAfterjwksUriLength;
  if (EverParseIsSuccess(positionAfterClientMetadata28))
  {
    positionAfterjwksUriLength = positionAfterClientMetadata28;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "jwks_uri_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata28),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata28),
      Ctxt,
      Input,
      positionAfterhasJwksUri);
    positionAfterjwksUriLength = positionAfterClientMetadata28;
  }
  if (EverParseIsError(positionAfterjwksUriLength))
  {
    return positionAfterjwksUriLength;
  }
  uint32_t jwksUriLength = Load32Le(Input + (uint32_t)positionAfterhasJwksUri);
  /* Validating field jwks_uri */
  BOOLEAN hasBytes30 = (uint64_t)jwksUriLength <= (InputLength - positionAfterjwksUriLength);
  uint64_t res21;
  if (hasBytes30)
  {
    res21 = positionAfterjwksUriLength + (uint64_t)jwksUriLength;
  }
  else
  {
    res21 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterjwksUriLength);
  }
  uint64_t positionAfterClientMetadata29 = res21;
  uint64_t positionAfterjwksUri;
  if (EverParseIsSuccess(positionAfterClientMetadata29))
  {
    positionAfterjwksUri = positionAfterClientMetadata29;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "jwks_uri",
      EverParseErrorReasonOfResult(positionAfterClientMetadata29),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata29),
      Ctxt,
      Input,
      positionAfterjwksUriLength);
    positionAfterjwksUri = positionAfterClientMetadata29;
  }
  if (EverParseIsError(positionAfterjwksUri))
  {
    return positionAfterjwksUri;
  }
  /* Validating field has_software_id */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes31 = 1ULL <= (InputLength - positionAfterjwksUri);
  uint64_t positionAfterClientMetadata30;
  if (hasBytes31)
  {
    positionAfterClientMetadata30 = positionAfterjwksUri + 1ULL;
  }
  else
  {
    positionAfterClientMetadata30 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterjwksUri);
  }
  uint64_t res22;
  if (EverParseIsSuccess(positionAfterClientMetadata30))
  {
    res22 = positionAfterClientMetadata30;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_software_id",
      EverParseErrorReasonOfResult(positionAfterClientMetadata30),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata30),
      Ctxt,
      Input,
      positionAfterjwksUri);
    res22 = positionAfterClientMetadata30;
  }
  uint64_t positionAfterhasSoftwareId = res22;
  if (EverParseIsError(positionAfterhasSoftwareId))
  {
    return positionAfterhasSoftwareId;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes32 = 4ULL <= (InputLength - positionAfterhasSoftwareId);
  uint64_t positionAfterClientMetadata31;
  if (hasBytes32)
  {
    positionAfterClientMetadata31 = positionAfterhasSoftwareId + 4ULL;
  }
  else
  {
    positionAfterClientMetadata31 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasSoftwareId);
  }
  uint64_t positionAftersoftwareIdLength;
  if (EverParseIsSuccess(positionAfterClientMetadata31))
  {
    positionAftersoftwareIdLength = positionAfterClientMetadata31;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "software_id_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata31),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata31),
      Ctxt,
      Input,
      positionAfterhasSoftwareId);
    positionAftersoftwareIdLength = positionAfterClientMetadata31;
  }
  if (EverParseIsError(positionAftersoftwareIdLength))
  {
    return positionAftersoftwareIdLength;
  }
  uint32_t softwareIdLength = Load32Le(Input + (uint32_t)positionAfterhasSoftwareId);
  /* Validating field software_id */
  BOOLEAN
  hasBytes33 = (uint64_t)softwareIdLength <= (InputLength - positionAftersoftwareIdLength);
  uint64_t res23;
  if (hasBytes33)
  {
    res23 = positionAftersoftwareIdLength + (uint64_t)softwareIdLength;
  }
  else
  {
    res23 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersoftwareIdLength);
  }
  uint64_t positionAfterClientMetadata32 = res23;
  uint64_t positionAftersoftwareId;
  if (EverParseIsSuccess(positionAfterClientMetadata32))
  {
    positionAftersoftwareId = positionAfterClientMetadata32;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "software_id",
      EverParseErrorReasonOfResult(positionAfterClientMetadata32),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata32),
      Ctxt,
      Input,
      positionAftersoftwareIdLength);
    positionAftersoftwareId = positionAfterClientMetadata32;
  }
  if (EverParseIsError(positionAftersoftwareId))
  {
    return positionAftersoftwareId;
  }
  /* Validating field has_software_version */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes34 = 1ULL <= (InputLength - positionAftersoftwareId);
  uint64_t positionAfterClientMetadata33;
  if (hasBytes34)
  {
    positionAfterClientMetadata33 = positionAftersoftwareId + 1ULL;
  }
  else
  {
    positionAfterClientMetadata33 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersoftwareId);
  }
  uint64_t res24;
  if (EverParseIsSuccess(positionAfterClientMetadata33))
  {
    res24 = positionAfterClientMetadata33;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_software_version",
      EverParseErrorReasonOfResult(positionAfterClientMetadata33),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata33),
      Ctxt,
      Input,
      positionAftersoftwareId);
    res24 = positionAfterClientMetadata33;
  }
  uint64_t positionAfterhasSoftwareVersion = res24;
  if (EverParseIsError(positionAfterhasSoftwareVersion))
  {
    return positionAfterhasSoftwareVersion;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes35 = 4ULL <= (InputLength - positionAfterhasSoftwareVersion);
  uint64_t positionAfterClientMetadata34;
  if (hasBytes35)
  {
    positionAfterClientMetadata34 = positionAfterhasSoftwareVersion + 4ULL;
  }
  else
  {
    positionAfterClientMetadata34 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasSoftwareVersion);
  }
  uint64_t positionAftersoftwareVersionLength;
  if (EverParseIsSuccess(positionAfterClientMetadata34))
  {
    positionAftersoftwareVersionLength = positionAfterClientMetadata34;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "software_version_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata34),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata34),
      Ctxt,
      Input,
      positionAfterhasSoftwareVersion);
    positionAftersoftwareVersionLength = positionAfterClientMetadata34;
  }
  if (EverParseIsError(positionAftersoftwareVersionLength))
  {
    return positionAftersoftwareVersionLength;
  }
  uint32_t softwareVersionLength = Load32Le(Input + (uint32_t)positionAfterhasSoftwareVersion);
  /*  OAuth 2.1 / RFC 9700 additions */
  BOOLEAN
  hasBytes36 =
    (uint64_t)softwareVersionLength <= (InputLength - positionAftersoftwareVersionLength);
  uint64_t res25;
  if (hasBytes36)
  {
    res25 = positionAftersoftwareVersionLength + (uint64_t)softwareVersionLength;
  }
  else
  {
    res25 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersoftwareVersionLength);
  }
  uint64_t positionAfterClientMetadata35 = res25;
  uint64_t positionAftersoftwareVersion;
  if (EverParseIsSuccess(positionAfterClientMetadata35))
  {
    positionAftersoftwareVersion = positionAfterClientMetadata35;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "software_version",
      EverParseErrorReasonOfResult(positionAfterClientMetadata35),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata35),
      Ctxt,
      Input,
      positionAftersoftwareVersionLength);
    positionAftersoftwareVersion = positionAfterClientMetadata35;
  }
  if (EverParseIsError(positionAftersoftwareVersion))
  {
    return positionAftersoftwareVersion;
  }
  /* Validating field requires_pkce */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes37 = 1ULL <= (InputLength - positionAftersoftwareVersion);
  uint64_t positionAfterClientMetadata36;
  if (hasBytes37)
  {
    positionAfterClientMetadata36 = positionAftersoftwareVersion + 1ULL;
  }
  else
  {
    positionAfterClientMetadata36 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersoftwareVersion);
  }
  uint64_t res26;
  if (EverParseIsSuccess(positionAfterClientMetadata36))
  {
    res26 = positionAfterClientMetadata36;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "requires_pkce",
      EverParseErrorReasonOfResult(positionAfterClientMetadata36),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata36),
      Ctxt,
      Input,
      positionAftersoftwareVersion);
    res26 = positionAfterClientMetadata36;
  }
  uint64_t positionAfterrequiresPkce = res26;
  if (EverParseIsError(positionAfterrequiresPkce))
  {
    return positionAfterrequiresPkce;
  }
  /* Validating field requires_dpop */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes38 = 1ULL <= (InputLength - positionAfterrequiresPkce);
  uint64_t positionAfterClientMetadata37;
  if (hasBytes38)
  {
    positionAfterClientMetadata37 = positionAfterrequiresPkce + 1ULL;
  }
  else
  {
    positionAfterClientMetadata37 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequiresPkce);
  }
  uint64_t res27;
  if (EverParseIsSuccess(positionAfterClientMetadata37))
  {
    res27 = positionAfterClientMetadata37;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "requires_dpop",
      EverParseErrorReasonOfResult(positionAfterClientMetadata37),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata37),
      Ctxt,
      Input,
      positionAfterrequiresPkce);
    res27 = positionAfterClientMetadata37;
  }
  uint64_t positionAfterrequiresDpop = res27;
  if (EverParseIsError(positionAfterrequiresDpop))
  {
    return positionAfterrequiresDpop;
  }
  /*  Sender-constrained token support */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes39 = 1ULL <= (InputLength - positionAfterrequiresDpop);
  uint64_t positionAfterClientMetadata38;
  if (hasBytes39)
  {
    positionAfterClientMetadata38 = positionAfterrequiresDpop + 1ULL;
  }
  else
  {
    positionAfterClientMetadata38 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequiresDpop);
  }
  uint64_t res28;
  if (EverParseIsSuccess(positionAfterClientMetadata38))
  {
    res28 = positionAfterClientMetadata38;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "requires_par",
      EverParseErrorReasonOfResult(positionAfterClientMetadata38),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata38),
      Ctxt,
      Input,
      positionAfterrequiresDpop);
    res28 = positionAfterClientMetadata38;
  }
  uint64_t positionAfterrequiresPar = res28;
  if (EverParseIsError(positionAfterrequiresPar))
  {
    return positionAfterrequiresPar;
  }
  /* Validating field has_require_sender_constrained_tokens */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes40 = 1ULL <= (InputLength - positionAfterrequiresPar);
  uint64_t positionAfterClientMetadata39;
  if (hasBytes40)
  {
    positionAfterClientMetadata39 = positionAfterrequiresPar + 1ULL;
  }
  else
  {
    positionAfterClientMetadata39 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequiresPar);
  }
  uint64_t res29;
  if (EverParseIsSuccess(positionAfterClientMetadata39))
  {
    res29 = positionAfterClientMetadata39;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_require_sender_constrained_tokens",
      EverParseErrorReasonOfResult(positionAfterClientMetadata39),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata39),
      Ctxt,
      Input,
      positionAfterrequiresPar);
    res29 = positionAfterClientMetadata39;
  }
  uint64_t positionAfterhasRequireSenderConstrainedTokens = res29;
  if (EverParseIsError(positionAfterhasRequireSenderConstrainedTokens))
  {
    return positionAfterhasRequireSenderConstrainedTokens;
  }
  /* Validating field require_sender_constrained_tokens */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes41 = 1ULL <= (InputLength - positionAfterhasRequireSenderConstrainedTokens);
  uint64_t positionAfterClientMetadata40;
  if (hasBytes41)
  {
    positionAfterClientMetadata40 = positionAfterhasRequireSenderConstrainedTokens + 1ULL;
  }
  else
  {
    positionAfterClientMetadata40 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasRequireSenderConstrainedTokens);
  }
  uint64_t res30;
  if (EverParseIsSuccess(positionAfterClientMetadata40))
  {
    res30 = positionAfterClientMetadata40;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "require_sender_constrained_tokens",
      EverParseErrorReasonOfResult(positionAfterClientMetadata40),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata40),
      Ctxt,
      Input,
      positionAfterhasRequireSenderConstrainedTokens);
    res30 = positionAfterClientMetadata40;
  }
  uint64_t positionAfterrequireSenderConstrainedTokens = res30;
  if (EverParseIsError(positionAfterrequireSenderConstrainedTokens))
  {
    return positionAfterrequireSenderConstrainedTokens;
  }
  /* Validating field has_sender_constrained_methods */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes42 = 1ULL <= (InputLength - positionAfterrequireSenderConstrainedTokens);
  uint64_t positionAfterClientMetadata41;
  if (hasBytes42)
  {
    positionAfterClientMetadata41 = positionAfterrequireSenderConstrainedTokens + 1ULL;
  }
  else
  {
    positionAfterClientMetadata41 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterrequireSenderConstrainedTokens);
  }
  uint64_t res31;
  if (EverParseIsSuccess(positionAfterClientMetadata41))
  {
    res31 = positionAfterClientMetadata41;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "has_sender_constrained_methods",
      EverParseErrorReasonOfResult(positionAfterClientMetadata41),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata41),
      Ctxt,
      Input,
      positionAfterrequireSenderConstrainedTokens);
    res31 = positionAfterClientMetadata41;
  }
  uint64_t positionAfterhasSenderConstrainedMethods = res31;
  if (EverParseIsError(positionAfterhasSenderConstrainedMethods))
  {
    return positionAfterhasSenderConstrainedMethods;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes43 = 4ULL <= (InputLength - positionAfterhasSenderConstrainedMethods);
  uint64_t positionAfterClientMetadata42;
  if (hasBytes43)
  {
    positionAfterClientMetadata42 = positionAfterhasSenderConstrainedMethods + 4ULL;
  }
  else
  {
    positionAfterClientMetadata42 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasSenderConstrainedMethods);
  }
  uint64_t positionAftersenderConstrainedMethodsLength;
  if (EverParseIsSuccess(positionAfterClientMetadata42))
  {
    positionAftersenderConstrainedMethodsLength = positionAfterClientMetadata42;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "sender_constrained_methods_length",
      EverParseErrorReasonOfResult(positionAfterClientMetadata42),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata42),
      Ctxt,
      Input,
      positionAfterhasSenderConstrainedMethods);
    positionAftersenderConstrainedMethodsLength = positionAfterClientMetadata42;
  }
  if (EverParseIsError(positionAftersenderConstrainedMethodsLength))
  {
    return positionAftersenderConstrainedMethodsLength;
  }
  uint32_t
  senderConstrainedMethodsLength =
    Load32Le(Input + (uint32_t)positionAfterhasSenderConstrainedMethods);
  /*  Method names */
  BOOLEAN
  hasBytes44 =
    (uint64_t)senderConstrainedMethodsLength <=
      (InputLength - positionAftersenderConstrainedMethodsLength);
  uint64_t res;
  if (hasBytes44)
  {
    res = positionAftersenderConstrainedMethodsLength + (uint64_t)senderConstrainedMethodsLength;
  }
  else
  {
    res =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftersenderConstrainedMethodsLength);
  }
  uint64_t positionAfterClientMetadata43 = res;
  uint64_t positionAftersenderConstrainedMethods;
  if (EverParseIsSuccess(positionAfterClientMetadata43))
  {
    positionAftersenderConstrainedMethods = positionAfterClientMetadata43;
  }
  else
  {
    ErrorHandlerFn("_client_metadata",
      "sender_constrained_methods",
      EverParseErrorReasonOfResult(positionAfterClientMetadata43),
      EverParseGetValidatorErrorKind(positionAfterClientMetadata43),
      Ctxt,
      Input,
      positionAftersenderConstrainedMethodsLength);
    positionAftersenderConstrainedMethods = positionAfterClientMetadata43;
  }
  if (EverParseIsError(positionAftersenderConstrainedMethods))
  {
    return positionAftersenderConstrainedMethods;
  }
  BOOLEAN hasBytes = 2ULL <= (InputLength - positionAftersenderConstrainedMethods);
  if (hasBytes)
  {
    return positionAftersenderConstrainedMethods + 2ULL;
  }
  return
    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
      positionAftersenderConstrainedMethods);
}

uint64_t
DcrValidateRegistrationRequest(
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
  /*  Protocol version (should be 1) */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes0 = 4ULL <= (InputLength - StartPosition);
  uint64_t positionAfterRegistrationRequest;
  if (hasBytes0)
  {
    positionAfterRegistrationRequest = StartPosition + 4ULL;
  }
  else
  {
    positionAfterRegistrationRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t res;
  if (EverParseIsSuccess(positionAfterRegistrationRequest))
  {
    res = positionAfterRegistrationRequest;
  }
  else
  {
    ErrorHandlerFn("_registration_request",
      "version",
      EverParseErrorReasonOfResult(positionAfterRegistrationRequest),
      EverParseGetValidatorErrorKind(positionAfterRegistrationRequest),
      Ctxt,
      Input,
      StartPosition);
    res = positionAfterRegistrationRequest;
  }
  uint64_t positionAfterversion = res;
  if (EverParseIsError(positionAfterversion))
  {
    return positionAfterversion;
  }
  /*  Optional initial access token reference */
  uint64_t
  positionAfterRegistrationRequest0 =
    ValidateClientMetadata(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterversion);
  uint64_t positionAftermetadata;
  if (EverParseIsSuccess(positionAfterRegistrationRequest0))
  {
    positionAftermetadata = positionAfterRegistrationRequest0;
  }
  else
  {
    ErrorHandlerFn("_registration_request",
      "metadata",
      EverParseErrorReasonOfResult(positionAfterRegistrationRequest0),
      EverParseGetValidatorErrorKind(positionAfterRegistrationRequest0),
      Ctxt,
      Input,
      positionAfterversion);
    positionAftermetadata = positionAfterRegistrationRequest0;
  }
  if (EverParseIsError(positionAftermetadata))
  {
    return positionAftermetadata;
  }
  BOOLEAN hasBytes = 5ULL <= (InputLength - positionAftermetadata);
  if (hasBytes)
  {
    return positionAftermetadata + 5ULL;
  }
  return
    EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
      positionAftermetadata);
}

uint64_t
DcrValidateRegistrationResponse(
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
  uint64_t positionAfterRegistrationResponse;
  if (hasBytes0)
  {
    positionAfterRegistrationResponse = StartPosition + 4ULL;
  }
  else
  {
    positionAfterRegistrationResponse =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterclientIdLength;
  if (EverParseIsSuccess(positionAfterRegistrationResponse))
  {
    positionAfterclientIdLength = positionAfterRegistrationResponse;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "client_id_length",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse),
      Ctxt,
      Input,
      StartPosition);
    positionAfterclientIdLength = positionAfterRegistrationResponse;
  }
  if (EverParseIsError(positionAfterclientIdLength))
  {
    return positionAfterclientIdLength;
  }
  uint32_t clientIdLength = Load32Le(Input + (uint32_t)StartPosition);
  /* Validating field client_id */
  BOOLEAN hasBytes1 = (uint64_t)clientIdLength <= (InputLength - positionAfterclientIdLength);
  uint64_t res0;
  if (hasBytes1)
  {
    res0 = positionAfterclientIdLength + (uint64_t)clientIdLength;
  }
  else
  {
    res0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientIdLength);
  }
  uint64_t positionAfterRegistrationResponse0 = res0;
  uint64_t positionAfterclientId;
  if (EverParseIsSuccess(positionAfterRegistrationResponse0))
  {
    positionAfterclientId = positionAfterRegistrationResponse0;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "client_id",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse0),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse0),
      Ctxt,
      Input,
      positionAfterclientIdLength);
    positionAfterclientId = positionAfterRegistrationResponse0;
  }
  if (EverParseIsError(positionAfterclientId))
  {
    return positionAfterclientId;
  }
  /* Validating field has_client_secret */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes2 = 1ULL <= (InputLength - positionAfterclientId);
  uint64_t positionAfterRegistrationResponse1;
  if (hasBytes2)
  {
    positionAfterRegistrationResponse1 = positionAfterclientId + 1ULL;
  }
  else
  {
    positionAfterRegistrationResponse1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientId);
  }
  uint64_t res1;
  if (EverParseIsSuccess(positionAfterRegistrationResponse1))
  {
    res1 = positionAfterRegistrationResponse1;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "has_client_secret",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse1),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse1),
      Ctxt,
      Input,
      positionAfterclientId);
    res1 = positionAfterRegistrationResponse1;
  }
  uint64_t positionAfterhasClientSecret = res1;
  if (EverParseIsError(positionAfterhasClientSecret))
  {
    return positionAfterhasClientSecret;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes3 = 4ULL <= (InputLength - positionAfterhasClientSecret);
  uint64_t positionAfterRegistrationResponse2;
  if (hasBytes3)
  {
    positionAfterRegistrationResponse2 = positionAfterhasClientSecret + 4ULL;
  }
  else
  {
    positionAfterRegistrationResponse2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasClientSecret);
  }
  uint64_t positionAfterclientSecretLength;
  if (EverParseIsSuccess(positionAfterRegistrationResponse2))
  {
    positionAfterclientSecretLength = positionAfterRegistrationResponse2;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "client_secret_length",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse2),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse2),
      Ctxt,
      Input,
      positionAfterhasClientSecret);
    positionAfterclientSecretLength = positionAfterRegistrationResponse2;
  }
  if (EverParseIsError(positionAfterclientSecretLength))
  {
    return positionAfterclientSecretLength;
  }
  uint32_t clientSecretLength = Load32Le(Input + (uint32_t)positionAfterhasClientSecret);
  /* Validating field client_secret */
  BOOLEAN
  hasBytes4 = (uint64_t)clientSecretLength <= (InputLength - positionAfterclientSecretLength);
  uint64_t res2;
  if (hasBytes4)
  {
    res2 = positionAfterclientSecretLength + (uint64_t)clientSecretLength;
  }
  else
  {
    res2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientSecretLength);
  }
  uint64_t positionAfterRegistrationResponse3 = res2;
  uint64_t positionAfterclientSecret;
  if (EverParseIsSuccess(positionAfterRegistrationResponse3))
  {
    positionAfterclientSecret = positionAfterRegistrationResponse3;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "client_secret",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse3),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse3),
      Ctxt,
      Input,
      positionAfterclientSecretLength);
    positionAfterclientSecret = positionAfterRegistrationResponse3;
  }
  if (EverParseIsError(positionAfterclientSecret))
  {
    return positionAfterclientSecret;
  }
  /*  Unix timestamp */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes5 = 4ULL <= (InputLength - positionAfterclientSecret);
  uint64_t positionAfterRegistrationResponse4;
  if (hasBytes5)
  {
    positionAfterRegistrationResponse4 = positionAfterclientSecret + 4ULL;
  }
  else
  {
    positionAfterRegistrationResponse4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientSecret);
  }
  uint64_t res3;
  if (EverParseIsSuccess(positionAfterRegistrationResponse4))
  {
    res3 = positionAfterRegistrationResponse4;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "client_id_issued_at",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse4),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse4),
      Ctxt,
      Input,
      positionAfterclientSecret);
    res3 = positionAfterRegistrationResponse4;
  }
  uint64_t positionAfterclientIdIssuedAt = res3;
  if (EverParseIsError(positionAfterclientIdIssuedAt))
  {
    return positionAfterclientIdIssuedAt;
  }
  /* Validating field has_client_secret_expires_at */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes6 = 1ULL <= (InputLength - positionAfterclientIdIssuedAt);
  uint64_t positionAfterRegistrationResponse5;
  if (hasBytes6)
  {
    positionAfterRegistrationResponse5 = positionAfterclientIdIssuedAt + 1ULL;
  }
  else
  {
    positionAfterRegistrationResponse5 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientIdIssuedAt);
  }
  uint64_t res4;
  if (EverParseIsSuccess(positionAfterRegistrationResponse5))
  {
    res4 = positionAfterRegistrationResponse5;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "has_client_secret_expires_at",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse5),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse5),
      Ctxt,
      Input,
      positionAfterclientIdIssuedAt);
    res4 = positionAfterRegistrationResponse5;
  }
  uint64_t positionAfterhasClientSecretExpiresAt = res4;
  if (EverParseIsError(positionAfterhasClientSecretExpiresAt))
  {
    return positionAfterhasClientSecretExpiresAt;
  }
  /*  Unix timestamp or 0 for no expiry;  Echo back the registered metadata */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes7 = 4ULL <= (InputLength - positionAfterhasClientSecretExpiresAt);
  uint64_t positionAfterRegistrationResponse6;
  if (hasBytes7)
  {
    positionAfterRegistrationResponse6 = positionAfterhasClientSecretExpiresAt + 4ULL;
  }
  else
  {
    positionAfterRegistrationResponse6 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasClientSecretExpiresAt);
  }
  uint64_t res5;
  if (EverParseIsSuccess(positionAfterRegistrationResponse6))
  {
    res5 = positionAfterRegistrationResponse6;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "client_secret_expires_at",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse6),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse6),
      Ctxt,
      Input,
      positionAfterhasClientSecretExpiresAt);
    res5 = positionAfterRegistrationResponse6;
  }
  uint64_t positionAfterclientSecretExpiresAt = res5;
  if (EverParseIsError(positionAfterclientSecretExpiresAt))
  {
    return positionAfterclientSecretExpiresAt;
  }
  /*  Registration management */
  uint64_t
  positionAfterRegistrationResponse7 =
    ValidateClientMetadata(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterclientSecretExpiresAt);
  uint64_t positionAfterregisteredMetadata;
  if (EverParseIsSuccess(positionAfterRegistrationResponse7))
  {
    positionAfterregisteredMetadata = positionAfterRegistrationResponse7;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "registered_metadata",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse7),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse7),
      Ctxt,
      Input,
      positionAfterclientSecretExpiresAt);
    positionAfterregisteredMetadata = positionAfterRegistrationResponse7;
  }
  if (EverParseIsError(positionAfterregisteredMetadata))
  {
    return positionAfterregisteredMetadata;
  }
  /* Validating field has_registration_access_token */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes8 = 1ULL <= (InputLength - positionAfterregisteredMetadata);
  uint64_t positionAfterRegistrationResponse8;
  if (hasBytes8)
  {
    positionAfterRegistrationResponse8 = positionAfterregisteredMetadata + 1ULL;
  }
  else
  {
    positionAfterRegistrationResponse8 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterregisteredMetadata);
  }
  uint64_t res6;
  if (EverParseIsSuccess(positionAfterRegistrationResponse8))
  {
    res6 = positionAfterRegistrationResponse8;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "has_registration_access_token",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse8),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse8),
      Ctxt,
      Input,
      positionAfterregisteredMetadata);
    res6 = positionAfterRegistrationResponse8;
  }
  uint64_t positionAfterhasRegistrationAccessToken = res6;
  if (EverParseIsError(positionAfterhasRegistrationAccessToken))
  {
    return positionAfterhasRegistrationAccessToken;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes9 = 4ULL <= (InputLength - positionAfterhasRegistrationAccessToken);
  uint64_t positionAfterRegistrationResponse9;
  if (hasBytes9)
  {
    positionAfterRegistrationResponse9 = positionAfterhasRegistrationAccessToken + 4ULL;
  }
  else
  {
    positionAfterRegistrationResponse9 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasRegistrationAccessToken);
  }
  uint64_t positionAfterregistrationAccessTokenLength;
  if (EverParseIsSuccess(positionAfterRegistrationResponse9))
  {
    positionAfterregistrationAccessTokenLength = positionAfterRegistrationResponse9;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "registration_access_token_length",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse9),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse9),
      Ctxt,
      Input,
      positionAfterhasRegistrationAccessToken);
    positionAfterregistrationAccessTokenLength = positionAfterRegistrationResponse9;
  }
  if (EverParseIsError(positionAfterregistrationAccessTokenLength))
  {
    return positionAfterregistrationAccessTokenLength;
  }
  uint32_t
  registrationAccessTokenLength =
    Load32Le(Input + (uint32_t)positionAfterhasRegistrationAccessToken);
  /* Validating field registration_access_token */
  BOOLEAN
  hasBytes10 =
    (uint64_t)registrationAccessTokenLength <=
      (InputLength - positionAfterregistrationAccessTokenLength);
  uint64_t res7;
  if (hasBytes10)
  {
    res7 = positionAfterregistrationAccessTokenLength + (uint64_t)registrationAccessTokenLength;
  }
  else
  {
    res7 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterregistrationAccessTokenLength);
  }
  uint64_t positionAfterRegistrationResponse10 = res7;
  uint64_t positionAfterregistrationAccessToken;
  if (EverParseIsSuccess(positionAfterRegistrationResponse10))
  {
    positionAfterregistrationAccessToken = positionAfterRegistrationResponse10;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "registration_access_token",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse10),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse10),
      Ctxt,
      Input,
      positionAfterregistrationAccessTokenLength);
    positionAfterregistrationAccessToken = positionAfterRegistrationResponse10;
  }
  if (EverParseIsError(positionAfterregistrationAccessToken))
  {
    return positionAfterregistrationAccessToken;
  }
  /* Validating field has_registration_client_uri */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes11 = 1ULL <= (InputLength - positionAfterregistrationAccessToken);
  uint64_t positionAfterRegistrationResponse11;
  if (hasBytes11)
  {
    positionAfterRegistrationResponse11 = positionAfterregistrationAccessToken + 1ULL;
  }
  else
  {
    positionAfterRegistrationResponse11 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterregistrationAccessToken);
  }
  uint64_t res8;
  if (EverParseIsSuccess(positionAfterRegistrationResponse11))
  {
    res8 = positionAfterRegistrationResponse11;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "has_registration_client_uri",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse11),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse11),
      Ctxt,
      Input,
      positionAfterregistrationAccessToken);
    res8 = positionAfterRegistrationResponse11;
  }
  uint64_t positionAfterhasRegistrationClientUri = res8;
  if (EverParseIsError(positionAfterhasRegistrationClientUri))
  {
    return positionAfterhasRegistrationClientUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes12 = 4ULL <= (InputLength - positionAfterhasRegistrationClientUri);
  uint64_t positionAfterRegistrationResponse12;
  if (hasBytes12)
  {
    positionAfterRegistrationResponse12 = positionAfterhasRegistrationClientUri + 4ULL;
  }
  else
  {
    positionAfterRegistrationResponse12 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasRegistrationClientUri);
  }
  uint64_t positionAfterregistrationClientUriLength;
  if (EverParseIsSuccess(positionAfterRegistrationResponse12))
  {
    positionAfterregistrationClientUriLength = positionAfterRegistrationResponse12;
  }
  else
  {
    ErrorHandlerFn("_registration_response",
      "registration_client_uri_length",
      EverParseErrorReasonOfResult(positionAfterRegistrationResponse12),
      EverParseGetValidatorErrorKind(positionAfterRegistrationResponse12),
      Ctxt,
      Input,
      positionAfterhasRegistrationClientUri);
    positionAfterregistrationClientUriLength = positionAfterRegistrationResponse12;
  }
  if (EverParseIsError(positionAfterregistrationClientUriLength))
  {
    return positionAfterregistrationClientUriLength;
  }
  uint32_t
  registrationClientUriLength = Load32Le(Input + (uint32_t)positionAfterhasRegistrationClientUri);
  /* Validating field registration_client_uri */
  BOOLEAN
  hasBytes =
    (uint64_t)registrationClientUriLength <=
      (InputLength - positionAfterregistrationClientUriLength);
  uint64_t res;
  if (hasBytes)
  {
    res = positionAfterregistrationClientUriLength + (uint64_t)registrationClientUriLength;
  }
  else
  {
    res =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterregistrationClientUriLength);
  }
  uint64_t positionAfterRegistrationResponse13 = res;
  if (EverParseIsSuccess(positionAfterRegistrationResponse13))
  {
    return positionAfterRegistrationResponse13;
  }
  ErrorHandlerFn("_registration_response",
    "registration_client_uri",
    EverParseErrorReasonOfResult(positionAfterRegistrationResponse13),
    EverParseGetValidatorErrorKind(positionAfterRegistrationResponse13),
    Ctxt,
    Input,
    positionAfterregistrationClientUriLength);
  return positionAfterRegistrationResponse13;
}

uint64_t
DcrValidateUpdateRequest(
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
  uint64_t positionAfterUpdateRequest;
  if (hasBytes0)
  {
    positionAfterUpdateRequest = StartPosition + 4ULL;
  }
  else
  {
    positionAfterUpdateRequest =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t positionAfterclientIdLength;
  if (EverParseIsSuccess(positionAfterUpdateRequest))
  {
    positionAfterclientIdLength = positionAfterUpdateRequest;
  }
  else
  {
    ErrorHandlerFn("_update_request",
      "client_id_length",
      EverParseErrorReasonOfResult(positionAfterUpdateRequest),
      EverParseGetValidatorErrorKind(positionAfterUpdateRequest),
      Ctxt,
      Input,
      StartPosition);
    positionAfterclientIdLength = positionAfterUpdateRequest;
  }
  if (EverParseIsError(positionAfterclientIdLength))
  {
    return positionAfterclientIdLength;
  }
  uint32_t clientIdLength = Load32Le(Input + (uint32_t)StartPosition);
  /* Validating field client_id */
  BOOLEAN hasBytes1 = (uint64_t)clientIdLength <= (InputLength - positionAfterclientIdLength);
  uint64_t res0;
  if (hasBytes1)
  {
    res0 = positionAfterclientIdLength + (uint64_t)clientIdLength;
  }
  else
  {
    res0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientIdLength);
  }
  uint64_t positionAfterUpdateRequest0 = res0;
  uint64_t positionAfterclientId;
  if (EverParseIsSuccess(positionAfterUpdateRequest0))
  {
    positionAfterclientId = positionAfterUpdateRequest0;
  }
  else
  {
    ErrorHandlerFn("_update_request",
      "client_id",
      EverParseErrorReasonOfResult(positionAfterUpdateRequest0),
      EverParseGetValidatorErrorKind(positionAfterUpdateRequest0),
      Ctxt,
      Input,
      positionAfterclientIdLength);
    positionAfterclientId = positionAfterUpdateRequest0;
  }
  if (EverParseIsError(positionAfterclientId))
  {
    return positionAfterclientId;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterclientId);
  uint64_t positionAfterUpdateRequest1;
  if (hasBytes2)
  {
    positionAfterUpdateRequest1 = positionAfterclientId + 4ULL;
  }
  else
  {
    positionAfterUpdateRequest1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterclientId);
  }
  uint64_t positionAfterregistrationAccessTokenLength;
  if (EverParseIsSuccess(positionAfterUpdateRequest1))
  {
    positionAfterregistrationAccessTokenLength = positionAfterUpdateRequest1;
  }
  else
  {
    ErrorHandlerFn("_update_request",
      "registration_access_token_length",
      EverParseErrorReasonOfResult(positionAfterUpdateRequest1),
      EverParseGetValidatorErrorKind(positionAfterUpdateRequest1),
      Ctxt,
      Input,
      positionAfterclientId);
    positionAfterregistrationAccessTokenLength = positionAfterUpdateRequest1;
  }
  if (EverParseIsError(positionAfterregistrationAccessTokenLength))
  {
    return positionAfterregistrationAccessTokenLength;
  }
  uint32_t registrationAccessTokenLength = Load32Le(Input + (uint32_t)positionAfterclientId);
  /* Validating field registration_access_token */
  BOOLEAN
  hasBytes =
    (uint64_t)registrationAccessTokenLength <=
      (InputLength - positionAfterregistrationAccessTokenLength);
  uint64_t res;
  if (hasBytes)
  {
    res = positionAfterregistrationAccessTokenLength + (uint64_t)registrationAccessTokenLength;
  }
  else
  {
    res =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterregistrationAccessTokenLength);
  }
  uint64_t positionAfterUpdateRequest2 = res;
  uint64_t positionAfterregistrationAccessToken;
  if (EverParseIsSuccess(positionAfterUpdateRequest2))
  {
    positionAfterregistrationAccessToken = positionAfterUpdateRequest2;
  }
  else
  {
    ErrorHandlerFn("_update_request",
      "registration_access_token",
      EverParseErrorReasonOfResult(positionAfterUpdateRequest2),
      EverParseGetValidatorErrorKind(positionAfterUpdateRequest2),
      Ctxt,
      Input,
      positionAfterregistrationAccessTokenLength);
    positionAfterregistrationAccessToken = positionAfterUpdateRequest2;
  }
  if (EverParseIsError(positionAfterregistrationAccessToken))
  {
    return positionAfterregistrationAccessToken;
  }
  /* Validating field updated_metadata */
  uint64_t
  positionAfterUpdateRequest3 =
    ValidateClientMetadata(Ctxt,
      ErrorHandlerFn,
      Input,
      InputLength,
      positionAfterregistrationAccessToken);
  if (EverParseIsSuccess(positionAfterUpdateRequest3))
  {
    return positionAfterUpdateRequest3;
  }
  ErrorHandlerFn("_update_request",
    "updated_metadata",
    EverParseErrorReasonOfResult(positionAfterUpdateRequest3),
    EverParseGetValidatorErrorKind(positionAfterUpdateRequest3),
    Ctxt,
    Input,
    positionAfterregistrationAccessToken);
  return positionAfterUpdateRequest3;
}

uint64_t
DcrValidateErrorResponse(
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
  /*  0=invalid_redirect_uri, 1=invalid_client_metadata, 2=invalid_software_statement */
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes0 = 4ULL <= (InputLength - StartPosition);
  uint64_t positionAfterErrorResponse;
  if (hasBytes0)
  {
    positionAfterErrorResponse = StartPosition + 4ULL;
  }
  else
  {
    positionAfterErrorResponse =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        StartPosition);
  }
  uint64_t res0;
  if (EverParseIsSuccess(positionAfterErrorResponse))
  {
    res0 = positionAfterErrorResponse;
  }
  else
  {
    ErrorHandlerFn("_error_response",
      "error_code",
      EverParseErrorReasonOfResult(positionAfterErrorResponse),
      EverParseGetValidatorErrorKind(positionAfterErrorResponse),
      Ctxt,
      Input,
      StartPosition);
    res0 = positionAfterErrorResponse;
  }
  uint64_t positionAftererrorCode = res0;
  if (EverParseIsError(positionAftererrorCode))
  {
    return positionAftererrorCode;
  }
  /* Validating field has_error_description */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes1 = 1ULL <= (InputLength - positionAftererrorCode);
  uint64_t positionAfterErrorResponse0;
  if (hasBytes1)
  {
    positionAfterErrorResponse0 = positionAftererrorCode + 1ULL;
  }
  else
  {
    positionAfterErrorResponse0 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftererrorCode);
  }
  uint64_t res1;
  if (EverParseIsSuccess(positionAfterErrorResponse0))
  {
    res1 = positionAfterErrorResponse0;
  }
  else
  {
    ErrorHandlerFn("_error_response",
      "has_error_description",
      EverParseErrorReasonOfResult(positionAfterErrorResponse0),
      EverParseGetValidatorErrorKind(positionAfterErrorResponse0),
      Ctxt,
      Input,
      positionAftererrorCode);
    res1 = positionAfterErrorResponse0;
  }
  uint64_t positionAfterhasErrorDescription = res1;
  if (EverParseIsError(positionAfterhasErrorDescription))
  {
    return positionAfterhasErrorDescription;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes2 = 4ULL <= (InputLength - positionAfterhasErrorDescription);
  uint64_t positionAfterErrorResponse1;
  if (hasBytes2)
  {
    positionAfterErrorResponse1 = positionAfterhasErrorDescription + 4ULL;
  }
  else
  {
    positionAfterErrorResponse1 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasErrorDescription);
  }
  uint64_t positionAftererrorDescriptionLength;
  if (EverParseIsSuccess(positionAfterErrorResponse1))
  {
    positionAftererrorDescriptionLength = positionAfterErrorResponse1;
  }
  else
  {
    ErrorHandlerFn("_error_response",
      "error_description_length",
      EverParseErrorReasonOfResult(positionAfterErrorResponse1),
      EverParseGetValidatorErrorKind(positionAfterErrorResponse1),
      Ctxt,
      Input,
      positionAfterhasErrorDescription);
    positionAftererrorDescriptionLength = positionAfterErrorResponse1;
  }
  if (EverParseIsError(positionAftererrorDescriptionLength))
  {
    return positionAftererrorDescriptionLength;
  }
  uint32_t errorDescriptionLength = Load32Le(Input + (uint32_t)positionAfterhasErrorDescription);
  /* Validating field error_description */
  BOOLEAN
  hasBytes3 =
    (uint64_t)errorDescriptionLength <= (InputLength - positionAftererrorDescriptionLength);
  uint64_t res2;
  if (hasBytes3)
  {
    res2 = positionAftererrorDescriptionLength + (uint64_t)errorDescriptionLength;
  }
  else
  {
    res2 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftererrorDescriptionLength);
  }
  uint64_t positionAfterErrorResponse2 = res2;
  uint64_t positionAftererrorDescription;
  if (EverParseIsSuccess(positionAfterErrorResponse2))
  {
    positionAftererrorDescription = positionAfterErrorResponse2;
  }
  else
  {
    ErrorHandlerFn("_error_response",
      "error_description",
      EverParseErrorReasonOfResult(positionAfterErrorResponse2),
      EverParseGetValidatorErrorKind(positionAfterErrorResponse2),
      Ctxt,
      Input,
      positionAftererrorDescriptionLength);
    positionAftererrorDescription = positionAfterErrorResponse2;
  }
  if (EverParseIsError(positionAftererrorDescription))
  {
    return positionAftererrorDescription;
  }
  /* Validating field has_error_uri */
  /* Checking that we have enough space for a UINT8, i.e., 1 byte */
  BOOLEAN hasBytes4 = 1ULL <= (InputLength - positionAftererrorDescription);
  uint64_t positionAfterErrorResponse3;
  if (hasBytes4)
  {
    positionAfterErrorResponse3 = positionAftererrorDescription + 1ULL;
  }
  else
  {
    positionAfterErrorResponse3 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftererrorDescription);
  }
  uint64_t res3;
  if (EverParseIsSuccess(positionAfterErrorResponse3))
  {
    res3 = positionAfterErrorResponse3;
  }
  else
  {
    ErrorHandlerFn("_error_response",
      "has_error_uri",
      EverParseErrorReasonOfResult(positionAfterErrorResponse3),
      EverParseGetValidatorErrorKind(positionAfterErrorResponse3),
      Ctxt,
      Input,
      positionAftererrorDescription);
    res3 = positionAfterErrorResponse3;
  }
  uint64_t positionAfterhasErrorUri = res3;
  if (EverParseIsError(positionAfterhasErrorUri))
  {
    return positionAfterhasErrorUri;
  }
  /* Checking that we have enough space for a UINT32, i.e., 4 bytes */
  BOOLEAN hasBytes5 = 4ULL <= (InputLength - positionAfterhasErrorUri);
  uint64_t positionAfterErrorResponse4;
  if (hasBytes5)
  {
    positionAfterErrorResponse4 = positionAfterhasErrorUri + 4ULL;
  }
  else
  {
    positionAfterErrorResponse4 =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAfterhasErrorUri);
  }
  uint64_t positionAftererrorUriLength;
  if (EverParseIsSuccess(positionAfterErrorResponse4))
  {
    positionAftererrorUriLength = positionAfterErrorResponse4;
  }
  else
  {
    ErrorHandlerFn("_error_response",
      "error_uri_length",
      EverParseErrorReasonOfResult(positionAfterErrorResponse4),
      EverParseGetValidatorErrorKind(positionAfterErrorResponse4),
      Ctxt,
      Input,
      positionAfterhasErrorUri);
    positionAftererrorUriLength = positionAfterErrorResponse4;
  }
  if (EverParseIsError(positionAftererrorUriLength))
  {
    return positionAftererrorUriLength;
  }
  uint32_t errorUriLength = Load32Le(Input + (uint32_t)positionAfterhasErrorUri);
  /* Validating field error_uri */
  BOOLEAN hasBytes = (uint64_t)errorUriLength <= (InputLength - positionAftererrorUriLength);
  uint64_t res;
  if (hasBytes)
  {
    res = positionAftererrorUriLength + (uint64_t)errorUriLength;
  }
  else
  {
    res =
      EverParseSetValidatorErrorPos(EVERPARSE_VALIDATOR_ERROR_NOT_ENOUGH_DATA,
        positionAftererrorUriLength);
  }
  uint64_t positionAfterErrorResponse5 = res;
  if (EverParseIsSuccess(positionAfterErrorResponse5))
  {
    return positionAfterErrorResponse5;
  }
  ErrorHandlerFn("_error_response",
    "error_uri",
    EverParseErrorReasonOfResult(positionAfterErrorResponse5),
    EverParseGetValidatorErrorKind(positionAfterErrorResponse5),
    Ctxt,
    Input,
    positionAftererrorUriLength);
  return positionAfterErrorResponse5;
}
