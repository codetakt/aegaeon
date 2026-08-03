#include "JoseHeaderWrapper.h"
#include "EverParse.h"
#include "JoseHeader.h"
void JoseHeaderEverParseError(const char *StructName, const char *FieldName, const char *Reason);

static
void DefaultErrorHandler(
    const char *typename_s,
    const char *fieldname,
    const char *reason,
    uint64_t error_code,
    uint8_t *context,
    EVERPARSE_INPUT_BUFFER input,
    uint64_t start_pos)
{
    EVERPARSE_ERROR_FRAME *frame = (EVERPARSE_ERROR_FRAME*)context;
    EverParseDefaultErrorHandler(
        typename_s,
        fieldname,
        reason,
        error_code,
        frame,
        input,
        start_pos
    );
}

static
uint64_t JoseHeaderRunValidation(
    uint8_t *base,
    uint32_t len,
    EVERPARSE_ERROR_FRAME *frame)
{
    frame->filled = FALSE;
    return JoseHeaderValidateJoseHeaderEntry(
        (uint8_t *)frame,
        &DefaultErrorHandler,
        base,
        len,
        0
    );
}

BOOLEAN JoseHeaderCheckJoseHeaderEntry(uint8_t *base, uint32_t len) {
    EVERPARSE_ERROR_FRAME frame;
    uint64_t result = JoseHeaderRunValidation(base, len, &frame);
    if (EverParseIsError(result))
    {
        if (frame.filled)
        {
            JoseHeaderEverParseError(frame.typename_s, frame.fieldname, frame.reason);
        }
        return FALSE;
    }
    return TRUE;
}

uint64_t JoseHeaderGetJoseHeaderEntryErrorCode(uint8_t *base, uint32_t len) {
    EVERPARSE_ERROR_FRAME frame;
    uint64_t result = JoseHeaderRunValidation(base, len, &frame);
    if (EverParseIsError(result))
    {
        if (frame.filled)
        {
            JoseHeaderEverParseError(frame.typename_s, frame.fieldname, frame.reason);
        }
        return EverParseGetValidatorErrorKind(result);
    }
    return EVERPARSE_SUCCESS;
}
