#include "IdTokenSchemaWrapper.h"
#include "EverParse.h"
#include "IdTokenSchema.h"
void IdTokenSchemaEverParseError(const char *StructName, const char *FieldName, const char *Reason);

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

BOOLEAN IdTokenSchemaCheckIdTokenJwtEntry(uint8_t *base, uint32_t len) {
	EVERPARSE_ERROR_FRAME frame;
	frame.filled = FALSE;
	uint64_t result = IdTokenSchemaValidateIdTokenJwtEntry( (uint8_t*)&frame, &DefaultErrorHandler, base, len, 0);
	if (EverParseIsError(result))
	{
		if (frame.filled)
		{
			IdTokenSchemaEverParseError(frame.typename_s, frame.fieldname, frame.reason);
		}
		return FALSE;
	}
	return TRUE;
}

BOOLEAN IdTokenSchemaCheckIdTokenClaimsEntry(uint8_t *base, uint32_t len) {
	EVERPARSE_ERROR_FRAME frame;
	frame.filled = FALSE;
	uint64_t result = IdTokenSchemaValidateIdTokenClaimsEntry( (uint8_t*)&frame, &DefaultErrorHandler, base, len, 0);
	if (EverParseIsError(result))
	{
		if (frame.filled)
		{
			IdTokenSchemaEverParseError(frame.typename_s, frame.fieldname, frame.reason);
		}
		return FALSE;
	}
	return TRUE;
}

BOOLEAN IdTokenSchemaCheckUserinfoResponseEntry(uint8_t *base, uint32_t len) {
	EVERPARSE_ERROR_FRAME frame;
	frame.filled = FALSE;
	uint64_t result = IdTokenSchemaValidateUserinfoResponseEntry( (uint8_t*)&frame, &DefaultErrorHandler, base, len, 0);
	if (EverParseIsError(result))
	{
		if (frame.filled)
		{
			IdTokenSchemaEverParseError(frame.typename_s, frame.fieldname, frame.reason);
		}
		return FALSE;
	}
	return TRUE;
}
