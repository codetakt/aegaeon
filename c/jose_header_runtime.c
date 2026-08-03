#include <stdint.h>

#include "JoseHeaderWrapper.h"

uint32_t Jose_HeaderParser_Runtime_jose_header_entry_error_code(
    uint8_t *input,
    uint32_t input_len)
{
    return (uint32_t)JoseHeaderGetJoseHeaderEntryErrorCode(input, input_len);
}
