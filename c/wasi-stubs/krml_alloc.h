/* Minimal allocator declarations for HACL* C files.
 * HACL* uses KRML_HOST_CALLOC (expands to calloc) but does not include <stdlib.h>.
 * Including full <stdlib.h> from the WASI sysroot causes type conflicts.
 * This header provides ONLY allocator declarations using compiler builtins. */
#ifndef KRML_ALLOC_H
#define KRML_ALLOC_H
typedef __SIZE_TYPE__ __krml_size_t;
void *malloc(__krml_size_t);
void *calloc(__krml_size_t, __krml_size_t);
void *realloc(void *, __krml_size_t);
void free(void *);
#endif
