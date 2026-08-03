#ifndef AEG_WASI_STUB_STDLIB_H
#define AEG_WASI_STUB_STDLIB_H

#include <stdint.h>

typedef __SIZE_TYPE__ size_t;

void exit(int status);
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

#endif /* AEG_WASI_STUB_STDLIB_H */
