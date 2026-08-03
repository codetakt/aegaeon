#ifndef AEG_WASI_STUB_STRING_H
#define AEG_WASI_STUB_STRING_H

#include <stdint.h>

typedef unsigned long size_t;

void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);

#endif /* AEG_WASI_STUB_STRING_H */
