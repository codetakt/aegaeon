#ifndef AEG_WASI_STUB_STDIO_H
#define AEG_WASI_STUB_STDIO_H

typedef void FILE;
extern FILE *stderr;

int fprintf(FILE *stream, const char *format, ...);
int printf(const char *format, ...);

#endif /* AEG_WASI_STUB_STDIO_H */
