#ifndef AEG_WASI_STUB_STDDEF_H
#define AEG_WASI_STUB_STDDEF_H

typedef unsigned long size_t;
typedef long ptrdiff_t;
typedef unsigned int wchar_t;

#define NULL ((void *)0)
#define offsetof(type, member) __builtin_offsetof(type, member)

#endif /* AEG_WASI_STUB_STDDEF_H */
