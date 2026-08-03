#ifndef AEG_WASI_STUB_ASSERT_H
#define AEG_WASI_STUB_ASSERT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef assert
#define assert(expr) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* AEG_WASI_STUB_ASSERT_H */
