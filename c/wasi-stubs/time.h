#ifndef AEG_WASI_STUB_TIME_H
#define AEG_WASI_STUB_TIME_H

/* Minimal time.h stub for KaRaMeL-extracted WASM code.
 * clock_t, time_t, struct timespec are provided by the WASI sysroot's
 * <sys/types.h> / <bits/alltypes.h> in a full toolchain.  In the direct
 * wasm build path used by our local verification flow, KaRaMeL's target shim
 * also references `time(NULL)`, so we provide a minimal declaration here. */

#include <stdint.h>

typedef int64_t time_t;

time_t time(time_t *seconds);

#define CLOCKS_PER_SEC 1000000

#endif /* AEG_WASI_STUB_TIME_H */
