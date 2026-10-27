#include "crypto_init.h"
#include "EverCrypt_AutoConfig2.h"
#include <pthread.h>
#include <stdlib.h>
/* Publish one shared CPU policy before native crypto reads it. Callers must
 * synchronize explicit feature-policy changes with concurrent crypto use. */
static pthread_once_t initialization = PTHREAD_ONCE_INIT;
void aegaeon_crypto_init(void) {
  if (pthread_once(&initialization, EverCrypt_AutoConfig2_init) != 0)
    abort();
}
