#include "observe.h"
/* Runs in the actual dynamic target at loader initialization, same PID after
 * exec. This adds an observer and establishes functional context only. */
__attribute__((constructor)) static void entry(void) { observe("target", 0); }
