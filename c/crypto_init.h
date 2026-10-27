#ifndef AEGAEON_CRYPTO_INIT_H
#define AEGAEON_CRYPTO_INIT_H
/* Call before every native Aegaeon entry point that can access EverCrypt CPU
 * policy. Configuration mutations remain a caller-synchronized startup action.
 */
void aegaeon_crypto_init(void);
#endif
