#ifndef FALCON_SIG_H
#define FALCON_SIG_H

#include <stddef.h>
#include <stdint.h>

int falcon_keygen(void);
int falcon_sign(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len);
int falcon_verify(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);
int falcon_get_public_key(uint8_t **out, size_t *out_len);

#endif
