#ifndef ECDSA_SIG_H
#define ECDSA_SIG_H

#include <stddef.h>
#include <stdint.h>

int ecdsa_keygen(void);
int ecdsa_sign(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len);
int ecdsa_verify(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len, const uint8_t *pubkey, size_t pubkey_len);
int ecdsa_get_public_key(uint8_t **out, size_t *out_len);

#endif
