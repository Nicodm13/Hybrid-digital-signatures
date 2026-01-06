#pragma once
#include <stddef.h>
#include <stdint.h>

int ecdsa_keygen(void);
int ecdsa_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len);
int ecdsa_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len);
void ecdsa_cleanup(void);
