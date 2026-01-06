#pragma once
#include <stddef.h>
#include <stdint.h>

int dilithium_keygen(void);
int dilithium_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len);
int dilithium_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len);
void dilithium_cleanup(void);
