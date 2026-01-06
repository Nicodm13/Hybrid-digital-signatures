#pragma once
#include <stddef.h>
#include <stdint.h>

int falcon_keygen(void);
int falcon_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len);
int falcon_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len);
void falcon_cleanup(void);
