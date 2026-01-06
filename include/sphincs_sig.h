#pragma once
#include <stddef.h>
#include <stdint.h>

int sphincs_keygen(void);
int sphincs_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len);
int sphincs_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len);
void sphincs_cleanup(void);
