#pragma once
#include <stddef.h>
#include <stdint.h>

int rsa_pss_keygen(void);

/* Signs a precomputed hash (e.g., SHA-256 digest). */
int rsa_pss_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len);

/* Verifies a signature over a precomputed hash. */
int rsa_pss_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len);

void rsa_pss_cleanup(void);
