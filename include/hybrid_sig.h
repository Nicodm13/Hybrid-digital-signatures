#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *ecdsa_sig;
    size_t   ecdsa_sig_len;
    uint8_t *pq_sig;
    size_t   pq_sig_len;
} hybrid_signature_t;

int hybrid_init(void);
int hybrid_sign(const uint8_t *msg, size_t msg_len, hybrid_signature_t *out);
int hybrid_verify(const uint8_t *msg, size_t msg_len, const hybrid_signature_t *sig);
void hybrid_signature_free(hybrid_signature_t *sig);
void hybrid_cleanup(void);
