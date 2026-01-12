#ifndef HYBRID_SIGNER_H
#define HYBRID_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#define HYBRID_MAX_SIG_SIZE (32 * 1024)

typedef struct {
    uint8_t data[HYBRID_MAX_SIG_SIZE];
    size_t  len;
} hybrid_signature_t;

int hybrid_get_public_keys(uint8_t **out, size_t *out_len);
int hybrid_sign_image(const uint8_t *image, size_t image_len, hybrid_signature_t *out_sig);
int hybrid_verify_image(const uint8_t *image, size_t image_len, const hybrid_signature_t *sig, const uint8_t *pubkeys, size_t pubkeys_len);


#endif
