#include "hybrid_signature.h"
#include "config.h"
#include "scheme.h"
#include "hash.h"

#include "ecdsa_sig.h"
#include "rsa_pss_sig.h"
#include "dilithium_sig.h"
#include "falcon_sig.h"
#include "sphincs_sig.h"

#include <stdint.h>
#include <string.h>

static void write_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

int hybrid_sign_image(
    const uint8_t *image,
    size_t image_len,
    hybrid_signature_t *out_sig
) {
    if (!image || !out_sig)
        return -1;

    uint8_t hash[HASH_LEN];
    sha256(image, image_len, hash);

    uint8_t *sig1 = NULL;
    uint8_t *sig2 = NULL;
    size_t sig1_len = 0;
    size_t sig2_len = 0;

    switch (HYBRID_SCHEME) {

        case SCHEME_ECDSA_SPHINCS:
            ecdsa_sign_hash(hash, HASH_LEN, &sig1, &sig1_len);
            sphincs_sign_hash(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_ECDSA_ML_DSA:
            ecdsa_sign_hash(hash, HASH_LEN, &sig1, &sig1_len);
            dilithium_sign_hash(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_ECDSA_FALCON:
            ecdsa_sign_hash(hash, HASH_LEN, &sig1, &sig1_len);
            falcon_sign_hash(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_RSA_PSS_SPHINCS:
            rsa_pss_sign_hash(hash, HASH_LEN, &sig1, &sig1_len);
            sphincs_sign_hash(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_RSA_PSS_ML_DSA:
            rsa_pss_sign_hash(hash, HASH_LEN, &sig1, &sig1_len);
            dilithium_sign_hash(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_RSA_PSS_FALCON:
            rsa_pss_sign_hash(hash, HASH_LEN, &sig1, &sig1_len);
            falcon_sign_hash(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        default:
            return -2;
    }

    size_t total_len = 2 + sig1_len + 2 + sig2_len;
    if (total_len > HYBRID_MAX_SIG_SIZE)
        return -3;

    uint8_t *p = out_sig->data;

    write_u16(p, (uint16_t)sig1_len);
    p += 2;
    memcpy(p, sig1, sig1_len);
    p += sig1_len;

    write_u16(p, (uint16_t)sig2_len);
    p += 2;
    memcpy(p, sig2, sig2_len);
    p += sig2_len;

    out_sig->len = total_len;
    return 0;
}

int hybrid_verify_image(
    const uint8_t *image,
    size_t image_len,
    const hybrid_signature_t *sig
) {
    if (!image || !sig || sig->len < 4)
        return -1;

    uint8_t hash[HASH_LEN];
    sha256(image, image_len, hash);

    const uint8_t *p = sig->data;
    size_t remaining = sig->len;

    uint16_t sig1_len = read_u16(p);
    p += 2;
    remaining -= 2;

    if (sig1_len > remaining)
        return -2;

    const uint8_t *sig1 = p;
    p += sig1_len;
    remaining -= sig1_len;

    if (remaining < 2)
        return -3;

    uint16_t sig2_len = read_u16(p);
    p += 2;
    remaining -= 2;

    if (sig2_len != remaining)
        return -4;

    const uint8_t *sig2 = p;

    switch (HYBRID_SCHEME) {

        case SCHEME_ECDSA_SPHINCS:
            return ecdsa_verify_hash(hash, HASH_LEN, sig1, sig1_len) == 0 &&
                   sphincs_verify_hash(hash, HASH_LEN, sig2, sig2_len) == 0;

        case SCHEME_ECDSA_ML_DSA:
            return ecdsa_verify_hash(hash, HASH_LEN, sig1, sig1_len) == 0 &&
                   dilithium_verify_hash(hash, HASH_LEN, sig2, sig2_len) == 0;

        case SCHEME_ECDSA_FALCON:
            return ecdsa_verify_hash(hash, HASH_LEN, sig1, sig1_len) == 0 &&
                   falcon_verify_hash(hash, HASH_LEN, sig2, sig2_len) == 0;

        case SCHEME_RSA_PSS_ML_DSA:
            return rsa_pss_verify_hash(hash, HASH_LEN, sig1, sig1_len) == 0 &&
                   dilithium_verify_hash(hash, HASH_LEN, sig2, sig2_len) == 0;

        default:
            return -5;
    }
}
