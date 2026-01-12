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
#include <stdlib.h>
#include <string.h>

/* ================= helpers ================= */

static void write_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}


int hybrid_get_public_keys(uint8_t **out, size_t *out_len)
{
    uint8_t *pk1 = NULL, *pk2 = NULL;
    size_t l1 = 0, l2 = 0;

    switch (HYBRID_SCHEME) {

        case SCHEME_ECDSA_SPHINCS:
            if (!ecdsa_get_public_key(&pk1, &l1)) return 0;
            if (!sphincs_get_public_key(&pk2, &l2)) return 0;
            break;

        case SCHEME_ECDSA_ML_DSA:
            if (!ecdsa_get_public_key(&pk1, &l1)) return 0;
            if (!dilithium_get_public_key(&pk2, &l2)) return 0;
            break;

        case SCHEME_ECDSA_FALCON:
            if (!ecdsa_get_public_key(&pk1, &l1)) return 0;
            if (!falcon_get_public_key(&pk2, &l2)) return 0;
            break;

        case SCHEME_RSA_PSS_SPHINCS:
            if (!rsa_pss_get_public_key(&pk1, &l1)) return 0;
            if (!sphincs_get_public_key(&pk2, &l2)) return 0;
            break;

        case SCHEME_RSA_PSS_ML_DSA:
            if (!rsa_pss_get_public_key(&pk1, &l1)) return 0;
            if (!dilithium_get_public_key(&pk2, &l2)) return 0;
            break;

        case SCHEME_RSA_PSS_FALCON:
            if (!rsa_pss_get_public_key(&pk1, &l1)) return 0;
            if (!falcon_get_public_key(&pk2, &l2)) return 0;
            break;

        default:
            return 0;
    }

    *out_len = 2 + l1 + 2 + l2;
    *out = malloc(*out_len);
    if (!*out) return 0;

    uint8_t *p = *out;
    write_u16(p, (uint16_t)l1); p += 2;
    memcpy(p, pk1, l1); p += l1;
    write_u16(p, (uint16_t)l2); p += 2;
    memcpy(p, pk2, l2);

    free(pk1);
    free(pk2);
    return 1;
}

int hybrid_sign_image(const uint8_t *image, size_t image_len, hybrid_signature_t *out_sig)
{
    if (!image || !out_sig)
        return -1;

    uint8_t hash[HASH_LEN];
    sha256(image, image_len, hash);

    uint8_t *sig1 = NULL, *sig2 = NULL;
    size_t sig1_len = 0, sig2_len = 0;

    switch (HYBRID_SCHEME) {

        case SCHEME_ECDSA_SPHINCS:
            ecdsa_sign(hash, HASH_LEN, &sig1, &sig1_len);
            sphincs_sign(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_ECDSA_ML_DSA:
            ecdsa_sign(hash, HASH_LEN, &sig1, &sig1_len);
            dilithium_sign(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_ECDSA_FALCON:
            ecdsa_sign(hash, HASH_LEN, &sig1, &sig1_len);
            falcon_sign(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_RSA_PSS_SPHINCS:
            rsa_pss_sign(hash, HASH_LEN, &sig1, &sig1_len);
            sphincs_sign(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_RSA_PSS_ML_DSA:
            rsa_pss_sign(hash, HASH_LEN, &sig1, &sig1_len);
            dilithium_sign(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        case SCHEME_RSA_PSS_FALCON:
            rsa_pss_sign(hash, HASH_LEN, &sig1, &sig1_len);
            falcon_sign(hash, HASH_LEN, &sig2, &sig2_len);
            break;

        default:
            return -2;
    }

    size_t total_len = 2 + sig1_len + 2 + sig2_len;
    if (total_len > HYBRID_MAX_SIG_SIZE)
        return -3;

    uint8_t *p = out_sig->data;
    write_u16(p, (uint16_t)sig1_len); p += 2;
    memcpy(p, sig1, sig1_len); p += sig1_len;
    write_u16(p, (uint16_t)sig2_len); p += 2;
    memcpy(p, sig2, sig2_len);

    out_sig->len = total_len;

    free(sig1);
    free(sig2);
    return 0;
}

int hybrid_verify_image(const uint8_t *image, size_t image_len, const hybrid_signature_t *sig, const uint8_t *pubkeys, size_t pubkeys_len)
{
    if (!image || !sig || !pubkeys || sig->len < 4)
        return -1;

    uint8_t hash[HASH_LEN];
    sha256(image, image_len, hash);

    /* parse signature */
    const uint8_t *p = sig->data;
    size_t remaining = sig->len;

    uint16_t sig1_len = read_u16(p); p += 2; remaining -= 2;
    if (sig1_len > remaining) return -2;

    const uint8_t *sig1 = p; p += sig1_len; remaining -= sig1_len;
    if (remaining < 2) return -3;

    uint16_t sig2_len = read_u16(p); p += 2; remaining -= 2;
    if (sig2_len != remaining) return -4;

    const uint8_t *sig2 = p;

    /* parse public keys */
    if (pubkeys_len < 4) return -5;

    const uint8_t *k = pubkeys;
    uint16_t pk1_len = read_u16(k); k += 2;
    const uint8_t *pk1 = k; k += pk1_len;
    uint16_t pk2_len = read_u16(k); k += 2;
    const uint8_t *pk2 = k;

    switch (HYBRID_SCHEME) {

        case SCHEME_ECDSA_SPHINCS:
            return ecdsa_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0 &&
                   sphincs_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0;

        case SCHEME_ECDSA_ML_DSA:
            return ecdsa_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0 &&
                   dilithium_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0;

        case SCHEME_ECDSA_FALCON:
            return ecdsa_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0 &&
                   falcon_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0;

        case SCHEME_RSA_PSS_SPHINCS:
            return rsa_pss_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0 &&
                   sphincs_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0;

        case SCHEME_RSA_PSS_ML_DSA:
            return rsa_pss_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0 &&
                   dilithium_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0;

        case SCHEME_RSA_PSS_FALCON:
            return rsa_pss_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0 &&
                   falcon_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0;

        default:
            return -6;
    }
}
