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
            if (!sphincs_get_public_key(&pk2, &l2)) { free(pk1); return 0; }
            break;

        case SCHEME_ECDSA_ML_DSA:
            if (!ecdsa_get_public_key(&pk1, &l1)) return 0;
            if (!dilithium_get_public_key(&pk2, &l2)) { free(pk1); return 0; }
            break;

        case SCHEME_ECDSA_FALCON:
            if (!ecdsa_get_public_key(&pk1, &l1)) return 0;
            if (!falcon_get_public_key(&pk2, &l2)) { free(pk1); return 0; }
            break;

        /* RSA-PSS public key is transported inside the signature blob */
        case SCHEME_RSA_PSS_SPHINCS:
            l1 = 0; pk1 = NULL;
            if (!sphincs_get_public_key(&pk2, &l2)) return 0;
            break;

        case SCHEME_RSA_PSS_ML_DSA:
            l1 = 0; pk1 = NULL;
            if (!dilithium_get_public_key(&pk2, &l2)) return 0;
            break;

        case SCHEME_RSA_PSS_FALCON:
            l1 = 0; pk1 = NULL;
            if (!falcon_get_public_key(&pk2, &l2)) return 0;
            break;

        default:
            return 0;
    }

    *out_len = 2 + l1 + 2 + l2;
    *out = (uint8_t *)malloc(*out_len);
    if (!*out) {
        free(pk1);
        free(pk2);
        return 0;
    }

    uint8_t *p = *out;
    write_u16(p, (uint16_t)l1); p += 2;
    if (l1) { memcpy(p, pk1, l1); p += l1; }
    write_u16(p, (uint16_t)l2); p += 2;
    if (l2) { memcpy(p, pk2, l2); }

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

    /* RSA-only transported key */
    uint8_t *rsa_pk = NULL;
    size_t rsa_pk_len = 0;

    switch (HYBRID_SCHEME) {

        case SCHEME_ECDSA_SPHINCS:
            if (!ecdsa_sign(hash, HASH_LEN, &sig1, &sig1_len)) return -2;
            if (!sphincs_sign(hash, HASH_LEN, &sig2, &sig2_len)) { free(sig1); return -2; }
            break;

        case SCHEME_ECDSA_ML_DSA:
            if (!ecdsa_sign(hash, HASH_LEN, &sig1, &sig1_len)) return -2;
            if (!dilithium_sign(hash, HASH_LEN, &sig2, &sig2_len)) { free(sig1); return -2; }
            break;

        case SCHEME_ECDSA_FALCON:
            if (!ecdsa_sign(hash, HASH_LEN, &sig1, &sig1_len)) return -2;
            if (!falcon_sign(hash, HASH_LEN, &sig2, &sig2_len)) { free(sig1); return -2; }
            break;

        case SCHEME_RSA_PSS_SPHINCS:
            if (!rsa_pss_sign(hash, HASH_LEN, &sig1, &sig1_len)) return -2;
            if (!rsa_pss_get_public_key(&rsa_pk, &rsa_pk_len)) { free(sig1); return -2; }
            if (!sphincs_sign(hash, HASH_LEN, &sig2, &sig2_len)) { free(sig1); free(rsa_pk); return -2; }
            break;

        case SCHEME_RSA_PSS_ML_DSA:
            if (!rsa_pss_sign(hash, HASH_LEN, &sig1, &sig1_len)) return -2;
            if (!rsa_pss_get_public_key(&rsa_pk, &rsa_pk_len)) { free(sig1); return -2; }
            if (!dilithium_sign(hash, HASH_LEN, &sig2, &sig2_len)) { free(sig1); free(rsa_pk); return -2; }
            break;

        case SCHEME_RSA_PSS_FALCON:
            if (!rsa_pss_sign(hash, HASH_LEN, &sig1, &sig1_len)) return -2;
            if (!rsa_pss_get_public_key(&rsa_pk, &rsa_pk_len)) { free(sig1); return -2; }
            if (!falcon_sign(hash, HASH_LEN, &sig2, &sig2_len)) { free(sig1); free(rsa_pk); return -2; }
            break;

        default:
            return -3;
    }

    size_t total_len;
    if (HYBRID_SCHEME == SCHEME_RSA_PSS_SPHINCS ||
        HYBRID_SCHEME == SCHEME_RSA_PSS_ML_DSA ||
        HYBRID_SCHEME == SCHEME_RSA_PSS_FALCON) {

        /* [u16 rsa_sig_len][rsa_sig][u16 rsa_pk_len][rsa_pk][u16 sig2_len][sig2] */
        total_len = 2 + sig1_len + 2 + rsa_pk_len + 2 + sig2_len;
    } else {
        /* [u16 sig1_len][sig1][u16 sig2_len][sig2] */
        total_len = 2 + sig1_len + 2 + sig2_len;
    }

    if (total_len > HYBRID_MAX_SIG_SIZE) {
        free(sig1);
        free(sig2);
        free(rsa_pk);
        return -4;
    }

    uint8_t *p = out_sig->data;

    if (HYBRID_SCHEME == SCHEME_RSA_PSS_SPHINCS ||
        HYBRID_SCHEME == SCHEME_RSA_PSS_ML_DSA ||
        HYBRID_SCHEME == SCHEME_RSA_PSS_FALCON) {

        write_u16(p, (uint16_t)sig1_len); p += 2;
        memcpy(p, sig1, sig1_len); p += sig1_len;

        write_u16(p, (uint16_t)rsa_pk_len); p += 2;
        memcpy(p, rsa_pk, rsa_pk_len); p += rsa_pk_len;

        write_u16(p, (uint16_t)sig2_len); p += 2;
        memcpy(p, sig2, sig2_len); p += sig2_len;

    } else {
        write_u16(p, (uint16_t)sig1_len); p += 2;
        memcpy(p, sig1, sig1_len); p += sig1_len;

        write_u16(p, (uint16_t)sig2_len); p += 2;
        memcpy(p, sig2, sig2_len); p += sig2_len;
    }

    out_sig->len = total_len;

    free(sig1);
    free(sig2);
    free(rsa_pk);
    return 0;
}

int hybrid_verify_image(const uint8_t *image, size_t image_len,
                        const hybrid_signature_t *sig,
                        const uint8_t *pubkeys, size_t pubkeys_len)
{
    if (!image || !sig || sig->len < 4)
        return -1;

    uint8_t hash[HASH_LEN];
    sha256(image, image_len, hash);

    /* Parse public keys */
    if (!pubkeys || pubkeys_len < 4) return -2;
    const uint8_t *k = pubkeys;
    uint16_t pk1_len = read_u16(k); k += 2;
    const uint8_t *pk1 = k; k += pk1_len;
    if ((size_t)(k - pubkeys) + 2 > pubkeys_len) return -3;
    uint16_t pk2_len = read_u16(k); k += 2;
    const uint8_t *pk2 = k;
    if ((size_t)(k - pubkeys) + pk2_len > pubkeys_len) return -4;

    /* Parse signature */
    const uint8_t *p = sig->data;
    size_t remaining = sig->len;

    if (HYBRID_SCHEME == SCHEME_RSA_PSS_SPHINCS ||
        HYBRID_SCHEME == SCHEME_RSA_PSS_ML_DSA ||
        HYBRID_SCHEME == SCHEME_RSA_PSS_FALCON) {

        /* [u16 rsa_sig_len][rsa_sig][u16 rsa_pk_len][rsa_pk][u16 sig2_len][sig2] */

        if (remaining < 2) return -5;
        uint16_t rsa_sig_len = read_u16(p); p += 2; remaining -= 2;
        if (rsa_sig_len > remaining) return -6;
        const uint8_t *rsa_sig = p; p += rsa_sig_len; remaining -= rsa_sig_len;

        if (remaining < 2) return -7;
        uint16_t rsa_pk_len = read_u16(p); p += 2; remaining -= 2;
        if (rsa_pk_len > remaining) return -8;
        const uint8_t *rsa_pk = p; p += rsa_pk_len; remaining -= rsa_pk_len;

        if (remaining < 2) return -9;
        uint16_t sig2_len = read_u16(p); p += 2; remaining -= 2;
        if (sig2_len != remaining) return -10;
        const uint8_t *sig2 = p;

        /* Verify RSA using embedded key, PQ using pubkeys */
        switch (HYBRID_SCHEME) {

            case SCHEME_RSA_PSS_SPHINCS:
                return rsa_pss_verify(hash, HASH_LEN, rsa_sig, rsa_sig_len, rsa_pk, rsa_pk_len) &&
                       (sphincs_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0);

            case SCHEME_RSA_PSS_ML_DSA:
                return rsa_pss_verify(hash, HASH_LEN, rsa_sig, rsa_sig_len, rsa_pk, rsa_pk_len) &&
                       (dilithium_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0);

            case SCHEME_RSA_PSS_FALCON:
                return rsa_pss_verify(hash, HASH_LEN, rsa_sig, rsa_sig_len, rsa_pk, rsa_pk_len) &&
                       (falcon_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0);

            default:
                return -11;
        }

    } else {

        /* Non-RSA format: [u16 sig1_len][sig1][u16 sig2_len][sig2] */

        uint16_t sig1_len = read_u16(p); p += 2; remaining -= 2;
        if (sig1_len > remaining) return -12;
        const uint8_t *sig1 = p; p += sig1_len; remaining -= sig1_len;
        if (remaining < 2) return -13;

        uint16_t sig2_len = read_u16(p); p += 2; remaining -= 2;
        if (sig2_len != remaining) return -14;
        const uint8_t *sig2 = p;

        switch (HYBRID_SCHEME) {

            case SCHEME_ECDSA_SPHINCS:
                return (ecdsa_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0) &&
                       (sphincs_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0);

            case SCHEME_ECDSA_ML_DSA:
                return (ecdsa_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0) &&
                       (dilithium_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0);

            case SCHEME_ECDSA_FALCON:
                return (ecdsa_verify(hash, HASH_LEN, sig1, sig1_len, pk1, pk1_len) == 0) &&
                       (falcon_verify(hash, HASH_LEN, sig2, sig2_len, pk2, pk2_len) == 0);

            default:
                return -15;
        }
    }
}
