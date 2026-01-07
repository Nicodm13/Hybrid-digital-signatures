//
// Created by Nico2 on 06/01/2026.
//
#include "rsa_pss_sig.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdlib.h>

static EVP_PKEY *g_rsa_key = NULL;

/* Choose a key size. 2048 is faster; 3072 is a more conservative classical level. */
#ifndef RSA_PSS_BITS
#define RSA_PSS_BITS 3072
#endif

int rsa_pss_keygen(void) {
    if (g_rsa_key) return 0;

    int rc = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_PSS_BITS) <= 0) goto done;

    if (EVP_PKEY_keygen(ctx, &g_rsa_key) <= 0) goto done;

    rc = 0;

done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int rsa_pss_config_ctx(EVP_PKEY_CTX *ctx, size_t hash_len) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) return -1;

    /* Use SHA-256 as the PSS hash/MGF1 hash unless you deliberately change it. */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) return -1;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) return -1;

    /* Salt length: typically equals hash length. */
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, (int)hash_len) <= 0) return -1;

    return 0;
}

int rsa_pss_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len) {
    if (!hash || !sig || !sig_len) return -1;
    if (!g_rsa_key && rsa_pss_keygen() != 0) return -1;

    int rc = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(g_rsa_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_sign_init(ctx) <= 0) goto done;
    if (rsa_pss_config_ctx(ctx, hash_len) != 0) goto done;

    size_t out_len = 0;
    if (EVP_PKEY_sign(ctx, NULL, &out_len, hash, hash_len) <= 0) goto done;

    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) goto done;

    if (EVP_PKEY_sign(ctx, out, &out_len, hash, hash_len) <= 0) {
        free(out);
        goto done;
    }

    *sig = out;
    *sig_len = out_len;
    rc = 0;

done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int rsa_pss_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len) {
    if (!hash || !sig) return -1;
    if (!g_rsa_key) return -1;

    int rc = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(g_rsa_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_verify_init(ctx) <= 0) goto done;
    if (rsa_pss_config_ctx(ctx, hash_len) != 0) goto done;

    int ok = EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len);
    rc = (ok == 1) ? 0 : -1;

done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

void rsa_pss_cleanup(void) {
    EVP_PKEY_free(g_rsa_key);
    g_rsa_key = NULL;
}
