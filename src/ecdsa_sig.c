#include "ecdsa_sig.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

static EVP_PKEY *g_ecdsa_key = NULL;

int ecdsa_keygen(void) {
    if (g_ecdsa_key) return 0;

    int rc = -1;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) goto done;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) goto done;

    if (EVP_PKEY_keygen(ctx, &g_ecdsa_key) <= 0) goto done;

    rc = 0;

done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* Signs a precomputed hash. For ECDSA, EVP_PKEY_sign signs the digest directly. */
int ecdsa_sign_hash(const uint8_t *hash, size_t hash_len, uint8_t **sig, size_t *sig_len) {
    if (!hash || !sig || !sig_len) return -1;
    if (!g_ecdsa_key && ecdsa_keygen() != 0) return -1;

    int rc = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(g_ecdsa_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_sign_init(ctx) <= 0) goto done;

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

int ecdsa_verify_hash(const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len) {
    if (!hash || !sig) return -1;
    if (!g_ecdsa_key) return -1;

    int rc = -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(g_ecdsa_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_verify_init(ctx) <= 0) goto done;

    int ok = EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len);
    rc = (ok == 1) ? 0 : -1;

done:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

void ecdsa_cleanup(void) {
    EVP_PKEY_free(g_ecdsa_key);
    g_ecdsa_key = NULL;
}
